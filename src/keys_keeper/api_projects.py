"""Authenticated, local-only Admin API for catalog organization."""
from __future__ import annotations

import json
from urllib.parse import ParseResult, parse_qs, unquote

from keys_keeper.project_service import ProjectCatalogError, ProjectService
from keys_keeper.store import MetadataStore, NotFound, StoreError


def _body(body: bytes | None) -> dict:
    try:
        value = json.loads(body or b"{}")
    except (TypeError, json.JSONDecodeError) as ex:
        raise ValueError("request body must be a JSON object") from ex
    if not isinstance(value, dict):
        raise ValueError("request body must be a JSON object")
    return value


def _catalog_payload(paths, *, context=None) -> dict:
    """Return catalog data only from an authoritative master context."""
    if context is not None and context.kind != "master":
        return {
            "enabled": False,
            "schema_version": None,
            "entries": [],
            "shared_usages": {},
            "recipients": [],
            "delivery": "not_available_for_selected_profile",
            "profile": {"kind": context.kind, "profile_id": context.profile_id},
        }
    store = context.store if context is not None else MetadataStore(paths)
    try:
        catalog = store.catalog_state()
    except StoreError as ex:
        if "explicit schema-v3 migration" not in str(ex):
            raise
        return {"enabled": False, "schema_version": 2}
    entries = [
        {"id": entry.id, "name": entry.name, "type": entry.type.value,
         "folder_id": entry.folder_id, "distribution": entry.distribution}
        for entry in store.list()
    ]
    shared_usages = ProjectService(store).effective_shared_usages()
    return {"enabled": True, "schema_version": 3, "catalog": catalog, "entries": entries,
            "shared_usages": shared_usages,
            "recipients": [], "delivery": "not_implemented"}


def dispatch_project_api(handler, paths, method: str, parsed: ParseResult, body: bytes | None,
                         *, context=None) -> bool:
    """Handle `/api/projects*`; always return False for other API prefixes."""
    if not parsed.path.startswith("/api/projects"):
        return False
    try:
        if context is not None and context.kind != "master":
            if method == "GET" and parsed.path == "/api/projects":
                handler._send_json(200, _catalog_payload(paths, context=context))
            else:
                handler._send_json(403, {"error": "project catalog is managed by the master profile"})
            return True
        store = context.store if context is not None else MetadataStore(paths)
        service = ProjectService(store)
        route = parsed.path
        if method == "GET" and route == "/api/projects":
            handler._send_json(200, _catalog_payload(paths, context=context)); return True
        if method == "POST" and route == "/api/projects/init":
            handler._send_json(409, {"error": "catalog migration requires a verified recovery backup; run `keys project-sync migrate --out BACKUP --password-file FILE`"}); return True
        data = _body(body)
        if method == "POST" and route == "/api/projects/folders":
            item = service.create_folder(data.get("name"), parent_id=data.get("parent_id"), position=data.get("position"))
        elif method == "PATCH" and route.startswith("/api/projects/folders/"):
            folder_id = unquote(route.rsplit("/", 1)[-1])
            item = service.rename_folder(folder_id, data["name"]) if "name" in data else service.move_folder(folder_id, parent_id=data.get("parent_id"), position=data.get("position"))
        elif method == "DELETE" and route.startswith("/api/projects/folders/"):
            destination = parse_qs(parsed.query).get("destination", [None])[0]
            item = service.delete_folder(unquote(route.rsplit("/", 1)[-1]), destination_id=destination)
        elif method == "POST" and route == "/api/projects":
            item = service.create_project(data.get("slug"), data.get("name"), state=data.get("state", "active"))
        elif method == "PATCH" and route.startswith("/api/projects/") and route.count("/") == 3:
            project_id = unquote(route.rsplit("/", 1)[-1])
            item = service.rename_project(project_id, data["name"], slug=data.get("slug"))
        elif method == "POST" and route.startswith("/api/projects/") and route.endswith("/archive"):
            project_id = unquote(route[len("/api/projects/"):-len("/archive")])
            item = service.archive_project(project_id)
        elif method == "POST" and route == "/api/projects/scopes":
            item = service.create_scope(data.get("project_id"), data.get("environment", "default"))
        elif method == "POST" and route == "/api/projects/bindings":
            item = service.assign(data.get("scope_id"), data.get("entry_id"), local_name=data.get("local_name"), export=data.get("export"))
        elif method == "DELETE" and route.startswith("/api/projects/bindings/"):
            scope_id, entry_id = unquote(route[len("/api/projects/bindings/"):]).split("/", 1)
            item = service.unassign(scope_id, entry_id)
        elif method == "PATCH" and route.startswith("/api/projects/entries/") and route.endswith("/distribution"):
            entry_id = unquote(route[len("/api/projects/entries/"):-len("/distribution")])
            item = service.set_entry_distribution(entry_id, data.get("distribution"))
        elif method == "PATCH" and route.startswith("/api/projects/entries/") and route.endswith("/folder"):
            entry_id = unquote(route[len("/api/projects/entries/"):-len("/folder")])
            folder_id = data.get("folder_id")
            if folder_id is not None and not isinstance(folder_id, str):
                raise ValueError("folder_id must be a string or null")
            item = service.set_entry_folder(entry_id, folder_id)
        else:
            handler._send_json(404, {"error": "not found"}); return True
        handler._send_json(200, {"ok": True, "item": item.to_dict()})
    except (ValueError, KeyError, NotFound, ProjectCatalogError, StoreError) as ex:
        handler._send_json(400 if not isinstance(ex, NotFound) else 404, {"error": str(ex)})
    return True
