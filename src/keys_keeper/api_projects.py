"""Authenticated, local-only Admin API for catalog organization."""
from __future__ import annotations

from urllib.parse import ParseResult, parse_qs, unquote

from keys_keeper.project_service import ProjectCatalogError, ProjectService
from keys_keeper.store import MetadataStore, NotFound, StoreError
from keys_keeper.request_json import InvalidRequest, request_object


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
            request_object(body, {})
            handler._send_json(409, {"error": "catalog migration requires a verified recovery backup; run `keys project-sync migrate --out BACKUP --password-file FILE`"}); return True
        if method == "POST" and route == "/api/projects/folders":
            data = request_object(body, {"name": str, "parent_id": (str, type(None)), "position": int}, required={"name"})
            item = service.create_folder(data.get("name"), parent_id=data.get("parent_id"), position=data.get("position"))
        elif method == "PATCH" and route.startswith("/api/projects/folders/"):
            data = request_object(body, {"name": str, "parent_id": (str, type(None)), "position": int})
            if not data or ("name" in data and set(data) != {"name"}):
                raise InvalidRequest()
            folder_id = unquote(route.rsplit("/", 1)[-1])
            item = service.rename_folder(folder_id, data["name"]) if "name" in data else service.move_folder(folder_id, parent_id=data.get("parent_id"), position=data.get("position"))
        elif method == "DELETE" and route.startswith("/api/projects/folders/"):
            destination = parse_qs(parsed.query).get("destination", [None])[0]
            item = service.delete_folder(unquote(route.rsplit("/", 1)[-1]), destination_id=destination)
        elif method == "POST" and route == "/api/projects":
            data = request_object(body, {"slug": str, "name": str, "state": str}, required={"slug", "name"})
            item = service.create_project(data.get("slug"), data.get("name"), state=data.get("state", "active"))
        elif method == "PATCH" and route.startswith("/api/projects/") and route.count("/") == 3:
            data = request_object(body, {"name": str, "slug": str}, required={"name"})
            project_id = unquote(route.rsplit("/", 1)[-1])
            item = service.rename_project(project_id, data["name"], slug=data.get("slug"))
        elif method == "POST" and route.startswith("/api/projects/") and route.endswith("/archive"):
            request_object(body, {})
            project_id = unquote(route[len("/api/projects/"):-len("/archive")])
            item = service.archive_project(project_id)
        elif method == "POST" and route == "/api/projects/scopes":
            data = request_object(body, {"project_id": str, "environment": str}, required={"project_id"})
            item = service.create_scope(data.get("project_id"), data.get("environment", "default"))
        elif method == "POST" and route == "/api/projects/bindings":
            data = request_object(body, {"scope_id": str, "entry_id": str,
                                        "local_name": str, "export": dict}, required={"scope_id", "entry_id"})
            item = service.assign(data.get("scope_id"), data.get("entry_id"), local_name=data.get("local_name"), export=data.get("export"))
        elif method == "DELETE" and route.startswith("/api/projects/bindings/"):
            scope_id, entry_id = unquote(route[len("/api/projects/bindings/"):]).split("/", 1)
            item = service.unassign(scope_id, entry_id)
        elif method == "PATCH" and route.startswith("/api/projects/entries/") and route.endswith("/distribution"):
            data = request_object(body, {"distribution": str}, required={"distribution"})
            entry_id = unquote(route[len("/api/projects/entries/"):-len("/distribution")])
            item = service.set_entry_distribution(entry_id, data.get("distribution"))
        elif method == "PATCH" and route.startswith("/api/projects/entries/") and route.endswith("/folder"):
            data = request_object(body, {"folder_id": (str, type(None))}, required={"folder_id"})
            entry_id = unquote(route[len("/api/projects/entries/"):-len("/folder")])
            folder_id = data.get("folder_id")
            item = service.set_entry_folder(entry_id, folder_id)
        else:
            handler._send_json(404, {"error": "not found"}); return True
        handler._send_json(200, {"ok": True, "item": item.to_dict()})
    except NotFound:
        handler._send_json(404, {"error": "not found"})
    except (ValueError, KeyError, TypeError, ProjectCatalogError) as ex:
        if getattr(ex, "committed", None) is True:
            raise
        handler._send_json(400, {"error": "Invalid project request"})
    except Exception as ex:
        if getattr(ex, "committed", None) is True:
            raise
        handler._send_json(503, {"error": "Project operation unavailable"})
    return True
