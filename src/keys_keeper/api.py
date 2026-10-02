"""JSON API handlers for the admin server."""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections.abc import Callable
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from keys_keeper import clipboard
from keys_keeper.audit import normalize_outcome, record_outcome
from keys_keeper.backend import KeychainError
from keys_keeper.composition import AccessContext, build_backend
from keys_keeper.models import Entry, EntryType, ValidationError, now_iso
from keys_keeper.paths import Paths
from keys_keeper.refs import reverse_refs
from keys_keeper.project_service import ProjectService
from keys_keeper.service import HasDependents, SecretInput
from keys_keeper.store import NameConflict, NotFound, StoreError
from keys_keeper.request_json import request_object


def _web_backend(paths: Paths):
    """Build a backend that is forbidden from opening OS authorization UI."""
    return build_backend(paths=paths, access=AccessContext.UI_FORBIDDEN)


def _selector(parsed: ParseResult, server_selector: str | None) -> str | None:
    query = parse_qs(parsed.query, keep_blank_values=True)
    profiles = query.get("profile", [])
    projects = query.get("project", [])
    environments = query.get("env", [])
    if len(profiles) > 1 or len(projects) > 1 or len(environments) > 1:
        raise ValueError("profile selector must be specified once")
    if any(not value for value in profiles + projects + environments):
        raise ValueError("profile selector cannot be empty")
    if projects or environments:
        if len(projects) != 1 or len(environments) != 1:
            raise ValueError("project and env must be supplied together")
        if profiles:
            raise ValueError("choose profile or project/env, not both")
        selected = projects[0] + "/" + environments[0]
    else:
        selected = profiles[0] if profiles else None
    if server_selector is not None:
        if selected is not None and selected != server_selector:
            raise ValueError("server profile is fixed for this admin session")
        return server_selector
    return selected


def _request_context(handler, paths: Paths, parsed: ParseResult, *, runtime=None,
                     server_selector: str | None = None):
    """Resolve a request scope before any backend access occurs."""
    from keys_keeper.project_runtime import ProjectRuntime

    active_runtime = runtime or getattr(handler, "project_runtime", None)
    if active_runtime is None:
        active_runtime = ProjectRuntime(
            paths,
            access=AccessContext.UI_FORBIDDEN,
            backend_factory=lambda: _web_backend(paths),
        )
    context = active_runtime.context(_selector(parsed, server_selector))
    handler._kk_runtime = getattr(context, "runtime", active_runtime)
    handler._kk_context = context
    return context


def _context(handler, paths: Paths):
    """Return the request context, with a master default for direct unit calls."""
    context = getattr(handler, "_kk_context", None)
    if context is not None:
        return context
    parsed = urlparse("/")
    return _request_context(handler, paths, parsed)


def _runtime(handler, paths: Paths):
    runtime = getattr(handler, "_kk_runtime", None)
    if runtime is not None:
        return runtime
    _context(handler, paths)
    return handler._kk_runtime


def _context_payload(context) -> dict:
    """Metadata-only selected-profile state for the web client."""
    kind = context.kind
    return {
        "kind": kind,
        "profile_id": context.profile_id,
        "scope_id": context.scope_id,
        "can_create": kind in {"master", "replica"} and (getattr(context, "item", None) or {}).get("status", "active") == "active",
        "can_mutate": kind == "master",
    }


def _require_master(handler, context) -> bool:
    if context.kind == "master":
        return True
    handler._send_json(403, {"error": "selected profile is read-only"})
    return False


def handle_api(
    handler, *, paths: Paths, method: str, path: str, body: bytes | None,
    runtime=None, server_selector: str | None = None,
) -> None:
    from keys_keeper.project_runtime import RuntimeErrorSafe

    parsed = urlparse(path)
    try:
        if parsed.path == "/api/sync" or parsed.path.startswith("/api/sync/"):
            handler._send_json(410, {
                "error": "S3 synchronization has been removed; use My computers or keys sync vps",
            })
            return
        if parsed.path.startswith("/api/personal-sync/"):
            from keys_keeper.api_personal_sync import handle_personal_api
            handle_personal_api(handler, paths=paths, method=method, parsed=parsed,
                                body=body, runtime=runtime, server_selector=server_selector)
            return
        _request_context(handler, paths, parsed, runtime=runtime,
                         server_selector=server_selector)
        exact = _EXACT_ROUTES.get((method, parsed.path))
        if exact is not None:
            exact(handler, paths, parsed, body)
            return
        from keys_keeper.api_projects import dispatch_project_api
        if dispatch_project_api(handler, paths, method, parsed, body,
                                context=_context(handler, paths)):
            return
        if _dispatch_entry_route(handler, paths, method, parsed, body):
            return
        handler._send_json(404, {"error": "not found"})
    except NotFound as ex:
        if not _committed_exception(handler, ex):
            handler._send_json(404, {"error": "not found", **normalize_outcome(committed=False, error=ex)})
    except RuntimeErrorSafe as ex:
        if not _committed_exception(handler, ex):
            handler._send_json(400, {"error": str(ex), **normalize_outcome(error=ex)})
    except (ValueError, TypeError, KeyError) as ex:
        if not _committed_exception(handler, ex):
            handler._send_json(400, {"error": "Invalid request", **normalize_outcome(committed=False, error=ex)})
    except Exception as ex:
        # Backend/process errors can contain a value or a private filesystem
        # path. No unclassified exception message crosses the HTTP boundary.
        if not _committed_exception(handler, ex):
            handler._send_json(503, {"error": "Operation unavailable; inspect state before retrying",
                                     **normalize_outcome(error=ex)})


def _committed_exception(handler, ex: Exception) -> bool:
    receipt = normalize_outcome(error=ex)
    if receipt["committed"] is not True:
        return False
    handler._send_json(503, {"error": "Change was published; confirm state before retrying",
                             **receipt})
    return True


def _committed(handler, audit, *, op: str, entry: Entry | None = None,
               affected_entry_ids: list[str] | None = None,
               status: int = 200, **payload) -> None:
    """Report a completed side effect even when its audit sink is unavailable."""
    audit_status = record_outcome(
        audit, op=op, name=entry.name if entry else "<batch>",
        id_=entry.id if entry else "<batch>", affected_entry_ids=affected_entry_ids,
        committed=True,
    )
    handler._send_json(status, {**payload, **normalize_outcome(committed=True, audit_status=audit_status)})


def _operation_failed(handler, audit, *, op: str, entry: Entry | None = None,
                      affected_entry_ids: list[str] | None = None,
                      status: int = 503, message: str = "Operation unavailable",
                      committed: bool | None = False, error: Exception | None = None) -> None:
    receipt = normalize_outcome(committed=committed, error=error)
    audit_status = record_outcome(
        audit, op=op, name=entry.name if entry else "<batch>",
        id_=entry.id if entry else "<batch>", success=False,
        affected_entry_ids=affected_entry_ids, committed=receipt["committed"],
    )
    if receipt["committed"] is True:
        message = "Change was published; confirm state before retrying"
    elif receipt["committed"] is None:
        message = "Operation outcome is unconfirmed; inspect recovery state before retrying"
    handler._send_json(status, {"error": message,
                                **normalize_outcome(committed=receipt["committed"], audit_status=audit_status, error=error)})


_ApiRoute = Callable[[object, Paths, ParseResult, bytes | None], None]


def _route_entries(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _entries(handler, paths, parsed.query)


def _route_copy(handler, paths: Paths, parsed: ParseResult, body: bytes | None) -> None:
    _copy(handler, paths, body)


def _route_heartbeat(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    request_object(body, {})
    handler._send_json(200, {"ok": True})


def _route_shutdown(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    request_object(body, {})
    # Schedule a shutdown only after the success response has been sent.
    handler._send_json(200, {"ok": True})
    threading.Thread(target=_shutdown_self, daemon=True).start()


def _route_audit(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _audit(handler, paths, parsed.query)


def _route_create_entry(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _create_entry(handler, paths, body)


def _route_bulk_import(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _bulk_import(handler, paths, parsed.query, body)


def _route_status(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _status(handler, paths)


def _route_context(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    handler._send_json(200, _context_payload(_context(handler, paths)))


def _route_project_sync_status(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _project_sync_status(handler, paths)


def _route_project_sync_preview(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _project_sync_preview(handler, paths, parsed)


def _route_project_sync_run(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _project_sync_run(handler, paths, body)


def _route_project_sync_revoke(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _project_sync_revoke(handler, paths, body)


def _route_project_sync_initialize(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _project_sync_initialize(handler, paths, body)


def _route_env_names(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _env_names(handler)


_EXACT_ROUTES: dict[tuple[str, str], _ApiRoute] = {
    ("GET", "/api/entries"): _route_entries,
    ("POST", "/api/copy"): _route_copy,
    ("POST", "/api/heartbeat"): _route_heartbeat,
    ("POST", "/api/shutdown"): _route_shutdown,
    ("GET", "/api/audit"): _route_audit,
    ("POST", "/api/entries"): _route_create_entry,
    ("POST", "/api/bulk-import"): _route_bulk_import,
    ("GET", "/api/status"): _route_status,
    ("GET", "/api/context"): _route_context,
    ("GET", "/api/project-sync/status"): _route_project_sync_status,
    ("GET", "/api/project-sync/preview"): _route_project_sync_preview,
    ("POST", "/api/project-sync/sync"): _route_project_sync_run,
    ("POST", "/api/project-sync/revoke"): _route_project_sync_revoke,
    ("POST", "/api/project-sync/initialize"): _route_project_sync_initialize,
    ("GET", "/api/env-names"): _route_env_names,
}


def _dispatch_entry_route(
    handler,
    paths: Paths,
    method: str,
    parsed: ParseResult,
    body: bytes | None,
) -> bool:
    route = parsed.path
    prefix = "/api/entries/"
    if not route.startswith(prefix):
        return False
    if method == "POST" and route.endswith("/replace-secret"):
        entry_id = unquote(route[len(prefix) : -len("/replace-secret")])
        _replace_secret(handler, paths, entry_id, body)
        return True
    if method == "GET":
        _entry_detail(handler, paths, unquote(route.rsplit("/", 1)[-1]))
        return True
    if method == "PATCH":
        _patch_entry(handler, paths, unquote(route.rsplit("/", 1)[-1]), body)
        return True
    if method == "DELETE":
        _delete_entry(handler, paths, unquote(route.rsplit("/", 1)[-1]), parsed.query)
        return True
    return False


def _delete_entry(handler, paths: Paths, entry_id: str, query: str) -> None:
    # Mirror CLI's `rm --cascade`: opt-in via ?cascade=1.
    cascade = parse_qs(query).get("cascade", ["0"])[0] in ("1", "true", "yes")
    context = _context(handler, paths)
    if not _require_master(handler, context):
        return
    store = context.store
    audit = context.audit
    e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    try:
        result = context.service.delete_entry(e.id, cascade=cascade)
    except HasDependents as ex:
        handler._send_json(
            409,
            {"error": "has dependents", "dependents": ex.dependents},
        )
        return
    except Exception as ex:
        _operation_failed(handler, audit, op="delete", entry=e, committed=None, error=ex,
                          message="Vault operation failed; check recovery status before retrying")
        return
    _committed(handler, audit, op="delete", entry=e, ok=True, cascaded=result.cascaded)


def _project_target(handler, paths: Paths, *, selector: str | None = None,
                    require_master_scope: bool = False):
    """Resolve a project profile without allowing a worker to escape its scope."""
    context = _context(handler, paths)
    runtime = _runtime(handler, paths)
    if context.kind != "master":
        if selector is not None and selector != context.profile_id:
            raise ValueError("selected profile cannot be changed by this request")
        target = context
    else:
        if not selector:
            raise ValueError("a project scope profile is required")
        target = runtime.context(selector)
    if require_master_scope and target.kind != "master_scope":
        raise ValueError("master scope profile is required")
    return runtime, target


def _safe_project_error(handler, ex: Exception) -> None:
    from keys_keeper.project_runtime import RuntimeErrorSafe

    if _committed_exception(handler, ex):
        return
    if isinstance(ex, RuntimeErrorSafe):
        handler._send_json(400, {"error": str(ex)})
    elif isinstance(ex, (ValueError, TypeError, KeyError)):
        handler._send_json(400, {"error": "Invalid request"})
    else:
        handler._send_json(503, {"error": "Operation unavailable"})


def _project_sync_status(handler, paths: Paths) -> None:
    context = _context(handler, paths)
    runtime = _runtime(handler, paths)
    try:
        if context.kind != "master":
            handler._send_json(200, {"context": _context_payload(context),
                                     "profile": runtime.status(context.profile_id)})
            return
        root = runtime.status("master")
        profiles = [runtime.status(item["id"]) for item in root["profiles"]]
        union: dict[str, list[dict]] = {}
        for profile in profiles:
            for recipient in profile.get("recipients", []):
                union.setdefault(recipient["device_id"], []).append({
                    "scope_id": profile["scope_id"], "project": profile["project"],
                    "environment": profile["environment"], "role": recipient["role"],
                    "grant_id": recipient["grant_id"],
                })
        shared_usages, pending_publications = {}, {}
        try:
            catalog_service = ProjectService(context.store)
            shared_usages = catalog_service.effective_shared_usages()
            for intent in catalog_service.publication_intents():
                if intent["desired_revision"] > intent["applied_revision"]:
                    pending_publications[intent["scope_id"]] = pending_publications.get(intent["scope_id"], 0) + 1
        except StoreError:
            pass
        for profile in profiles:
            profile["publication_pending"] = pending_publications.get(profile["scope_id"], 0)
        handler._send_json(200, {
            "context": _context_payload(context), "profiles": profiles,
            "device_union": union, "shared_usages": shared_usages,
            "publication_pending": pending_publications,
        })
    except (ValueError, RuntimeError, KeychainError) as ex:
        _safe_project_error(handler, ex)


def _project_sync_preview(handler, paths: Paths, parsed: ParseResult) -> None:
    query = parse_qs(parsed.query, keep_blank_values=True)
    scopes = query.get("scope", [])
    if len(scopes) > 1 or (scopes and not scopes[0]):
        handler._send_json(400, {"error": "scope must be specified once"})
        return
    try:
        context = _context(handler, paths)
        selector = scopes[0] if scopes else (context.profile_id if context.kind != "master" else None)
        runtime, target = _project_target(handler, paths, selector=selector,
                                          require_master_scope=True)
        preview = runtime.preview(target.profile_id)
        # A projection preview is intentionally an access plan: it must not
        # turn note text, exported fields, or secret-bearing records into API
        # output merely because they are selected for a future publication.
        entries = [
            {"id": item["id"], "name": item["name"], "type": item["type"]}
            for item in preview["entries"]
        ]
        handler._send_json(200, {
            "scope_id": preview["scope_id"], "source_revision": preview["source_revision"],
            "catalog_revision": preview["catalog_revision"], "count": preview["count"],
            "entries": entries, "recipients": preview.get("recipients", []),
            "policy_hash": preview.get("policy_hash"),
        })
    except (ValueError, RuntimeError) as ex:
        _safe_project_error(handler, ex)


def _project_sync_run(handler, paths: Paths, body: bytes | None) -> None:
    try:
        data = request_object(body, {"scope_id": str})
        selector = data.get("scope_id")
        runtime, target = _project_target(handler, paths, selector=selector)
        result = runtime.sync(target.profile_id)
        handler._send_json(200, {"ok": True, "profile_id": target.profile_id, "result": result})
    except (ValueError, RuntimeError) as ex:
        _safe_project_error(handler, ex)


def _project_sync_revoke(handler, paths: Paths, body: bytes | None) -> None:
    try:
        if _context(handler, paths).kind != "master":
            handler._send_json(403, {"error": "device revocation requires the master profile"})
            return
        data = request_object(body, {"scope_id": str, "device_id": str},
                              required={"scope_id", "device_id"})
        runtime, target = _project_target(handler, paths, selector=data["scope_id"],
                                          require_master_scope=True)
        result = runtime.master(target.item).revoke(data["device_id"])
        handler._send_json(200, {"ok": True, "scope_id": target.scope_id, "result": result,
                                 "warning": "Revocation blocks future access; it cannot erase material already held by this device."})
    except (ValueError, RuntimeError) as ex:
        _safe_project_error(handler, ex)


def _project_sync_initialize(handler, paths: Paths, body: bytes | None) -> None:
    try:
        context = _context(handler, paths)
        if context.kind != "master":
            handler._send_json(403, {"error": "scope initialization requires the master profile"})
            return
        data = request_object(body, {"scope_id": str, "endpoint": str, "admin_token_entry": str},
                              required={"scope_id", "endpoint", "admin_token_entry"})
        scope_id, endpoint, token_entry = (data.get("scope_id"), data.get("endpoint"), data.get("admin_token_entry"))
        if not all(isinstance(value, str) and value for value in (scope_id, endpoint, token_entry)):
            raise ValueError("scope_id, endpoint, and admin_token_entry are required")
        runtime = _runtime(handler, paths)
        entry = context.store.get_by_id(token_entry) or context.store.get_by_name(token_entry)
        if entry is None:
            raise ValueError("admin token entry is unavailable")
        result = runtime.initialize(scope_id, endpoint, admin_token=runtime.master_backend.get(entry.id))
        handler._send_json(200, {"ok": True, "result": result})
    except (ValueError, RuntimeError, KeychainError) as ex:
        _safe_project_error(handler, ex)


def _env_names(handler) -> None:
    """Return the *names* of process env vars — never the values.

    The dashboard surfaces this to help users find env-resident secrets
    that should migrate into keys-keeper. Values stay on the backend; if
    we ever expose them here we break the project's central guarantee
    (any agent that fetches /dashboard could parse plaintext from HTML).
    """
    names = sorted(os.environ.keys())
    handler._send_json(200, {"names": names})


def _entries(handler, paths: Paths, query: str) -> None:
    store = _context(handler, paths).store
    entries = store.list()
    rev = reverse_refs(entries)
    out = []
    for e in entries:
        d = e.to_dict()
        d["used_by"] = rev.get(e.name, [])
        out.append(d)
    handler._send_json(200, {"entries": out})


def _entry_detail(handler, paths: Paths, entry_id: str) -> None:
    context = _context(handler, paths)
    store = context.store
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    rev = reverse_refs(store.list())
    d = e.to_dict()
    d["used_by"] = rev.get(e.name, [])
    # also inline last 5 audit events for this entry
    audit = context.audit
    d["recent_events"] = list(audit.search(entry_id=e.id, limit=5, newest_first=True))
    handler._send_json(200, d)


DEFAULT_CLIPBOARD_CLEAR_SEC = 30


def _copy(handler, paths: Paths, body: bytes) -> None:
    from keys_keeper.models import entry_requires_secret

    payload = request_object(body, {"id": str, "clear_after": int}, required={"id"})
    entry_id = payload.get("id")
    # Mirror the CLI's `--clear-after` flag (cli.py default: 30, 0 disables).
    clear_after = payload.get("clear_after", DEFAULT_CLIPBOARD_CLEAR_SEC)
    if not 0 <= clear_after <= clipboard.MAX_CLEAR_DELAY_SECONDS:
        handler._send_json(400, {"error": "clear_after must be from 0 to 86400 seconds"})
        return
    context = _context(handler, paths)
    store = context.store
    audit = context.audit
    e = store.get_by_id(entry_id) if entry_id else None
    if e is None:
        handler._send_json(404, {"error": "entry not found"})
        return
    if not entry_requires_secret(e):
        handler._send_json(400, {"error": "This entry does not have a secret body"})
        return
    try:
        sealed = context.backend.get(e.id)
    except Exception:
        _operation_failed(handler, audit, op="copy", entry=e,
                          message="Credential unavailable")
        return
    # Clipboard sink (controlled, not transcript-visible to the agent).
    value = sealed.unseal()
    try:
        written = clipboard.write(value)
    except Exception:
        written = False
    if not written:
        _operation_failed(handler, audit, op="copy", entry=e,
                          message="Clipboard unavailable")
        return
    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    try:
        clipboard.schedule_clear_after(written_hash, clear_after)
        clear_status = "scheduled" if clear_after else "disabled"
    except Exception:
        clear_status = "unavailable"
    _committed(handler, audit, op="copy", entry=e, ok=True,
               clear_after=clear_after, clear_status=clear_status)


def _audit(handler, paths: Paths, query: str) -> None:
    qs = parse_qs(query)
    op = qs.get("op", [None])[0]
    name = qs.get("name", [None])[0]
    entry_id = qs.get("entry_id", [None])[0]
    limits = qs.get("limit", ["100"])
    try:
        if len(limits) != 1:
            raise ValueError
        limit = int(limits[0])
        if not 1 <= limit <= 2000:
            raise ValueError
    except ValueError:
        handler._send_json(400, {"error": "limit must be an integer from 1 to 2000"})
        return
    audit = _context(handler, paths).audit
    # The journal opened from the menu must show current activity, even once
    # the file contains more than the UI's 2,000-event limit.
    from keys_keeper.audit import AuditReadLimit
    try:
        events = list(audit.search(op=op, name=name, entry_id=entry_id,
                                   limit=limit, newest_first=True))
    except AuditReadLimit:
        handler._send_json(413, {"error": "audit read limit exceeded; narrow the filter or rotate the log"})
        return
    handler._send_json(200, {"events": events})


def _create_entry(handler, paths: Paths, body: bytes) -> None:
    from keys_keeper.models import entry_requires_secret

    payload = request_object(body, {
        "name": str, "type": str, "fields": dict, "tags": list,
        "note": str, "refs": list, "value": str,
    }, required={"name", "type"})
    try:
        type_ = EntryType(payload["type"])
        e = Entry.new(
            name=payload["name"],
            type=type_,
            fields=payload.get("fields", {}),
            tags=payload.get("tags", []),
            note=payload.get("note", ""),
            refs=payload.get("refs", []),
        )
        e = Entry.from_untrusted_dict(e.to_dict())
        if entry_requires_secret(e) and not payload.get("value"):
            raise ValidationError("value required")
        if not entry_requires_secret(e) and "value" in payload:
            raise ValidationError("entry type does not accept a value")
    except (ValidationError, KeyError, ValueError):
        handler._send_json(400, {"error": "Invalid entry"})
        return
    context = _context(handler, paths)
    if context.kind not in {"master", "replica"}:
        handler._send_json(403, {"error": "selected profile is read-only"})
        return
    audit = context.audit
    try:
        context.service.create_entry(
            e,
            secrets=SecretInput(value=payload["value"])
            if payload.get("value")
            else None,
        )
    except NameConflict:
        handler._send_json(409, {"error": "Entry name already exists"})
        return
    except ValidationError:
        _operation_failed(handler, audit, op="add", entry=e,
                          status=400, message="Invalid entry")
        return
    except Exception as ex:
        _operation_failed(handler, audit, op="add", entry=e, committed=None, error=ex,
                          message="Vault operation failed; check recovery status before retrying")
        return
    _committed(handler, audit, op="add", entry=e, status=201, id=e.id, name=e.name)


def _patch_entry(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    from keys_keeper.models import entry_requires_secret

    payload = request_object(body, {
        "fields": dict, "tags": list, "note": str, "refs": list, "value": str,
    })
    context = _context(handler, paths)
    if not _require_master(handler, context):
        return
    store = context.store
    audit = context.audit
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    candidate = e.to_dict()
    if "tags" in payload:
        candidate["tags"] = payload["tags"]
    if "note" in payload:
        candidate["note"] = payload["note"]
    if "fields" in payload:
        candidate["fields"] = {**candidate["fields"], **payload["fields"]}
    if "refs" in payload:
        candidate["refs"] = payload["refs"]
    candidate["updated_at"] = now_iso()
    try:
        updated = Entry.from_untrusted_dict(candidate, allow_project_fields=True)
        if e.type == EntryType.NOTE and updated.fields["secret_body"] != e.fields["secret_body"]:
            raise ValidationError("note storage cannot be changed by a metadata edit")
        if "value" in payload and (not entry_requires_secret(updated) or not payload["value"]):
            raise ValidationError("invalid secret replacement")
    except (ValidationError, TypeError, ValueError):
        handler._send_json(400, {"error": "Invalid entry"})
        return
    try:
        context.service.update_entry(
            updated,
            secrets=SecretInput(value=payload["value"])
            if payload.get("value")
            else None,
        )
    except NameConflict:
        handler._send_json(409, {"error": "Entry name already exists"})
        return
    except ValidationError:
        _operation_failed(handler, audit, op="update", entry=e,
                          status=400, message="Invalid entry")
        return
    except Exception as ex:
        _operation_failed(handler, audit, op="update", entry=e, committed=None, error=ex,
                          message="Vault operation failed; check recovery status before retrying")
        return
    _committed(handler, audit, op="update", entry=updated, ok=True)


def _shutdown_self() -> None:
    # graceful exit — the test server handles the actual stop via close
    time.sleep(0.05)
    os._exit(0)


def _bulk_import(handler, paths: Paths, query: str, body: bytes) -> None:
    from keys_keeper.parser import parse_bulk

    context = _context(handler, paths)
    if not _require_master(handler, context):
        return
    payload = request_object(body, {"source": str}, required={"source"})
    text = payload.get("source", "")
    dry = "dry-run=1" in (query or "")
    rows = parse_bulk(text)

    # This line format carries no structured fields or refs. Keep its scope
    # honest instead of guessing SSH public keys or server configuration.
    for row in rows:
        if not row.error and row.type not in {"api_key", "note"}:
            row.error = "this type requires the new entry form"
        if not row.error and not row.value:
            row.error = "a nonempty secret value is required"

    out = [
        {
            "line": r.line,
            "name": r.name,
            "type": r.type,
            "has_value": bool(r.value),
            "tags": r.tags,
            "error": r.error,
        }
        for r in rows
    ]

    if dry:
        handler._send_json(200, {"rows": out})
        return

    if any(r.error for r in rows):
        handler._send_json(400, {"error": "rows have errors", "rows": out})
        return

    store = context.store
    audit = context.audit
    existing = {e.name for e in store.list()}
    collisions = [r.name for r in rows if r.name in existing]
    if collisions:
        handler._send_json(409, {"error": "name collisions", "names": collisions})
        return

    prepared = []
    for r in rows:
        type_ = EntryType(r.type)
        fields: dict = {"secret_body": True} if type_ == EntryType.NOTE else {}
        try:
            entry = Entry.new(name=r.name, type=type_, fields=fields, tags=r.tags)
            entry = Entry.from_untrusted_dict(entry.to_dict())
        except ValidationError:
            handler._send_json(400, {"error": "Invalid entry in bulk input"})
            return
        prepared.append((entry, SecretInput(value=r.value)))
    try:
        imported = context.service.bulk_create(prepared)
    except NameConflict:
        handler._send_json(409, {"error": "Entry name already exists"})
        return
    except Exception as ex:
        _operation_failed(handler, audit, op="bulk_import", committed=None, error=ex,
                          affected_entry_ids=[entry.id for entry, _ in prepared],
                          message="Vault operation failed; check recovery status before retrying")
        return
    _committed(handler, audit, op="bulk_import", affected_entry_ids=[entry.id for entry in imported],
               ok=True, imported=len(rows))


def _status(handler, paths: Paths) -> None:
    import os
    import sys
    import time

    from keys_keeper import __version__
    from keys_keeper.keychain_config import load_keychain_config

    context = _context(handler, paths)
    context_paths = context.paths
    info = {
        "version": __version__,
        "config_dir": str(context_paths.root),
        "data_json": str(context_paths.data_json),
        "audit_jsonl": str(context_paths.audit_jsonl),
        "reveal_env_set": os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1",
        "uptime_sec": int(
            time.monotonic() - getattr(handler.server, "_kk_started", time.monotonic())
        ),
        "keychain_mode": load_keychain_config(context_paths).mode
        if sys.platform == "darwin"
        else None,
    }
    info["context"] = _context_payload(context)
    handler._send_json(200, info)


def _replace_secret(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    from keys_keeper.models import entry_requires_secret

    context = _context(handler, paths)
    if not _require_master(handler, context):
        return
    payload = request_object(body, {"value": str}, required={"value"})
    value = payload.get("value")
    if not value:
        handler._send_json(400, {"error": "value required"})
        return
    store = context.store
    audit = context.audit
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    if not entry_requires_secret(e):
        handler._send_json(400, {"error": "This entry does not have a secret body"})
        return
    e.updated_at = now_iso()
    try:
        context.service.update_entry(e, secrets=SecretInput(value=value))
    except Exception as ex:
        _operation_failed(handler, audit, op="replace_secret", entry=e, committed=None, error=ex,
                          message="Vault operation failed; check recovery status before retrying")
        return
    _committed(handler, audit, op="replace_secret", entry=e, ok=True)
