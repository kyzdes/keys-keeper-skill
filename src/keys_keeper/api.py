"""JSON API handlers for the admin server."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Callable
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

from keys_keeper import clipboard
from keys_keeper.audit import AuditLog
from keys_keeper.composition import AccessContext, build_backend
from keys_keeper.models import Entry, EntryType, ValidationError, now_iso
from keys_keeper.paths import Paths
from keys_keeper.refs import reverse_refs
from keys_keeper.service import HasDependents, SecretInput, VaultService
from keys_keeper.store import MetadataStore, NameConflict


def _web_backend():
    """Build a backend that is forbidden from opening OS authorization UI."""
    return build_backend(access=AccessContext.UI_FORBIDDEN)


def _web_service(store: MetadataStore) -> VaultService:
    """Compose a web-safe service without duplicating the access policy."""
    return VaultService(store, _web_backend())


def handle_api(
    handler, *, paths: Paths, method: str, path: str, body: bytes | None
) -> None:
    parsed = urlparse(path)
    exact = _EXACT_ROUTES.get((method, parsed.path))
    if exact is not None:
        exact(handler, paths, parsed, body)
        return
    if _dispatch_entry_route(handler, paths, method, parsed, body):
        return

    handler._send_json(404, {"error": "not found"})


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
    handler._send_json(200, {"ok": True})


def _route_shutdown(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
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


def _route_env_names(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _env_names(handler)


def _route_sync_setup(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    data = json.loads(body or b"{}")
    _sync_action(handler, lambda: _sync_mod().web_setup(paths, data))


def _route_sync_status(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _sync_action(handler, lambda: _sync_mod().web_status(paths))


def _route_sync_push(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _sync_action(handler, lambda: _sync_mod().web_push(paths))


def _route_sync_pull(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    _sync_action(handler, lambda: _sync_mod().web_pull(paths))


def _route_sync_mode(
    handler, paths: Paths, parsed: ParseResult, body: bytes | None
) -> None:
    mode = json.loads(body or b"{}").get("mode") or ""
    _sync_action(handler, lambda: _sync_mod().web_set_mode(paths, mode))


_EXACT_ROUTES: dict[tuple[str, str], _ApiRoute] = {
    ("GET", "/api/entries"): _route_entries,
    ("POST", "/api/copy"): _route_copy,
    ("POST", "/api/heartbeat"): _route_heartbeat,
    ("POST", "/api/shutdown"): _route_shutdown,
    ("GET", "/api/audit"): _route_audit,
    ("POST", "/api/entries"): _route_create_entry,
    ("POST", "/api/bulk-import"): _route_bulk_import,
    ("GET", "/api/status"): _route_status,
    ("GET", "/api/env-names"): _route_env_names,
    ("POST", "/api/sync/setup"): _route_sync_setup,
    ("GET", "/api/sync/status"): _route_sync_status,
    ("POST", "/api/sync/push"): _route_sync_push,
    ("POST", "/api/sync/pull"): _route_sync_pull,
    ("POST", "/api/sync/mode"): _route_sync_mode,
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
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    service = _web_service(store)
    try:
        result = service.delete_entry(e.id, cascade=cascade)
    except HasDependents as ex:
        handler._send_json(
            409,
            {"error": "has dependents", "dependents": ex.dependents},
        )
        return
    except Exception as ex:
        audit.record(op="delete", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    audit.record(op="delete", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True, "cascaded": result.cascaded})


def _sync_mod():
    from keys_keeper import cli_sync

    return cli_sync


def _sync_action(handler, fn) -> None:
    """Run a sync web action; map expected failures to safe JSON errors.

    Error strings here are our own (endpoint/exception-type), never a secret.
    """
    from keys_keeper.backend import KeychainError
    from keys_keeper.config import SyncConfigError
    from keys_keeper.crypto import BadPassword
    from keys_keeper.sync_remote import AuthError, TransportError

    try:
        handler._send_json(200, fn())
    except (SyncConfigError, KeychainError) as e:
        handler._send_json(400, {"error": str(e)})
    except (AuthError, TransportError, BadPassword) as e:
        handler._send_json(502, {"error": str(e)})


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
    store = MetadataStore(paths)
    entries = store.list()
    rev = reverse_refs(entries)
    out = []
    for e in entries:
        d = e.to_dict()
        d["used_by"] = rev.get(e.name, [])
        out.append(d)
    handler._send_json(200, {"entries": out})


def _entry_detail(handler, paths: Paths, entry_id: str) -> None:
    store = MetadataStore(paths)
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    rev = reverse_refs(store.list())
    d = e.to_dict()
    d["used_by"] = rev.get(e.name, [])
    # also inline last 5 audit events for this entry
    audit = AuditLog(paths)
    d["recent_events"] = list(audit.search(name=e.name, limit=5))
    handler._send_json(200, d)


DEFAULT_CLIPBOARD_CLEAR_SEC = 30


def _copy(handler, paths: Paths, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    entry_id = payload.get("id")
    # Mirror the CLI's `--clear-after` flag (cli.py default: 30, 0 disables).
    try:
        clear_after = int(payload.get("clear_after", DEFAULT_CLIPBOARD_CLEAR_SEC))
    except (TypeError, ValueError):
        handler._send_json(400, {"error": "clear_after must be an integer"})
        return
    if clear_after < 0:
        handler._send_json(400, {"error": "clear_after must be >= 0"})
        return
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id) if entry_id else None
    if e is None:
        handler._send_json(404, {"error": "entry not found"})
        return
    backend = _web_backend()
    try:
        sealed = backend.get(e.id)
    except Exception as ex:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    # Clipboard sink (controlled, not transcript-visible to the agent).
    value = sealed.unseal()
    if not clipboard.write(value):
        audit.record(
            op="copy",
            name=e.name,
            id_=e.id,
            success=False,
            error="clipboard write failed",
        )
        handler._send_json(500, {"error": "clipboard write failed"})
        return
    audit.record(op="copy", name=e.name, id_=e.id, success=True)
    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    if clear_after > 0:
        threading.Thread(
            target=_clipboard_clear_after,
            args=(written_hash, clear_after),
            daemon=True,
        ).start()
    handler._send_json(200, {"ok": True, "clear_after": clear_after})


def _clipboard_clear_after(written_hash: str, delay: int) -> None:
    time.sleep(delay)
    current = clipboard.read()
    current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
    if current_hash == written_hash:
        clipboard.clear()


def _audit(handler, paths: Paths, query: str) -> None:
    qs = parse_qs(query)
    op = qs.get("op", [None])[0]
    name = qs.get("name", [None])[0]
    limit = int(qs.get("limit", ["100"])[0])
    audit = AuditLog(paths)
    events = list(audit.search(op=op, name=name, limit=limit))
    handler._send_json(200, {"events": events})


def _create_entry(handler, paths: Paths, body: bytes) -> None:
    payload = json.loads(body or b"{}")
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
    except (ValidationError, KeyError, ValueError) as ex:
        handler._send_json(400, {"error": str(ex)})
        return
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    service = _web_service(store)
    try:
        service.create_entry(
            e,
            secrets=SecretInput(value=payload["value"])
            if payload.get("value")
            else None,
        )
    except NameConflict as ex:
        handler._send_json(409, {"error": str(ex)})
        return
    except Exception as ex:
        audit.record(op="add", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    audit.record(op="add", name=e.name, id_=e.id, success=True)
    handler._send_json(201, {"id": e.id, "name": e.name})


def _patch_entry(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    store = MetadataStore(paths)
    audit = AuditLog(paths)
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
        try:
            candidate["fields"] = {**candidate["fields"], **payload["fields"]}
        except TypeError as ex:
            handler._send_json(400, {"error": str(ex)})
            return
    if "refs" in payload:
        candidate["refs"] = payload["refs"]
    candidate["updated_at"] = now_iso()
    try:
        updated = Entry.from_untrusted_dict(candidate)
    except (ValidationError, TypeError, ValueError) as ex:
        handler._send_json(400, {"error": str(ex)})
        return
    service = _web_service(store)
    try:
        service.update_entry(
            updated,
            secrets=SecretInput(value=payload["value"])
            if payload.get("value")
            else None,
        )
    except NameConflict as ex:
        handler._send_json(409, {"error": str(ex)})
        return
    except Exception as ex:
        audit.record(op="update", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    audit.record(op="update", name=updated.name, id_=updated.id, success=True)
    handler._send_json(200, {"ok": True})


def _shutdown_self() -> None:
    # graceful exit — the test server handles the actual stop via close
    time.sleep(0.05)
    os._exit(0)


def _bulk_import(handler, paths: Paths, query: str, body: bytes) -> None:
    from keys_keeper.parser import parse_bulk

    payload = json.loads(body or b"{}")
    text = payload.get("source", "")
    dry = "dry-run=1" in (query or "")
    rows = parse_bulk(text)

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

    store = MetadataStore(paths)
    audit = AuditLog(paths)
    service = _web_service(store)
    existing = {e.name for e in store.list()}
    collisions = [r.name for r in rows if r.name in existing]
    if collisions:
        handler._send_json(409, {"error": "name collisions", "names": collisions})
        return

    prepared = []
    for r in rows:
        type_ = EntryType(r.type)
        fields: dict = {}
        try:
            entry = Entry.new(name=r.name, type=type_, fields=fields, tags=r.tags)
        except ValidationError as ex:
            handler._send_json(500, {"error": f"row {r.line}: {ex}"})
            return
        secrets = (
            SecretInput(value=r.value)
            if type_ in (EntryType.API_KEY, EntryType.SSH_KEY, EntryType.NOTE)
            else None
        )
        prepared.append((entry, secrets))
    try:
        imported = service.bulk_create(prepared)
    except NameConflict as ex:
        handler._send_json(409, {"error": str(ex)})
        return
    except Exception as ex:
        handler._send_json(500, {"error": str(ex)})
        return
    for entry in imported:
        audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    handler._send_json(200, {"ok": True, "imported": len(rows)})


def _status(handler, paths: Paths) -> None:
    import os
    import sys
    import time

    from keys_keeper import __version__
    from keys_keeper.keychain_config import load_keychain_config

    info = {
        "version": __version__,
        "config_dir": str(paths.root),
        "data_json": str(paths.data_json),
        "audit_jsonl": str(paths.audit_jsonl),
        "reveal_env_set": os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1",
        "uptime_sec": int(
            time.monotonic() - getattr(handler.server, "_kk_started", time.monotonic())
        ),
        "keychain_mode": load_keychain_config(paths).mode
        if sys.platform == "darwin"
        else None,
    }
    handler._send_json(200, info)


def _replace_secret(handler, paths: Paths, entry_id: str, body: bytes) -> None:
    payload = json.loads(body or b"{}")
    value = payload.get("value")
    if not value:
        handler._send_json(400, {"error": "value required"})
        return
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_id(entry_id)
    if e is None:
        handler._send_json(404, {"error": "not found"})
        return
    e.updated_at = now_iso()
    service = _web_service(store)
    try:
        service.update_entry(e, secrets=SecretInput(value=value))
    except Exception as ex:
        audit.record(
            op="replace_secret", name=e.name, id_=e.id, success=False, error=str(ex)
        )
        handler._send_json(500, {"error": str(ex)})
        return
    audit.record(op="replace_secret", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True})
