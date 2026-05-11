"""JSON API handlers for the admin server."""
from __future__ import annotations
import hashlib
import json
import os
import subprocess
import threading
import time
from urllib.parse import parse_qs, unquote, urlparse
from keys_keeper import clipboard
from keys_keeper.audit import AuditLog
from keys_keeper.composition import build_backend
from keys_keeper.models import now_iso
from keys_keeper.paths import Paths
from keys_keeper.refs import reverse_refs
from keys_keeper.store import MetadataStore


def handle_api(handler, *, paths: Paths, method: str, path: str, body: bytes | None) -> None:
    parsed = urlparse(path)
    route = parsed.path

    if route == "/api/entries" and method == "GET":
        return _entries(handler, paths, parsed.query)
    if route.startswith("/api/entries/") and method == "GET":
        entry_id = unquote(route.rsplit("/", 1)[-1])
        return _entry_detail(handler, paths, entry_id)
    if route == "/api/copy" and method == "POST":
        return _copy(handler, paths, body)
    if route == "/api/heartbeat" and method == "POST":
        handler._send_json(200, {"ok": True})
        return
    if route == "/api/shutdown" and method == "POST":
        # schedule a shutdown after responding
        handler._send_json(200, {"ok": True})
        threading.Thread(target=_shutdown_self, daemon=True).start()
        return
    if route == "/api/audit" and method == "GET":
        return _audit(handler, paths, parsed.query)
    if route == "/api/entries" and method == "POST":
        return _create_entry(handler, paths, body)
    if route.startswith("/api/entries/") and method == "PATCH":
        entry_id = unquote(route.rsplit("/", 1)[-1])
        return _patch_entry(handler, paths, entry_id, body)
    if route.startswith("/api/entries/") and method == "DELETE":
        entry_id = unquote(route.rsplit("/", 1)[-1])
        # Mirror CLI's `rm --cascade`: opt-in via ?cascade=1.
        cascade = parse_qs(parsed.query).get("cascade", ["0"])[0] in ("1", "true", "yes")
        store = MetadataStore(paths)
        audit = AuditLog(paths)
        e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
        if e is None:
            handler._send_json(404, {"error": "not found"})
            return
        deps = [x for x in store.list() if any(r.get("name") == e.name for r in x.refs)]
        if deps and not cascade:
            handler._send_json(409, {"error": "has dependents", "dependents": [d.name for d in deps]})
            return
        if deps and cascade:
            # Strip the now-dangling ref from each dependent (same algorithm as cli.py:373).
            for d in deps:
                d.refs = [r for r in d.refs if r.get("name") != e.name]
                store.update(d)
        store.delete_by_name(e.name)
        backend = build_backend()
        backend.delete(e.id)
        backend.delete(e.id + ":passphrase")
        audit.record(op="delete", name=e.name, id_=e.id, success=True)
        handler._send_json(200, {"ok": True, "cascaded": [d.name for d in deps] if cascade else []})
        return

    if route == "/api/bulk-import" and method == "POST":
        return _bulk_import(handler, paths, parsed.query, body)

    if route.startswith("/api/entries/") and route.endswith("/replace-secret") and method == "POST":
        entry_id = unquote(route[len("/api/entries/"):-len("/replace-secret")])
        return _replace_secret(handler, paths, entry_id, body)

    if route == "/api/status" and method == "GET":
        return _status(handler, paths)

    if route == "/api/env-names" and method == "GET":
        return _env_names(handler)

    handler._send_json(404, {"error": "not found"})


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
    backend = build_backend()
    try:
        sealed = backend.get(e.id)
    except Exception as ex:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error=str(ex))
        handler._send_json(500, {"error": str(ex)})
        return
    # Clipboard sink (controlled, not transcript-visible to the agent).
    value = sealed.unseal()
    if not clipboard.write(value):
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error="clipboard write failed")
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
    from keys_keeper.models import Entry, EntryType, ValidationError
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
    backend = build_backend()
    try:
        store.add(e)
    except Exception as ex:
        handler._send_json(409, {"error": str(ex)})
        return
    if payload.get("value"):
        backend.set(e.id, payload["value"])
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
    if "tags" in payload:
        e.tags = list(payload["tags"])
    if "note" in payload:
        e.note = payload["note"]
    if "fields" in payload:
        e.fields = {**e.fields, **payload["fields"]}
    if "refs" in payload:
        e.refs = list(payload["refs"])
    e.updated_at = now_iso()
    store.update(e)
    if payload.get("value"):
        build_backend().set(e.id, payload["value"])
    audit.record(op="update", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True})


def _shutdown_self() -> None:
    # graceful exit — the test server handles the actual stop via close
    time.sleep(0.05)
    os._exit(0)


def _bulk_import(handler, paths: Paths, query: str, body: bytes) -> None:
    from keys_keeper.parser import parse_bulk
    from keys_keeper.models import Entry, EntryType, ValidationError
    payload = json.loads(body or b"{}")
    text = payload.get("source", "")
    dry = "dry-run=1" in (query or "")
    rows = parse_bulk(text)

    out = [{
        "line": r.line,
        "name": r.name,
        "type": r.type,
        "value": r.value,
        "tags": r.tags,
        "error": r.error,
    } for r in rows]

    if dry:
        handler._send_json(200, {"rows": out})
        return

    if any(r.error for r in rows):
        handler._send_json(400, {"error": "rows have errors", "rows": out})
        return

    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = build_backend()
    existing = {e.name for e in store.list()}
    collisions = [r.name for r in rows if r.name in existing]
    if collisions:
        handler._send_json(409, {"error": "name collisions", "names": collisions})
        return

    for r in rows:
        type_ = EntryType(r.type)
        fields: dict = {}
        try:
            entry = Entry.new(name=r.name, type=type_, fields=fields, tags=r.tags)
        except ValidationError as ex:
            handler._send_json(500, {"error": f"row {r.line}: {ex}"})
            return
        store.add(entry)
        if type_ in (EntryType.API_KEY, EntryType.SSH_KEY) or type_ == EntryType.NOTE:
            backend.set(entry.id, r.value)
        audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    handler._send_json(200, {"ok": True, "imported": len(rows)})


def _status(handler, paths: Paths) -> None:
    import os, time
    from keys_keeper import __version__
    info = {
        "version": __version__,
        "config_dir": str(paths.root),
        "data_json": str(paths.data_json),
        "audit_jsonl": str(paths.audit_jsonl),
        "reveal_env_set": os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1",
        "uptime_sec": int(time.monotonic() - getattr(handler.server, "_kk_started", time.monotonic())),
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
    backend = build_backend()
    backend.set(e.id, value)
    e.updated_at = now_iso()
    store.update(e)
    audit.record(op="replace_secret", name=e.name, id_=e.id, success=True)
    handler._send_json(200, {"ok": True})
