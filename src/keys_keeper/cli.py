"""keys CLI — argparse routing + subcommand dispatch."""
from __future__ import annotations
import argparse
import getpass
import hashlib
import os
import re
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

from keys_keeper import __version__, clipboard
from keys_keeper.audit import AuditLog
from keys_keeper.composition import build_backend
from keys_keeper.models import Entry, EntryType, ValidationError, now_iso
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, NameConflict, NotFound, StoreError


# ----- input source resolution -----

def _read_input(args: argparse.Namespace) -> str:
    sources = [
        bool(args.from_clipboard),
        bool(args.from_file),
        bool(args.stdin),
        bool(args.web),
    ]
    if sum(sources) != 1:
        sys.stderr.write(
            "error: must specify exactly one input source: "
            "--from-clipboard | --from-file PATH | --stdin | --web\n"
        )
        return ""
    if args.from_clipboard:
        return clipboard.read().lstrip("﻿")
    if args.from_file:
        # PowerShell on Windows defaults to writing UTF-8 with BOM; strip it
        # so the stored secret doesn't carry an invisible ﻿ at the start.
        return Path(args.from_file).read_text(encoding="utf-8-sig")
    if args.stdin:
        return sys.stdin.read().lstrip("﻿").rstrip("\n")
    if args.web:
        sys.stderr.write("--web flag is implemented in admin UI; not supported here yet\n")
        return ""
    return ""


# ----- subcommand handlers -----

def cmd_add(args: argparse.Namespace) -> int:
    paths = Paths()
    paths.ensure()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = build_backend()
    type_ = EntryType(args.type)

    # merge --field flags into fields dict
    fields: dict = {}
    if args.service:
        fields["service"] = args.service
    for kv in args.field or []:
        k, _, v = kv.partition("=")
        if not _:
            sys.stderr.write(f"--field expects KEY=VALUE, got {kv!r}\n")
            return 2
        # numeric coercion for known int fields
        if k == "port":
            v = int(v)
        elif k == "secret_body":
            v = v.lower() in ("1", "true", "yes")
        fields[k] = v

    # parse --ref flags
    refs = []
    for kv in args.ref or []:
        role, _, name = kv.partition("=")
        if not _:
            sys.stderr.write(f"--ref expects ROLE=NAME, got {kv!r}\n")
            return 2
        refs.append({"role": role, "name": name})

    # determine if this entry type stores a secret
    needs_secret = type_ in (EntryType.API_KEY, EntryType.SSH_KEY) or (
        type_ == EntryType.NOTE and fields.get("secret_body", False)
    )

    value = ""
    if needs_secret:
        value = _read_input(args)
        if not value and not args.from_file:
            return 2

    try:
        entry = Entry.new(
            name=args.name, type=type_, fields=fields,
            tags=args.tag or [], note=args.note or "", refs=refs,
        )
    except ValidationError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    try:
        if args.replace and store.get_by_name(args.name):
            existing = store.get_by_name(args.name)
            entry.id = existing.id
            store.replace_by_name(entry)
        else:
            store.add(entry)
    except NameConflict as e:
        sys.stderr.write(f"error: {e}\n")
        return 1

    if needs_secret:
        backend.set(entry.id, value)
    audit.record(op="add", name=entry.name, id_=entry.id, success=True)
    print(f"added {entry.type.value} '{entry.name}' (id={entry.id})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = MetadataStore(Paths())
    entries = store.list()
    if args.type:
        entries = [e for e in entries if e.type.value == args.type]
    if args.tag:
        entries = [e for e in entries if args.tag in e.tags]
    if args.search:
        q = args.search.lower()
        entries = [e for e in entries if q in e.name.lower() or q in (e.note or "").lower()]
    if not entries:
        print("no entries")
        return 0
    for e in entries:
        tag_str = "[" + ",".join(e.tags) + "]" if e.tags else ""
        print(f"{e.type.value:10s}  {e.name:30s}  {tag_str}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    store = MetadataStore(Paths())
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    print(f"name:       {e.name}")
    print(f"type:       {e.type.value}")
    print(f"id:         {e.id}")
    print(f"created:    {e.created_at}")
    print(f"updated:    {e.updated_at}")
    print(f"tags:       {', '.join(e.tags) or '-'}")
    print(f"note:       {e.note or '-'}")
    if e.fields:
        print("fields:")
        for k, v in e.fields.items():
            print(f"  {k}: {v}")
    if e.refs:
        print("refs:")
        for r in e.refs:
            print(f"  {r['role']} -> {r['name']}")
    # reverse refs
    from keys_keeper.refs import reverse_refs
    rev = reverse_refs(store.list())
    if e.name in rev:
        print("used by:")
        for dependent in rev[e.name]:
            print(f"  {dependent}")
    return 0


def cmd_reveal(args: argparse.Namespace) -> int:
    if os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") != "1":
        if sys.platform == "win32":
            hint = "run `setx KEYS_KEEPER_ALLOW_REVEAL 1` (takes effect in new shells)"
        else:
            hint = "add `export KEYS_KEEPER_ALLOW_REVEAL=1` to ~/.zshrc"
        sys.stderr.write(
            "error: `keys reveal` requires KEYS_KEEPER_ALLOW_REVEAL=1 in env. "
            f"{hint}. (This guard exists so AI agents can't accidentally "
            "extract plaintext.)\n"
        )
        return 2
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = build_backend()
    try:
        sealed = backend.get(e.id)
    except Exception as ex:
        audit.record(op="reveal", name=e.name, id_=e.id, success=False, error=str(ex))
        sys.stderr.write(f"failed to read keychain: {ex}\n")
        return 1
    # ⚠️  load-bearing: this is the only stdout-bound .unseal() in the codebase.
    # The env gate above is the structural guarantee; .unseal() here is the
    # explicit unwrap that grep -rn finds when auditing the threat model.
    value = sealed.unseal()
    if args.as_env:
        # NAME=value format for `eval $(keys reveal X --as-env)`
        env_name = e.name.upper().replace("-", "_").replace(".", "_")
        print(f"{env_name}={_shell_quote(value)}")
    else:
        sys.stdout.write(value)
        if not value.endswith("\n"):
            sys.stdout.write("\n")
    audit.record(op="reveal", name=e.name, id_=e.id, success=True)
    return 0


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def cmd_copy(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = build_backend()
    try:
        sealed = backend.get(e.id)
    except Exception as ex:
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error=str(ex))
        sys.stderr.write(f"failed to read keychain: {ex}\n")
        return 1

    # Clipboard is a controlled (non-transcript) sink. Unwrap is local; the
    # plaintext does not leave this scope as a printable.
    value = sealed.unseal()
    if not clipboard.write(value):
        audit.record(op="copy", name=e.name, id_=e.id, success=False, error="clipboard write failed")
        sys.stderr.write("clipboard write failed\n")
        return 1

    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    print(f"copied {e.name} to clipboard · auto-clear in {args.clear_after}s")
    audit.record(op="copy", name=e.name, id_=e.id, success=True)

    if args.clear_after > 0:
        clipboard.spawn_clear_after(written_hash, args.clear_after)
    return 0


# inject
def cmd_inject(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    backend = build_backend()
    # File sink (controlled, not transcript-visible).
    value = backend.get(e.id).unseal()
    target = Path(args.file)
    if target.exists():
        existing = target.read_text()
        existing_lines = existing.splitlines()
        match_idx = None
        for i, line in enumerate(existing_lines):
            if line.startswith(f"{args.as_env}="):
                match_idx = i
                break
        if match_idx is not None:
            if not args.replace:
                sys.stderr.write(
                    f"error: {args.as_env} already exists in {target} "
                    f"(use --replace to overwrite)\n"
                )
                return 1
            existing_lines[match_idx] = f"{args.as_env}={value}"
            new_content = "\n".join(existing_lines) + ("\n" if existing.endswith("\n") else "")
        else:
            sep = "" if existing.endswith("\n") or not existing else "\n"
            new_content = existing + sep + f"{args.as_env}={value}\n"
    else:
        new_content = f"{args.as_env}={value}\n"
    target.write_text(new_content)
    audit.record(op="inject", name=e.name, id_=e.id, file_target=str(target), success=True)
    print(f"injected {e.name} → {target} as {args.as_env}")
    return 0


# resolve
_RESOLVE_RE = re.compile(r"__KEYS:([a-z0-9][a-z0-9._-]*[a-z0-9])(?::([a-z_]+))?__")


def cmd_resolve(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = build_backend()
    target = Path(args.file)
    content = target.read_text()
    errors = []
    count = 0

    def replace(match: re.Match) -> str:
        nonlocal count
        name = match.group(1)
        field_name = match.group(2)
        e = store.get_by_name(name)
        if e is None:
            errors.append(f"unknown entry: {name}")
            return match.group(0)
        if field_name:
            v = e.fields.get(field_name)
            if v is None:
                errors.append(f"entry {name} has no field {field_name}")
                return match.group(0)
            count += 1
            return str(v)
        else:
            count += 1
            try:
                # File-substitution sink (controlled, not transcript).
                return backend.get(e.id).unseal()
            except Exception as ex:
                errors.append(f"keychain miss for {name}: {ex}")
                return match.group(0)

    new_content = _RESOLVE_RE.sub(replace, content)
    if errors:
        sys.stderr.write("error: resolve failed:\n")
        for err in errors:
            sys.stderr.write(f"  - {err}\n")
        return 1
    target.write_text(new_content)
    audit.record(op="resolve", name="<file>", id_=str(target), file_target=str(target), success=True)
    print(f"resolved {count} placeholder(s) in {target}")
    return 0


# rm
def cmd_rm(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    # check reverse refs
    dependents = [
        x for x in store.list()
        if any(r.get("name") == e.name for r in x.refs)
    ]
    if dependents and not args.cascade:
        sys.stderr.write(
            f"error: {e.name} is referenced by: {[d.name for d in dependents]}. "
            f"Use --cascade to remove the references too.\n"
        )
        return 1
    if dependents and args.cascade:
        for d in dependents:
            d.refs = [r for r in d.refs if r.get("name") != e.name]
            store.update(d)
    store.delete_by_name(args.name)
    backend = build_backend()
    backend.delete(e.id)
    backend.delete(e.id + ":passphrase")  # in case ssh_key had passphrase
    audit.record(op="delete", name=e.name, id_=e.id, success=True)
    print(f"removed {e.name}")
    return 0


# edit
def cmd_edit(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    if args.add_tag:
        for t in args.add_tag:
            if t not in e.tags:
                e.tags.append(t)
    if args.rm_tag:
        e.tags = [t for t in e.tags if t not in args.rm_tag]
    if args.note is not None:
        e.note = args.note
    if args.field:
        for kv in args.field:
            k, _, v = kv.partition("=")
            if not _:
                sys.stderr.write(f"--field expects KEY=VALUE, got {kv!r}\n")
                return 2
            e.fields[k] = v
    if args.ref:
        for kv in args.ref:
            role, _, name = kv.partition("=")
            if not _:
                sys.stderr.write(f"--ref expects ROLE=NAME, got {kv!r}\n")
                return 2
            e.refs = [r for r in e.refs if r.get("role") != role]
            e.refs.append({"role": role, "name": name})
    if args.new_name:
        try:
            from keys_keeper.models import validate_name
            validate_name(args.new_name)
        except Exception as ex:
            sys.stderr.write(f"error: {ex}\n")
            return 2
        if store.get_by_name(args.new_name) is not None:
            sys.stderr.write(f"error: name {args.new_name!r} already taken\n")
            return 1
        e.name = args.new_name
    e.updated_at = now_iso()
    store.update(e)
    audit.record(op="update", name=e.name, id_=e.id, success=True)
    print(f"updated {e.name}")
    return 0


# doctor
def cmd_doctor(args: argparse.Namespace) -> int:
    paths = Paths()
    paths.ensure()
    print(f"keys-keeper {__version__}")
    print(f"config dir: {paths.root}")
    print(f"  data.json:    {'exists' if paths.data_json.exists() else 'will be created on first add'}")
    print(f"  audit.jsonl:  {'exists' if paths.audit_jsonl.exists() else '(none yet)'}")
    print(f"  config.toml:  {'exists' if paths.config_toml.exists() else '(default)'}")
    # keychain access probe
    try:
        backend = build_backend()
        backend.list_ids()
        print("keychain:     ✓ accessible")
    except Exception as ex:
        print(f"keychain:     ✗ ERROR — {ex}")
    if os.environ.get("KEYS_KEEPER_ALLOW_REVEAL") == "1":
        print("KEYS_KEEPER_ALLOW_REVEAL: ✓ set")
    else:
        print("KEYS_KEEPER_ALLOW_REVEAL: ⚠ not set — `keys reveal` will refuse to print plaintext")
        if sys.platform == "win32":
            print("  run `setx KEYS_KEEPER_ALLOW_REVEAL 1` to enable (effective in new shells)")
        else:
            print("  add `export KEYS_KEEPER_ALLOW_REVEAL=1` to ~/.zshrc to enable")

    # data.json validity + entry count
    try:
        store = MetadataStore(paths)
        entries = store.list()
        print(f"data.json:    ✓ {len(entries)} entries")
    except Exception as ex:
        print(f"data.json:    ✗ ERROR — {ex}")
        return 0

    # ref integrity
    from keys_keeper.refs import detect_cycles, RefCycleError
    try:
        detect_cycles(entries)
        print("refs:         ✓ no cycles")
    except RefCycleError as ex:
        print(f"refs:         ✗ {ex}")

    # orphan refs (target missing)
    by_name = {e.name for e in entries}
    orphans = []
    for e in entries:
        for r in e.refs:
            if r.get("name") not in by_name:
                orphans.append((e.name, r.get("name")))
    if orphans:
        print(f"refs:         ⚠ {len(orphans)} orphan ref(s):")
        for src, tgt in orphans:
            print(f"   {src} → {tgt} (missing)")
    else:
        print("refs:         ✓ all targets exist")

    # keychain orphans (account exists but no metadata) and missing (metadata but no keychain)
    try:
        kc_ids = set(build_backend().list_ids())
    except Exception:
        kc_ids = None
    if kc_ids is not None:
        meta_ids = {e.id for e in entries}
        # passphrase variants
        meta_ids |= {e.id + ":passphrase" for e in entries if e.type.value == "ssh_key"}
        kc_orphans = kc_ids - meta_ids
        meta_orphans = {e.id for e in entries if e.type.value in ("api_key", "ssh_key", "note") and e.id not in kc_ids}
        if kc_orphans:
            print(f"keychain:     ⚠ {len(kc_orphans)} keychain entry/entries without metadata")
        if meta_orphans:
            print(f"keychain:     ⚠ {len(meta_orphans)} metadata entry/entries missing keychain blobs")
        if not kc_orphans and not meta_orphans:
            print("keychain:     ✓ in sync with metadata")
    return 0


def cmd_ssh(args: argparse.Namespace) -> int:
    from keys_keeper.ssh_runner import run_ssh
    paths = Paths()
    store = MetadataStore(paths)
    audit = AuditLog(paths)
    backend = build_backend()
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    try:
        rc = run_ssh(store=store, backend=backend, server_name=args.name, extra_cmd=args.cmd)
    except ValueError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    audit.record(op="ssh", name=e.name, id_=e.id, success=(rc == 0))
    return rc


def cmd_serve(args: argparse.Namespace) -> int:
    from keys_keeper.server import AdminServer
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=args.port, idle_timeout_sec=15 * 60)
    url = f"http://127.0.0.1:{args.port or 7777}/?t={server.token}"
    print(f"keys-keeper admin starting on {url}")
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    paths = Paths()
    store = MetadataStore(paths)
    backend = build_backend()
    audit = AuditLog(paths)
    pw = getpass.getpass("Export password: ")
    pw2 = getpass.getpass("Confirm: ")
    if pw != pw2:
        sys.stderr.write("passwords do not match\n")
        return 1
    payload = {
        "schema_version": 1,
        "entries": [],
    }
    for e in store.list():
        rec = e.to_dict()
        rec["_secret"] = None
        rec["_secret_passphrase"] = None
        try:
            # AES-GCM-encrypted blob sink (controlled, not transcript).
            rec["_secret"] = backend.get(e.id).unseal()
        except Exception:
            pass
        try:
            rec["_secret_passphrase"] = backend.get(e.id + ":passphrase").unseal()
        except Exception:
            pass
        payload["entries"].append(rec)
    from keys_keeper.crypto import encrypt_blob
    import json as _json
    blob = encrypt_blob(_json.dumps(payload).encode("utf-8"), password=pw)
    Path(args.file).write_bytes(blob)
    audit.record(op="export", name="<all>", id_="-", file_target=args.file, success=True)
    print(f"exported {len(payload['entries'])} entries to {args.file}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    from keys_keeper.crypto import decrypt_blob, BadPassword
    import json as _json
    paths = Paths()
    paths.ensure()
    pw = getpass.getpass("Import password: ")
    blob = Path(args.file).read_bytes()
    try:
        raw = decrypt_blob(blob, password=pw)
    except BadPassword as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    payload = _json.loads(raw)
    store = MetadataStore(paths)
    backend = build_backend()
    audit = AuditLog(paths)
    existing = {e.name for e in store.list()}
    imported = 0
    for rec in payload["entries"]:
        secret = rec.pop("_secret", None)
        passphrase = rec.pop("_secret_passphrase", None)
        from keys_keeper.models import Entry
        e = Entry.from_dict(rec)
        if e.name in existing:
            if args.replace:
                store.replace_by_name(e)
            else:
                continue
        else:
            store.add(e)
        if secret:
            backend.set(e.id, secret)
        if passphrase:
            backend.set(e.id + ":passphrase", passphrase)
        imported += 1
    audit.record(op="import", name="<all>", id_="-", file_target=args.file, success=True)
    print(f"imported {imported} entries")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    paths = Paths()
    audit = AuditLog(paths)
    from datetime import datetime, timezone, timedelta
    since = None
    if args.since:
        amount = int(args.since[:-1])
        unit = args.since[-1]
        delta = {"h": "hours", "d": "days"}[unit]
        since = datetime.now(timezone.utc) - timedelta(**{delta: amount})
    events = list(audit.search(op=args.op, name=args.name, since=since, limit=args.limit))
    if args.tail:
        events = events[-args.limit:]
    for ev in events:
        print(f"{ev['ts']}  {ev['op']:8s}  {ev['name']:24s}  {ev.get('file_target') or '-'}")
    return 0


# ----- top-level parser -----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keys", description="personal secrets manager")
    p.add_argument("--version", action="version", version=f"keys-keeper {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # add
    a = sub.add_parser("add", help="add a new entry")
    a.add_argument("name")
    a.add_argument("--type", choices=[t.value for t in EntryType], default="api_key")
    a.add_argument("--from-clipboard", action="store_true")
    a.add_argument("--from-file")
    a.add_argument("--stdin", action="store_true")
    a.add_argument("--web", action="store_true")
    a.add_argument("--service")
    a.add_argument("--tag", action="append", default=[])
    a.add_argument("--note", default="")
    a.add_argument("--replace", action="store_true")
    a.add_argument("--field", action="append", default=[], help="KEY=VALUE")
    a.add_argument("--ref", action="append", default=[], help="ROLE=NAME")
    a.set_defaults(func=cmd_add)

    # list
    l = sub.add_parser("list", help="list entries")
    l.add_argument("--type")
    l.add_argument("--tag")
    l.add_argument("--search")
    l.set_defaults(func=cmd_list)

    # info
    i = sub.add_parser("info", help="show entry metadata (no value)")
    i.add_argument("name")
    i.set_defaults(func=cmd_info)

    # reveal
    rv = sub.add_parser("reveal", help="print value to stdout (gated by env-var)")
    rv.add_argument("name")
    rv.add_argument("--as-env", action="store_true", help="print as NAME=value for eval")
    rv.set_defaults(func=cmd_reveal)

    # copy
    cp = sub.add_parser("copy", help="copy value to clipboard with auto-clear")
    cp.add_argument("name")
    cp.add_argument("--clear-after", type=int, default=30, help="seconds before auto-clear (0 = never)")
    cp.set_defaults(func=cmd_copy)

    # inject
    inj = sub.add_parser("inject", help="append ENV=value to a file")
    inj.add_argument("name")
    inj.add_argument("--file", required=True)
    inj.add_argument("--as", dest="as_env", required=True, metavar="ENV_NAME")
    inj.add_argument("--replace", action="store_true")
    inj.set_defaults(func=cmd_inject)

    # resolve
    rs = sub.add_parser("resolve", help="replace __KEYS:name__ placeholders in a file")
    rs.add_argument("file")
    rs.set_defaults(func=cmd_resolve)

    # rm
    rm = sub.add_parser("rm", help="delete an entry")
    rm.add_argument("name")
    rm.add_argument("--cascade", action="store_true")
    rm.set_defaults(func=cmd_rm)

    # edit
    ed = sub.add_parser("edit", help="modify entry metadata")
    ed.add_argument("name")
    ed.add_argument("--name", dest="new_name")
    ed.add_argument("--add-tag", action="append", default=[])
    ed.add_argument("--rm-tag", action="append", default=[])
    ed.add_argument("--note", default=None)
    ed.add_argument("--field", action="append", default=[], help="KEY=VALUE")
    ed.add_argument("--ref", action="append", default=[], help="ROLE=NAME")
    ed.set_defaults(func=cmd_edit)

    # doctor
    dr = sub.add_parser("doctor", help="health check + paths")
    dr.set_defaults(func=cmd_doctor)

    sh = sub.add_parser("ssh", help="open ssh session to a server entry")
    sh.add_argument("name")
    sh.add_argument("--cmd", help="run a one-shot command instead of interactive shell")
    sh.set_defaults(func=cmd_ssh)

    sv = sub.add_parser("serve", help="run the local web admin")
    sv.add_argument("--port", type=int, default=7777)
    sv.add_argument("--no-open", action="store_true")
    sv.set_defaults(func=cmd_serve)

    ex = sub.add_parser("export", help="encrypted backup to file")
    ex.add_argument("file")
    ex.set_defaults(func=cmd_export)

    im = sub.add_parser("import", help="restore from encrypted backup")
    im.add_argument("file")
    im.add_argument("--replace", action="store_true", help="overwrite existing names")
    im.add_argument("--merge", action="store_true", help="(default) skip name collisions")
    im.set_defaults(func=cmd_import)

    au = sub.add_parser("audit", help="show audit log")
    au.add_argument("--name")
    au.add_argument("--op")
    au.add_argument("--since", help="e.g. 24h, 7d")
    au.add_argument("--limit", type=int, default=100)
    au.add_argument("--tail", action="store_true")
    au.set_defaults(func=cmd_audit)

    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles + Python default to cp1252 for the standard streams.
    # We need UTF-8 on:
    #   - stdout/stderr — so doctor's ✓/✗ glyphs and non-ASCII secret names render
    #   - stdin — so PowerShell pipes (which emit UTF-8 bytes with BOM) decode
    #     into the expected `﻿`-prefixed string we can strip; otherwise
    #     cp1252 turns the BOM into three separate Latin-1 chars (ï»¿) that
    #     leak into the stored secret.
    # No-op on macOS (already UTF-8). errors="replace" is a fallback for
    # ancient terminals that can't be reconfigured.
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
