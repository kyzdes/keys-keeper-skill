"""keys CLI — argparse routing + subcommand dispatch."""
from __future__ import annotations
import argparse
import errno
import getpass
import hashlib
import json
import os
import re
import subprocess
import sys
import webbrowser
from pathlib import Path

from keys_keeper import __version__, clipboard
from keys_keeper.audit import AuditLog, record_outcome
from keys_keeper.backend import SecretAccessDenied, SecretNotFound, SecretUnavailable
from keys_keeper.composition import build_backend
from keys_keeper.models import (
    Entry,
    EntryType,
    ValidationError,
    entry_requires_secret,
    now_iso,
    validate_snapshot_payload,
)
from keys_keeper.paths import Paths
from keys_keeper.secure_io import SecureFileError, read_secure_text, replace_secure_text
from keys_keeper.service import HasDependents, SecretInput, VaultService
from keys_keeper.store import MetadataStore, NameConflict, StoreError


def _audit_outcome(audit, *, committed=..., **event) -> str:
    """Audit is observational: never conceal an already committed side effect."""
    status = record_outcome(audit, **event)
    if status != "recorded":
        sys.stderr.write(json.dumps({
            "operation": event["op"],
            "committed": event.get("success", True) if committed is ... else committed,
            "audit_status": status,
        }, separators=(",", ":")) + "\n")
    return status


def _secret_read_error(error: Exception) -> str:
    if isinstance(error, SecretNotFound):
        return "secret is missing"
    if isinstance(error, SecretAccessDenied):
        return "secret access denied"
    if isinstance(error, SecretUnavailable):
        return "secret provider unavailable"
    return "secret read failed"


def _operation_failure(operation: str, error: Exception | None = None, *,
                       committed: bool | None = None, audit_status: str = "unknown") -> int:
    """One value-free adapter receipt, preserving typed publication outcomes."""
    if getattr(error, "committed", None) is True:
        committed = True
    reported_audit = getattr(error, "audit_status", audit_status)
    if not isinstance(reported_audit, str) or reported_audit not in {"recorded", "unavailable", "unknown"}:
        reported_audit = "unknown"
    outcome = "published" if committed is True else "failed" if committed is False else "unconfirmed"
    sys.stderr.write(json.dumps({"operation": operation, "committed": committed,
                               "outcome": outcome, "audit_status": reported_audit},
                              separators=(",", ":")) + "\n")
    if committed is False:
        sys.stderr.write("error: operation failed before a confirmed change\n")
    else:
        sys.stderr.write("error: operation did not return a verified receipt; inspect state before retrying\n")
    return 1


def _mutation_failure(audit, *, op: str, entry: Entry) -> int:
    """An unexpected durable mutation failure may require forward recovery."""
    status = _audit_outcome(audit, op=op, name=entry.name, id_=entry.id,
                           success=False, committed=None)
    sys.stderr.write(json.dumps({"operation": op, "committed": None, "audit_status": status},
                               separators=(",", ":")) + "\n")
    sys.stderr.write("error: mutation did not return a verified receipt; check vault recovery before retrying\n")
    return 1


def _profile_selector(args: argparse.Namespace) -> str | None:
    """Normalize the global profile selector without guessing a scope."""
    selector = getattr(args, "profile_selector", None)
    environment = getattr(args, "profile_environment", None)
    if environment is None:
        return selector
    if not selector:
        raise ValueError("--env requires --profile or --project")
    if "/" in selector:
        raise ValueError("choose either project/environment or a profile UUID, not both")
    return f"{selector}/{environment}"


def _context(args: argparse.Namespace, *, access=None):
    """Build exactly one selected vault context for a command invocation.

    The import is lazy while project runtime is optional during catalog-only
    upgrades.  The nullary factory keeps legacy CLI tests able to substitute
    ``build_backend`` without mutating module globals.
    """
    from keys_keeper.composition import AccessContext
    from keys_keeper.project_runtime import ProjectRuntime

    selected_access = AccessContext.INTERACTIVE if access is None else access
    runtime = ProjectRuntime(
        Paths(), access=selected_access,
        # Keep the legacy default seam, but never drop an explicit no-UI policy.
        backend_factory=(lambda: build_backend()) if access is None else (
            lambda: build_backend(access=selected_access)
        ),
    )
    return runtime.context(_profile_selector(args))


def _context_or_error(args: argparse.Namespace, *, access=None):
    try:
        return _context(args, access=access)
    except (ValueError, RuntimeError) as ex:
        sys.stderr.write(f"error: {ex}\n")
        return None


# ----- input source resolution -----

_MAX_INPUT_CHARS = 1_048_576


def _field_value(key: str, value: str):
    if key == "port":
        return int(value)
    if key == "secret_body":
        if value.lower() not in ("1", "true", "yes", "0", "false", "no"):
            raise ValueError("secret_body must be true or false")
        return value.lower() in ("1", "true", "yes")
    return value

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
        value = clipboard.read().lstrip("﻿")
    elif args.from_file:
        # PowerShell on Windows defaults to writing UTF-8 with BOM; strip it
        # so the stored secret doesn't carry an invisible ﻿ at the start.
        value = read_secure_text(Path(args.from_file), missing_ok=False,
                                 encoding="utf-8-sig", max_bytes=4 * _MAX_INPUT_CHARS + 3).text
    elif args.stdin:
        value = sys.stdin.read(_MAX_INPUT_CHARS + 1)
        if len(value) > _MAX_INPUT_CHARS:
            raise ValueError("secret input exceeds size limit")
        value = value.lstrip("﻿").rstrip("\n")
    elif args.web:
        sys.stderr.write("--web flag is implemented in admin UI; not supported here yet\n")
        return ""
    else:
        return ""
    if len(value) > _MAX_INPUT_CHARS:
        raise ValueError("secret input exceeds size limit")
    return value


# ----- subcommand handlers -----

def cmd_add(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    # The profile registry remains at the root. The context above validates a
    # selector, while the server resolves that fixed selector on every request.
    paths = Paths()
    paths.ensure()
    store = ctx.store
    audit = ctx.audit
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
        try:
            fields[k] = _field_value(k, v)
        except ValueError:
            sys.stderr.write("error: port must be an integer and secret_body must be true or false\n")
            return 2

    # parse --ref flags
    refs = []
    for kv in args.ref or []:
        role, _, name = kv.partition("=")
        if not _:
            sys.stderr.write(f"--ref expects ROLE=NAME, got {kv!r}\n")
            return 2
        refs.append({"role": role, "name": name})

    try:
        entry = Entry.new(
            name=args.name, type=type_, fields=fields,
            tags=args.tag or [], note=args.note or "", refs=refs,
        )
    except ValidationError as e:
        sys.stderr.write(f"error: {e}\n")
        return 2

    needs_secret = entry_requires_secret(entry)
    value = ""
    if needs_secret:
        try:
            value = _read_input(args)
        except Exception:
            _audit_outcome(audit, op="add", name=entry.name, id_=entry.id, success=False)
            sys.stderr.write("error: secret input is unavailable, unsafe, or exceeds the size limit\n")
            return 2
        if not value and not args.from_file:
            return 2
    try:
        entry = ctx.service.create_entry(
            entry,
            secrets=SecretInput(value=value) if needs_secret else None,
            replace=args.replace,
        )
    except NameConflict as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    except ValidationError:
        sys.stderr.write("error: invalid entry or secret input\n")
        return 2
    except Exception:
        return _mutation_failure(audit, op="add", entry=entry)
    _audit_outcome(audit, op="add", name=entry.name, id_=entry.id, success=True)
    print(f"added {entry.type.value} '{entry.name}' (id={entry.id})")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    entries = store.list()
    if args.type:
        entries = [e for e in entries if e.type.value == args.type]
    if args.tag:
        entries = [e for e in entries if args.tag in e.tags]
    if args.search:
        q = args.search.lower()
        entries = [e for e in entries if q in e.name.lower() or q in (e.note or "").lower()]
    if not entries:
        # Distinguish "store is empty" from "filters matched nothing" so a new
        # user gets pointed at quickstart instead of a dead end.
        if not (args.type or args.tag or args.search):
            print("no entries yet — run `keys quickstart` to add your first key")
        else:
            print("no entries match those filters")
        return 0
    for e in entries:
        tag_str = "[" + ",".join(e.tags) + "]" if e.tags else ""
        print(f"{e.type.value:10s}  {e.name:30s}  {tag_str}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
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
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    env_name = e.name.upper().replace("-", "_").replace(".", "_")
    if args.as_env and not _ENV_NAME_RE.fullmatch(env_name):
        sys.stderr.write("error: entry name cannot be used as an environment identifier\n")
        return 2
    try:
        sealed = ctx.backend.get(e.id)
    except Exception as ex:
        _audit_outcome(audit, op="reveal", name=e.name, id_=e.id, success=False)
        sys.stderr.write(f"error: {_secret_read_error(ex)}\n")
        return 1
    # ⚠️  load-bearing: this is the only stdout-bound .unseal() in the codebase.
    # The env gate above is the structural guarantee; .unseal() here is the
    # explicit unwrap that grep -rn finds when auditing the threat model.
    value = sealed.unseal()
    if args.as_env:
        # NAME=value format for `eval $(keys reveal X --as-env)`
        print(f"{env_name}={_shell_quote(value)}")
    else:
        sys.stdout.write(value)
        if not value.endswith("\n"):
            sys.stdout.write("\n")
    _audit_outcome(audit, op="reveal", name=e.name, id_=e.id, success=True)
    return 0


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def cmd_copy(args: argparse.Namespace) -> int:
    if not 0 <= args.clear_after <= clipboard.MAX_CLEAR_DELAY_SECONDS:
        sys.stderr.write("clear-after must be from 0 to 86400 seconds\n")
        return 1
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    try:
        sealed = ctx.backend.get(e.id)
    except Exception as ex:
        _audit_outcome(audit, op="copy", name=e.name, id_=e.id, success=False)
        sys.stderr.write(f"error: {_secret_read_error(ex)}\n")
        return 1

    # Clipboard is a controlled (non-transcript) sink. Unwrap is local; the
    # plaintext does not leave this scope as a printable.
    value = sealed.unseal()
    try:
        written = clipboard.write(value)
    except Exception:
        written = False
    if not written:
        _audit_outcome(audit, op="copy", name=e.name, id_=e.id, success=False)
        sys.stderr.write("clipboard write failed\n")
        return 1

    written_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    _audit_outcome(audit, op="copy", name=e.name, id_=e.id, success=True)

    if args.clear_after > 0:
        try:
            clipboard.spawn_clear_after(written_hash, args.clear_after)
        except Exception:
            sys.stderr.write('{"operation":"copy","committed":true,"auto_clear":"unavailable"}\n')
            sys.stderr.write("error: clipboard was written but automatic clearing could not be scheduled\n")
            return 1
    print(f"copied {e.name} to clipboard · auto-clear in {args.clear_after}s")
    return 0


# inject
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_BARE_ENV_VALUE_RE = re.compile(r"[A-Za-z0-9_./:@%+,-]*\Z")


def _dotenv_literal(value: str) -> str:
    """The supported dotenv subset: one literal line, no dialect escapes.

    Bare portable tokens preserve existing output. Other literals are quoted
    once; line breaks, interpolation and dialect-dependent escaping are
    rejected instead of silently transforming a credential.
    """
    if any(ord(ch) < 32 or ord(ch) == 127 or ch in "\x85\u2028\u2029" for ch in value) or any(
        marker in value for marker in ("'", "\\", "$")
    ):
        raise ValueError("unsupported dotenv literal")
    return value if _BARE_ENV_VALUE_RE.fullmatch(value) else "'" + value + "'"


def _dotenv_matches(text: str, env_name: str) -> tuple[list[str], list[int]]:
    lines = text.splitlines(keepends=True)
    assignment = re.compile(r"^\s*(?:export\s+)?" + re.escape(env_name) + r"\s*=")
    indices = [i for i, line in enumerate(lines) if assignment.match(line)]
    return lines, indices


def _single_line_assignment(line: str) -> bool:
    """Do not replace just the first physical line of a multiline value."""
    value = line.split("=", 1)[1].strip()
    if value.startswith("'"):
        return re.fullmatch(r"'[^']*'\s*(?:#.*)?", value) is not None
    if value.startswith('"'):
        return re.fullmatch(r'"(?:[^"\\]|\\.)*"\s*(?:#.*)?', value) is not None
    return not value.endswith("\\")


def cmd_inject(args: argparse.Namespace) -> int:
    if not _ENV_NAME_RE.fullmatch(args.as_env):
        sys.stderr.write("error: --as requires an environment identifier (letters, digits, underscore)\n")
        return 2
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    target = Path(args.file)
    try:
        target_state = read_secure_text(target, missing_ok=True)
    except SecureFileError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1

    existing = target_state.text
    lines, matches = _dotenv_matches(existing, args.as_env)
    if len(matches) > 1:
        sys.stderr.write(f"error: duplicate {args.as_env} assignments; resolve the ambiguity before injection\n")
        return 1
    if matches and (not args.replace or not _single_line_assignment(lines[matches[0]])):
        sys.stderr.write(f"error: {args.as_env} already exists; --replace requires one single-line assignment\n")
        return 1
    try:
        # This is a file exposure sink; neither value nor provider diagnostics
        # enter the receipt. Stop after one failed provider read.
        value = ctx.backend.get(e.id).unseal()
    except Exception as ex:
        _audit_outcome(audit, op="inject", name=e.name, id_=e.id,
                       file_target=str(target), success=False)
        sys.stderr.write(f"error: {_secret_read_error(ex)}\n")
        return 1
    try:
        literal = _dotenv_literal(value)
    except ValueError:
        _audit_outcome(audit, op="inject", name=e.name, id_=e.id,
                       file_target=str(target), success=False)
        sys.stderr.write("error: inject supports literal single-line dotenv values without escapes or interpolation\n")
        return 1
    assignment = f"{args.as_env}={literal}"
    if matches:
        index = matches[0]
        ending = "\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
        lines[index] = assignment + ending
        new_content = "".join(lines)
    else:
        separator = "" if not existing or existing.endswith("\n") else "\n"
        new_content = existing + separator + assignment + "\n"
    try:
        replace_secure_text(target_state, new_content)
    except SecureFileError as ex:
        _audit_outcome(audit,
            op="inject", name=e.name, id_=e.id, file_target=str(target),
            success=False, error="secure file write failed",
        )
        sys.stderr.write(f"error: {ex}\n")
        return 1
    _audit_outcome(audit, op="inject", name=e.name, id_=e.id, file_target=str(target), success=True)
    print(f"injected {e.name} → {target} as {args.as_env}")
    return 0


# resolve
_RESOLVE_RE = re.compile(r"__KEYS:([a-z0-9][a-z0-9._-]*[a-z0-9])(?::([a-z_]+))?__")


def cmd_resolve(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    target = Path(args.file)
    try:
        target_state = read_secure_text(target, missing_ok=False)
    except SecureFileError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    content = target_state.text
    matches = list(_RESOLVE_RE.finditer(content))
    keys = list(dict.fromkeys((m.group(1), m.group(2)) for m in matches))
    entries = {e.name: e for e in store.list()}  # one metadata-only preflight
    replacements: dict[tuple[str, str | None], str] = {}
    secret_entries: dict[str, Entry] = {}
    affected_ids = list(dict.fromkeys(entries[name].id for name, _ in keys if name in entries))
    error = None
    if "__KEYS:" in _RESOLVE_RE.sub("", content):
        error = "invalid placeholder syntax"
    for name, field_name in keys:
        e = entries.get(name)
        if e is None:
            error = f"unknown entry: {name}"
            break
        if field_name:
            if e.fields.get(field_name) is None:
                error = f"entry {name} has no field {field_name}"
                break
            replacements[name, field_name] = str(e.fields[field_name])
        elif not entry_requires_secret(e):
            error = f"entry {name} does not declare a secret"
            break
        else:
            secret_entries[name] = e
    if error:
        _audit_outcome(audit, op="resolve", name="<file>", id_=str(target),
                       file_target=str(target), affected_entry_ids=affected_ids, success=False)
        sys.stderr.write(f"error: resolve failed: {error}\n")
        return 1
    try:
        for name, e in secret_entries.items():
            replacements[name, None] = ctx.backend.get(e.id).unseal()
    except Exception as ex:
        _audit_outcome(audit, op="resolve", name="<file>", id_=str(target),
                       file_target=str(target), affected_entry_ids=affected_ids, success=False)
        sys.stderr.write(f"error: resolve failed: {_secret_read_error(ex)}\n")
        return 1
    if not matches:
        print(f"resolved 0 placeholder(s) in {target}")
        return 0
    new_content = _RESOLVE_RE.sub(lambda m: replacements[m.group(1), m.group(2)], content)
    try:
        replace_secure_text(target_state, new_content)
    except SecureFileError as ex:
        _audit_outcome(audit,
            op="resolve", name="<file>", id_=str(target),
            file_target=str(target), success=False,
            error="secure file write failed",
            affected_entry_ids=affected_ids,
        )
        sys.stderr.write(f"error: {ex}\n")
        return 1
    _audit_outcome(audit, op="resolve", name="<file>", id_=str(target), file_target=str(target),
                   affected_entry_ids=affected_ids, success=True)
    print(f"resolved {len(matches)} placeholder(s) in {target}")
    return 0


# rm
def cmd_rm(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    try:
        ctx.service.delete_entry(e.id, cascade=args.cascade)
    except HasDependents as ex:
        sys.stderr.write(
            f"error: {e.name} is referenced by: {ex.dependents}. "
            f"Use --cascade to remove the references too.\n"
        )
        return 1
    except Exception:
        return _mutation_failure(audit, op="delete", entry=e)
    _audit_outcome(audit, op="delete", name=e.name, id_=e.id, success=True)
    print(f"removed {e.name}")
    return 0


# edit
def cmd_edit(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
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
            try:
                e.fields[k] = _field_value(k, v)
            except ValueError:
                sys.stderr.write("error: port must be an integer and secret_body must be true or false\n")
                return 2
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
    try:
        ctx.service.update_entry(e)
    except NameConflict as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    except ValidationError:
        sys.stderr.write("error: invalid entry metadata\n")
        return 2
    except Exception:
        return _mutation_failure(audit, op="update", entry=e)
    _audit_outcome(audit, op="update", name=e.name, id_=e.id, success=True)
    print(f"updated {e.name}")
    return 0


# doctor
def cmd_doctor(args: argparse.Namespace) -> int:
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    recover = getattr(args, "recover", False)
    # A projected or replica context must never obtain the authority backend
    # merely because recovery was requested for its selected profile.
    if recover and ctx.kind != "master":
        sys.stderr.write("error: doctor --recover is available only to the master profile\n")
        return 1
    paths = ctx.paths
    paths.ensure()
    print(f"keys-keeper {__version__}")
    print(f"config dir: {paths.root}")
    print(f"  data.json:    {'exists' if paths.data_json.exists() else 'will be created on first add'}")
    print(f"  audit.jsonl:  {'exists' if paths.audit_jsonl.exists() else '(none yet)'}")
    if paths.config_toml.exists() or paths.config_toml.is_symlink():
        print("  config.toml:  legacy S3 config retained; S3 synchronization has been removed")
    from keys_keeper.master_journal import MASTER_MUTATION_KIND, compose_master_mutations
    from keys_keeper.operation_journal import pending_operation_refs

    pending = None
    if ctx.kind == "master":
        try:
            pending = pending_operation_refs(paths, kind=MASTER_MUTATION_KIND)
            if pending:
                print(f"recovery:     ⚠ {len(pending)} pending mutation(s); run `keys doctor --recover`")
            else:
                print("recovery:     ✓ no pending mutations")
        except Exception:
            print("recovery:     ✗ pending state is unavailable or unsafe")
            if recover:
                print(json.dumps({"operation": "recover", "status": "blocked",
                                  "committed": False, "recovered_count": 0},
                                 separators=(",", ":")))
                return 1
    if recover:
        try:
            manager = compose_master_mutations(ctx.store, ctx.backend)
            recovered = manager.recover()
        except Exception:
            status = record_outcome(ctx.audit, op="recover", name="master", id_="",
                                    success=False)
            print(json.dumps({"operation": "recover", "status": "unconfirmed",
                              "committed": None, "recovered_count": None,
                              "audit_status": status}, separators=(",", ":")))
            sys.stderr.write("error: recovery did not return a verified receipt; inspect pending state before retrying\n")
            return 1
        status = record_outcome(ctx.audit, op="recover", name="master", id_="")
        print(json.dumps({"operation": "recover", "status": "completed",
                          "committed": True, "recovered_count": len(recovered),
                          "pending_count": 0, "audit_status": status},
                         separators=(",", ":")))

    # Presence-only diagnostics: one enumeration, no entry credential reads.
    kc_ids = None
    try:
        backend = ctx.backend
        print(f"backend:      {type(backend).__name__}")
        # Match by class name (not isinstance) so cli.py doesn't import the
        # Linux-only backend module on macOS/Windows — keeps platform specifics
        # confined to composition.py (D-017).
        if type(backend).__name__ == "EncryptedFileBackend":
            if os.environ.get("KEYS_KEEPER_MASTER_KEY"):
                print("  KEYS_KEEPER_MASTER_KEY: ✓ set (file backend unlockable)")
            else:
                print("  KEYS_KEEPER_MASTER_KEY: not set (another configured unlock source may apply)")
        kc_ids = set(backend.list_ids())
        print("keychain:     ✓ accessible")
    except Exception as ex:
        print(f"keychain:     ✗ {_secret_read_error(ex)}")
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
        store = ctx.store
        entries = store.list()
        print(f"data.json:    ✓ {len(entries)} entries")
    except Exception:
        print("data.json:    ✗ metadata is unavailable or invalid")
        return 0

    # ref integrity
    from keys_keeper.refs import detect_cycles, RefCycleError
    try:
        detect_cycles(entries)
        print("refs:         ✓ no cycles")
    except RefCycleError:
        print("refs:         ✗ reference cycle detected")

    # orphan refs (target missing)
    by_name = {e.name for e in entries}
    orphans = []
    for e in entries:
        for r in e.refs:
            if r.get("name") not in by_name:
                orphans.append((e.name, r.get("name")))
    if orphans:
        print(f"refs:         ⚠ {len(orphans)} orphan ref(s)")
    else:
        print("refs:         ✓ all targets exist")

    # keychain orphans (account exists but no metadata) and missing (metadata but no keychain)
    if kc_ids is not None:
        meta_ids = {e.id for e in entries}
        # passphrase variants
        meta_ids |= {e.id + ":passphrase" for e in entries if e.type.value == "ssh_key"}
        reserved_prefixes = ("kk:sync-", "kk:project-", "kk:personal-")
        kc_orphans = {account for account in kc_ids - meta_ids
                      if not account.startswith(reserved_prefixes)}
        meta_orphans = {e.id for e in entries if entry_requires_secret(e) and e.id not in kc_ids}
        if kc_orphans:
            print(f"keychain:     ⚠ {len(kc_orphans)} keychain entry/entries without metadata")
        if meta_orphans:
            print(f"keychain:     ⚠ {len(meta_orphans)} metadata entry/entries missing keychain blobs")
        if not kc_orphans and not meta_orphans:
            print("keychain:     ✓ in sync with metadata")
    return 0


def cmd_quickstart(args: argparse.Namespace) -> int:
    """Friendly getting-started: orient a brand-new user without ever touching
    a secret value. Safe to run any time — read-only, no plaintext."""
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    paths = ctx.paths
    try:
        n = len(ctx.store.list())
    except Exception:
        n = 0

    print("┌─ keys-keeper · quickstart ──────────────────────────────┐")
    print("│ A secrets vault that routes secrets to explicit sinks.   │")
    print("└─────────────────────────────────────────────────────────┘")
    print()
    print(f"  version:    keys-keeper {__version__}")
    print(f"  config dir: {paths.root}")
    print(f"  entries:    {n}")
    print()
    print("The 4 commands you'll use most (none of these ever print a value):")
    print("  keys add NAME --from-clipboard --type api_key   save a secret you copied")
    print("  keys list                                       see what's stored (names only)")
    print("  keys inject NAME --file .env --as ENV_VAR        write a secret into a file")
    print("  keys serve                                      open the web admin in a browser")
    print()

    if n == 0:
        print("Looks empty — let's add your first key:")
        print("  1. Copy the secret to your clipboard (Cmd/Ctrl-C from wherever it lives).")
        print("  2. Run:  keys add my-first-key --from-clipboard --type api_key --tag demo")
        print("  3. Check it landed:  keys list")
        print("  4. Use it:  keys inject my-first-key --file .env --as MY_FIRST_KEY")
        print()
        print("Why the clipboard and not just typing the value? So the secret never")
        print("passes through a terminal, an AI transcript, or your shell history.")
    else:
        print(f"You already have {n} {'entry' if n == 1 else 'entries'}.")
        print("  browse:  keys list          inspect:  keys info NAME")
        print("  admin:   keys serve         shortcut: keys app install")
    print()
    print("Full command surface:  keys --help     ·     health check:  keys doctor")
    return 0


def cmd_ssh(args: argparse.Namespace) -> int:
    from keys_keeper.ssh_runner import run_ssh
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    store = ctx.store
    audit = ctx.audit
    backend = ctx.backend
    e = store.get_by_name(args.name)
    if e is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1
    try:
        rc = run_ssh(store=store, backend=backend, server_name=args.name, extra_cmd=args.cmd)
    except ValueError:
        _audit_outcome(audit, op="ssh", name=e.name, id_=e.id, success=False)
        sys.stderr.write("error: SSH target or configuration is unsafe or unavailable\n")
        return 1
    except Exception as ex:
        status = _audit_outcome(audit, op="ssh", name=e.name, id_=e.id,
                               success=False, committed=None)
        return _operation_failure("ssh", ex, audit_status=status)
    _audit_outcome(audit, op="ssh", name=e.name, id_=e.id, success=(rc == 0), committed=True)
    return rc


def cmd_serve(args: argparse.Namespace) -> int:
    from keys_keeper.server import AdminServer
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    paths = ctx.paths
    paths.ensure()
    server = AdminServer(paths=paths, port=args.port, idle_timeout_sec=15 * 60,
                         profile_selector=_profile_selector(args))
    try:
        # Bind before creating, saving, or opening a capability URL.  A second
        # `keys serve` used to mint a dead token, overwrite the live URL
        # handoff, and then fail at this point with EADDRINUSE.
        server.start()
    except OSError as ex:
        if ex.errno == errno.EADDRINUSE:
            sys.stderr.write(
                f"keys-keeper admin is already using 127.0.0.1:{args.port}. "
                "Close that local server or choose another port, for example: "
                "keys serve --port 0\n"
            )
        else:
            sys.stderr.write(f"could not start keys-keeper admin: {ex}\n")
        return 1

    url = f"http://127.0.0.1:{server.bound_port}/?t={server.token}"
    print(f"keys-keeper admin started on {url}")
    _maybe_suggest_app_install()
    _write_serve_url(paths, url)
    if not args.no_open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()
    finally:
        _clear_serve_url(paths)
    return 0


def _write_serve_url(paths: Paths, url: str) -> None:
    """Persist the live admin URL (with token) so the macOS quick-launch app can
    re-open the running server's tab. Best-effort; 0600; removed on shutdown."""
    try:
        from keys_keeper.private_files import atomic_write_bytes, PrivateFileError
        atomic_write_bytes(paths.serve_url_file, url.encode("utf-8"))
    except (OSError, PrivateFileError):
        pass


def _clear_serve_url(paths: Paths) -> None:
    """Remove the persisted admin URL on shutdown (best-effort)."""
    try:
        paths.serve_url_file.unlink()
    except OSError:
        pass


def _maybe_suggest_app_install() -> None:
    """Hint about `keys app install` if the shortcut isn't there yet."""
    if sys.platform != "darwin":
        return
    try:
        from keys_keeper import macos_app
        if not macos_app.is_installed():
            print('tip: run `keys app install` to add a Spotlight launcher (Cmd+Space → "Keys Keeper")')
    except Exception:
        pass


def _legacy_full_vault_preflight(args: argparse.Namespace, operation: str):
    """Refuse legacy writers before a prompt or a credential-backend access.

    Schema v3 has catalog bindings which the old encrypted backup format cannot
    represent.  Reading ``catalog_state`` is intentionally side-effect free;
    it does not migrate legacy metadata.
    """
    ctx = _context_or_error(args)
    if ctx is None:
        return None
    if ctx.kind != "master":
        sys.stderr.write(f"error: legacy {operation} is only available to the master profile\n")
        return None
    paths = ctx.paths
    store = ctx.store
    try:
        store.catalog_state()
    except StoreError as ex:
        if "explicit schema-v3 migration" in str(ex):
            return ctx
        sys.stderr.write(f"error: cannot verify legacy {operation} compatibility: {ex}\n")
        return None
    sys.stderr.write(
        f"error: legacy {operation} is disabled for catalog schema v3 because it "
        "cannot preserve project scopes. Use project-scoped recovery, or restore "
        "the verified pre-migration backup with a compatible legacy client.\n"
    )
    return None


def cmd_export(args: argparse.Namespace) -> int:
    ctx = _legacy_full_vault_preflight(args, "export")
    if ctx is None:
        return 1
    from keys_keeper.private_files import (
        PrivateFileCommitError, PrivateFileError,
        atomic_write_bytes, secure_read, secure_read_state,
    )
    from keys_keeper.vault_snapshot import MAX_SNAPSHOT_BLOB_BYTES, build_snapshot_payload, encrypt_snapshot
    target = Path(args.file)
    replace_existing = getattr(args, "replace", False)
    try:
        state = secure_read_state(target, max_bytes=MAX_SNAPSHOT_BLOB_BYTES,
                                  require_private=False, missing_ok=True)
        if state.identity is not None and not replace_existing:
            sys.stderr.write("error: backup already exists; use --replace to overwrite it\n")
            return 1
    except (PrivateFileError, OSError):
        sys.stderr.write("error: backup target is not a safe regular file\n")
        return 1
    audit = ctx.audit
    pw = getpass.getpass("Export password: ")
    pw2 = getpass.getpass("Confirm: ")
    if pw != pw2 or not pw:
        sys.stderr.write("passwords do not match or are empty\n")
        return 1
    try:
        # Export and KK1/KK2 use one complete-snapshot contract. No partial
        # backup can appear after a denied/unavailable credential read.
        payload = build_snapshot_payload(ctx.store, ctx.backend)
        blob = encrypt_snapshot(payload, passphrase=pw)
    except Exception:
        _audit_outcome(audit, op="export", name="<all>", id_="-",
                       file_target=str(target), success=False)
        sys.stderr.write("error: complete encrypted backup could not be prepared; no backup was written\n")
        return 1
    try:
        atomic_write_bytes(target, blob, replace_existing=replace_existing,
                           expected=state, ensure_parent_private=False)
    except PrivateFileCommitError:
        _audit_outcome(audit, op="export", name="<all>", id_="-",
                       file_target=str(target), success=True)
        sys.stderr.write('{"operation":"export","committed":true,"durability":"unconfirmed"}\n')
        sys.stderr.write("error: backup was published but directory durability could not be confirmed; inspect before retrying\n")
        return 1
    except (PrivateFileError, OSError):
        _audit_outcome(audit, op="export", name="<all>", id_="-",
                       file_target=str(target), success=False)
        sys.stderr.write("error: backup publication failed; target may have changed\n")
        return 1
    try:
        verified = secure_read(target, max_bytes=MAX_SNAPSHOT_BLOB_BYTES) == blob
    except (PrivateFileError, OSError):
        verified = False
    if not verified:
        _audit_outcome(audit, op="export", name="<all>", id_="-",
                       file_target=str(target), success=True)
        sys.stderr.write('{"operation":"export","committed":true,"verification":"failed"}\n')
        sys.stderr.write("error: backup was published but verification failed; inspect before retrying\n")
        return 1
    _audit_outcome(audit, op="export", name="<all>", id_="-", file_target=str(target), success=True)
    print(f"exported {len(payload['entries'])} entries to {target}")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    ctx = _legacy_full_vault_preflight(args, "import")
    if ctx is None:
        return 1
    from keys_keeper.crypto import BadPassword
    from keys_keeper.private_files import PrivateFileError, secure_read
    from keys_keeper.vault_snapshot import MAX_SNAPSHOT_BLOB_BYTES, decrypt_snapshot
    try:
        blob = secure_read(Path(args.file), max_bytes=MAX_SNAPSHOT_BLOB_BYTES,
                           require_private=False)
    except (PrivateFileError, OSError):
        sys.stderr.write("error: backup source is unsafe, unavailable, or exceeds the size limit\n")
        return 1
    if len(blob) < 48 or blob[:4] != b"KK1\x00":
        sys.stderr.write("error: not a keys-keeper encrypted backup\n")
        return 1
    pw = getpass.getpass("Import password: ")
    try:
        payload = decrypt_snapshot(blob, passphrase=pw)
    except BadPassword as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    try:
        validated_entries, _ = validate_snapshot_payload(payload)
    except ValidationError:
        sys.stderr.write("error: invalid or incomplete import payload\n")
        return 1
    service = ctx.service
    audit = ctx.audit
    existing = {e.name for e in ctx.store.list()}
    imported = 0
    for rec, e in zip(payload["entries"], validated_entries):
        secret = rec.get("_secret")
        passphrase = rec.get("_secret_passphrase")
        fresh = e.name not in existing
        if not fresh and not args.replace:
            continue
        try:
            service.create_entry(
                e,
                secrets=SecretInput(value=secret, passphrase=passphrase),
                replace=not fresh,
            )
        except Exception:
            # ``VaultService`` has already compensated metadata and secret
            # writes. Stop after the first failure so a rerun can resume at the
            # same entry without a flood of repeated backend errors.
            status = _audit_outcome(audit, op="import", name=e.name, id_=e.id,
                                    file_target=args.file, success=False,
                                    committed=True if imported else None)
            sys.stderr.write(json.dumps({"operation": "import", "committed": True if imported else None,
                                        "stored_entries": imported, "audit_status": status},
                                       separators=(",", ":")) + "\n")
            sys.stderr.write(
                f"error: stored {imported} entr{'y' if imported == 1 else 'ies'}, "
                f"then stopped on {e.name!r}. Check vault recovery before continuing; "
                f"already-stored entries are skipped by a merge import.\n"
            )
            return 1
        existing.add(e.name)
        imported += 1
    _audit_outcome(audit, op="import", name="<all>", id_="-", file_target=args.file, success=True)
    print(f"imported {imported} entries")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    if getattr(args, "summary", False):
        if _profile_selector(args):
            sys.stderr.write("daily summary covers all local profiles; omit --profile/--project\n")
            return 1
        import json
        from keys_keeper.desktop_stats import today_summary
        print(json.dumps(today_summary(Paths()), ensure_ascii=False))
        return 0
    ctx = _context_or_error(args)
    if ctx is None:
        return 1
    audit = ctx.audit
    from datetime import datetime, timezone, timedelta
    since = None
    if args.since:
        amount = int(args.since[:-1])
        unit = args.since[-1]
        delta = {"h": "hours", "d": "days"}[unit]
        since = datetime.now(timezone.utc) - timedelta(**{delta: amount})
    entry = ctx.store.get_by_name(args.name) if args.name else None
    selector = {"entry_id": entry.id} if entry is not None else {"name": args.name}
    events = list(audit.search(op=args.op, since=since, limit=args.limit,
                               newest_first=True, **selector))
    if args.tail:
        events.reverse()  # newest N, displayed in chronological log order
    for ev in events:
        print(f"{ev['ts']}  {ev['op']:8s}  {ev['name']:24s}  {ev.get('file_target') or '-'}")
    return 0


# ----- app install/uninstall -----

def cmd_app_install(args: argparse.Namespace) -> int:
    if sys.platform == "darwin":
        from keys_keeper import macos_app
        target = macos_app.system_dir() if args.system else macos_app.default_user_dir()
        try:
            installer = macos_app.install_menubar_app if getattr(args, "menubar", False) else macos_app.install_app
            result = installer(target, force=args.force)
        except FileExistsError as ex:
            sys.stderr.write(
                f"already installed at {ex.args[0]}. Re-run with --force to overwrite.\n"
            )
            return 1
        except PermissionError as ex:
            sys.stderr.write(
                f"permission denied writing to {target} — try without --system, or run with sudo.\n  ({ex})\n"
            )
            return 1
        except RuntimeError as ex:
            sys.stderr.write(f"{ex}\n")
            return 1
        verb = "installed" if result.created else "reinstalled"
        print(f"{verb} {result.bundle_path}")
        print('hit Cmd+Space → "Keys Keeper" to launch')
        return 0
    if getattr(args, "menubar", False):
        sys.stderr.write("--menubar is available on macOS only.\n")
        return 1
    if sys.platform == "win32":
        from keys_keeper import windows_app
        if args.system:
            sys.stderr.write("--system is macOS-only; on Windows the shortcut goes into the per-user Start Menu.\n")
            return 1
        try:
            result = windows_app.install_app(force=args.force)
        except FileExistsError as ex:
            sys.stderr.write(
                f"already installed at {ex.args[0]}. Re-run with --force to overwrite.\n"
            )
            return 1
        except FileNotFoundError as ex:
            sys.stderr.write(f"{ex}\n")
            return 1
        except subprocess.CalledProcessError as ex:
            sys.stderr.write(
                f"PowerShell failed to create the shortcut (exit {ex.returncode}).\n"
                f"  stderr: {ex.stderr.decode(errors='replace').strip() if ex.stderr else '(empty)'}\n"
            )
            return 1
        verb = "installed" if result.created else "reinstalled"
        print(f"{verb} {result.bundle_path}")
        print('search "Keys Keeper" in the Start Menu to launch')
        return 0
    sys.stderr.write(f"`keys app install` is not supported on platform '{sys.platform}'.\n")
    return 1


def cmd_app_uninstall(args: argparse.Namespace) -> int:
    if sys.platform == "darwin":
        from keys_keeper import macos_app
        target = macos_app.system_dir() if args.system else macos_app.default_user_dir()
        removed = macos_app.uninstall_app(target)
        if removed:
            print(f"removed {target / macos_app.BUNDLE_NAME}")
            return 0
        sys.stderr.write(f"nothing to remove at {target / macos_app.BUNDLE_NAME}\n")
        return 1
    if sys.platform == "win32":
        from keys_keeper import windows_app
        removed = windows_app.uninstall_app()
        if removed:
            print(f"removed {windows_app.default_user_dir() / windows_app.SHORTCUT_NAME}")
            return 0
        sys.stderr.write("nothing to remove\n")
        return 1
    sys.stderr.write(f"`keys app uninstall` is not supported on platform '{sys.platform}'.\n")
    return 1


# ----- top-level parser -----

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keys", description="personal secrets manager")
    p.add_argument("--version", action="version", version=f"keys-keeper {__version__}")
    p.add_argument("--profile", "--project", dest="profile_selector", metavar="PROFILE_OR_PROJECT",
                   help="select a replica profile UUID or project slug (with --env)")
    p.add_argument("--env", dest="profile_environment", metavar="ENVIRONMENT",
                   help="environment used with --project before the command")
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
    dr.add_argument("--recover", action="store_true",
                    help="explicitly recover pending master mutations; may read and write secrets")
    dr.set_defaults(func=cmd_doctor)

    # keychain — native macOS prompt/bypass policy
    from keys_keeper.cli_keychain import register_keychain
    register_keychain(sub)

    qs = sub.add_parser("quickstart", help="friendly getting-started (no secrets shown)")
    qs.set_defaults(func=cmd_quickstart)

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
    ex.add_argument("--replace", action="store_true", help="explicitly replace an existing backup")
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
    au.add_argument("--summary", action="store_true", help="value-free JSON summary of today's recorded access across local profiles")
    au.set_defaults(func=cmd_audit)

    # init — emit an agent rule file for a given target
    from keys_keeper.init_cmd import TARGETS as _INIT_TARGETS, cmd_init
    init = sub.add_parser(
        "init",
        help=(
            "emit an agent rule file "
            "(claude / cursor / aider / codex / codex-skill / cline / generic)"
        ),
    )
    init.add_argument("target", choices=list(_INIT_TARGETS.keys()))
    init.add_argument("--out", help="override default destination path")
    init.add_argument("--force", action="store_true", help="overwrite existing file")
    init.add_argument("--check", action="store_true", help="exit non-zero on drift (CI hook)")
    init.add_argument("--stdout", action="store_true", help="write to stdout instead of file")
    init.set_defaults(func=cmd_init)

    # app — OS-native quick-launch shortcut (Spotlight-app on macOS, Start Menu .lnk on Windows)
    app_p = sub.add_parser("app", help="install/uninstall the OS quick-launch shortcut")
    app_sub = app_p.add_subparsers(dest="app_command", required=True)
    app_install = app_sub.add_parser("install", help="install a Spotlight/Start-Menu shortcut for `keys serve`")
    app_install.add_argument("--force", action="store_true", help="overwrite if already installed")
    app_install.add_argument("--system", action="store_true", help="install to /Applications (macOS only, may need sudo)")
    app_install.add_argument("--menubar", action="store_true", help="build native macOS menu bar app with daily activity (requires Xcode tools)")
    app_install.set_defaults(func=cmd_app_install)
    app_uninstall = app_sub.add_parser("uninstall", help="remove the shortcut")
    app_uninstall.add_argument("--system", action="store_true", help="remove from /Applications (macOS only)")
    app_uninstall.set_defaults(func=cmd_app_uninstall)

    sync = sub.add_parser("sync", help="private VPS synchronization")
    sync_commands = sync.add_subparsers(dest="sync_command", required=True)
    from keys_keeper.cli_sync_vps import register_vps_sync
    register_vps_sync(sync_commands)

    from keys_keeper.cli_catalog import register_catalog
    register_catalog(sub)

    from keys_keeper.cli_project_sync import register as register_project_sync
    register_project_sync(sub)
    from keys_keeper.cli_devices import register as register_devices
    register_devices(sub)

    return p


def _removed_legacy_command(argv: list[str]) -> str | None:
    # Diagnose retired commands before parsing their old credential flags, so
    # argparse never repeats values from an obsolete setup invocation.
    position = 0
    selectors = {"--profile", "--project", "--env"}
    while position < len(argv) and argv[position].startswith("--"):
        option = argv[position]
        if option in selectors:
            position += 2
        elif option.split("=", 1)[0] in selectors and "=" in option:
            position += 1
        else:
            return None
    if position >= len(argv):
        return None
    if argv[position] == "webvault":
        return "S3 WebVault has been removed; use the local admin with keys serve"
    if (argv[position] == "sync" and position + 1 < len(argv)
            and argv[position + 1] in {"setup", "push", "pull", "status", "mode", "rollback", "auto"}):
        return "S3 synchronization has been removed; use My computers or keys sync vps"
    return None


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
    argv = list(sys.argv[1:] if argv is None else argv)
    removed = _removed_legacy_command(argv)
    if removed:
        sys.stderr.write("error: " + removed + "\n")
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    # These legacy/canonical catalog writers always target the authoritative
    # root. They must never quietly operate on the root while a worker profile
    # was selected.
    if args.command in {"folders", "projects", "sync"}:
        context = _context_or_error(args)
        if context is None:
            return 1
        if context.kind != "master":
            sys.stderr.write("error: this command is available only to the master profile\n")
            return 1
    try:
        return args.func(args)
    except Exception as ex:
        # A last-resort adapter boundary must neither print provider data nor
        # promise rollback for an operation whose receipt was never returned.
        return _operation_failure(args.command, ex)


if __name__ == "__main__":
    sys.exit(main())
