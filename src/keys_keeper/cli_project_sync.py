"""Project synchronization commands; public output is metadata only."""
from __future__ import annotations

import argparse
import dataclasses
import getpass
import json
import sys
import time
from pathlib import Path

from keys_keeper.composition import AccessContext
from keys_keeper.paths import Paths
from keys_keeper.project_runtime import ProjectRuntime, RuntimeErrorSafe, _json_read, write_bundle
from keys_keeper import project_protocol as wire


def _selector(args):
    from keys_keeper.cli import _profile_selector
    if getattr(args, "scope", None):
        return args.scope
    if getattr(args, "profile_selector", None) or getattr(args, "profile_environment", None):
        return _profile_selector(args)
    selected = getattr(args, "scope", None) or getattr(args, "profile", None)
    if selected:
        return selected
    project = getattr(args, "project", None)
    environment = getattr(args, "environment", None) or getattr(args, "env", None)
    if project or environment:
        if not project or not environment:
            raise RuntimeErrorSafe("project and environment are required together")
        return project + "/" + environment
    return None


def _password(args, *, confirm=False):
    if getattr(args, "password_file", None):
        from keys_keeper.operation_journal import _secure_read
        value = _secure_read(Path(args.password_file), max_bytes=4096).rstrip(b"\r\n")
        if not 12 <= len(value) <= 4096:
            raise RuntimeErrorSafe("recovery password file must contain 12 to 4096 bytes")
        return value
    value = getpass.getpass("Recovery password: ")
    if len(value) < 12:
        raise RuntimeErrorSafe("recovery password must contain at least 12 characters")
    if confirm and getpass.getpass("Repeat recovery password: ") != value:
        raise RuntimeErrorSafe("recovery passwords do not match")
    return value


def _run(args):
    command = args.project_action
    access = AccessContext.INTERACTIVE if command in {"init", "backup", "migrate"} else AccessContext.UI_FORBIDDEN
    runtime = ProjectRuntime(Paths(), access=access)
    selector = _selector(args)
    if command not in {"inspect-backup", "restore", "recover-takeover"}:
        runtime.assert_available()
    if command == "profiles":
        runtime.assert_available()
        return {"profiles": runtime.registry.list(), "default_profile": runtime.registry.read()["default_profile"]}
    if command == "use":
        runtime.assert_available()
        runtime.registry.set_default(args.scope)
        return {"default_profile": runtime.registry.read()["default_profile"]}
    if command == "status":
        return runtime.status(selector)
    if command == "init":
        entry = runtime.master_store.get_by_name(args.admin_token_entry)
        if entry is None:
            raise RuntimeErrorSafe("bootstrap token entry is unavailable")
        return runtime.initialize(args.scope, args.endpoint, admin_token=runtime.master_backend.get(entry.id))
    if command == "preview":
        return runtime.preview(selector)
    if command == "invite":
        bundle = runtime.invite(selector, ttl=args.ttl)
        write_bundle(Path(args.out), bundle)
        import hashlib
        return {"invite_file": str(Path(args.out).absolute()), "fingerprint": hashlib.sha256(wire.decode_key(bundle["pin"])).hexdigest()}
    if command == "join":
        bundle = _json_read(Path(args.invite))
        result = runtime.join(bundle, fingerprint=args.fingerprint, role=args.role)
        write_bundle(Path(args.out), result["request_bundle"])
        return {"profile_id": result["profile_id"], "request_file": str(Path(args.out).absolute()),
                "fingerprint": wire.canonical_hash(result["request_bundle"]["request"])}
    if command == "approve":
        bundle = runtime.approve(_json_read(Path(args.request)), fingerprint=args.fingerprint)
        write_bundle(Path(args.out), bundle)
        return {"response_file": str(Path(args.out).absolute()), "device_id": bundle["request"]["payload"]["device_id"]}
    if command == "finish":
        return runtime.finish(selector, _json_read(Path(args.bundle)))
    if command in {"backup", "migrate"}:
        result = runtime.backup(selector if command == "backup" else "master", Path(args.out), _password(args, confirm=True))
        if command == "migrate":
            runtime.master_store.migrate_catalog_v3(
                expected_revision=result["metadata_revision"]
            )
            return {"backup": result, "schema_version": 3}
        return result
    if command in {"inspect-backup", "restore"}:
        from keys_keeper.project_backup import inspect_backup, restore_backup
        password = _password(args)
        if command == "inspect-backup":
            return dataclasses.asdict(inspect_backup(Path(args.file), password=password))
        profile = restore_backup(Path(args.file), password=password, recovery_root=Path(args.root), recovery_password=password, resume=args.resume)
        return {"root": str(profile.paths.root.absolute()), "kind": profile.kind, "status": "recovery_required",
                "entries": profile.manifest.entry_count}
    if command == "recover-takeover":
        from keys_keeper.backend import Sealed
        from keys_keeper.operation_journal import _secure_read
        from keys_keeper.project_backup import RecoveryProfile, inspect_backup
        from keys_keeper.project_recovery import recover_takeover
        password = _password(args)
        manifest = inspect_backup(Path(args.file), password=password)
        profile = RecoveryProfile(Paths(Path(args.root)), manifest.kind, manifest)
        token = _secure_read(Path(args.admin_token_file), max_bytes=4096).rstrip(b"\r\n")
        if not 16 <= len(token) <= 4096:
            raise RuntimeErrorSafe("invalid protected bootstrap token file")
        try:
            token_text = token.decode("utf-8")
        except UnicodeDecodeError:
            raise RuntimeErrorSafe("invalid protected bootstrap token file") from None
        result = recover_takeover(profile, recovery_password=password, endpoint=args.endpoint,
                                  admin_token=Sealed(token_text))
        return dataclasses.asdict(result)
    if command == "sync":
        return runtime.sync(selector)
    if command == "watch":
        if not 5 <= args.interval <= 86400 or args.cycles < 0:
            raise RuntimeErrorSafe("invalid synchronization interval or cycle count")
        return runtime.watch(selector, interval=args.interval, cycles=args.cycles,
                             report=lambda result: print(json.dumps(result), flush=True))
    item = runtime.registry.resolve(selector)
    if item is None:
        raise RuntimeErrorSafe("select a configured project scope")
    if command in {"publish", "receive", "revoke"}:
        master = runtime.master(item)
        if command == "revoke":
            return master.revoke(args.device)
        if command == "publish":
            return master.publish()
        return master.receive()
    if command in {"pull", "submit"}:
        return getattr(runtime.replica(item), command)()
    raise RuntimeErrorSafe("unknown project operation")


def command(args):
    try:
        result = _run(args)
    except KeyboardInterrupt:
        return 130
    except Exception as ex:
        # Lower layers process hostile encrypted entry fields. Do not print
        # arbitrary exception strings or reprs into an agent transcript.
        detail = str(ex) if isinstance(ex, RuntimeErrorSafe) else type(ex).__name__
        sys.stderr.write("project operation failed: " + detail + "\n")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def register(subparsers):
    root = subparsers.add_parser("project-sync", help="isolated project delivery and create-only replicas")
    commands = root.add_subparsers(dest="project_action", required=True)
    for name in ("profiles", "status", "preview", "publish", "receive", "pull", "submit", "sync"):
        parser = commands.add_parser(name)
        if name != "profiles":
            parser.add_argument("--scope", help="profile UUID or project/environment")
        parser.set_defaults(func=command)
    use = commands.add_parser("use", help="choose the default local profile")
    use.add_argument("scope")
    use.set_defaults(func=command)
    init = commands.add_parser("init", help="initialize master relay scope from a stored bootstrap token")
    init.add_argument("--scope", required=True)
    init.add_argument("--endpoint", required=True)
    init.add_argument("--admin-token-entry", required=True)
    init.set_defaults(func=command)
    invite = commands.add_parser("invite")
    invite.add_argument("--scope", required=True)
    invite.add_argument("--out", required=True)
    invite.add_argument("--ttl", type=int, default=900)
    invite.set_defaults(func=command)
    join = commands.add_parser("join")
    join.add_argument("--invite", required=True)
    join.add_argument("--fingerprint", required=True, help="master fingerprint verified through a trusted channel")
    join.add_argument("--role", choices=("reader", "contributor"), default="contributor")
    join.add_argument("--out", required=True)
    join.set_defaults(func=command)
    approve = commands.add_parser("approve")
    approve.add_argument("--request", required=True)
    approve.add_argument("--fingerprint", required=True, help="device request fingerprint verified on the worker")
    approve.add_argument("--out", required=True)
    approve.set_defaults(func=command)
    finish = commands.add_parser("finish")
    finish.add_argument("--scope", required=True)
    finish.add_argument("--bundle", required=True)
    finish.set_defaults(func=command)
    revoke = commands.add_parser("revoke")
    revoke.add_argument("--scope", required=True)
    revoke.add_argument("--device", required=True)
    revoke.set_defaults(func=command)
    for name in ("backup", "migrate"):
        parser = commands.add_parser(name, help="create a verified encrypted recovery bundle" if name == "backup" else "back up and enable the project catalog")
        parser.add_argument("--out", required=True)
        parser.add_argument("--password-file")
        if name == "backup":
            parser.add_argument("--scope")
        parser.set_defaults(func=command)
    for name in ("inspect-backup", "restore"):
        parser = commands.add_parser(name)
        parser.add_argument("--file", required=True)
        parser.add_argument("--password-file")
        if name == "restore":
            parser.add_argument("--root", required=True, help="new empty recovery directory")
            parser.add_argument("--resume", action="store_true", help="resume only the same interrupted restore")
        parser.set_defaults(func=command)
    takeover = commands.add_parser("recover-takeover", help="activate a restored master with new authority and fresh scopes")
    takeover.add_argument("--file", required=True, help="the original verified backup")
    takeover.add_argument("--root", required=True, help="the restored recovery-only root")
    takeover.add_argument("--endpoint", required=True)
    takeover.add_argument("--admin-token-file", required=True, help="protected bootstrap token file")
    takeover.add_argument("--password-file")
    takeover.set_defaults(func=command)
    watch = commands.add_parser("watch", help="run bounded retries in a background-safe foreground worker")
    watch.add_argument("--scope")
    watch.add_argument("--interval", type=int, default=60)
    watch.add_argument("--cycles", type=int, default=0, help="0 continues until stopped")
    watch.set_defaults(func=command)
