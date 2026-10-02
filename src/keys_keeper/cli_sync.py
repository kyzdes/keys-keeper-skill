"""CLI adapter for the shared S3 sync application.

Only this adapter prompts or writes terminal output. Automatic hooks remain
silent; the bounded worker executes the shared application directly.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from functools import wraps

from keys_keeper import sync_application as application
from keys_keeper.auto_worker import run_auto_worker, start_auto_worker
from keys_keeper.backend import KeychainError
from keys_keeper.composition import AccessContext
from keys_keeper.config import SyncConfig, SyncConfigError
from keys_keeper.crypto import BadPassword
from keys_keeper.paths import Paths
from keys_keeper.sync_remote import AuthError, TransportError

# Existing imports remain compatible; HTTP and worker consumers use the
# application module directly and do not depend on these CLI aliases.
from keys_keeper.sync_application import (
    MIN_SYNC_PASSPHRASE_LEN, SYNC_ACCESS, SYNC_PASS, SYNC_SECRET,
    WeakPassphraseError, _auto_debounce_seconds, _auto_debounced, _auto_log,
    _build_engine, _build_remote, _run_auto_worker, _touch_auto_stamp,
    _validate_passphrase_strength, web_pull, web_push, web_set_mode,
    web_setup, web_status,
)


def _sync_passphrase(backend, *, allow_prompt: bool) -> str:
    accounts = set(backend.list_ids())
    if SYNC_PASS not in accounts:
        if allow_prompt:
            return getpass.getpass("Backup passphrase: ")
        from keys_keeper.backend import SecretNotFound
        raise SecretNotFound("sync passphrase is not stored")
    return backend.get(SYNC_PASS).unseal()


def _receipt(result: dict, operation: str) -> None:
    if result["audit_status"] == "unavailable":
        sys.stderr.write(json.dumps({"operation": operation, "committed": True,
                                     "audit_status": "unavailable"}) + "\n")


def _loud(fn):
    @wraps(fn)
    def wrapped(args):
        try:
            return fn(args)
        except Exception as ex:
            if getattr(ex, "committed", None) is True:
                sys.stderr.write(json.dumps({"operation": fn.__name__.replace("cmd_sync_", "sync."),
                                             "committed": True,
                                             "audit_status": getattr(ex, "audit_status", "unknown"),
                                             "error": "Sync change was published; confirm state before retrying"}) + "\n")
                return 1
            if isinstance(ex, WeakPassphraseError):
                message = str(ex)  # fixed strength rule, never the passphrase
            elif isinstance(ex, (SyncConfigError, KeychainError)):
                message = "Sync configuration or credential is unavailable"
            elif isinstance(ex, (AuthError, TransportError, BadPassword)):
                message = "Sync transport or authentication failed"
            else:
                message = "Sync operation failed; check recovery status before retrying"
            sys.stderr.write("error: " + message + "\n")
            if fn.__name__ != "cmd_sync_status":
                audit_status = getattr(ex, "audit_status", "unknown")
                if type(audit_status) is not str or audit_status not in {"recorded", "unavailable"}:
                    audit_status = "unknown"
                sys.stderr.write(json.dumps({"operation": fn.__name__.replace("cmd_sync_", "sync."),
                                             "committed": None, "audit_status": audit_status,
                                             "error": "Check recovery status before retrying"}) + "\n")
            return 1
    return wrapped


@_loud
def cmd_sync_setup(args: argparse.Namespace) -> int:
    cfg = SyncConfig(mode="auto" if args.auto else "manual", endpoint=args.endpoint,
                     bucket=args.bucket, region=args.region, prefix=args.prefix,
                     addressing=args.addressing, insecure=args.insecure,
                     retain_snapshots=args.retain).with_device_id()
    cfg.validate()
    secret = getpass.getpass("S3 secret access key: ")
    if not secret:
        sys.stderr.write("error: empty secret key\n")
        return 1
    passphrase = getpass.getpass("Backup passphrase (encrypts the cloud copy): ")
    confirmation = getpass.getpass("Confirm passphrase: ")
    if passphrase != confirmation or not passphrase:
        sys.stderr.write("error: passphrases do not match (or empty)\n")
        return 1
    result = application.setup(Paths(), cfg, access_key_id=args.access_key_id,
                               secret_key=secret, passphrase=passphrase,
                               access=AccessContext.INTERACTIVE)
    _receipt(result, "sync.setup")
    print(f"sync configured ({result['mode']}) -> {cfg.bucket} @ {cfg.endpoint}")
    if not result["cas_supported"]:
        print("note: this provider lacks conditional writes; concurrent devices use a read-back check")
    return 0


def _manual_action(operation: str, *, version: int | None = None) -> dict:
    result = application.run_action(Paths(), operation, access=AccessContext.INTERACTIVE,
                                    passphrase_provider=lambda backend: _sync_passphrase(backend, allow_prompt=True),
                                    version=version)
    _receipt(result, "sync." + operation)
    return result


@_loud
def cmd_sync_push(args: argparse.Namespace) -> int:
    result = _manual_action("push")
    print(f"pushed - {result['synced']} change(s) synced")
    return 0


@_loud
def cmd_sync_pull(args: argparse.Namespace) -> int:
    result = _manual_action("pull")
    print(f"pulled - {result['merged']} change(s) merged")
    return 0


@_loud
def cmd_sync_status(args: argparse.Namespace) -> int:
    status = application.status(Paths(), access=AccessContext.INTERACTIVE)
    print(f"mode:     {status['mode']}")
    if not status["configured"]:
        print("not configured - run keys sync setup")
        return 0
    print(f"endpoint: {status['endpoint']}")
    print(f"bucket:   {status['bucket']}  (prefix: {status['prefix'] or '-'})")
    print(f"remote version:  {status['remote_version'] if status['remote_version'] is not None else '-'}")
    print(f"local synced:    {status['local_synced'] if status['local_synced'] is not None else '-'}")
    print(f"local changes:   {'yes (push to publish)' if status['dirty'] else 'none'}")
    return 0


@_loud
def cmd_sync_mode(args: argparse.Namespace) -> int:
    result = application.web_set_mode(Paths(), args.mode)
    _receipt(result, "sync.mode")
    print(f"sync mode set to {result['mode']}")
    return 0


@_loud
def cmd_sync_rollback(args: argparse.Namespace) -> int:
    result = _manual_action("rollback", version=args.version)
    print(f"rolled back to snapshot {args.version}; published as version {result['version']}")
    return 0


def _spawn_worker(paths=None) -> None:
    start_auto_worker("s3", paths or Paths())


def cmd_sync_auto(args: argparse.Namespace) -> int:
    """The hook claims an attempt before launch and always returns quietly."""
    try:
        paths = Paths()
        if application.claim_automatic_attempt(paths, force=args.force):
            if args.foreground:
                run_auto_worker("s3", paths)
            else:
                _spawn_worker(paths)
    except Exception:
        pass
    return 0


# ---------------- registration ----------------

def register_sync(sub) -> None:
    sp = sub.add_parser("sync", help="legacy S3/KK2 sync; use Settings → My computers for personal VPS sync")
    ss = sp.add_subparsers(dest="sync_command", required=True)

    # The VPS workflow is namespaced so existing `keys sync setup/push/pull`
    # commands remain backwards-compatible with the S3 transport.
    from keys_keeper.cli_sync_vps import register_vps_sync
    register_vps_sync(ss)

    setup = ss.add_parser("setup", help="configure an S3 endpoint (stores creds in the keychain)")
    setup.add_argument("--endpoint", required=True)
    setup.add_argument("--bucket", required=True)
    setup.add_argument("--access-key-id", required=True, dest="access_key_id")
    setup.add_argument("--region", default="us-east-1")
    setup.add_argument("--prefix", default="keys-keeper")
    setup.add_argument("--addressing", default="path", choices=["path", "virtual"])
    setup.add_argument("--retain", type=int, default=20)
    setup.add_argument("--auto", action="store_true", help="enable auto-sync on session start")
    setup.add_argument("--insecure", action="store_true", help="allow a plain http endpoint")
    setup.set_defaults(func=cmd_sync_setup)

    for name, fn, help_ in [
        ("push", cmd_sync_push, "encrypt + upload the vault as a new version"),
        ("pull", cmd_sync_pull, "download + merge the latest version"),
        ("status", cmd_sync_status, "show sync mode + local/remote versions"),
    ]:
        p = ss.add_parser(name, help=help_)
        p.set_defaults(func=fn)

    mode = ss.add_parser("mode", help="set sync mode")
    mode.add_argument("mode", choices=["off", "manual", "auto"])
    mode.set_defaults(func=cmd_sync_mode)

    rb = ss.add_parser("rollback", help="restore an earlier snapshot version")
    rb.add_argument("version", type=int)
    rb.set_defaults(func=cmd_sync_rollback)

    auto = ss.add_parser("auto", help="(hook) auto-sync if enabled; always exits 0")
    auto.add_argument("--foreground", action="store_true")
    auto.add_argument("--force", action="store_true",
                      help="explicit manual sync override for the daily timing limit")
    auto.set_defaults(func=cmd_sync_auto)
