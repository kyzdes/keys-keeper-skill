"""`keys sync ...` commands: setup / push / pull / status / mode / rollback / auto.

Secrets (S3 access key id, S3 secret key, backup passphrase) live in the OS
keychain under reserved kk:sync-* accounts — never in config.toml, argv, logs,
or stdout. The `auto` entrypoint (SessionStart hook) is non-interactive and
fails OPEN + SILENT: any missing credential or network error exits 0.
"""
from __future__ import annotations

import argparse
import getpass
import os
import subprocess
import sys
from dataclasses import replace
from datetime import datetime, timezone

from keys_keeper.audit import AuditLog
from keys_keeper.backend import KeychainError
from keys_keeper.composition import build_backend
from keys_keeper.config import (
    SyncConfig, SyncConfigError, load_sync_config, save_sync_config, set_mode,
)
from keys_keeper.models import now_iso
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.sync import SyncEngine
from keys_keeper.sync_remote import (
    S3Remote, S3Signer, AuthError, TransportError,
)
from keys_keeper.crypto import BadPassword

# Reserved keychain accounts. Namespaced so they can never collide with an
# entry id (kk:<uuid4>) or be emitted into a snapshot's entries[] (S7).
SYNC_ACCESS = "kk:sync-s3-access-key-id"
SYNC_SECRET = "kk:sync-s3-secret-key"
SYNC_PASS = "kk:sync-passphrase"

_DEBOUNCE_SEC = int(os.environ.get("KEYS_KEEPER_SYNC_DEBOUNCE_SEC", "600"))

# Zero-knowledge sync reduces the security of the whole cloud copy to the
# entropy of this one passphrase, so we refuse to let a user pick a trivially
# weak one. This is a floor, not a strength meter.
MIN_SYNC_PASSPHRASE_LEN = 12


class WeakPassphraseError(SyncConfigError):
    """The backup passphrase is too weak to protect a zero-knowledge cloud copy."""


def _validate_passphrase_strength(passphrase: str) -> None:
    """Reject passphrases that are too short or trivially patterned.

    Raised as SyncConfigError so the existing _loud / web error handling
    surfaces it cleanly (exit 1 / HTTP 400) without leaking the value.
    """
    if len(passphrase) < MIN_SYNC_PASSPHRASE_LEN:
        raise WeakPassphraseError(
            f"backup passphrase must be at least {MIN_SYNC_PASSPHRASE_LEN} "
            f"characters (got {len(passphrase)})"
        )
    stripped = passphrase.strip()
    if not stripped or len(set(stripped)) < 4:
        # all-whitespace, or a near-constant string like "aaaaaaaaaaaa" /
        # "111111111111" — far too little entropy regardless of length.
        raise WeakPassphraseError(
            "backup passphrase is too simple — use a longer, more varied phrase"
        )


# ---------------- builders (monkeypatched in tests) ----------------

def _build_remote(cfg: SyncConfig, backend) -> S3Remote:
    akid = backend.get(SYNC_ACCESS).unseal()
    secret = backend.get(SYNC_SECRET)  # Sealed — stays sealed into the signer
    signer = S3Signer(akid, secret, region=cfg.region)
    return S3Remote(signer=signer, endpoint=cfg.endpoint, bucket=cfg.bucket,
                    prefix=cfg.prefix, addressing=cfg.addressing)


def _build_engine(paths: Paths):
    cfg = load_sync_config(paths)
    if not cfg.endpoint or not cfg.bucket:
        raise SyncConfigError("sync is not configured — run `keys sync setup`")
    backend = build_backend()
    remote = _build_remote(cfg, backend)
    engine = SyncEngine(remote=remote, store=MetadataStore(paths), backend=backend,
                        device_id=cfg.device_id, retain_snapshots=cfg.retain_snapshots,
                        paths=paths, cas_supported=cfg.cas_supported)
    return engine, cfg, backend


def _sync_passphrase(backend, *, allow_prompt: bool) -> str:
    try:
        return backend.get(SYNC_PASS).unseal()
    except KeychainError:
        if not allow_prompt:
            raise KeychainError("no stored sync passphrase")
    return getpass.getpass("Backup passphrase: ")


def _loud(fn):
    """Wrap a manual command: turn expected failures into a clean exit 1."""
    def wrapped(args):
        try:
            return fn(args)
        except (SyncConfigError, AuthError, TransportError, BadPassword,
                KeychainError) as e:
            sys.stderr.write(f"error: {e}\n")
            return 1
    return wrapped


# ---------------- commands ----------------

@_loud
def cmd_sync_setup(args: argparse.Namespace) -> int:
    cfg = SyncConfig(
        mode="auto" if args.auto else "manual",
        endpoint=args.endpoint, bucket=args.bucket, region=args.region,
        prefix=args.prefix, addressing=args.addressing, insecure=args.insecure,
        retain_snapshots=args.retain,
    ).with_device_id()
    cfg.validate()

    backend = build_backend()
    secret = getpass.getpass("S3 secret access key: ")
    if not secret:
        sys.stderr.write("error: empty secret key\n")
        return 1
    p1 = getpass.getpass("Backup passphrase (encrypts the cloud copy): ")
    p2 = getpass.getpass("Confirm passphrase: ")
    if p1 != p2 or not p1:
        sys.stderr.write("error: passphrases do not match (or empty)\n")
        return 1
    try:
        _validate_passphrase_strength(p1)
    except WeakPassphraseError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    backend.set(SYNC_ACCESS, args.access_key_id)
    backend.set(SYNC_SECRET, secret)
    backend.set(SYNC_PASS, p1)

    remote = _build_remote(cfg, backend)
    remote.head_object("HEAD")          # probes credentials (AuthError if bad)
    cas = remote.probe_cas()
    cfg = replace(cfg, cas_supported=cas)  # persist so every push knows
    save_sync_config(cfg, Paths())
    AuditLog(Paths()).record(op="sync.setup", name="<all>", id_="-",
                             file_target=cfg.endpoint)
    print(f"sync configured ({cfg.mode}) -> {cfg.bucket} @ {cfg.endpoint}")
    if not cas:
        print("note: this provider ignores conditional writes (If-None-Match), so "
              "true compare-and-swap isn't available. keys-keeper falls back to a "
              "read-back-after-write check that still detects and retries a clobbered "
              "push, but a CAS-capable provider (AWS S3 / Cloudflare R2 / modern "
              "MinIO) is recommended for concurrent multi-device use.")
    return 0


@_loud
def cmd_sync_push(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, cfg, backend = _build_engine(paths)
    pw = _sync_passphrase(backend, allow_prompt=True)
    n = engine.push(pw)
    AuditLog(paths).record(op="sync.push", name=f"<+{n}>", id_="-",
                           file_target=cfg.endpoint)
    print(f"pushed — {n} change(s) synced to {cfg.bucket}")
    return 0


@_loud
def cmd_sync_pull(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, cfg, backend = _build_engine(paths)
    pw = _sync_passphrase(backend, allow_prompt=True)
    n = engine.pull(pw)
    AuditLog(paths).record(op="sync.pull", name=f"<+{n}>", id_="-",
                           file_target=cfg.endpoint)
    print(f"pulled — {n} change(s) merged from {cfg.bucket}")
    return 0


@_loud
def cmd_sync_status(args: argparse.Namespace) -> int:
    paths = Paths()
    cfg = load_sync_config(paths)
    print(f"mode:     {cfg.mode}")
    if not cfg.endpoint:
        print("not configured — run `keys sync setup`")
        return 0
    print(f"endpoint: {cfg.endpoint}")
    print(f"bucket:   {cfg.bucket}  (prefix: {cfg.prefix or '-'})")
    engine, _, _ = _build_engine(paths)
    st = engine.status()
    print(f"remote version:  {st.remote_version if st.remote_version is not None else '-'}")
    print(f"local synced:    {st.local_synced_version if st.local_synced_version is not None else '-'}")
    print(f"local changes:   {'yes (push to publish)' if st.dirty else 'none'}")
    return 0


def cmd_sync_mode(args: argparse.Namespace) -> int:
    try:
        set_mode(args.mode, Paths())
    except SyncConfigError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1
    print(f"sync mode set to {args.mode}")
    return 0


@_loud
def cmd_sync_rollback(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, cfg, backend = _build_engine(paths)
    pw = _sync_passphrase(backend, allow_prompt=True)
    v = engine.rollback(args.version, pw)
    AuditLog(paths).record(op="sync.rollback", name=f"<to {args.version}>", id_="-",
                           file_target=cfg.endpoint)
    print(f"rolled back to snapshot {args.version}; published as version {v}")
    return 0


# ---------------- auto (SessionStart hook) ----------------

def cmd_sync_auto(args: argparse.Namespace) -> int:
    """Hook entrypoint. ALWAYS exits 0. Does nothing unless mode == auto."""
    try:
        paths = Paths()
        cfg = load_sync_config(paths)
        if cfg.mode != "auto":
            return 0
        if not args.force and _auto_debounced(paths):
            return 0
        # Stamp at ATTEMPT time (before the work): a per-session-start hook should
        # throttle by attempt, not by success — otherwise a flapping endpoint would
        # retry on every new session. A manual `keys sync push/pull` is unaffected.
        _touch_auto_stamp(paths)
        if args.foreground:
            _run_auto_worker(paths)
        else:
            _spawn_worker()
    except Exception:
        pass  # fail OPEN + SILENT — never block or noise up session start
    return 0


def _run_auto_worker(paths: Paths) -> None:
    try:
        engine, cfg, backend = _build_engine(paths)
        pw = _sync_passphrase(backend, allow_prompt=False)  # never prompts (S6)
        engine.pull(pw)
        engine.push(pw)
        _auto_log(paths, "ok")
    except Exception as e:
        # Log the EXCEPTION TYPE only — never its message/value (S2).
        _auto_log(paths, f"skipped:{type(e).__name__}")


def _spawn_worker() -> None:
    kwargs = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    else:
        kwargs["creationflags"] = 0x00000008  # DETACHED_PROCESS
    subprocess.Popen(
        [sys.executable, "-m", "keys_keeper", "sync", "auto", "--foreground", "--force"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        **kwargs,
    )


def _auto_debounced(paths: Paths) -> bool:
    import json
    try:
        state = json.loads(paths.sync_state_json.read_text())
        last = datetime.strptime(state["last_auto_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (OSError, ValueError, KeyError):
        return False
    age = (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).total_seconds()
    return age < _DEBOUNCE_SEC


def _touch_auto_stamp(paths: Paths) -> None:
    import json
    paths.ensure()
    try:
        state = json.loads(paths.sync_state_json.read_text())
    except (OSError, ValueError):
        state = {}
    state["last_auto_at"] = now_iso()
    try:
        paths.sync_state_json.write_text(json.dumps(state))
        try:
            os.chmod(paths.sync_state_json, 0o600)  # S11 (no-op on Windows)
        except OSError:
            pass
    except OSError:
        pass


def _auto_log(paths: Paths, msg: str) -> None:
    try:
        log = paths.root / "sync.log"
        existed = log.exists()
        line = f"{now_iso()} auto-sync {msg}\n"
        log.open("a", encoding="utf-8").write(line)
        if not existed:
            try:
                os.chmod(log, 0o600)  # S11 (no-op on Windows)
            except OSError:
                pass
    except OSError:
        pass


# ---------------- web admin API (no secrets in/out) ----------------

def web_status(paths: Paths) -> dict:
    cfg = load_sync_config(paths)
    out = {
        "configured": bool(cfg.endpoint and cfg.bucket),
        "mode": cfg.mode, "endpoint": cfg.endpoint,
        "bucket": cfg.bucket, "prefix": cfg.prefix,
    }
    if out["configured"]:
        try:
            engine, _, _ = _build_engine(paths)
            st = engine.status()
            out.update(remote_version=st.remote_version,
                       local_synced=st.local_synced_version, dirty=st.dirty)
        except (AuthError, TransportError, KeychainError) as e:
            out["reachable"] = False
            out["note"] = type(e).__name__
    return out


def web_push(paths: Paths) -> dict:
    engine, cfg, backend = _build_engine(paths)
    pw = _sync_passphrase(backend, allow_prompt=False)  # web cannot prompt
    n = engine.push(pw)
    AuditLog(paths).record(op="sync.push", name=f"<+{n}>", id_="-",
                           file_target=cfg.endpoint)
    return {"ok": True, "synced": n, "version": engine._tip_version()}


def web_pull(paths: Paths) -> dict:
    engine, cfg, backend = _build_engine(paths)
    pw = _sync_passphrase(backend, allow_prompt=False)
    n = engine.pull(pw)
    AuditLog(paths).record(op="sync.pull", name=f"<+{n}>", id_="-",
                           file_target=cfg.endpoint)
    return {"ok": True, "merged": n}


def web_set_mode(paths: Paths, mode: str) -> dict:
    set_mode(mode, paths)
    return {"ok": True, "mode": mode}


def web_setup(paths: Paths, data: dict) -> dict:
    """Configure S3 from the web admin. Secrets (secret key, passphrase) are
    posted over the loopback+token-gated channel straight into the keychain;
    they are never echoed back or written to config."""
    endpoint = (data.get("endpoint") or "").strip()
    bucket = (data.get("bucket") or "").strip()
    akid = (data.get("access_key_id") or "").strip()
    secret = data.get("secret_key") or ""          # not trimmed — it's a secret
    passphrase = data.get("passphrase") or ""
    if not (endpoint and bucket and akid and secret and passphrase):
        raise SyncConfigError(
            "endpoint, bucket, access key id, secret key and passphrase are all required"
        )
    _validate_passphrase_strength(passphrase)  # raises SyncConfigError -> HTTP 400
    cfg = SyncConfig(
        mode=(data.get("mode") or "manual"),
        endpoint=endpoint, bucket=bucket,
        region=(data.get("region") or "us-east-1").strip(),
        prefix=(data.get("prefix") or "keys-keeper").strip(),
        addressing=(data.get("addressing") or "path"),
        insecure=bool(data.get("insecure")),
    ).with_device_id()
    cfg.validate()
    backend = build_backend()
    backend.set(SYNC_ACCESS, akid)
    backend.set(SYNC_SECRET, secret)
    backend.set(SYNC_PASS, passphrase)
    remote = _build_remote(cfg, backend)
    remote.head_object("HEAD")                      # probe credentials (AuthError if bad)
    cfg = replace(cfg, cas_supported=remote.probe_cas())
    save_sync_config(cfg, paths)
    AuditLog(paths).record(op="sync.setup", name="<all>", id_="-", file_target=cfg.endpoint)
    return {"ok": True, "mode": cfg.mode, "cas_supported": cfg.cas_supported}


# ---------------- registration ----------------

def register_sync(sub) -> None:
    sp = sub.add_parser("sync", help="back up / sync the vault to S3")
    ss = sp.add_subparsers(dest="sync_command", required=True)

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
    auto.add_argument("--force", action="store_true", help="ignore the debounce window")
    auto.set_defaults(func=cmd_sync_auto)
