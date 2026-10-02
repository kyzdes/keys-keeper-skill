"""S3 sync use cases shared by the CLI, loopback API and bounded worker.

This layer owns credentials and sync receipts. It never prompts, prints or
starts a process; those are adapter decisions.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Callable

from keys_keeper.audit import AuditLog, record_outcome
from keys_keeper.auto_schedule import DAILY_INTERVAL, claim_auto_sync
from keys_keeper.backend import KeychainError, SecretNotFound
from keys_keeper.composition import AccessContext, build_backend
from keys_keeper.config import SyncConfig, SyncConfigError, load_sync_config, save_sync_config, set_mode
from keys_keeper.models import now_iso
from keys_keeper.operation_journal import _atomic_write_bytes, _secure_read, profile_lock
from keys_keeper.paths import Paths
from keys_keeper.private_files import open_private_file
from keys_keeper.service import compensating_secret_update
from keys_keeper.store import MetadataStore
from keys_keeper.sync import SyncEngine
from keys_keeper.sync_remote import AuthError, S3Remote, S3Signer, TransportError


SYNC_ACCESS = "kk:sync-s3-access-key-id"
SYNC_SECRET = "kk:sync-s3-secret-key"
SYNC_PASS = "kk:sync-passphrase"
MIN_SYNC_PASSPHRASE_LEN = 12


class WeakPassphraseError(SyncConfigError):
    """A user-selected cloud passphrase falls below the minimum strength."""


def _validate_passphrase_strength(passphrase: str) -> None:
    if len(passphrase) < MIN_SYNC_PASSPHRASE_LEN:
        raise WeakPassphraseError(
            f"backup passphrase must be at least {MIN_SYNC_PASSPHRASE_LEN} characters"
        )
    if not passphrase.strip() or len(set(passphrase.strip())) < 4:
        raise WeakPassphraseError("backup passphrase is too simple; use a more varied phrase")


def _build_remote(cfg: SyncConfig, backend) -> S3Remote:
    signer = S3Signer(backend.get(SYNC_ACCESS).unseal(), backend.get(SYNC_SECRET), region=cfg.region)
    return S3Remote(signer=signer, endpoint=cfg.endpoint, bucket=cfg.bucket,
                    prefix=cfg.prefix, addressing=cfg.addressing, proxy=cfg.proxy)


def _build_engine(paths: Paths, *, access: AccessContext = AccessContext.INTERACTIVE):
    cfg = load_sync_config(paths)
    if not cfg.endpoint or not cfg.bucket:
        raise SyncConfigError("sync is not configured; run keys sync setup")
    backend = build_backend(paths=paths, access=access)
    engine = SyncEngine(remote=_build_remote(cfg, backend), store=MetadataStore(paths),
                        backend=backend, device_id=cfg.device_id,
                        retain_snapshots=cfg.retain_snapshots, paths=paths,
                        cas_supported=cfg.cas_supported)
    return engine, cfg, backend


def stored_passphrase(backend) -> str:
    # Only positive metadata absence is a missing credential. A present item
    # whose read is denied/unavailable must stop here without another read.
    if SYNC_PASS not in set(backend.list_ids()):
        raise SecretNotFound("sync passphrase is not stored")
    return backend.get(SYNC_PASS).unseal()


def _outcome(paths: Paths, op: str, *, endpoint: str | None = None,
             name: str = "<all>", success: bool = True) -> str:
    return record_outcome(AuditLog(paths), op=op, name=name, id_="-",
                          file_target=endpoint, success=success)


def setup(paths: Paths, cfg: SyncConfig, *, access_key_id: str, secret_key: str,
          passphrase: str, access: AccessContext = AccessContext.UI_FORBIDDEN) -> dict:
    """Validate and configure the reserved credentials with ordinary rollback."""
    from keys_keeper.config import SyncConfigCommitError

    deferred_error = None
    try:
        cfg.validate()
        if not all(type(value) is str and value for value in (access_key_id, secret_key, passphrase)):
            raise SyncConfigError("sync credentials are required")
        _validate_passphrase_strength(passphrase)
        backend = build_backend(paths=paths, access=access)
        with compensating_secret_update(backend, {
            SYNC_ACCESS: access_key_id, SYNC_SECRET: secret_key, SYNC_PASS: passphrase,
        }):
            remote = _build_remote(cfg, backend)
            remote.head_object("HEAD")
            cfg = replace(cfg, cas_supported=remote.probe_cas())
            try:
                save_sync_config(cfg, paths)
            except SyncConfigCommitError as ex:
                # Config publication succeeded. Preserve its matching new
                # credentials and report durability uncertainty afterwards.
                deferred_error = ex
    except Exception as ex:
        ex.audit_status = _outcome(paths, "sync.setup", success=False)
        raise
    audit_status = _outcome(paths, "sync.setup", endpoint=cfg.endpoint)
    if deferred_error is not None:
        deferred_error.audit_status = audit_status
        raise deferred_error
    return {"ok": True, "mode": cfg.mode, "cas_supported": cfg.cas_supported,
            "committed": True, "audit_status": audit_status}


def _run_prepared(paths: Paths, operation: str, engine, cfg: SyncConfig,
                  passphrase: str, *, version: int | None = None) -> dict:
    try:
        if operation == "push":
            n = engine.push(passphrase)
            result = {"synced": n}
        elif operation == "pull":
            n = engine.pull(passphrase)
            result = {"merged": n}
        elif operation == "rollback":
            result = {"version": engine.rollback(version, passphrase)}
            n = version
        else:
            raise ValueError("unsupported sync operation")
    except Exception as ex:
        ex.audit_status = _outcome(paths, f"sync.{operation}", endpoint=cfg.endpoint, success=False)
        raise
    audit_status = _outcome(paths, f"sync.{operation}", endpoint=cfg.endpoint,
                            name=f"<to {n}>" if operation == "rollback" else f"<+{n}>")
    if operation == "push":
        # A committed push must not become a failure because a second remote
        # query or a local informational read fails afterwards.
        try:
            version = _read_timing_state(paths).get("last_version")
            result["version"] = version if type(version) is int and 0 <= version < 2**63 else None
        except Exception:
            result["version"] = None
    return {"ok": True, **result, "committed": True, "audit_status": audit_status}


def run_action(paths: Paths, operation: str, *, access: AccessContext = AccessContext.UI_FORBIDDEN,
               passphrase_provider: Callable | None = None, version: int | None = None) -> dict:
    if operation not in {"push", "pull", "rollback"}:
        raise ValueError("unsupported sync operation")
    try:
        engine, cfg, backend = _build_engine(paths, access=access)
        passphrase = (passphrase_provider or stored_passphrase)(backend)
    except Exception as ex:
        ex.audit_status = _outcome(paths, f"sync.{operation}", success=False)
        raise
    return _run_prepared(paths, operation, engine, cfg, passphrase, version=version)


def status(paths: Paths, *, access: AccessContext = AccessContext.UI_FORBIDDEN) -> dict:
    cfg = load_sync_config(paths)
    out = {"configured": bool(cfg.endpoint and cfg.bucket), "mode": cfg.mode,
           "endpoint": cfg.endpoint, "bucket": cfg.bucket, "prefix": cfg.prefix}
    if out["configured"]:
        engine, _, _ = _build_engine(paths, access=access)
        st = engine.status()
        out.update(remote_version=st.remote_version, local_synced=st.local_synced_version, dirty=st.dirty)
    return out


def web_status(paths: Paths) -> dict:
    try:
        return status(paths)
    except (AuthError, TransportError, KeychainError):
        cfg = load_sync_config(paths)
        return {"configured": bool(cfg.endpoint and cfg.bucket), "mode": cfg.mode,
                "endpoint": cfg.endpoint, "bucket": cfg.bucket, "prefix": cfg.prefix,
                "reachable": False, "note": "Sync connection or credential is unavailable"}


def web_push(paths: Paths) -> dict:
    return run_action(paths, "push")


def web_pull(paths: Paths) -> dict:
    return run_action(paths, "pull")


def web_set_mode(paths: Paths, mode: str) -> dict:
    from keys_keeper.config import SyncConfigCommitError

    try:
        set_mode(mode, paths)
    except SyncConfigCommitError as ex:
        ex.audit_status = _outcome(paths, "sync.mode")
        raise
    except Exception as ex:
        ex.audit_status = _outcome(paths, "sync.mode", success=False)
        raise
    return {"ok": True, "mode": mode, "committed": True,
            "audit_status": _outcome(paths, "sync.mode")}


def web_setup(paths: Paths, data: dict) -> dict:
    endpoint, bucket, akid = ((data.get(key) or "").strip()
                              for key in ("endpoint", "bucket", "access_key_id"))
    if not endpoint or not bucket:
        raise SyncConfigError("endpoint and bucket are required")
    cfg = SyncConfig(mode=data.get("mode") or "manual", endpoint=endpoint, bucket=bucket,
                     region=(data.get("region") or "us-east-1").strip(),
                     prefix=(data.get("prefix") or "keys-keeper").strip(),
                     addressing=data.get("addressing") or "path",
                     insecure=data.get("insecure", False)).with_device_id()
    return setup(paths, cfg, access_key_id=akid, secret_key=data.get("secret_key") or "",
                 passphrase=data.get("passphrase") or "")


def _auto_debounce_seconds() -> int:
    try:
        configured = int(os.environ.get("KEYS_KEEPER_SYNC_DEBOUNCE_SEC", str(DAILY_INTERVAL)))
    except ValueError:
        configured = DAILY_INTERVAL
    return max(DAILY_INTERVAL, configured)


_DEBOUNCE_SEC = _auto_debounce_seconds()


def _read_timing_state(paths: Paths) -> dict:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("invalid sync timing metadata")
            out[key] = value
        return out

    def invalid_constant(_value):
        raise ValueError("invalid sync timing metadata")

    state = json.loads(_secure_read(paths.sync_state_json, max_bytes=1024 * 1024),
                       object_pairs_hook=pairs, parse_constant=invalid_constant)
    if not isinstance(state, dict):
        raise ValueError("invalid sync timing metadata")
    return state


def _auto_debounced(paths: Paths) -> bool:
    try:
        state = _read_timing_state(paths)
    except FileNotFoundError:
        return False
    except Exception:
        return True
    if "last_auto_at" not in state:
        return False
    try:
        last = datetime.strptime(state["last_auto_at"], "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return True
    age = (datetime.now(timezone.utc) - last.replace(tzinfo=timezone.utc)).total_seconds()
    return age < max(DAILY_INTERVAL, _DEBOUNCE_SEC)


def _touch_auto_stamp(paths: Paths) -> None:
    with profile_lock(Paths(paths.root / "sync-auto-status"), timeout=1):
        try:
            state = _read_timing_state(paths)
        except FileNotFoundError:
            state = {}
        state["last_auto_at"] = now_iso()
        _atomic_write_bytes(paths.sync_state_json, json.dumps(state).encode())


def claim_automatic_attempt(paths: Paths, *, force: bool = False) -> bool:
    if load_sync_config(paths).mode != "auto" or (not force and _auto_debounced(paths)):
        return False
    claimed, _due = claim_auto_sync(Paths(paths.root / "sync-auto-schedule"), time.time(),
                                    interval=max(DAILY_INTERVAL, _DEBOUNCE_SEC), force=force)
    if not claimed:
        return False
    _touch_auto_stamp(paths)
    return True


def _auto_log(paths: Paths, status_code: str) -> None:
    try:
        paths.ensure()
        fd = open_private_file(paths.root / "sync.log", os.O_WRONLY | os.O_APPEND | os.O_CREAT)
        with os.fdopen(fd, "a", encoding="utf-8") as stream:
            stream.write(f"{now_iso()} auto-sync {status_code}\n")
    except Exception:
        pass


def _run_auto_worker(paths: Paths) -> bool:
    """Execute after the supervisor rechecks the master role; never prompt."""
    try:
        if load_sync_config(paths).mode != "auto":
            return True
        try:
            engine, cfg, backend = _build_engine(paths, access=AccessContext.UI_FORBIDDEN)
            pw = stored_passphrase(backend)
        except Exception:
            _outcome(paths, "sync.auto", success=False)
            raise
        _run_prepared(paths, "pull", engine, cfg, pw)
        _run_prepared(paths, "push", engine, cfg, pw)
        _auto_log(paths, "ok")
        return True
    except Exception:
        _auto_log(paths, "unavailable")
        return False
