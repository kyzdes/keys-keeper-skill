"""End-to-end KK2 client-side sync for a zero-knowledge VPS relay.

The VPS stores only public device records, signed commit manifests, and opaque
encrypted snapshots.  Vault keys, device private keys, and bearer tokens are
kept in the local credential backend and never written to the JSON sidecars in
this module.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
import weakref
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from time import monotonic as _lock_clock
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from keys_keeper.backend import KeychainBackend
from keys_keeper import private_files
from keys_keeper._locking import lock_exclusive, unlock
from keys_keeper.models import ValidationError as VaultValidationError, validate_snapshot_payload
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper.request_json import request_object
from keys_keeper.secure_io import SecureFileError, read_secure_text, replace_secure_text
from keys_keeper.service import ConcurrentMutation, VaultService
from keys_keeper.store import MetadataStore
from keys_keeper.vault_snapshot import build_snapshot_payload, content_hash, merge, prepare_snapshot_payload
from keys_keeper.sync_protocol_v2 import (
    KK2Error,
    VerifiedCommit,
    build_signed_commit,
    canonical_json_bytes,
    compute_manifest_hash,
    open_snapshot,
    seal_snapshot,
    verify_commit_signature,
)
from keys_keeper.sync_vps_client import (
    VpsBadRequestError, VpsConflictError, VpsProtocolError, VpsTransportError, _decode_json,
)


SYNC_VPS_TOKEN = "kk:sync-vps-device-token"
SYNC_VPS_VAULT_KEY = "kk:sync-vps-vault-key"
SYNC_VPS_SIGNING_PRIVATE = "kk:sync-vps-signing-private"
SYNC_VPS_WRAPPING_PRIVATE = "kk:sync-vps-wrapping-private"

MEMBERSHIP_PROFILE = "kk2-device-membership-ed25519-v1"
REVOCATION_PROFILE = "kk2-device-revocation-ed25519-v1"
_MEMBERSHIP_DOMAIN = b"keys-keeper/KK2/device-membership/v1\x00"
_REVOCATION_DOMAIN = b"keys-keeper/KK2/device-revocation/v1\x00"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_STATE_FIELDS = {
    "commit_id": str, "manifest_hash": str, "sequence": int, "manifest": dict,
    "revocations": dict, "last_sync_at": str, "pending_revoke": dict,
}
_ANCHOR_FIELDS = {"commit_id", "manifest_hash", "sequence", "manifest"}
MAX_CHAIN_COMMITS = 10_000
HISTORY_PAGE_SIZE = 100
_KEEP_PENDING = object()
_OPERATION_LOCKS = weakref.WeakValueDictionary()
_OPERATION_LOCKS_GUARD = threading.Lock()


class _VpsOperationLock:
    """One bounded, reentrant owner per local vault, across engine instances.

    Lock order is VPS, journal, metadata. Network calls hold only this VPS
    lock; ordinary vault operations do not wait for network while locked.
    """

    def __init__(self, root):
        self.root = root
        self.thread_lock = threading.RLock()
        self.depth = 0
        self.pid = os.getpid()
        self.fd = None

    @contextmanager
    def locked(self, timeout):
        if self.pid != os.getpid():
            # A forked child must not inherit the parent's reentrant ownership.
            if self.fd is not None:
                os.close(self.fd)
            self.thread_lock, self.depth, self.fd = threading.RLock(), 0, None
            self.pid = os.getpid()
        deadline = _lock_clock() + timeout
        if not self.thread_lock.acquire(timeout=timeout):
            raise VpsSyncError("VPS operation is busy; retry later")
        try:
            if self.depth:
                self.depth += 1
                try:
                    yield
                finally:
                    self.depth -= 1
                return
            ensure_private_dir(self.root)
            ensure_private_dir(self.root / "locks")
            fd = private_files.open_private_file(
                self.root / "locks" / "vps-sync.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
            )
            self.fd = fd
            try:
                try:
                    lock_exclusive(fd, timeout=max(0, deadline - _lock_clock()))
                except TimeoutError:
                    raise VpsSyncError("VPS operation is busy; retry later") from None
                self.depth = 1
                try:
                    yield
                finally:
                    self.depth = 0
                    unlock(fd)
            finally:
                self.fd = None
                os.close(fd)
        finally:
            self.thread_lock.release()


def _after_fork():
    global _OPERATION_LOCKS_GUARD
    _OPERATION_LOCKS_GUARD = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork)


def _serialized(operation):
    @wraps(operation)
    def guarded(self, *args, **kwargs):
        with self._operation_lock.locked(self.lock_timeout):
            return operation(self, *args, **kwargs)
    return guarded


class VpsSyncError(VpsTransportError):
    """A safe, user-facing VPS sync failure."""


class VpsTrustError(VpsSyncError):
    """The relay returned data that does not extend the local trust anchor."""


class VpsSyncCommitError(VpsSyncError):
    """A sync side effect completed but a subsequent local step failed."""

    committed = True


class VpsRevokePreparationError(VpsSyncError):
    """The local intent could not be durably prepared; no POST was sent."""

    committed = False


@dataclass(frozen=True)
class VpsSyncConfig:
    endpoint: str
    vault_id: str
    device_id: str
    root_device_id: str
    root_sign_public_key: str
    sign_public_key: str
    wrap_public_key: str
    status: str = "active"  # active | pending
    invite_id: str = ""
    inviter_device_id: str = ""
    inviter_sign_public_key: str = ""
    proxy: str = "direct"
    trusted_checkpoint_commit_id: str = ""
    trusted_checkpoint_manifest_hash: str = ""
    trusted_checkpoint_sequence: int = 0

    def validate(self) -> None:
        from keys_keeper.sync_vps_client import VpsSyncClient

        # Reuse the transport's HTTPS/loopback and credential-in-URL policy.
        if any(type(getattr(self, name)) is not (int if name == "trusted_checkpoint_sequence" else str)
               for name in self.__annotations__):
            raise VpsTrustError("VPS sync configuration has invalid field types")
        VpsSyncClient(base_url=self.endpoint, proxy=self.proxy)
        for label in ("vault_id", "device_id", "root_device_id"):
            value = getattr(self, label)
            if not isinstance(value, str) or not _ID_RE.fullmatch(value):
                raise VpsTrustError(f"invalid {label} in VPS sync configuration")
        if self.status not in ("active", "pending"):
            raise VpsTrustError("invalid VPS sync enrollment status")
        if self.status == "pending" and not self.invite_id:
            raise VpsTrustError("pending VPS sync enrollment has no invite id")
        _decode_b64(self.root_sign_public_key, label="root signing public key", length=32)
        _decode_b64(self.sign_public_key, label="device signing public key", length=32)
        _decode_b64(self.wrap_public_key, label="device wrapping public key", length=32)
        if self.inviter_sign_public_key:
            _decode_b64(
                self.inviter_sign_public_key,
                label="inviter signing public key",
                length=32,
            )
        if isinstance(self.trusted_checkpoint_sequence, bool) or not isinstance(
            self.trusted_checkpoint_sequence, int
        ) or self.trusted_checkpoint_sequence < 0:
            raise VpsTrustError("invalid trusted onboarding checkpoint sequence")
        if self.trusted_checkpoint_sequence == 0:
            if self.trusted_checkpoint_commit_id or self.trusted_checkpoint_manifest_hash:
                raise VpsTrustError("empty onboarding checkpoint must not contain hashes")
        elif (
            not _HASH_RE.fullmatch(self.trusted_checkpoint_commit_id)
            or not _HASH_RE.fullmatch(self.trusted_checkpoint_manifest_hash)
        ):
            raise VpsTrustError("invalid trusted onboarding checkpoint")
        if self.proxy not in ("direct", "system") and not self.proxy.startswith(
            ("http://", "https://")
        ):
            raise VpsTrustError("invalid VPS sync proxy policy")


@dataclass(frozen=True)
class VpsSyncStatus:
    remote_sequence: int | None
    local_sequence: int | None
    dirty: bool


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64(value: Any, *, label: str, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise VpsTrustError(f"{label} is not canonical base64")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise VpsTrustError(f"{label} is not canonical base64")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise VpsTrustError(f"{label} is malformed") from exc
    if _b64(decoded) != value or (length is not None and len(decoded) != length):
        raise VpsTrustError(f"{label} is not canonical base64")
    return decoded


def _wire_bytes(value: Any, *, label: str, maximum: int = 32 * 1024 * 1024) -> bytes:
    """Decode the server's unpadded URL-safe base64 byte fields strictly."""
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4 + 4:
        raise VpsProtocolError(f"sync server returned an invalid {label}")
    try:
        out = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError):
        raise VpsProtocolError(f"sync server returned an invalid {label}") from None
    if len(out) > maximum or _b64(out) != value:
        raise VpsProtocolError(f"sync server returned a non-canonical {label}")
    return out


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sidecar(paths: Paths) -> Path:
    return paths.root / "vps-sync.json"


def _state_sidecar(paths: Paths) -> Path:
    return paths.root / "vps-sync-state.json"


def save_vps_config(config: VpsSyncConfig, paths: Paths | None = None) -> None:
    config.validate()
    paths = paths or Paths()
    paths.ensure()
    state = read_secure_text(_sidecar(paths), missing_ok=True)
    replace_secure_text(state, json.dumps(asdict(config), sort_keys=True, indent=2) + "\n")


def load_vps_config(paths: Paths | None = None) -> VpsSyncConfig:
    paths = paths or Paths()
    sidecar = _sidecar(paths)
    try:
        fields = {name: int if name == "trusted_checkpoint_sequence" else str
                  for name in VpsSyncConfig.__annotations__}
        raw = request_object(read_secure_text(sidecar, missing_ok=False, max_bytes=64 * 1024).text.encode("utf-8"),
                             fields, required={"endpoint", "vault_id", "device_id", "root_device_id",
                                               "root_sign_public_key", "sign_public_key", "wrap_public_key"})
        config = VpsSyncConfig(**raw)
        config.validate()
        return config
    except FileNotFoundError as exc:
        raise VpsSyncError("VPS sync is not configured; run `keys sync vps init`") from exc
    except (OSError, ValueError, TypeError, SecureFileError) as exc:
        raise VpsSyncError(
            f"VPS sync configuration is unsafe or malformed: {sidecar}; "
            "preserve it for diagnosis, then restore enrollment from a trusted bundle"
        ) from exc


def make_membership_statement(
    *,
    vault_id: str,
    device_id: str,
    sign_public_key: str,
    wrap_public_key: str,
    approved_by_device_id: str,
    checkpoint_commit_id: str | None,
    checkpoint_manifest_hash: str | None,
    checkpoint_sequence: int,
    issued_at: str | None = None,
) -> dict[str, Any]:
    statement = {
        "protocol": "KK2",
        "format_profile": MEMBERSHIP_PROFILE,
        "vault_id": vault_id,
        "device_id": device_id,
        "sign_public_key": sign_public_key,
        "wrap_public_key": wrap_public_key,
        "approved_by_device_id": approved_by_device_id,
        "checkpoint_commit_id": checkpoint_commit_id,
        "checkpoint_manifest_hash": checkpoint_manifest_hash,
        "checkpoint_sequence": checkpoint_sequence,
        "issued_at": issued_at or _utc_now(),
    }
    _validate_membership(statement)
    return statement


def _validate_membership(value: Any) -> dict[str, Any]:
    fields = {
        "protocol", "format_profile", "vault_id", "device_id",
        "sign_public_key", "wrap_public_key", "approved_by_device_id",
        "checkpoint_commit_id", "checkpoint_manifest_hash",
        "checkpoint_sequence", "issued_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise VpsTrustError("device membership statement has invalid fields")
    if value["protocol"] != "KK2" or value["format_profile"] != MEMBERSHIP_PROFILE:
        raise VpsTrustError("unsupported device membership profile")
    for name in ("vault_id", "device_id", "approved_by_device_id"):
        if not isinstance(value[name], str) or not _ID_RE.fullmatch(value[name]):
            raise VpsTrustError(f"device membership has invalid {name}")
    _decode_b64(value["sign_public_key"], label="membership signing key", length=32)
    _decode_b64(value["wrap_public_key"], label="membership wrapping key", length=32)
    sequence = value["checkpoint_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise VpsTrustError("device membership has invalid checkpoint sequence")
    commit_id, manifest_hash = value["checkpoint_commit_id"], value["checkpoint_manifest_hash"]
    if sequence == 0:
        if commit_id is not None or manifest_hash is not None:
            raise VpsTrustError("empty membership checkpoint must have null hashes")
    else:
        if not isinstance(commit_id, str) or not _HASH_RE.fullmatch(commit_id):
            raise VpsTrustError("device membership has invalid checkpoint commit id")
        if not isinstance(manifest_hash, str) or not _HASH_RE.fullmatch(manifest_hash):
            raise VpsTrustError("device membership has invalid checkpoint manifest hash")
    if not isinstance(value["issued_at"], str) or not value["issued_at"].endswith("Z"):
        raise VpsTrustError("device membership has invalid issue timestamp")
    return value


def sign_membership(statement: Mapping[str, Any], private_key: bytes) -> str:
    checked = _validate_membership(dict(statement))
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        _MEMBERSHIP_DOMAIN + canonical_json_bytes(checked)
    )
    return _b64(signature)


def verify_membership(
    statement: Mapping[str, Any], signature: str, approver_public_key: bytes
) -> dict[str, Any]:
    checked = _validate_membership(dict(statement))
    raw_signature = _decode_b64(signature, label="membership signature", length=64)
    try:
        Ed25519PublicKey.from_public_bytes(approver_public_key).verify(
            raw_signature, _MEMBERSHIP_DOMAIN + canonical_json_bytes(checked)
        )
    except (InvalidSignature, ValueError) as exc:
        raise VpsTrustError("device membership signature is invalid") from exc
    return checked


def make_revocation_statement(
    *,
    vault_id: str,
    device_id: str,
    revoked_by_device_id: str,
    checkpoint_commit_id: str | None,
    checkpoint_manifest_hash: str | None,
    checkpoint_sequence: int,
    issued_at: str | None = None,
) -> dict[str, Any]:
    for value in (vault_id, device_id, revoked_by_device_id):
        if not _ID_RE.fullmatch(value):
            raise VpsTrustError("invalid device revocation identifier")
    statement = {
        "protocol": "KK2",
        "format_profile": REVOCATION_PROFILE,
        "vault_id": vault_id,
        "device_id": device_id,
        "revoked_by_device_id": revoked_by_device_id,
        "checkpoint_commit_id": checkpoint_commit_id,
        "checkpoint_manifest_hash": checkpoint_manifest_hash,
        "checkpoint_sequence": checkpoint_sequence,
        "issued_at": issued_at or _utc_now(),
    }
    return _validate_revocation(statement)


def _validate_revocation(value: Any) -> dict[str, Any]:
    fields = {
        "protocol", "format_profile", "vault_id", "device_id",
        "revoked_by_device_id", "checkpoint_commit_id",
        "checkpoint_manifest_hash", "checkpoint_sequence", "issued_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise VpsTrustError("device revocation statement has invalid fields")
    if value["protocol"] != "KK2" or value["format_profile"] != REVOCATION_PROFILE:
        raise VpsTrustError("unsupported device revocation profile")
    for name in ("vault_id", "device_id", "revoked_by_device_id"):
        if not isinstance(value[name], str) or not _ID_RE.fullmatch(value[name]):
            raise VpsTrustError(f"device revocation has invalid {name}")
    sequence = value["checkpoint_sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise VpsTrustError("device revocation has invalid checkpoint sequence")
    commit_id, manifest_hash = value["checkpoint_commit_id"], value["checkpoint_manifest_hash"]
    if sequence == 0:
        if commit_id is not None or manifest_hash is not None:
            raise VpsTrustError("empty revocation checkpoint must have null hashes")
    elif (
        not isinstance(commit_id, str)
        or not _HASH_RE.fullmatch(commit_id)
        or not isinstance(manifest_hash, str)
        or not _HASH_RE.fullmatch(manifest_hash)
    ):
        raise VpsTrustError("device revocation has invalid checkpoint hashes")
    if not isinstance(value["issued_at"], str) or not value["issued_at"].endswith("Z"):
        raise VpsTrustError("device revocation has invalid issue timestamp")
    return value


def sign_revocation(statement: Mapping[str, Any], private_key: bytes) -> str:
    checked = _validate_revocation(dict(statement))
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        _REVOCATION_DOMAIN + canonical_json_bytes(checked)
    )
    return _b64(signature)


def verify_revocation(
    statement: Mapping[str, Any], signature: str, revoker_public_key: bytes
) -> dict[str, Any]:
    checked = _validate_revocation(dict(statement))
    raw_signature = _decode_b64(signature, label="revocation signature", length=64)
    try:
        Ed25519PublicKey.from_public_bytes(revoker_public_key).verify(
            raw_signature, _REVOCATION_DOMAIN + canonical_json_bytes(checked)
        )
    except (InvalidSignature, ValueError) as exc:
        raise VpsTrustError("device revocation signature is invalid") from exc
    return checked


class VpsSyncEngine:
    """Merge the local vault with a signed KK2 commit chain over HTTP."""

    def __init__(
        self,
        *,
        client,
        config: VpsSyncConfig,
        store: MetadataStore,
        backend: KeychainBackend,
        vault_key: bytes,
        signing_private_key: bytes,
        paths: Paths,
        max_retries: int = 5,
        max_history_seconds: float = 60.0,
        lock_timeout: float = 10.0,
    ) -> None:
        config.validate()
        if config.status != "active":
            raise VpsSyncError("this device is not approved yet; run `keys sync vps finish`")
        if not isinstance(vault_key, bytes) or not isinstance(signing_private_key, bytes) or len(vault_key) != 32 or len(signing_private_key) != 32:
            raise VpsTrustError("invalid local VPS sync key material")
        from cryptography.hazmat.primitives import serialization
        public_key = Ed25519PrivateKey.from_private_bytes(signing_private_key).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
        if public_key != _decode_b64(config.sign_public_key, label="device signing key", length=32):
            raise VpsTrustError("local VPS signing key does not match the pinned device identity")
        if type(max_retries) is not int or not 1 <= max_retries <= 20:
            raise VpsSyncError("VPS retry limit must be between 1 and 20")
        if (isinstance(max_history_seconds, bool) or not isinstance(max_history_seconds, (int, float))
                or not math.isfinite(max_history_seconds) or max_history_seconds <= 0):
            raise VpsSyncError("VPS history deadline must be positive")
        self.client = client
        self.config = config
        self.store = store
        self.backend = backend
        self.vault_key = vault_key
        self.signing_private_key = signing_private_key
        self.paths = paths
        self.max_retries = max_retries
        self.max_history_seconds = float(max_history_seconds)
        if (isinstance(lock_timeout, bool) or not isinstance(lock_timeout, (int, float))
                or not math.isfinite(lock_timeout) or not 0 <= lock_timeout <= 300):
            raise VpsSyncError("VPS lock timeout must be between 0 and 300 seconds")
        self.lock_timeout = float(lock_timeout)
        root = paths.root.absolute()
        key = os.path.normcase(str(root.resolve()))
        with _OPERATION_LOCKS_GUARD:
            operation_lock = _OPERATION_LOCKS.get(key)
            if operation_lock is None:
                operation_lock = _VpsOperationLock(root)
                _OPERATION_LOCKS[key] = operation_lock
            self._operation_lock = operation_lock

    def _evidence(self, device_id, evidence):
        if (not isinstance(device_id, str) or not _ID_RE.fullmatch(device_id)
                or device_id == self.config.root_device_id
                or not isinstance(evidence, dict) or set(evidence) != {"statement", "signature"}
                or not all(isinstance(value, str) for value in evidence.values())):
            raise VpsTrustError("local VPS revocation evidence is malformed")
        try:
            statement = json.loads(evidence["statement"])
            if canonical_json_bytes(statement).decode("utf-8") != evidence["statement"]:
                raise ValueError
            checked = verify_revocation(statement, evidence["signature"], _decode_b64(
                self.config.root_sign_public_key, label="root signing key", length=32))
            if (checked["vault_id"] != self.config.vault_id or checked["device_id"] != device_id
                    or checked["revoked_by_device_id"] != self.config.root_device_id):
                raise ValueError
            return checked
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise VpsTrustError("local VPS revocation evidence is malformed") from None

    def _parse_state(self, text):
        state = request_object(text.encode("utf-8"), _STATE_FIELDS)
        anchor_fields = set(state) & _ANCHOR_FIELDS
        if anchor_fields and anchor_fields != _ANCHOR_FIELDS:
            raise VpsTrustError("local VPS sync trust anchor is incomplete")
        anchor = self._anchor(state)
        records = dict(state.get("revocations", {}))
        pending = state.get("pending_revoke")
        if pending is not None:
            if set(pending) != {"device_id", "statement", "signature"}:
                raise VpsTrustError("local VPS pending revocation is malformed")
            device_id = pending["device_id"]
            evidence = {key: pending[key] for key in ("statement", "signature")}
            self._evidence(device_id, evidence)
            if device_id in records and records[device_id] != evidence:
                raise VpsTrustError("local VPS pending revocation conflicts with trusted evidence")
            records[device_id] = evidence
        for device_id, evidence in records.items():
            checked = self._evidence(device_id, evidence)
            if checked["checkpoint_sequence"] > (0 if anchor is None else anchor.sequence):
                raise VpsTrustError("local VPS revocation checkpoint exceeds its trust anchor")
        return state

    def _read_state(self) -> dict[str, Any]:
        try:
            state = read_secure_text(_state_sidecar(self.paths), missing_ok=True)
            if state.identity is None:
                return {}
            raw = self._parse_state(state.text)
        except (ValueError, OSError, SecureFileError) as exc:
            raise VpsTrustError("local VPS sync trust state is unreadable or malformed") from exc
        return raw

    @_serialized
    def _write_state(self, verified: VerifiedCommit | None, *, pending_revoke=_KEEP_PENDING) -> None:
        self.paths.ensure()
        previous = read_secure_text(_state_sidecar(self.paths), missing_ok=True)
        old = {} if previous.identity is None else self._parse_state(previous.text)
        anchor = self._anchor(old)
        if anchor is not None:
            if verified is None or anchor.sequence > verified.sequence or (
                    anchor.sequence == verified.sequence and anchor.commit_id != verified.commit_id):
                raise VpsTrustError("local VPS trust state advanced during this operation")
            if (anchor.sequence, anchor.commit_id, anchor.manifest_hash) not in getattr(self, "_last_chain_checkpoints", set()):
                raise VpsTrustError("local VPS trust state no longer belongs to the verified chain")
        records = dict(old.get("revocations", {}))
        for device_id, evidence in getattr(self, "_verified_revocation_records", {}).items():
            if device_id in records and records[device_id] != evidence:
                raise VpsTrustError("VPS rewrote a previously trusted revocation")
            records[device_id] = evidence
        for device_id, evidence in records.items():
            checked = self._evidence(device_id, evidence)
            checkpoint = (checked["checkpoint_sequence"], checked["checkpoint_commit_id"],
                          checked["checkpoint_manifest_hash"])
            if checkpoint[0] and checkpoint not in getattr(self, "_last_chain_checkpoints", set()):
                raise VpsTrustError("trusted revocation checkpoint is not in the verified chain")
            if any(sequence > checkpoint[0] for sequence in getattr(self, "_last_chain_authors", {}).get(device_id, ())):
                raise VpsTrustError("verified chain contains a commit after a trusted revocation")
        pending = old.get("pending_revoke") if pending_revoke is _KEEP_PENDING else pending_revoke
        old_pending = old.get("pending_revoke")
        if old_pending is not None and pending != old_pending:
            evidence = {key: old_pending[key] for key in ("statement", "signature")}
            if pending is not None or getattr(self, "_verified_revocation_records", {}).get(old_pending["device_id"]) != evidence:
                raise VpsTrustError("pending revocation requires exact fresh confirmation")
        state = {"revocations": records}
        if verified is not None:
            state.update(commit_id=verified.commit_id, manifest_hash=verified.manifest_hash,
                         sequence=verified.sequence, manifest=dict(verified.manifest))
        if pending is not None:
            state["pending_revoke"] = pending
        comparable = {key: value for key, value in old.items() if key != "last_sync_at"}
        comparable.setdefault("revocations", {})
        if comparable == state:
            return
        state["last_sync_at"] = _utc_now()
        encoded = json.dumps(state, sort_keys=True, indent=2) + "\n"
        self._parse_state(encoded)
        # Trust publication requires a real directory durability result. The
        # generic plaintext sink deliberately uses best-effort directory fsync.
        private_files.atomic_write_bytes(previous.path, encoded.encode("utf-8"),
                                        expected=previous._bytes_state)

    def _trusted_device_keys(self, state: dict | None = None, *, allow_pending=False) -> dict[str, bytes]:
        response = self.client.list_devices(self.config.vault_id)
        records = response.get("devices") if isinstance(response, dict) else None
        if not isinstance(records, list):
            raise VpsProtocolError("sync server returned an invalid device list")
        by_id: dict[str, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("device_id"), str):
                raise VpsProtocolError("sync server returned an invalid device record")
            if record["device_id"] in by_id:
                raise VpsTrustError("sync server returned duplicate device identities")
            by_id[record["device_id"]] = record

        root = by_id.get(self.config.root_device_id)
        if (
            root is None
            or root.get("status") != "active"
            or root.get("sign_public_key") != self.config.root_sign_public_key
        ):
            raise VpsTrustError("VPS root device does not match the pinned trust anchor")
        trusted: dict[str, bytes] = {
            self.config.root_device_id: _decode_b64(
                self.config.root_sign_public_key, label="root signing key", length=32
            )
        }
        memberships: dict[str, dict[str, Any]] = {}
        pending = {
            device_id
            for device_id, record in by_id.items()
            if device_id not in trusted and record.get("status") in ("active", "revoked")
        }
        while pending:
            progressed = False
            for device_id in list(pending):
                record = by_id[device_id]
                statement = record.get("membership_statement")
                signature = record.get("membership_signature")
                if isinstance(statement, str):
                    try:
                        parsed = json.loads(statement)
                    except ValueError:
                        raise VpsTrustError("device membership statement is malformed") from None
                    if canonical_json_bytes(parsed).decode("utf-8") != statement:
                        raise VpsTrustError("device membership statement is not canonical")
                    statement = parsed
                if not isinstance(statement, dict):
                    continue
                approver = statement.get("approved_by_device_id")
                if approver != self.config.root_device_id:
                    raise VpsTrustError("device membership was not approved by the root device")
                if approver not in trusted:
                    continue
                checked = verify_membership(statement, signature, trusted[approver])
                if (
                    checked["vault_id"] != self.config.vault_id
                    or checked["device_id"] != device_id
                    or checked["sign_public_key"] != record.get("sign_public_key")
                    or checked["wrap_public_key"] != record.get("wrap_public_key")
                ):
                    raise VpsTrustError("device record does not match its signed membership")
                trusted[device_id] = _decode_b64(
                    checked["sign_public_key"], label="device signing key", length=32
                )
                memberships[device_id] = checked
                pending.remove(device_id)
                progressed = True
            if not progressed:
                break
        if pending:
            raise VpsTrustError("an active device has no verifiable membership chain")
        own = by_id.get(self.config.device_id)
        if (own is None or own.get("status") not in ("active", "revoked")
                or own.get("sign_public_key") != self.config.sign_public_key
                or own.get("wrap_public_key") != self.config.wrap_public_key
                or self.config.device_id not in trusted):
            raise VpsTrustError("this device has no matching trusted membership")

        revocations: dict[str, dict[str, Any]] = {}
        revocation_records: dict[str, dict[str, str]] = {}
        for device_id, record in by_id.items():
            status = record.get("status")
            if status not in ("pending", "active", "revoked"):
                raise VpsTrustError("device record has an invalid status")
            if status != "revoked":
                continue
            raw_statement = record.get("revocation_statement")
            signature = record.get("revocation_signature")
            revoker = record.get("revoked_by_device_id")
            if not isinstance(raw_statement, str) or not isinstance(signature, str):
                raise VpsTrustError("revoked device has no signed revocation evidence")
            try:
                statement = json.loads(raw_statement)
            except ValueError:
                raise VpsTrustError("device revocation statement is malformed") from None
            if canonical_json_bytes(statement).decode("utf-8") != raw_statement:
                raise VpsTrustError("device revocation statement is not canonical")
            if revoker != self.config.root_device_id:
                raise VpsTrustError("device revocation was not signed by the root device")
            if revoker not in trusted:
                raise VpsTrustError("device revocation signer is not trusted")
            checked = verify_revocation(statement, signature, trusted[revoker])
            if (
                checked["vault_id"] != self.config.vault_id
                or checked["device_id"] != device_id
                or checked["revoked_by_device_id"] != revoker
            ):
                raise VpsTrustError("device record does not match its signed revocation")
            revocations[device_id] = checked
            revocation_records[device_id] = {
                "statement": raw_statement,
                "signature": signature,
            }

        state = self._read_state() if state is None else state
        pending = state.get("pending_revoke") if allow_pending else None
        pending_evidence = None if pending is None else {
            key: pending[key] for key in ("statement", "signature")}
        if pending is not None:
            found = revocation_records.get(pending["device_id"])
            if found is not None and found != pending_evidence:
                raise VpsTrustError("recovery_required: VPS returned conflicting revocation evidence")
            revocations[pending["device_id"]] = self._evidence(pending["device_id"], pending_evidence)
        pinned = state.get("revocations", {})
        if not isinstance(pinned, dict):
            raise VpsTrustError("local VPS sync revocation state is malformed")
        for device_id, evidence in pinned.items():
            if (not isinstance(evidence, dict) or set(evidence) != {"statement", "signature"}
                    or not all(isinstance(value, str) for value in evidence.values())):
                raise VpsTrustError("local VPS sync revocation state is malformed")
            if (pending is not None and device_id == pending["device_id"]
                    and evidence == pending_evidence and device_id not in revocation_records):
                continue
            if revocation_records.get(device_id) != evidence:
                raise VpsTrustError("VPS omitted or rewrote a previously trusted revocation")
        self._membership_checkpoints = memberships
        self._verified_revocations = revocations
        self._verified_revocation_records = revocation_records
        self._verified_device_statuses = {device_id: record["status"] for device_id, record in by_id.items()}
        return trusted

    @staticmethod
    def _head_id(response: Any) -> str | None:
        if not isinstance(response, dict):
            raise VpsProtocolError("sync server returned an invalid HEAD")
        value = response.get("head_commit_id", response.get("commit_id"))
        if value is None:
            return None
        if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
            raise VpsProtocolError("sync server returned an invalid HEAD commit id")
        return value

    def _anchor(self, state: dict | None = None) -> VerifiedCommit | None:
        state = self._read_state() if state is None else state
        if not set(state) & _ANCHOR_FIELDS:
            return None
        manifest = state.get("manifest")
        if not isinstance(manifest, dict):
            raise VpsTrustError("local VPS sync trust anchor is malformed")
        try:
            if set(state) - {
                "commit_id", "manifest_hash", "sequence", "manifest",
                "revocations", "last_sync_at", "pending_revoke",
            }:
                raise ValueError
            if (
                not isinstance(state["commit_id"], str)
                or not _HASH_RE.fullmatch(state["commit_id"])
                or not isinstance(state["manifest_hash"], str)
                or not _HASH_RE.fullmatch(state["manifest_hash"])
                or isinstance(state["sequence"], bool)
                or not isinstance(state["sequence"], int)
                or state["sequence"] < 1
                or manifest.get("sequence") != state["sequence"]
                or manifest.get("vault_id") != self.config.vault_id
                or compute_manifest_hash(manifest) != state["manifest_hash"]
            ):
                raise ValueError
            return VerifiedCommit(
                commit_id=state["commit_id"],
                manifest_hash=state["manifest_hash"],
                vault_id=manifest["vault_id"],
                sequence=state["sequence"],
                parent_commit_id=manifest["parent_commit_id"],
                parent_manifest_hash=manifest["parent_manifest_hash"],
                ciphertext_sha256=manifest["ciphertext_sha256"],
                author_device_id=manifest["author_device_id"],
                timestamp=manifest["timestamp"],
                manifest=manifest,
            )
        except (KeyError, TypeError, ValueError, KK2Error):
            raise VpsTrustError("local VPS sync trust anchor is malformed") from None

    @staticmethod
    def _record_matches(record: Any, verified: VerifiedCommit) -> None:
        expected = {
            "commit_id": verified.commit_id,
            "sequence": verified.sequence,
            "parent_commit_id": verified.parent_commit_id,
            "manifest_hash": verified.manifest_hash,
            "author_device_id": verified.author_device_id,
        }
        if (not isinstance(record, dict) or type(record.get("sequence")) is not int
                or any(key not in record or record[key] != value for key, value in expected.items())):
            raise VpsTrustError("VPS commit metadata does not match its signed envelope")

    def _verify_record(self, record: dict, trusted_keys: dict[str, bytes], *, snapshot=None) -> VerifiedCommit:
        blob = _wire_bytes(record.get("commit_blob"), label="commit blob", maximum=32 * 1024)
        try:
            raw = json.loads(blob)
            author = raw["manifest"]["author_device_id"]
            if not isinstance(author, str):
                raise ValueError
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            raise VpsTrustError("VPS commit envelope is malformed") from None
        public_key = trusted_keys.get(author)
        if public_key is None:
            raise VpsTrustError("commit author has no trusted device membership")
        try:
            verified = verify_commit_signature(
                blob, signing_public_key=public_key, snapshot_ciphertext=snapshot,
                expected_vault_id=self.config.vault_id, expected_author_device_id=author,
            )
        except KK2Error:
            raise VpsTrustError("VPS commit or snapshot authentication failed") from None
        self._record_matches(record, verified)
        return verified

    def _require_chain_checkpoints(self, checkpoints: set[tuple]) -> None:
        for membership in self._membership_checkpoints.values():
            checkpoint = (membership["checkpoint_sequence"], membership["checkpoint_commit_id"],
                          membership["checkpoint_manifest_hash"])
            if checkpoint[0] and checkpoint not in checkpoints:
                raise VpsTrustError("device membership checkpoint is not in the commit chain")
        for revocation in self._verified_revocations.values():
            checkpoint = (revocation["checkpoint_sequence"], revocation["checkpoint_commit_id"],
                          revocation["checkpoint_manifest_hash"])
            if checkpoint[0] and checkpoint not in checkpoints:
                raise VpsTrustError("device revocation checkpoint is not in the commit chain")
        if self.config.trusted_checkpoint_sequence and (
                self.config.trusted_checkpoint_sequence, self.config.trusted_checkpoint_commit_id,
                self.config.trusted_checkpoint_manifest_hash) not in checkpoints:
            raise VpsTrustError("VPS chain does not contain the signed onboarding checkpoint")

    @staticmethod
    def _history_budget(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise VpsSyncError("VPS history verification timed out")

    @_serialized
    def _verified_head(self, *, allow_pending=False) -> tuple[VerifiedCommit | None, dict | None]:
        # No retained trust cache: every operation refreshes device membership,
        # revocations and signed history. Pagination bounds memory and requests.
        deadline = time.monotonic() + self.max_history_seconds
        for _ in range(self.max_retries):
            try:
                return self._verify_advertised_head(deadline, allow_pending=allow_pending)
            except VpsConflictError:
                self._history_budget(deadline)
        raise VpsSyncError("VPS HEAD kept changing during history verification")

    def _verify_advertised_head(self, deadline: float, *, allow_pending=False) -> tuple[VerifiedCommit | None, dict | None]:
        self._history_budget(deadline)
        state = self._read_state()
        if state.get("pending_revoke") is not None and not allow_pending:
            raise VpsSyncError("recovery_required: resume the pending VPS device revocation before syncing")
        anchor = self._anchor(state)
        advertised = self.client.get_head(self.config.vault_id)
        head_id = self._head_id(advertised)
        self._history_budget(deadline)
        trusted_keys = self._trusted_device_keys(state, allow_pending=allow_pending)
        self._history_budget(deadline)
        if head_id is None:
            if advertised.get("sequence") is not None or advertised.get("manifest_hash") is not None:
                raise VpsProtocolError("sync server returned inconsistent empty HEAD metadata")
            if anchor is not None:
                raise VpsTrustError("VPS omitted a previously trusted commit chain")
            self._require_chain_checkpoints(set())
            self._last_chain_checkpoints = set()
            self._last_chain_authors = {}
            return None, None

        head_record = self.client.get_commit(self.config.vault_id, head_id)
        if not isinstance(head_record, dict):
            raise VpsProtocolError("sync server returned an invalid commit")
        snapshot = _wire_bytes(head_record.get("snapshot_ciphertext"),
                               label="snapshot ciphertext", maximum=24 * 1024 * 1024)
        head = self._verify_record(head_record, trusted_keys, snapshot=snapshot)
        if (type(advertised.get("sequence")) is not int or advertised["sequence"] != head.sequence
                or advertised.get("manifest_hash") != head.manifest_hash):
            raise VpsTrustError("VPS HEAD metadata does not match its signed envelope")
        # Keep only the signed envelope while traversing history; the full
        # base64 ciphertext response must not survive alongside decoded bytes.
        head_record = {key: value for key, value in head_record.items() if key != "snapshot_ciphertext"}
        if head.commit_id != head_id or head.sequence > MAX_CHAIN_COMMITS:
            raise VpsTrustError("VPS HEAD is misaddressed or its history is too long")
        self._history_budget(deadline)
        previous = None
        checkpoints: set[tuple] = set()
        identities: set[str] = set()
        authors: dict[str, list[int]] = {}
        after = 0
        include_commit = True
        include_snapshot = False
        while after < head.sequence:
            self._history_budget(deadline)
            try:
                page = self.client.list_commits(self.config.vault_id, after_sequence=after,
                                               limit=HISTORY_PAGE_SIZE, include_commit=include_commit)
            except VpsBadRequestError:
                if not include_commit:
                    raise
                # Released relays reject unknown query fields (36df576). One
                # compatibility retry removes only the optional batching hint.
                include_commit = False
                self._history_budget(deadline)
                page = self.client.list_commits(self.config.vault_id, after_sequence=after,
                                               limit=HISTORY_PAGE_SIZE)
            self._history_budget(deadline)
            records = page.get("commits") if isinstance(page, dict) else None
            if not isinstance(records, list) or not records or len(records) > HISTORY_PAGE_SIZE:
                raise VpsTrustError("VPS commit history is incomplete or malformed")
            if page.get("head_commit_id") != head_id:
                raise VpsConflictError("VPS HEAD changed while reading history")
            for record in records:
                self._history_budget(deadline)
                if (not isinstance(record, dict) or type(record.get("sequence")) is not int
                        or record["sequence"] != after + 1 or record["sequence"] > head.sequence
                        or not isinstance(record.get("commit_id"), str)
                        or not _HASH_RE.fullmatch(record["commit_id"])
                        or record["commit_id"] in identities):
                    raise VpsTrustError("VPS commit history is unordered, duplicated or has gaps")
                identities.add(record["commit_id"])
                if record["sequence"] == head.sequence:
                    verified = head
                    self._record_matches(record, verified)
                    if "commit_blob" in record and record["commit_blob"] != head_record["commit_blob"]:
                        raise VpsTrustError("VPS history rewrote the advertised HEAD envelope")
                else:
                    signed = record
                    if "commit_blob" not in record:
                        # Earlier relays return metadata-only pages and may
                        # ignore snapshot=0, returning a bounded full record.
                        try:
                            signed = self.client.get_commit(self.config.vault_id, record["commit_id"],
                                                            include_snapshot=include_snapshot)
                        except VpsBadRequestError:
                            if include_snapshot:
                                raise
                            include_snapshot = True
                            self._history_budget(deadline)
                            signed = self.client.get_commit(self.config.vault_id, record["commit_id"])
                        self._history_budget(deadline)
                        if not isinstance(signed, dict):
                            raise VpsProtocolError("sync server returned an invalid commit")
                    verified = self._verify_record(signed, trusted_keys)
                    self._record_matches(record, verified)
                    signed = None
                if previous is None:
                    if verified.sequence != 1 or verified.parent_commit_id is not None or verified.parent_manifest_hash is not None:
                        raise VpsTrustError("VPS did not provide a complete chain to genesis")
                elif (verified.sequence != previous.sequence + 1
                      or verified.parent_commit_id != previous.commit_id
                      or verified.parent_manifest_hash != previous.manifest_hash):
                    raise VpsTrustError("VPS commit chain does not extend the trusted anchor")
                membership = self._membership_checkpoints.get(verified.author_device_id)
                admission = 0 if verified.author_device_id == self.config.root_device_id else (
                    None if membership is None else membership["checkpoint_sequence"])
                if admission is None or verified.sequence <= admission:
                    raise VpsTrustError("device authored a commit before it was admitted")
                revocation = self._verified_revocations.get(verified.author_device_id)
                if revocation is not None and verified.sequence > revocation["checkpoint_sequence"]:
                    raise VpsTrustError("revoked device authored a commit after its revocation")
                checkpoints.add((verified.sequence, verified.commit_id, verified.manifest_hash))
                authors.setdefault(verified.author_device_id, []).append(verified.sequence)
                previous, after = verified, verified.sequence
        if previous is None or previous.commit_id != head_id:
            raise VpsTrustError("VPS HEAD verification did not reach the advertised commit")
        if anchor is not None and (anchor.sequence, anchor.commit_id, anchor.manifest_hash) not in checkpoints:
            raise VpsTrustError("VPS HEAD does not descend from the local trust anchor")
        self._require_chain_checkpoints(checkpoints)
        self._last_chain_checkpoints = checkpoints
        self._last_chain_authors = authors
        try:
            plaintext = open_snapshot(snapshot, vault_key=self.vault_key, expected_vault_id=self.config.vault_id)
            payload = _decode_json(plaintext)
            if (not isinstance(payload, dict) or set(payload) != {"schema_version", "entries", "tombstones"}
                    or type(payload["schema_version"]) is not int):
                raise VpsTrustError("latest VPS snapshot has invalid fields")
            validate_snapshot_payload(payload)
        except (KK2Error, VaultValidationError, VpsProtocolError, ValueError, UnicodeError, RecursionError):
            raise VpsTrustError("latest VPS snapshot failed authenticated validation") from None
        self._history_budget(deadline)
        return head, payload

    @_serialized
    def verified_head(self) -> VerifiedCommit | None:
        """Verify the remote chain and return its trusted HEAD metadata."""
        verified, _payload = self._verified_head()
        self._remember_observed_revocations(verified)
        return verified

    def _remember_observed_revocations(self, verified):
        # A successful inspection must not forget a revocation it has seen.
        # Ordinary unchanged status/head reads still perform no state writes.
        # The anchor tracks verified ancestry, independently of local payload
        # application (refresh_trust_anchor already has that same contract).
        if self._read_state().get("revocations", {}) != self._verified_revocation_records:
            self._write_state(verified)

    @_serialized
    def require_checkpoint(
        self, sequence: int, commit_id: str | None, manifest_hash: str | None
    ) -> VerifiedCommit | None:
        """Verify HEAD and require one exact prior checkpoint in its ancestry."""
        if type(sequence) is not int or sequence < 0:
            raise VpsTrustError("checkpoint sequence must be a non-negative integer")
        if sequence == 0:
            if commit_id is not None or manifest_hash is not None:
                raise VpsTrustError("empty checkpoint contains unexpected hashes")
        elif (not isinstance(commit_id, str) or not _HASH_RE.fullmatch(commit_id)
              or not isinstance(manifest_hash, str) or not _HASH_RE.fullmatch(manifest_hash)):
            raise VpsTrustError("checkpoint hashes are invalid")
        verified, _payload = self._verified_head()
        if sequence == 0:
            self._remember_observed_revocations(verified)
            return verified
        required = (sequence, commit_id, manifest_hash)
        if required not in getattr(self, "_last_chain_checkpoints", set()):
            raise VpsTrustError("VPS chain does not contain the invitation checkpoint")
        self._remember_observed_revocations(verified)
        return verified

    @_serialized
    def refresh_trust_anchor(self) -> VerifiedCommit | None:
        """Verify current device/revocation state and persist the resulting anchor."""
        verified, _payload = self._verified_head()
        self._write_state(verified)
        return verified

    @_serialized
    def revoke_device(self, device_id: str) -> None:
        """Durably prepare, publish and confirm one exact signed revocation.

        A pending intent survives an unknown HTTP outcome or a process crash.
        Resume may advance the transport CAS after proving that the original
        signed cutoff still excludes every later commit by the target device.
        """
        if self.config.device_id != self.config.root_device_id:
            raise VpsSyncError("only the pinned root device can revoke another device")
        if (not isinstance(device_id, str) or not _ID_RE.fullmatch(device_id)
                or device_id in (self.config.device_id, self.config.root_device_id)):
            raise VpsSyncError("invalid revocation target; the root device cannot be revoked")
        state = self._read_state()
        pending = state.get("pending_revoke")
        if pending is not None and pending["device_id"] != device_id:
            raise VpsSyncError("recovery_required: another VPS device revocation is pending")
        confirmed = False
        try:
            head, _payload = self._verified_head(allow_pending=pending is not None)
            if pending is None:
                if device_id in self._verified_revocation_records:
                    confirmed = True
                    self._write_state(head)
                    private_files.fsync_parent(self.paths.root)
                    return
                if self._verified_device_statuses.get(device_id) != "active":
                    raise VpsSyncError("revocation target is not a trusted active device")
                statement = make_revocation_statement(
                    vault_id=self.config.vault_id, device_id=device_id,
                    revoked_by_device_id=self.config.device_id,
                    checkpoint_commit_id=None if head is None else head.commit_id,
                    checkpoint_manifest_hash=None if head is None else head.manifest_hash,
                    checkpoint_sequence=0 if head is None else head.sequence,
                )
                pending = {"device_id": device_id,
                           "statement": canonical_json_bytes(statement).decode("utf-8"),
                           "signature": sign_revocation(statement, self.signing_private_key)}
                try:
                    self._write_state(head, pending_revoke=pending)
                except Exception:
                    # A published intent is not a published remote revocation.
                    # Preserve it for resume, but never POST after uncertain fsync.
                    raise VpsRevokePreparationError(
                        "VPS revocation intent durability is unconfirmed; no request was sent; retry to resume"
                    ) from None
            evidence = {key: pending[key] for key in ("statement", "signature")}
            for attempt in range(self.max_retries):
                if self._verified_revocation_records.get(device_id) == evidence:
                    confirmed = True
                    self._write_state(head, pending_revoke=None)
                    return
                if attempt:
                    head, _payload = self._verified_head(allow_pending=True)
                    if self._verified_revocation_records.get(device_id) == evidence:
                        confirmed = True
                        self._write_state(head, pending_revoke=None)
                        return
                try:
                    # A previous process may have published pending but failed
                    # its directory fsync. Confirm durability before any retry.
                    try:
                        private_files.fsync_parent(self.paths.root)
                    except OSError:
                        if confirmed:
                            raise
                        raise VpsRevokePreparationError(
                            "VPS revocation intent durability is unconfirmed; no request was sent"
                        ) from None
                    self.client.revoke_device(
                        self.config.vault_id, device_id,
                        expected_head=None if head is None else head.commit_id,
                        revocation_statement=evidence["statement"],
                        revocation_signature=evidence["signature"],
                    )
                except VpsConflictError:
                    # Neither CAS failure nor already_revoked confirms the
                    # statement. The next iteration obtains a complete proof.
                    continue
                # ACK is not signed confirmation. The already durable pending
                # intent closes the crash window and blocks ordinary sync.
                head, _payload = self._verified_head(allow_pending=True)
                if self._verified_revocation_records.get(device_id) != evidence:
                    raise VpsTrustError("recovery_required: VPS omitted the acknowledged revocation")
                confirmed = True
                self._write_state(head, pending_revoke=None)
                return
            raise VpsSyncError("recovery_required: VPS revocation conflicts require a retry")
        except VpsRevokePreparationError:
            raise
        except Exception:
            if confirmed:
                raise VpsSyncCommitError(
                    "VPS revocation was verified; local persistence is incomplete; recovery_required"
                ) from None
            if pending is not None:
                raise VpsSyncError(
                    "VPS revocation is unconfirmed; recovery_required: retry the same device revocation"
                ) from None
            raise

    def _apply_payload(self, payload: dict, *, prepared: tuple[dict, str] | None = None) -> int:
        try:
            remote_entries, remote_tombstones = validate_snapshot_payload(payload)
        except VaultValidationError as exc:
            raise VpsTrustError("VPS snapshot metadata is invalid") from exc
        remote_secrets = {
            item["id"]: (item.get("_secret"), item.get("_secret_passphrase"))
            for item in payload["entries"]
        }
        for _ in range(self.max_retries):
            local_payload, revision = prepared or prepare_snapshot_payload(self.store, self.backend)
            prepared = None
            local_entries, local_tombstones = validate_snapshot_payload(local_payload)
            local_secrets = {
                item["id"]: (item.get("_secret"), item.get("_secret_passphrase"))
                for item in local_payload["entries"]
            }
            result = merge(local_entries, local_tombstones, remote_entries, remote_tombstones)
            # Metadata timestamps have one-second precision, so two devices can
            # rotate only the secret while retaining byte-identical metadata.
            # Resolve that otherwise-invisible tie with a digest of the secret
            # pair.  The digest never leaves this process and gives every peer
            # the same winner, preventing endless alternating commits.
            local_by_id = {entry.id: entry for entry in local_entries}
            remote_by_id = {entry.id: entry for entry in remote_entries}
            live_ids = {entry.id for entry in result.entries}
            for entry_id in live_ids & local_by_id.keys() & remote_by_id.keys():
                if local_by_id[entry_id].to_dict() != remote_by_id[entry_id].to_dict():
                    continue
                local_pair = local_secrets[entry_id]
                remote_pair = remote_secrets[entry_id]
                local_digest = hashlib.sha256(
                    canonical_json_bytes(list(local_pair))
                ).digest()
                remote_digest = hashlib.sha256(
                    canonical_json_bytes(list(remote_pair))
                ).digest()
                if remote_digest > local_digest:
                    result.remote_win_ids.add(entry_id)
                    result.changed = True
            if not result.changed:
                return 0
            writes: dict[str, str] = {}
            deletes = {
                account
                for entry_id in result.secret_delete_ids
                for account in (entry_id, entry_id + ":passphrase")
            }
            for entry_id in result.remote_win_ids:
                if entry_id not in remote_secrets:
                    raise VpsTrustError("VPS snapshot is missing an authenticated secret slot")
                for account, value in zip((entry_id, entry_id + ":passphrase"), remote_secrets[entry_id]):
                    if value is None:
                        deletes.add(account)
                    else:
                        writes[account] = value
            try:
                expected_accounts = {}
                for account in set(writes) | deletes:
                    entry_id = account.removesuffix(":passphrase")
                    pair = local_secrets.get(entry_id, (None, None))
                    value = pair[1 if account.endswith(":passphrase") else 0]
                    expected_accounts[account] = ({"present": False} if value is None
                                                  else {"present": True, "value": value})
                VaultService(self.store, self.backend).apply_snapshot(
                    result.entries,
                    result.tombstones,
                    secret_writes=writes,
                    secret_deletes=deletes,
                    expected_revision=revision,
                    expected_accounts=expected_accounts,
                )
            except ConcurrentMutation:
                continue
            # Name disambiguation or a new tombstone may change metadata even
            # without a remote secret winner. Report an actual application.
            return max(1, len(result.remote_win_ids) + len(result.secret_delete_ids))
        raise VpsSyncError("local vault changed repeatedly while VPS sync was applying")

    @_serialized
    def pull(self) -> int:
        verified, payload = self._verified_head()
        if verified is None or payload is None:
            self._write_state(verified)
            return 0
        changed = self._apply_payload(payload)
        try:
            self._write_state(verified)
        except Exception:
            if changed:
                raise VpsSyncCommitError("VPS snapshot was applied; local trust state update failed") from None
            raise
        return changed

    @_serialized
    def push(self) -> int:
        pulled_total = 0
        for _ in range(self.max_retries):
            parent, remote_payload = self._verified_head()
            if self.config.device_id in getattr(self, "_verified_revocations", {}):
                raise VpsTrustError("this device has been revoked and cannot publish commits")
            if parent is not None and parent.sequence >= MAX_CHAIN_COMMITS:
                raise VpsSyncError("VPS history reached the supported commit limit")
            prepared = prepare_snapshot_payload(self.store, self.backend)
            if parent is not None and remote_payload is not None:
                changed = self._apply_payload(remote_payload, prepared=prepared)
                pulled_total += changed
                try:
                    self._write_state(parent)
                except Exception:
                    if pulled_total:
                        raise VpsSyncCommitError("VPS snapshot was applied; local trust state update failed") from None
                    raise
                if changed:
                    prepared = prepare_snapshot_payload(self.store, self.backend)
            payload = prepared[0]
            if parent is None and not payload["entries"] and not payload["tombstones"]:
                self._write_state(None)
                return pulled_total
            if remote_payload is not None and content_hash(remote_payload) == content_hash(payload):
                return pulled_total
            snapshot = seal_snapshot(
                canonical_json_bytes(payload), vault_key=self.vault_key, vault_id=self.config.vault_id
            )
            commit = build_signed_commit(
                snapshot,
                vault_id=self.config.vault_id,
                sequence=1 if parent is None else parent.sequence + 1,
                parent_commit_id=None if parent is None else parent.commit_id,
                parent_manifest_hash=None if parent is None else parent.manifest_hash,
                author_device_id=self.config.device_id,
                signing_private_key=self.signing_private_key,
            )
            own = verify_commit_signature(
                commit,
                signing_public_key=_decode_b64(
                    self.config.sign_public_key, label="device signing key", length=32
                ),
                snapshot_ciphertext=snapshot,
                expected_vault_id=self.config.vault_id,
                expected_author_device_id=self.config.device_id,
            )
            try:
                receipt = self.client.append_commit(
                    self.config.vault_id,
                    commit_blob=commit,
                    snapshot_ciphertext=snapshot,
                    expected_parent=None if parent is None else parent.commit_id,
                )
            except VpsConflictError:
                continue
            self._last_chain_checkpoints.add((own.sequence, own.commit_id, own.manifest_hash))
            try:
                if not isinstance(receipt, dict) or receipt.get("commit_id") != own.commit_id:
                    raise VpsProtocolError("VPS returned an inconsistent append receipt")
                self._write_state(own)
            except Exception:
                # A successful append response confirms the remote side effect.
                # Retrying automatically could publish the same change again.
                raise VpsSyncCommitError("VPS accepted the commit; local confirmation failed") from None
            return pulled_total + 1
        raise VpsSyncError("VPS push exceeded retries because another device kept winning CAS")

    @_serialized
    def status(self) -> VpsSyncStatus:
        local = self._anchor()
        remote, payload = self._verified_head()
        current = build_snapshot_payload(self.store, self.backend)
        self._remember_observed_revocations(remote)
        return VpsSyncStatus(
            remote_sequence=None if remote is None else remote.sequence,
            local_sequence=None if local is None else local.sequence,
            dirty=(remote is None and bool(current["entries"] or current["tombstones"]))
            or (payload is not None and content_hash(payload) != content_hash(current)),
        )


def new_device_token() -> str:
    return secrets.token_urlsafe(32)


def invite_secret() -> str:
    """Return the exact high-entropy text that a claimant sends to syncd."""
    return secrets.token_urlsafe(32)


def invite_secret_hash(secret: str) -> str:
    if not isinstance(secret, str) or len(secret) < 40 or any(ch.isspace() for ch in secret):
        raise VpsTrustError("invite secret must be a high-entropy token")
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


__all__ = [
    "MEMBERSHIP_PROFILE", "REVOCATION_PROFILE", "SYNC_VPS_SIGNING_PRIVATE",
    "SYNC_VPS_TOKEN", "SYNC_VPS_VAULT_KEY", "SYNC_VPS_WRAPPING_PRIVATE",
    "VpsSyncConfig", "VpsSyncEngine", "VpsSyncError", "VpsSyncCommitError", "VpsSyncStatus",
    "VpsTrustError", "invite_secret", "invite_secret_hash", "load_vps_config",
    "make_membership_statement", "make_revocation_statement", "new_device_token",
    "save_vps_config", "sign_membership", "sign_revocation", "verify_membership",
    "verify_revocation",
]
