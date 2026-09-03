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
import re
import secrets
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from keys_keeper.backend import KeychainBackend, KeychainError
from keys_keeper.models import ValidationError as VaultValidationError, validate_snapshot_payload
from keys_keeper.paths import Paths
from keys_keeper.secure_io import SecureFileError, read_secure_text, replace_secure_text
from keys_keeper.service import ConcurrentMutation, VaultService
from keys_keeper.store import MetadataStore
from keys_keeper.sync import build_snapshot_payload, content_hash, merge
from keys_keeper.sync_protocol_v2 import (
    KK2Error,
    VerifiedCommit,
    build_signed_commit,
    canonical_json_bytes,
    compute_manifest_hash,
    open_snapshot,
    seal_snapshot,
    verify_commit,
    verify_commit_signature,
)
from keys_keeper.sync_vps_client import VpsConflictError, VpsProtocolError, VpsTransportError


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


class VpsSyncError(VpsTransportError):
    """A safe, user-facing VPS sync failure."""


class VpsTrustError(VpsSyncError):
    """The relay returned data that does not extend the local trust anchor."""


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
        VpsSyncClient(base_url=self.endpoint, proxy=self.proxy)
        for label in ("vault_id", "device_id", "root_device_id"):
            value = getattr(self, label)
            if not _ID_RE.fullmatch(value):
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
        raw = json.loads(read_secure_text(sidecar, missing_ok=False).text)
        if not isinstance(raw, dict) or set(raw) != set(VpsSyncConfig.__annotations__):
            raise ValueError
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
    ) -> None:
        config.validate()
        if config.status != "active":
            raise VpsSyncError("this device is not approved yet; run `keys sync vps finish`")
        if len(vault_key) != 32 or len(signing_private_key) != 32:
            raise VpsTrustError("invalid local VPS sync key material")
        self.client = client
        self.config = config
        self.store = store
        self.backend = backend
        self.vault_key = vault_key
        self.signing_private_key = signing_private_key
        self.paths = paths
        self.max_retries = max_retries

    def _read_state(self) -> dict[str, Any]:
        try:
            state = read_secure_text(_state_sidecar(self.paths), missing_ok=True)
            if state.identity is None:
                return {}
            raw = json.loads(state.text)
        except (ValueError, OSError, SecureFileError) as exc:
            raise VpsTrustError("local VPS sync trust state is unreadable or malformed") from exc
        if not isinstance(raw, dict):
            raise VpsTrustError("local VPS sync trust state is malformed")
        return raw

    def _write_state(self, verified: VerifiedCommit) -> None:
        state = {
            "commit_id": verified.commit_id,
            "manifest_hash": verified.manifest_hash,
            "sequence": verified.sequence,
            "manifest": dict(verified.manifest),
            "revocations": getattr(self, "_verified_revocation_records", {}),
            "last_sync_at": _utc_now(),
        }
        self.paths.ensure()
        previous = read_secure_text(_state_sidecar(self.paths), missing_ok=True)
        replace_secure_text(previous, json.dumps(state, sort_keys=True, indent=2) + "\n")

    def _trusted_device_keys(self) -> dict[str, bytes]:
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

        pinned = self._read_state().get("revocations", {})
        if not isinstance(pinned, dict):
            raise VpsTrustError("local VPS sync revocation state is malformed")
        for device_id, evidence in pinned.items():
            if revocation_records.get(device_id) != evidence:
                raise VpsTrustError("VPS omitted or rewrote a previously trusted revocation")
        self._membership_checkpoints = memberships
        self._verified_revocations = revocations
        self._verified_revocation_records = revocation_records
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

    def _fetch_commit(self, commit_id: str) -> tuple[bytes, bytes]:
        response = self.client.get_commit(self.config.vault_id, commit_id)
        if not isinstance(response, dict):
            raise VpsProtocolError("sync server returned an invalid commit")
        return (
            _wire_bytes(response.get("commit_blob"), label="commit blob", maximum=32 * 1024),
            _wire_bytes(
                response.get("snapshot_ciphertext"),
                label="snapshot ciphertext",
                maximum=24 * 1024 * 1024,
            ),
        )

    def _anchor(self) -> VerifiedCommit | None:
        state = self._read_state()
        manifest = state.get("manifest")
        if not isinstance(manifest, dict):
            return None
        try:
            if set(state) - {
                "commit_id", "manifest_hash", "sequence", "manifest",
                "revocations", "last_sync_at",
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

    def _verified_head(self) -> tuple[VerifiedCommit | None, dict | None]:
        head_id = self._head_id(self.client.get_head(self.config.vault_id))
        if head_id is None:
            if self._anchor() is not None:
                raise VpsTrustError("VPS omitted a previously trusted commit chain")
            return None, None
        trusted_keys = self._trusted_device_keys()
        anchor = self._anchor()
        reverse: list[tuple[bytes, bytes, VerifiedCommit]] = []
        cursor = head_id
        seen: set[str] = set()
        while True:
            if cursor in seen or len(seen) >= 10_000:
                raise VpsTrustError("VPS commit chain is cyclic or too long")
            seen.add(cursor)
            commit_blob, snapshot = self._fetch_commit(cursor)
            try:
                raw = json.loads(commit_blob)
                author = raw["manifest"]["author_device_id"]
            except (ValueError, KeyError, TypeError):
                raise VpsTrustError("VPS commit envelope is malformed") from None
            public_key = trusted_keys.get(author)
            if public_key is None:
                raise VpsTrustError("commit author has no trusted device membership")
            try:
                verified = verify_commit_signature(
                    commit_blob,
                    signing_public_key=public_key,
                    snapshot_ciphertext=snapshot,
                    expected_vault_id=self.config.vault_id,
                    expected_author_device_id=author,
                )
            except KK2Error as exc:
                raise VpsTrustError("VPS commit or snapshot authentication failed") from exc
            if verified.commit_id != cursor:
                raise VpsTrustError("commit address does not match its signed id")
            reverse.append((commit_blob, snapshot, verified))
            if verified.parent_commit_id is None:
                break
            cursor = verified.parent_commit_id

        previous = None
        if reverse and reverse[-1][2].sequence != 1:
            raise VpsTrustError("VPS did not provide a complete chain to genesis")
        checkpoints = {
            (candidate.sequence, candidate.commit_id, candidate.manifest_hash)
            for _blob, _snapshot, candidate in reverse
        }
        for device_id, membership in self._membership_checkpoints.items():
            checkpoint = (
                membership["checkpoint_sequence"],
                membership["checkpoint_commit_id"],
                membership["checkpoint_manifest_hash"],
            )
            if checkpoint[0] and checkpoint not in checkpoints:
                raise VpsTrustError("device membership checkpoint is not in the commit chain")
            approver = membership["approved_by_device_id"]
            approver_membership = self._membership_checkpoints.get(approver)
            if approver != self.config.root_device_id and (
                approver_membership is None
                or membership["checkpoint_sequence"]
                < approver_membership["checkpoint_sequence"]
            ):
                raise VpsTrustError("device approved another member before it was admitted")
            approver_revocation = self._verified_revocations.get(approver)
            if approver_revocation is not None and (
                membership["checkpoint_sequence"]
                > approver_revocation["checkpoint_sequence"]
            ):
                raise VpsTrustError("revoked device approved a later membership")
        for commit_blob, snapshot, _candidate in reversed(reverse):
            author = _candidate.author_device_id
            membership = self._membership_checkpoints.get(author)
            if author == self.config.root_device_id:
                membership_checkpoint = (0, None, None)
            elif membership is None:
                raise VpsTrustError("commit author has no signed membership checkpoint")
            else:
                membership_checkpoint = (
                    membership["checkpoint_sequence"],
                    membership["checkpoint_commit_id"],
                    membership["checkpoint_manifest_hash"],
                )
            if membership_checkpoint[0] and membership_checkpoint not in checkpoints:
                raise VpsTrustError("device membership checkpoint is not in the commit chain")
            if _candidate.sequence <= membership_checkpoint[0]:
                raise VpsTrustError("device authored a commit before it was admitted")
            revocation = self._verified_revocations.get(author)
            if revocation is not None and _candidate.sequence > revocation["checkpoint_sequence"]:
                raise VpsTrustError("revoked device authored a commit after its revocation")
            try:
                previous = verify_commit(
                    commit_blob,
                    signing_public_key=trusted_keys[author],
                    snapshot_ciphertext=snapshot,
                    expected_vault_id=self.config.vault_id,
                    expected_author_device_id=author,
                    previous=previous,
                    require_genesis=previous is None,
                )
            except KK2Error as exc:
                raise VpsTrustError("VPS commit chain does not extend the trusted anchor") from exc
        if previous is None:
            raise VpsTrustError("VPS returned an empty commit chain")
        if previous.commit_id != head_id:
            raise VpsTrustError("VPS HEAD verification did not reach the advertised commit")
        if anchor is not None and (
            anchor.sequence, anchor.commit_id, anchor.manifest_hash
        ) not in checkpoints:
            raise VpsTrustError("VPS HEAD does not descend from the local trust anchor")
        for device_id, revocation in self._verified_revocations.items():
            checkpoint = (
                revocation["checkpoint_sequence"],
                revocation["checkpoint_commit_id"],
                revocation["checkpoint_manifest_hash"],
            )
            if checkpoint[0] and checkpoint not in checkpoints:
                raise VpsTrustError("device revocation checkpoint is not in the commit chain")
            revoker = revocation["revoked_by_device_id"]
            revoker_membership = self._membership_checkpoints.get(revoker)
            if revoker != self.config.root_device_id and (
                revoker_membership is None
                or revocation["checkpoint_sequence"] <= revoker_membership["checkpoint_sequence"]
            ):
                raise VpsTrustError("device signed a revocation before it was admitted")
            revoker_revocation = self._verified_revocations.get(revoker)
            if revoker_revocation is not None and (
                revocation["checkpoint_sequence"]
                > revoker_revocation["checkpoint_sequence"]
            ):
                raise VpsTrustError("revoked device signed a later revocation")
        checkpoint_sequence = self.config.trusted_checkpoint_sequence
        if checkpoint_sequence:
            required = (
                checkpoint_sequence,
                self.config.trusted_checkpoint_commit_id,
                self.config.trusted_checkpoint_manifest_hash,
            )
            if required not in checkpoints:
                raise VpsTrustError("VPS chain does not contain the signed onboarding checkpoint")
        self._last_chain_checkpoints = checkpoints
        head_snapshot = reverse[0][1]
        try:
            plaintext = open_snapshot(
                head_snapshot, vault_key=self.vault_key, expected_vault_id=self.config.vault_id
            )
            payload = json.loads(plaintext)
            validate_snapshot_payload(payload)
        except (KK2Error, VaultValidationError, ValueError, UnicodeDecodeError) as exc:
            raise VpsTrustError("latest VPS snapshot failed authenticated validation") from exc
        return previous, payload

    def verified_head(self) -> VerifiedCommit | None:
        """Verify the remote chain and return its trusted HEAD metadata."""
        verified, _payload = self._verified_head()
        return verified

    def require_checkpoint(
        self, sequence: int, commit_id: str | None, manifest_hash: str | None
    ) -> VerifiedCommit | None:
        """Verify HEAD and require one exact prior checkpoint in its ancestry."""
        verified = self.verified_head()
        if sequence == 0:
            if commit_id is not None or manifest_hash is not None:
                raise VpsTrustError("empty checkpoint contains unexpected hashes")
            return verified
        required = (sequence, commit_id, manifest_hash)
        if required not in getattr(self, "_last_chain_checkpoints", set()):
            raise VpsTrustError("VPS chain does not contain the invitation checkpoint")
        return verified

    def refresh_trust_anchor(self) -> VerifiedCommit | None:
        """Verify current device/revocation state and persist the resulting anchor."""
        verified, _payload = self._verified_head()
        if verified is not None:
            self._write_state(verified)
        return verified

    def _apply_payload(self, payload: dict) -> int:
        try:
            remote_entries, remote_tombstones = validate_snapshot_payload(payload)
        except VaultValidationError as exc:
            raise VpsTrustError("VPS snapshot metadata is invalid") from exc
        remote_secrets = {
            item["id"]: (item.get("_secret"), item.get("_secret_passphrase"))
            for item in payload["entries"]
        }
        for _ in range(self.max_retries):
            local = self.store.snapshot()
            result = merge(local.entries, local.tombstones, remote_entries, remote_tombstones)
            # Metadata timestamps have one-second precision, so two devices can
            # rotate only the secret while retaining byte-identical metadata.
            # Resolve that otherwise-invisible tie with a digest of the secret
            # pair.  The digest never leaves this process and gives every peer
            # the same winner, preventing endless alternating commits.
            local_by_id = {entry.id: entry for entry in local.entries}
            remote_by_id = {entry.id: entry for entry in remote_entries}
            live_ids = {entry.id for entry in result.entries}
            for entry_id in live_ids & local_by_id.keys() & remote_by_id.keys():
                if local_by_id[entry_id].to_dict() != remote_by_id[entry_id].to_dict():
                    continue
                local_pair = []
                for account in (entry_id, entry_id + ":passphrase"):
                    try:
                        local_pair.append(self.backend.get(account).unseal())
                    except KeychainError:
                        local_pair.append(None)
                remote_pair = remote_secrets[entry_id]
                local_digest = hashlib.sha256(
                    canonical_json_bytes([value or "" for value in local_pair])
                ).digest()
                remote_digest = hashlib.sha256(
                    canonical_json_bytes([value or "" for value in remote_pair])
                ).digest()
                if remote_digest > local_digest:
                    result.remote_win_ids.add(entry_id)
                    result.changed = True
            if not result.changed:
                return 0
            writes: dict[str, str] = {}
            for entry_id in result.remote_win_ids:
                if entry_id not in remote_secrets:
                    raise VpsTrustError("VPS snapshot is missing an authenticated secret slot")
                secret, passphrase = remote_secrets[entry_id]
                if secret is not None:
                    writes[entry_id] = secret
                if passphrase is not None:
                    writes[entry_id + ":passphrase"] = passphrase
            deletes = [
                account
                for entry_id in result.secret_delete_ids
                for account in (entry_id, entry_id + ":passphrase")
            ]
            try:
                VaultService(self.store, self.backend).apply_snapshot(
                    result.entries,
                    result.tombstones,
                    secret_writes=writes,
                    secret_deletes=deletes,
                    expected_revision=local.revision,
                )
            except ConcurrentMutation:
                continue
            return len(result.remote_win_ids) + len(result.secret_delete_ids)
        raise VpsSyncError("local vault changed repeatedly while VPS sync was applying")

    def pull(self) -> int:
        verified, payload = self._verified_head()
        if verified is None or payload is None:
            return 0
        changed = self._apply_payload(payload)
        self._write_state(verified)
        return changed

    def push(self) -> int:
        pulled_total = 0
        for _ in range(self.max_retries):
            parent, remote_payload = self._verified_head()
            if self.config.device_id in getattr(self, "_verified_revocations", {}):
                raise VpsTrustError("this device has been revoked and cannot publish commits")
            if parent is not None and remote_payload is not None:
                pulled_total += self._apply_payload(remote_payload)
                self._write_state(parent)
            payload = build_snapshot_payload(self.store, self.backend)
            if parent is None and not payload["entries"] and not payload["tombstones"]:
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
            try:
                self.client.append_commit(
                    self.config.vault_id,
                    commit_blob=commit,
                    snapshot_ciphertext=snapshot,
                    expected_parent=None if parent is None else parent.commit_id,
                )
            except VpsConflictError:
                continue
            own = verify_commit_signature(
                commit,
                signing_public_key=_decode_b64(
                    self.config.sign_public_key, label="device signing key", length=32
                ),
                snapshot_ciphertext=snapshot,
                expected_vault_id=self.config.vault_id,
                expected_author_device_id=self.config.device_id,
            )
            self._write_state(own)
            return pulled_total + 1
        raise VpsSyncError("VPS push exceeded retries because another device kept winning CAS")

    def status(self) -> VpsSyncStatus:
        local = self._anchor()
        remote, payload = self._verified_head()
        current = build_snapshot_payload(self.store, self.backend)
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
    "VpsSyncConfig", "VpsSyncEngine", "VpsSyncError", "VpsSyncStatus",
    "VpsTrustError", "invite_secret", "invite_secret_hash", "load_vps_config",
    "make_membership_statement", "make_revocation_statement", "new_device_token",
    "save_vps_config", "sign_membership", "sign_revocation", "verify_membership",
    "verify_revocation",
]
