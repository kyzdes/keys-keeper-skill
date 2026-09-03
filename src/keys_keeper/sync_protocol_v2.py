"""Zero-knowledge cryptographic primitives for the KK2 sync protocol.

The module deliberately has no storage, network, keychain, or vault access.  A
server can validate a signed commit and its opaque encrypted snapshot with
``verify_commit_signature`` without possessing the vault key.

All wire values are canonical UTF-8 JSON.  Binary fields use unpadded URL-safe
base64 and hashes use lower-case hexadecimal.  The parsers reject alternate
encodings, duplicate keys, unknown fields, and over-sized inputs.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL = "KK2"
SNAPSHOT_PROFILE = "kk2-snapshot-aes256gcm-hkdf-sha256-v1"
COMMIT_PROFILE = "kk2-commit-ed25519-sha256-v1"
DEVICE_WRAP_PROFILE = "kk2-device-wrap-x25519-aes256gcm-v1"
RECOVERY_WRAP_PROFILE = "kk2-recovery-wrap-aes256gcm-hkdf-sha256-v1"

VAULT_KEY_SIZE = 32
RECOVERY_SECRET_SIZE = 32
MAX_SNAPSHOT_PLAINTEXT_SIZE = 16 * 1024 * 1024
MAX_SNAPSHOT_BLOB_SIZE = 24 * 1024 * 1024
MAX_COMMIT_SIZE = 32 * 1024
MAX_KEY_WRAP_SIZE = 16 * 1024
MAX_CONTEXT_SIZE = 1024

_SALT_SIZE = 16
_NONCE_SIZE = 12
_TAG_SIZE = 16
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TIMESTAMP_RE = re.compile(
    r"^(?:19|[2-9][0-9])[0-9]{2}-(?:0[1-9]|1[0-2])-"
    r"(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:"
    r"[0-5][0-9]Z$"
)

_SNAPSHOT_KEY_INFO = b"keys-keeper/KK2/snapshot-key/v1\x00"
_SNAPSHOT_AAD_DOMAIN = b"keys-keeper/KK2/snapshot-aad/v1\x00"
_COMMIT_SIGNATURE_DOMAIN = b"keys-keeper/KK2/commit-signature/v1\x00"
_COMMIT_ID_DOMAIN = b"keys-keeper/KK2/commit-id/v1\x00"
_DEVICE_WRAP_KEY_INFO = b"keys-keeper/KK2/device-wrap-key/v1\x00"
_DEVICE_WRAP_AAD_DOMAIN = b"keys-keeper/KK2/device-wrap-aad/v1\x00"
_RECOVERY_WRAP_KEY_INFO = b"keys-keeper/KK2/recovery-wrap-key/v1\x00"
_RECOVERY_WRAP_AAD_DOMAIN = b"keys-keeper/KK2/recovery-wrap-aad/v1\x00"

_SNAPSHOT_FIELDS = {
    "protocol",
    "format_profile",
    "vault_id",
    "salt",
    "nonce",
    "ciphertext",
}
_MANIFEST_FIELDS = {
    "protocol",
    "format_profile",
    "vault_id",
    "sequence",
    "parent_commit_id",
    "parent_manifest_hash",
    "ciphertext_sha256",
    "author_device_id",
    "timestamp",
}
_COMMIT_FIELDS = {"commit_id", "manifest", "signature"}
_DEVICE_WRAP_FIELDS = {
    "protocol",
    "format_profile",
    "vault_id",
    "recipient_device_id",
    "ephemeral_public_key",
    "context_sha256",
    "salt",
    "nonce",
    "wrapped_vault_key",
}
_RECOVERY_WRAP_FIELDS = {
    "protocol",
    "format_profile",
    "vault_id",
    "salt",
    "nonce",
    "wrapped_vault_key",
}


class KK2Error(RuntimeError):
    """Base class for safe, non-secret KK2 failures."""


class ValidationError(KK2Error):
    """The supplied value is malformed, non-canonical, or too large."""


class AuthenticationError(KK2Error):
    """Authenticated decryption failed."""


class SignatureVerificationError(KK2Error):
    """A commit signature, commit id, or ciphertext binding is invalid."""


class ChainValidationError(KK2Error):
    """A commit does not extend the expected parent."""


class ReplayDetected(ChainValidationError):
    """A commit sequence is not newer than the trusted watermark."""


@dataclass(frozen=True)
class DeviceIdentity:
    """A device's independent signing and key-agreement identities."""

    device_id: str
    signing_private_key: Ed25519PrivateKey = field(repr=False)
    agreement_private_key: X25519PrivateKey = field(repr=False)

    @property
    def signing_public_key(self) -> Ed25519PublicKey:
        return self.signing_private_key.public_key()

    @property
    def agreement_public_key(self) -> X25519PublicKey:
        return self.agreement_private_key.public_key()

    @property
    def signing_public_bytes(self) -> bytes:
        return _raw_public_bytes(self.signing_public_key)

    @property
    def agreement_public_bytes(self) -> bytes:
        return _raw_public_bytes(self.agreement_public_key)

    @property
    def signing_private_bytes(self) -> bytes:
        return self.signing_private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @property
    def agreement_private_bytes(self) -> bytes:
        return self.agreement_private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )


@dataclass(frozen=True)
class VerifiedCommit:
    """Validated commit metadata safe for a server to persist as its HEAD."""

    commit_id: str
    manifest_hash: str
    vault_id: str
    sequence: int
    parent_commit_id: str | None
    parent_manifest_hash: str | None
    ciphertext_sha256: str
    author_device_id: str
    timestamp: str
    manifest: Mapping[str, Any] = field(repr=False)


def _validate_json_value(value: Any, *, path: str = "$", depth: int = 0) -> None:
    if depth > 64:
        raise ValidationError("JSON nesting is too deep")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        if value < -(2**63) or value > 2**63 - 1:
            raise ValidationError(f"integer at {path} is outside the 64-bit range")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, path=f"{path}[{index}]", depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError(f"object key at {path} is not a string")
            _validate_json_value(item, path=f"{path}.{key}", depth=depth + 1)
        return
    raise ValidationError(f"unsupported JSON value at {path}")


def canonical_json_bytes(value: Any) -> bytes:
    """Encode the supported JSON subset in one deterministic representation."""

    _validate_json_value(value)
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValidationError("value cannot be encoded as canonical UTF-8 JSON") from exc


def _reject_float(value: str) -> None:
    raise ValidationError(f"floating-point JSON numbers are not supported: {value}")


def _reject_constant(value: str) -> None:
    raise ValidationError(f"non-finite JSON number is not supported: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _parse_canonical_json(blob: bytes, *, maximum: int, label: str) -> Any:
    if not isinstance(blob, bytes):
        raise ValidationError(f"{label} must be bytes")
    if len(blob) > maximum:
        raise ValidationError(f"{label} exceeds the size limit")
    try:
        text = blob.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except ValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label} is not valid UTF-8 JSON") from exc
    _validate_json_value(value)
    if canonical_json_bytes(value) != blob:
        raise ValidationError(f"{label} is not canonical JSON")
    return value


def _require_exact_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{label} must be a JSON object")
    if set(value) != fields:
        missing = sorted(fields - set(value))
        unknown = sorted(set(value) - fields)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise ValidationError(f"{label} has invalid fields ({', '.join(details)})")
    return value


def _require_bytes(value: bytes, *, length: int | None = None, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise ValidationError(f"{label} must be bytes")
    if length is not None and len(value) != length:
        raise ValidationError(f"{label} must be exactly {length} bytes")
    return value


def _validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"{label} has an invalid format")
    return value


def _validate_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
        raise ValidationError(f"{label} must be a lower-case SHA-256 hex digest")
    return value


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not _TIMESTAMP_RE.fullmatch(value):
        raise ValidationError("timestamp must be UTC RFC 3339 with whole seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValidationError("timestamp is not a real calendar time") from exc
    return value


def _timestamp_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: Any, *, label: str, exact_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value:
        raise ValidationError(f"{label} must be unpadded URL-safe base64")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValidationError(f"{label} must be unpadded URL-safe base64")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as exc:
        raise ValidationError(f"{label} is malformed base64") from exc
    if _b64encode(decoded) != value:
        raise ValidationError(f"{label} is not canonical base64")
    if exact_length is not None and len(decoded) != exact_length:
        raise ValidationError(f"{label} must decode to exactly {exact_length} bytes")
    return decoded


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hkdf(ikm: bytes, *, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=info
    ).derive(ikm)


def _raw_public_bytes(key: Ed25519PublicKey | X25519PublicKey) -> bytes:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _ed25519_private(value: Ed25519PrivateKey | bytes) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    return Ed25519PrivateKey.from_private_bytes(
        _require_bytes(value, length=32, label="Ed25519 private key")
    )


def _ed25519_public(value: Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    return Ed25519PublicKey.from_public_bytes(
        _require_bytes(value, length=32, label="Ed25519 public key")
    )


def _x25519_private(value: X25519PrivateKey | bytes) -> X25519PrivateKey:
    if isinstance(value, X25519PrivateKey):
        return value
    return X25519PrivateKey.from_private_bytes(
        _require_bytes(value, length=32, label="X25519 private key")
    )


def _x25519_public(value: X25519PublicKey | bytes) -> X25519PublicKey:
    if isinstance(value, X25519PublicKey):
        return value
    return X25519PublicKey.from_public_bytes(
        _require_bytes(value, length=32, label="X25519 public key")
    )


def generate_vault_key() -> bytes:
    """Return a new random AES-256 vault root key."""

    return secrets.token_bytes(VAULT_KEY_SIZE)


def generate_recovery_secret() -> bytes:
    """Return a high-entropy recovery secret; user passwords are not accepted."""

    return secrets.token_bytes(RECOVERY_SECRET_SIZE)


def generate_device_identity(device_id: str | None = None) -> DeviceIdentity:
    signing = Ed25519PrivateKey.generate()
    agreement = X25519PrivateKey.generate()
    if device_id is None:
        fingerprint = _sha256(_raw_public_bytes(signing.public_key()))[:32]
        device_id = f"dev-{fingerprint}"
    _validate_id(device_id, "device_id")
    return DeviceIdentity(device_id, signing, agreement)


def _snapshot_aad(vault_id: str) -> bytes:
    metadata = {
        "format_profile": SNAPSHOT_PROFILE,
        "protocol": PROTOCOL,
        "vault_id": vault_id,
    }
    return _SNAPSHOT_AAD_DOMAIN + canonical_json_bytes(metadata)


def seal_snapshot(plaintext: bytes, *, vault_key: bytes, vault_id: str) -> bytes:
    """Encrypt one opaque snapshot with a domain-separated vault subkey."""

    _require_bytes(plaintext, label="snapshot plaintext")
    if len(plaintext) > MAX_SNAPSHOT_PLAINTEXT_SIZE:
        raise ValidationError("snapshot plaintext exceeds the size limit")
    root_key = _require_bytes(vault_key, length=VAULT_KEY_SIZE, label="vault_key")
    checked_vault_id = _validate_id(vault_id, "vault_id")
    salt = secrets.token_bytes(_SALT_SIZE)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    aad = _snapshot_aad(checked_vault_id)
    key = _hkdf(root_key, salt=salt, info=_SNAPSHOT_KEY_INFO + aad)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    envelope = {
        "protocol": PROTOCOL,
        "format_profile": SNAPSHOT_PROFILE,
        "vault_id": checked_vault_id,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    blob = canonical_json_bytes(envelope)
    if len(blob) > MAX_SNAPSHOT_BLOB_SIZE:
        raise ValidationError("encrypted snapshot exceeds the size limit")
    return blob


def _parse_snapshot(blob: bytes) -> tuple[dict[str, Any], bytes, bytes, bytes]:
    envelope = _require_exact_fields(
        _parse_canonical_json(blob, maximum=MAX_SNAPSHOT_BLOB_SIZE, label="snapshot"),
        _SNAPSHOT_FIELDS,
        "snapshot",
    )
    if envelope["protocol"] != PROTOCOL or envelope["format_profile"] != SNAPSHOT_PROFILE:
        raise ValidationError("unsupported snapshot protocol or format profile")
    _validate_id(envelope["vault_id"], "vault_id")
    salt = _b64decode(envelope["salt"], label="salt", exact_length=_SALT_SIZE)
    nonce = _b64decode(envelope["nonce"], label="nonce", exact_length=_NONCE_SIZE)
    ciphertext = _b64decode(envelope["ciphertext"], label="ciphertext")
    if len(ciphertext) < _TAG_SIZE:
        raise ValidationError("snapshot ciphertext is too short")
    if len(ciphertext) > MAX_SNAPSHOT_PLAINTEXT_SIZE + _TAG_SIZE:
        raise ValidationError("snapshot ciphertext exceeds the size limit")
    return envelope, salt, nonce, ciphertext


def open_snapshot(blob: bytes, *, vault_key: bytes, expected_vault_id: str) -> bytes:
    """Validate and decrypt a KK2 snapshot."""

    root_key = _require_bytes(vault_key, length=VAULT_KEY_SIZE, label="vault_key")
    expected = _validate_id(expected_vault_id, "expected_vault_id")
    envelope, salt, nonce, ciphertext = _parse_snapshot(blob)
    if envelope["vault_id"] != expected:
        raise AuthenticationError("snapshot belongs to a different vault")
    aad = _snapshot_aad(expected)
    key = _hkdf(root_key, salt=salt, info=_SNAPSHOT_KEY_INFO + aad)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise AuthenticationError("snapshot authentication failed") from exc


def _validate_manifest(value: Any) -> dict[str, Any]:
    manifest = _require_exact_fields(value, _MANIFEST_FIELDS, "manifest")
    if manifest["protocol"] != PROTOCOL or manifest["format_profile"] != COMMIT_PROFILE:
        raise ValidationError("unsupported commit protocol or format profile")
    _validate_id(manifest["vault_id"], "vault_id")
    _validate_id(manifest["author_device_id"], "author_device_id")
    sequence = manifest["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or not 1 <= sequence < 2**63:
        raise ValidationError("sequence must be an integer between 1 and 2^63-1")
    parent_id = manifest["parent_commit_id"]
    parent_hash = manifest["parent_manifest_hash"]
    if sequence == 1:
        if parent_id is not None or parent_hash is not None:
            raise ValidationError("genesis commit must have null parent bindings")
    else:
        _validate_hash(parent_id, "parent_commit_id")
        _validate_hash(parent_hash, "parent_manifest_hash")
    _validate_hash(manifest["ciphertext_sha256"], "ciphertext_sha256")
    _validate_timestamp(manifest["timestamp"])
    return manifest


def _commit_id(manifest: Mapping[str, Any], signature: str) -> str:
    signed_record = {"manifest": dict(manifest), "signature": signature}
    return _sha256(_COMMIT_ID_DOMAIN + canonical_json_bytes(signed_record))


def compute_manifest_hash(manifest: Mapping[str, Any]) -> str:
    """Return the chain hash of a validated commit manifest."""

    checked = _validate_manifest(dict(manifest))
    return _sha256(canonical_json_bytes(checked))


def build_signed_commit(
    snapshot_ciphertext: bytes,
    *,
    vault_id: str,
    sequence: int,
    parent_commit_id: str | None,
    parent_manifest_hash: str | None,
    author_device_id: str,
    signing_private_key: Ed25519PrivateKey | bytes,
    timestamp: str | None = None,
) -> bytes:
    """Build and sign a deterministic content-addressed KK2 commit."""

    snapshot, _, _, _ = _parse_snapshot(snapshot_ciphertext)
    checked_vault_id = _validate_id(vault_id, "vault_id")
    if snapshot["vault_id"] != checked_vault_id:
        raise ValidationError("snapshot and commit vault_id differ")
    manifest = {
        "protocol": PROTOCOL,
        "format_profile": COMMIT_PROFILE,
        "vault_id": checked_vault_id,
        "sequence": sequence,
        "parent_commit_id": parent_commit_id,
        "parent_manifest_hash": parent_manifest_hash,
        "ciphertext_sha256": _sha256(snapshot_ciphertext),
        "author_device_id": _validate_id(author_device_id, "author_device_id"),
        "timestamp": timestamp if timestamp is not None else _timestamp_now(),
    }
    _validate_manifest(manifest)
    manifest_bytes = canonical_json_bytes(manifest)
    signature = _b64encode(
        _ed25519_private(signing_private_key).sign(
            _COMMIT_SIGNATURE_DOMAIN + manifest_bytes
        )
    )
    commit = {
        "commit_id": _commit_id(manifest, signature),
        "manifest": manifest,
        "signature": signature,
    }
    return canonical_json_bytes(commit)


def verify_commit_signature(
    commit_blob: bytes,
    *,
    signing_public_key: Ed25519PublicKey | bytes,
    snapshot_ciphertext: bytes | None = None,
    expected_vault_id: str | None = None,
    expected_author_device_id: str | None = None,
) -> VerifiedCommit:
    """Verify a commit without decrypting its snapshot.

    Servers should resolve ``signing_public_key`` from the manifest's registered
    ``author_device_id`` rather than trusting a key supplied alongside a commit.
    """

    commit = _require_exact_fields(
        _parse_canonical_json(commit_blob, maximum=MAX_COMMIT_SIZE, label="commit"),
        _COMMIT_FIELDS,
        "commit",
    )
    manifest = _validate_manifest(commit["manifest"])
    commit_id = _validate_hash(commit["commit_id"], "commit_id")
    signature_bytes = _b64decode(
        commit["signature"], label="signature", exact_length=64
    )
    expected_id = _commit_id(manifest, commit["signature"])
    if not secrets.compare_digest(commit_id, expected_id):
        raise SignatureVerificationError("commit_id does not match the signed record")
    manifest_bytes = canonical_json_bytes(manifest)
    try:
        _ed25519_public(signing_public_key).verify(
            signature_bytes, _COMMIT_SIGNATURE_DOMAIN + manifest_bytes
        )
    except InvalidSignature as exc:
        raise SignatureVerificationError("commit signature is invalid") from exc
    if expected_vault_id is not None:
        expected = _validate_id(expected_vault_id, "expected_vault_id")
        if manifest["vault_id"] != expected:
            raise SignatureVerificationError("commit belongs to a different vault")
    if expected_author_device_id is not None:
        author = _validate_id(expected_author_device_id, "expected_author_device_id")
        if manifest["author_device_id"] != author:
            raise SignatureVerificationError("commit author does not match the trusted device")
    if snapshot_ciphertext is not None:
        snapshot, _, _, _ = _parse_snapshot(snapshot_ciphertext)
        if snapshot["vault_id"] != manifest["vault_id"]:
            raise SignatureVerificationError("snapshot belongs to a different vault")
        digest = _sha256(snapshot_ciphertext)
        if not secrets.compare_digest(digest, manifest["ciphertext_sha256"]):
            raise SignatureVerificationError("snapshot ciphertext hash does not match manifest")
    return VerifiedCommit(
        commit_id=commit_id,
        manifest_hash=compute_manifest_hash(manifest),
        vault_id=manifest["vault_id"],
        sequence=manifest["sequence"],
        parent_commit_id=manifest["parent_commit_id"],
        parent_manifest_hash=manifest["parent_manifest_hash"],
        ciphertext_sha256=manifest["ciphertext_sha256"],
        author_device_id=manifest["author_device_id"],
        timestamp=manifest["timestamp"],
        manifest=dict(manifest),
    )


def verify_commit(
    commit_blob: bytes,
    *,
    signing_public_key: Ed25519PublicKey | bytes,
    snapshot_ciphertext: bytes | None = None,
    expected_vault_id: str | None = None,
    expected_author_device_id: str | None = None,
    previous: VerifiedCommit | None = None,
    minimum_sequence: int | None = None,
    require_genesis: bool = False,
) -> VerifiedCommit:
    """Verify signature/bindings plus optional chain and replay constraints."""

    verified = verify_commit_signature(
        commit_blob,
        signing_public_key=signing_public_key,
        snapshot_ciphertext=snapshot_ciphertext,
        expected_vault_id=expected_vault_id,
        expected_author_device_id=expected_author_device_id,
    )
    if minimum_sequence is not None:
        if (
            isinstance(minimum_sequence, bool)
            or not isinstance(minimum_sequence, int)
            or minimum_sequence < 0
        ):
            raise ValidationError("minimum_sequence must be a non-negative integer")
        if verified.sequence <= minimum_sequence:
            raise ReplayDetected("commit sequence is not newer than the trusted watermark")
    if require_genesis and (
        verified.sequence != 1
        or verified.parent_commit_id is not None
        or verified.parent_manifest_hash is not None
    ):
        raise ChainValidationError("expected a genesis commit")
    if previous is not None:
        if verified.vault_id != previous.vault_id:
            raise ChainValidationError("commit changes vault_id")
        if verified.sequence != previous.sequence + 1:
            if verified.sequence <= previous.sequence:
                raise ReplayDetected("commit does not advance the trusted sequence")
            raise ChainValidationError("commit sequence is not the next sequence")
        if verified.parent_commit_id != previous.commit_id:
            raise ChainValidationError("parent_commit_id does not match trusted HEAD")
        if verified.parent_manifest_hash != previous.manifest_hash:
            raise ChainValidationError("parent_manifest_hash does not match trusted HEAD")
    return verified


def _validate_context(context: bytes) -> bytes:
    _require_bytes(context, label="key-wrap context")
    if not context or len(context) > MAX_CONTEXT_SIZE:
        raise ValidationError("key-wrap context must contain 1 to 1024 bytes")
    return context


def _device_wrap_metadata(
    *,
    vault_id: str,
    recipient_device_id: str,
    ephemeral_public_key: str,
    context_sha256: str,
) -> dict[str, str]:
    return {
        "protocol": PROTOCOL,
        "format_profile": DEVICE_WRAP_PROFILE,
        "vault_id": vault_id,
        "recipient_device_id": recipient_device_id,
        "ephemeral_public_key": ephemeral_public_key,
        "context_sha256": context_sha256,
    }


def wrap_vault_key_for_recipient(
    vault_key: bytes,
    *,
    recipient_public_key: X25519PublicKey | bytes,
    vault_id: str,
    recipient_device_id: str,
    context: bytes,
) -> bytes:
    """Wrap a VaultKey to one recipient using an ephemeral X25519 key."""

    root_key = _require_bytes(vault_key, length=VAULT_KEY_SIZE, label="vault_key")
    recipient = _x25519_public(recipient_public_key)
    checked_vault_id = _validate_id(vault_id, "vault_id")
    checked_device_id = _validate_id(recipient_device_id, "recipient_device_id")
    checked_context = _validate_context(context)
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = _b64encode(_raw_public_bytes(ephemeral.public_key()))
    metadata = _device_wrap_metadata(
        vault_id=checked_vault_id,
        recipient_device_id=checked_device_id,
        ephemeral_public_key=ephemeral_public,
        context_sha256=_sha256(checked_context),
    )
    aad = _DEVICE_WRAP_AAD_DOMAIN + canonical_json_bytes(metadata)
    salt = secrets.token_bytes(_SALT_SIZE)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    try:
        shared_secret = ephemeral.exchange(recipient)
    except ValueError as exc:
        raise ValidationError("recipient X25519 public key is invalid") from exc
    key = _hkdf(shared_secret, salt=salt, info=_DEVICE_WRAP_KEY_INFO + aad)
    wrapped = AESGCM(key).encrypt(nonce, root_key, aad)
    envelope = {
        **metadata,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "wrapped_vault_key": _b64encode(wrapped),
    }
    return canonical_json_bytes(envelope)


def unwrap_vault_key_for_recipient(
    wrapped_blob: bytes,
    *,
    recipient_private_key: X25519PrivateKey | bytes,
    expected_vault_id: str,
    expected_recipient_device_id: str,
    context: bytes,
) -> bytes:
    """Validate a recipient/context binding and unwrap a VaultKey."""

    envelope = _require_exact_fields(
        _parse_canonical_json(
            wrapped_blob, maximum=MAX_KEY_WRAP_SIZE, label="device key wrap"
        ),
        _DEVICE_WRAP_FIELDS,
        "device key wrap",
    )
    if envelope["protocol"] != PROTOCOL or envelope["format_profile"] != DEVICE_WRAP_PROFILE:
        raise ValidationError("unsupported device key-wrap protocol or format profile")
    vault_id = _validate_id(envelope["vault_id"], "vault_id")
    device_id = _validate_id(envelope["recipient_device_id"], "recipient_device_id")
    expected_vault = _validate_id(expected_vault_id, "expected_vault_id")
    expected_device = _validate_id(
        expected_recipient_device_id, "expected_recipient_device_id"
    )
    checked_context = _validate_context(context)
    context_hash = _validate_hash(envelope["context_sha256"], "context_sha256")
    if vault_id != expected_vault or device_id != expected_device:
        raise AuthenticationError("device key-wrap recipient binding does not match")
    if not secrets.compare_digest(context_hash, _sha256(checked_context)):
        raise AuthenticationError("device key-wrap context does not match")
    ephemeral_bytes = _b64decode(
        envelope["ephemeral_public_key"],
        label="ephemeral_public_key",
        exact_length=32,
    )
    salt = _b64decode(envelope["salt"], label="salt", exact_length=_SALT_SIZE)
    nonce = _b64decode(envelope["nonce"], label="nonce", exact_length=_NONCE_SIZE)
    wrapped = _b64decode(
        envelope["wrapped_vault_key"],
        label="wrapped_vault_key",
        exact_length=VAULT_KEY_SIZE + _TAG_SIZE,
    )
    metadata = _device_wrap_metadata(
        vault_id=vault_id,
        recipient_device_id=device_id,
        ephemeral_public_key=envelope["ephemeral_public_key"],
        context_sha256=context_hash,
    )
    aad = _DEVICE_WRAP_AAD_DOMAIN + canonical_json_bytes(metadata)
    try:
        shared_secret = _x25519_private(recipient_private_key).exchange(
            X25519PublicKey.from_public_bytes(ephemeral_bytes)
        )
        key = _hkdf(shared_secret, salt=salt, info=_DEVICE_WRAP_KEY_INFO + aad)
        return AESGCM(key).decrypt(nonce, wrapped, aad)
    except (InvalidTag, ValueError) as exc:
        raise AuthenticationError("device key-wrap authentication failed") from exc


def _recovery_metadata(vault_id: str) -> dict[str, str]:
    return {
        "protocol": PROTOCOL,
        "format_profile": RECOVERY_WRAP_PROFILE,
        "vault_id": vault_id,
    }


def wrap_vault_key_for_recovery(
    vault_key: bytes, *, recovery_secret: bytes, vault_id: str
) -> bytes:
    """Wrap a VaultKey with a random 32-byte recovery secret."""

    root_key = _require_bytes(vault_key, length=VAULT_KEY_SIZE, label="vault_key")
    recovery = _require_bytes(
        recovery_secret, length=RECOVERY_SECRET_SIZE, label="recovery_secret"
    )
    checked_vault_id = _validate_id(vault_id, "vault_id")
    metadata = _recovery_metadata(checked_vault_id)
    aad = _RECOVERY_WRAP_AAD_DOMAIN + canonical_json_bytes(metadata)
    salt = secrets.token_bytes(_SALT_SIZE)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    key = _hkdf(recovery, salt=salt, info=_RECOVERY_WRAP_KEY_INFO + aad)
    wrapped = AESGCM(key).encrypt(nonce, root_key, aad)
    envelope = {
        **metadata,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "wrapped_vault_key": _b64encode(wrapped),
    }
    return canonical_json_bytes(envelope)


def unwrap_vault_key_for_recovery(
    wrapped_blob: bytes, *, recovery_secret: bytes, expected_vault_id: str
) -> bytes:
    """Unwrap a VaultKey with a random recovery secret (never a password)."""

    recovery = _require_bytes(
        recovery_secret, length=RECOVERY_SECRET_SIZE, label="recovery_secret"
    )
    envelope = _require_exact_fields(
        _parse_canonical_json(
            wrapped_blob, maximum=MAX_KEY_WRAP_SIZE, label="recovery key wrap"
        ),
        _RECOVERY_WRAP_FIELDS,
        "recovery key wrap",
    )
    if envelope["protocol"] != PROTOCOL or envelope["format_profile"] != RECOVERY_WRAP_PROFILE:
        raise ValidationError("unsupported recovery key-wrap protocol or format profile")
    vault_id = _validate_id(envelope["vault_id"], "vault_id")
    expected = _validate_id(expected_vault_id, "expected_vault_id")
    if vault_id != expected:
        raise AuthenticationError("recovery key wrap belongs to a different vault")
    salt = _b64decode(envelope["salt"], label="salt", exact_length=_SALT_SIZE)
    nonce = _b64decode(envelope["nonce"], label="nonce", exact_length=_NONCE_SIZE)
    wrapped = _b64decode(
        envelope["wrapped_vault_key"],
        label="wrapped_vault_key",
        exact_length=VAULT_KEY_SIZE + _TAG_SIZE,
    )
    metadata = _recovery_metadata(vault_id)
    aad = _RECOVERY_WRAP_AAD_DOMAIN + canonical_json_bytes(metadata)
    key = _hkdf(recovery, salt=salt, info=_RECOVERY_WRAP_KEY_INFO + aad)
    try:
        return AESGCM(key).decrypt(nonce, wrapped, aad)
    except InvalidTag as exc:
        raise AuthenticationError("recovery key-wrap authentication failed") from exc


__all__ = [
    "AuthenticationError",
    "ChainValidationError",
    "COMMIT_PROFILE",
    "DEVICE_WRAP_PROFILE",
    "DeviceIdentity",
    "KK2Error",
    "MAX_COMMIT_SIZE",
    "MAX_CONTEXT_SIZE",
    "MAX_KEY_WRAP_SIZE",
    "MAX_SNAPSHOT_BLOB_SIZE",
    "MAX_SNAPSHOT_PLAINTEXT_SIZE",
    "PROTOCOL",
    "RECOVERY_SECRET_SIZE",
    "RECOVERY_WRAP_PROFILE",
    "ReplayDetected",
    "SNAPSHOT_PROFILE",
    "SignatureVerificationError",
    "VAULT_KEY_SIZE",
    "ValidationError",
    "VerifiedCommit",
    "build_signed_commit",
    "canonical_json_bytes",
    "compute_manifest_hash",
    "generate_device_identity",
    "generate_recovery_secret",
    "generate_vault_key",
    "open_snapshot",
    "seal_snapshot",
    "unwrap_vault_key_for_recipient",
    "unwrap_vault_key_for_recovery",
    "verify_commit",
    "verify_commit_signature",
    "wrap_vault_key_for_recipient",
    "wrap_vault_key_for_recovery",
]
