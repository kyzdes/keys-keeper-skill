"""KK3 project protocol: bounded, typed, signed and context-bound records.

No storage or network access. Callers must persist verified policy/checkpoint
state atomically; these functions do not make an untrusted relay a trust anchor.
The public-key encryption construction is X25519/HKDF-SHA256/AES-256-GCM,
explicitly not HPKE. See PROJECT-PROTOCOL-CONTRACT.md.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PROFILE = "KK3-projects-v1"
MAX_RECORD_SIZE = 24 * 1024 * 1024
MAX_PLAINTEXT_SIZE = 16 * 1024 * 1024
MAX_CREATE_SIZE = 1024 * 1024
MAX_POLICY_SIZE = 256 * 1024
MAX_GRANTS = 512
# Client-enforced random 96-bit nonce budget per independently generated epoch key.
MAX_EPOCH_PUBLICATIONS = 2 ** 16
MAX_DEPTH = 24
MAX_NODES = 200_000
_DOMAIN = b"keys-keeper/KK3-projects-v1/"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


class ProtocolError(RuntimeError):
    """Safe protocol failure; messages never contain input values."""


class ValidationError(ProtocolError):
    pass


class AuthenticationError(ProtocolError):
    pass


class AuthorizationError(AuthenticationError):
    pass


class ReplayError(AuthenticationError):
    pass


# No formatting of caller-controlled fields in errors, including JSON keys.
def _fail(message: str = "invalid project record") -> None:
    raise ValidationError(message)


def _walk(value: Any, depth: int, budget: list[int]) -> None:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        _fail("JSON structure exceeds limit")
    if value is None or type(value) in (str, bool):
        if isinstance(value, str):
            budget[1] -= len(value)
            if budget[1] < 0:
                _fail("JSON strings exceed aggregate size limit")
        return
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            _fail("JSON integer exceeds limit")
        return
    if type(value) is list:
        if len(value) > MAX_NODES:
            _fail("JSON structure exceeds limit")
        for item in value:
            _walk(item, depth + 1, budget)
        return
    if type(value) is dict:
        if len(value) > MAX_NODES:
            _fail("JSON structure exceeds limit")
        for key, item in value.items():
            if type(key) is not str:
                _fail("invalid JSON key")
            _walk(key, depth + 1, budget)
            _walk(item, depth + 1, budget)
        return
    _fail("unsupported JSON type")


def canonical_bytes(value: Any, *, maximum: int = MAX_RECORD_SIZE) -> bytes:
    _walk(value, 0, [MAX_NODES, maximum])
    try:
        blob = json.dumps(value, sort_keys=True, ensure_ascii=False,
                          allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("invalid JSON encoding") from None
    if len(blob) > maximum:
        _fail("record exceeds size limit")
    return blob


def canonical_hash(value: Any) -> str:
    """SHA-256 of canonical JSON; hash complete signed records for links."""
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _pairs(pairs: list[tuple[str, Any]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            _fail("duplicate JSON key")
        result[key] = value
    return result


def _bad_number(_: str) -> None:
    _fail("unsupported JSON number")


def parse_record(blob: bytes | str | dict, *, maximum: int = MAX_RECORD_SIZE) -> dict:
    """Parse canonical JSON or defensively copy a bounded dict. No coercion."""
    if type(blob) is dict:
        blob = canonical_bytes(blob, maximum=maximum)
    if type(blob) is str:
        if len(blob) > maximum:
            _fail("invalid record size or type")
        try:
            blob = blob.encode("utf-8")
        except UnicodeError:
            raise ValidationError("invalid JSON encoding") from None
    if type(blob) is not bytes or len(blob) > maximum:
        _fail("invalid record size or type")
    try:
        obj = json.loads(blob.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_float=_bad_number, parse_constant=_bad_number)
    except (ValueError, UnicodeError, RecursionError):
        raise ValidationError("invalid JSON encoding") from None
    if type(obj) is not dict or canonical_bytes(obj, maximum=maximum) != blob:
        _fail("record is not canonical JSON object")
    return obj


def encode_key(key: bytes) -> str:
    return _b64(_key(key))


def decode_key(key: str) -> bytes:
    return _unb64(key, 32)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: Any, length: int | None = None, maximum: int = MAX_RECORD_SIZE) -> bytes:
    if type(value) is not str or len(value) > (maximum * 4 + 2) // 3:
        _fail("invalid binary encoding")
    try:
        result = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ValidationError("invalid binary encoding") from None
    if _b64(result) != value or len(result) > maximum or (length is not None and len(result) != length):
        _fail("invalid binary encoding")
    return result


def _key(value: Any) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail("invalid key size or type")
    return value


def generate_key() -> bytes:
    """Independent random 256-bit key; do not derive scope keys from each other."""
    return secrets.token_bytes(32)


def signing_public_key(private_key: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(_key(private_key)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def agreement_public_key(private_key: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(_key(private_key)).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _fields(obj: Any, fields: set[str]) -> None:
    if type(obj) is not dict or set(obj) != fields:
        _fail("invalid record fields")


def _id(value: Any) -> None:
    if type(value) is not str or len(value) != 36:
        _fail("invalid identifier")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValidationError("invalid identifier") from None
    if str(parsed) != value or parsed.version != 4:
        _fail("identifier must be canonical UUID4")


def _uint(value: Any, minimum: int = 0) -> None:
    if type(value) is not int or not minimum <= value < 2**63:
        _fail("invalid sequence or generation")


def _hash(value: Any, nullable: bool = False) -> None:
    if value is None and nullable:
        return
    if type(value) is not str or not _HASH.fullmatch(value):
        _fail("invalid hash")


def _sign(kind: str, payload: dict, private_key: bytes) -> dict:
    body = {"profile": PROFILE, "kind": kind, "payload": payload}
    signature = Ed25519PrivateKey.from_private_bytes(_key(private_key)).sign(
        _DOMAIN + b"signature/" + kind.encode("ascii") + b"\0" + canonical_bytes(body))
    return {**body, "signature": _b64(signature)}


def _verify(record: Any, kind: str, public_key: bytes, *, maximum: int = MAX_RECORD_SIZE) -> dict:
    obj = parse_record(record, maximum=maximum)
    _fields(obj, {"profile", "kind", "payload", "signature"})
    if obj["profile"] != PROFILE or obj["kind"] != kind or type(obj["payload"]) is not dict:
        _fail("unsupported profile or record kind")
    signature = _unb64(obj["signature"], 64)
    body = {key: obj[key] for key in ("profile", "kind", "payload")}
    try:
        Ed25519PublicKey.from_public_bytes(_key(public_key)).verify(
            signature, _DOMAIN + b"signature/" + kind.encode("ascii") + b"\0" + canonical_bytes(body))
    except (InvalidSignature, ValueError):
        raise AuthenticationError("project signature verification failed") from None
    return obj["payload"]


_POLICY_FIELDS = {"scope_id", "vault_id", "version", "epoch", "master_public_key",
                  "inbox_public_key", "master_device_id", "master_token_hash", "grants", "checkpoint_sequence", "checkpoint_hash", "parent_policy_hash"}
_GRANT_FIELDS = {"grant_id", "generation", "device_id", "role", "signing_public_key", "agreement_public_key", "token_hash"}


def _policy(payload: dict) -> None:
    _fields(payload, _POLICY_FIELDS)
    for field in ("scope_id", "vault_id", "master_device_id"):
        _id(payload[field])
    for field in ("version", "epoch"):
        _uint(payload[field], 1)
    _uint(payload["checkpoint_sequence"])
    _hash(payload["checkpoint_hash"], True)
    _hash(payload["parent_policy_hash"], True)
    if (payload["checkpoint_sequence"] == 0) != (payload["checkpoint_hash"] is None):
        _fail("invalid checkpoint binding")
    if (payload["version"] == 1) != (payload["parent_policy_hash"] is None):
        _fail("invalid policy parent binding")
    for field in ("master_public_key", "inbox_public_key"):
        decode_key(payload[field])
    _hash(payload["master_token_hash"])
    grants = payload["grants"]
    if type(grants) is not list or len(grants) > MAX_GRANTS:
        _fail("invalid grant list")
    devices, ids, signing_keys, agreement_keys, tokens = set(), set(), set(), set(), set()
    for grant in grants:
        _fields(grant, _GRANT_FIELDS)
        _id(grant["grant_id"])
        _id(grant["device_id"])
        _uint(grant["generation"], 1)
        _hash(grant["token_hash"])
        if grant["device_id"] == payload["master_device_id"] or grant["token_hash"] == payload["master_token_hash"]:
            _fail("master authentication cannot be delegated")
        if grant["role"] not in ("reader", "contributor"):
            _fail("invalid project role")
        for field, seen in (("device_id", devices), ("grant_id", ids),
                            ("signing_public_key", signing_keys), ("agreement_public_key", agreement_keys), ("token_hash", tokens)):
            if field.endswith("public_key"):
                decode_key(grant[field])
            if grant[field] in seen:
                _fail("duplicate grant identity")
            seen.add(grant[field])
        if grant["signing_public_key"] == payload["master_public_key"] or grant["agreement_public_key"] == payload["inbox_public_key"]:
            _fail("master key cannot be delegated")


def sign_policy(payload: dict, master_private_key: bytes) -> dict:
    payload = parse_record(payload, maximum=MAX_POLICY_SIZE)
    _policy(payload)
    if decode_key(payload["master_public_key"]) != signing_public_key(master_private_key):
        raise AuthorizationError("policy master identity mismatch")
    record = _sign("policy", payload, master_private_key)
    canonical_bytes(record, maximum=MAX_POLICY_SIZE)
    return record


def verify_policy(record: Any, pinned_master_public_key: bytes, *, expected_scope_id: str | None = None,
                  expected_vault_id: str | None = None, minimum_version: int = 0, minimum_epoch: int = 0) -> dict:
    payload = _verify(record, "policy", pinned_master_public_key, maximum=MAX_POLICY_SIZE)
    _policy(payload)
    if decode_key(payload["master_public_key"]) != _key(pinned_master_public_key):
        raise AuthorizationError("policy master identity mismatch")
    if ((expected_scope_id is not None and payload["scope_id"] != expected_scope_id) or
            (expected_vault_id is not None and payload["vault_id"] != expected_vault_id)):
        raise AuthorizationError("policy scope mismatch")
    _uint(minimum_version)
    _uint(minimum_epoch)
    if payload["version"] < minimum_version or payload["epoch"] < minimum_epoch:
        raise ReplayError("policy below trusted checkpoint")
    return payload


def authorize_grant(policy_payload: dict, device_id: str, operation: str, *, grant_id: str | None = None,
                    generation: int | None = None) -> dict:
    """Authorize an already verified policy payload. Never trust raw relay roles.

    Operations are read/create only; snapshot, policy, receipt and wrap are
    master-only and consequently never accepted here.
    """
    _policy(policy_payload)
    _id(device_id)
    if grant_id is not None:
        _id(grant_id)
    if generation is not None:
        _uint(generation, 1)
    if operation not in ("read", "create"):
        raise AuthorizationError("operation is not delegated")
    for grant in policy_payload["grants"]:
        if grant["device_id"] == device_id:
            if ((grant_id is not None and grant["grant_id"] != grant_id) or
                    (generation is not None and grant["generation"] != generation) or
                    (operation == "create" and grant["role"] != "contributor")):
                break
            return dict(grant)
    raise AuthorizationError("active project grant required")


def validate_policy_transition(old_record: Any, new_record: Any, pinned_master_public_key: bytes) -> dict:
    old = verify_policy(old_record, pinned_master_public_key)
    new = verify_policy(new_record, pinned_master_public_key, expected_scope_id=old["scope_id"], expected_vault_id=old["vault_id"],
                        minimum_version=old["version"] + 1, minimum_epoch=old["epoch"])
    if new["version"] != old["version"] + 1 or new["parent_policy_hash"] != canonical_hash(parse_record(old_record)):
        raise ReplayError("policy does not extend trusted policy")
    if new["epoch"] not in (old["epoch"], old["epoch"] + 1):
        raise ReplayError("invalid epoch transition")
    if (new["checkpoint_sequence"] < old["checkpoint_sequence"] or
            (new["checkpoint_sequence"] == old["checkpoint_sequence"] and new["checkpoint_hash"] != old["checkpoint_hash"])):
        raise ReplayError("policy checkpoint regressed or forked")
    old_grants = {g["device_id"]: g for g in old["grants"]}
    new_grants = {g["device_id"]: g for g in new["grants"]}
    if old_grants != new_grants and new["epoch"] != old["epoch"] + 1:
        raise AuthorizationError("grant change requires new epoch")
    if new["epoch"] == old["epoch"] and (new["checkpoint_sequence"], new["checkpoint_hash"]) != (old["checkpoint_sequence"], old["checkpoint_hash"]):
        raise ReplayError("epoch checkpoint cannot change without key rotation")
    old_grant_owners = {g["grant_id"]: g["device_id"] for g in old["grants"]}
    for device, grant in new_grants.items():
        if grant["grant_id"] in old_grant_owners and old_grant_owners[grant["grant_id"]] != device:
            raise AuthorizationError("grant identity cannot move between devices")
        prior = old_grants.get(device)
        if prior and grant != prior:
            if grant["grant_id"] == prior["grant_id"] or grant["generation"] <= prior["generation"]:
                raise AuthorizationError("grant change requires new identity and generation")
    # A separate, recoverable inbox migration is not part of a policy rollover.
    if new["master_device_id"] != old["master_device_id"]:
        raise AuthorizationError("master identity migration is unsupported")
    if new["inbox_public_key"] != old["inbox_public_key"]:
        raise AuthorizationError("inbox rotation requires a separate migration")
    return new


def _context(policy_record: Any, policy: dict) -> dict:
    return {"scope_id": policy["scope_id"], "vault_id": policy["vault_id"], "epoch": policy["epoch"],
            "policy_version": policy["version"], "policy_hash": canonical_hash(parse_record(policy_record))}


def _check_context(body: dict, policy_record: Any, policy: dict) -> None:
    if any(body.get(key) != value for key, value in _context(policy_record, policy).items()):
        raise AuthorizationError("project context mismatch")


def _master(private_key: bytes, pinned_key: bytes) -> None:
    if signing_public_key(private_key) != _key(pinned_key):
        raise AuthorizationError("master signing identity required")


def _aad(kind: str, context: dict) -> bytes:
    return _DOMAIN + b"aead/" + kind.encode("ascii") + b"\0" + canonical_bytes(context)


def _seal(data: bytes, key: bytes, kind: str, context: dict) -> dict:
    nonce = secrets.token_bytes(12)
    return {"nonce": _b64(nonce), "ciphertext": _b64(AESGCM(_key(key)).encrypt(nonce, data, _aad(kind, context)))}


def _open(sealed: dict, key: bytes, kind: str, context: dict, *, maximum: int) -> bytes:
    _fields(sealed, {"nonce", "ciphertext"})
    nonce = _unb64(sealed["nonce"], 12)
    ciphertext = _unb64(sealed["ciphertext"], maximum=maximum + 16)
    if len(ciphertext) < 16:
        _fail("invalid ciphertext length")
    try:
        return AESGCM(_key(key)).decrypt(nonce, ciphertext, _aad(kind, context))
    except InvalidTag:
        raise AuthenticationError("project decryption failed") from None


def _hybrid_key(private_key: bytes, public_key: bytes, salt: bytes, kind: str, context: dict, ephemeral: bytes) -> bytes:
    try:
        shared = X25519PrivateKey.from_private_bytes(_key(private_key)).exchange(X25519PublicKey.from_public_bytes(_key(public_key)))
    except ValueError:
        raise AuthenticationError("invalid key agreement") from None
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=_DOMAIN + b"kdf/" + kind.encode("ascii") + b"\0" + ephemeral + canonical_bytes(context)).derive(shared)


def _hybrid_seal(data: bytes, public_key: bytes, kind: str, context: dict) -> dict:
    ephemeral_private = generate_key()
    ephemeral = agreement_public_key(ephemeral_private)
    salt = secrets.token_bytes(32)
    key = _hybrid_key(ephemeral_private, public_key, salt, kind, context, ephemeral)
    return {"ephemeral_public_key": _b64(ephemeral), "salt": _b64(salt), **_seal(data, key, kind, context)}


def _hybrid_open(sealed: dict, private_key: bytes, kind: str, context: dict, *, maximum: int) -> bytes:
    _fields(sealed, {"ephemeral_public_key", "salt", "nonce", "ciphertext"})
    ephemeral = _unb64(sealed["ephemeral_public_key"], 32)
    key = _hybrid_key(private_key, ephemeral, _unb64(sealed["salt"], 32), kind, context, ephemeral)
    return _open({k: sealed[k] for k in ("nonce", "ciphertext")}, key, kind, context, maximum=maximum)


def _validate_sealed(sealed: dict, hybrid: bool, maximum: int) -> None:
    fields = {"nonce", "ciphertext"} | ({"ephemeral_public_key", "salt"} if hybrid else set())
    _fields(sealed, fields)
    _unb64(sealed["nonce"], 12)
    if len(_unb64(sealed["ciphertext"], maximum=maximum + 16)) < 16:
        _fail("invalid ciphertext length")
    if hybrid:
        _unb64(sealed["ephemeral_public_key"], 32)
        _unb64(sealed["salt"], 32)


_CONTEXT_FIELDS = {"scope_id", "vault_id", "epoch", "policy_version", "policy_hash"}


def build_snapshot(payload: dict, policy: Any, pinned_key: bytes, master_private_key: bytes, scope_key: bytes,
                   *, sequence: int, parent_hash: str | None = None) -> dict:
    p = verify_policy(policy, pinned_key)
    _master(master_private_key, pinned_key)
    _uint(sequence, 1)
    _hash(parent_hash, True)
    context = {**_context(policy, p), "sequence": sequence, "parent_hash": parent_hash}
    sealed = _seal(canonical_bytes(parse_record(payload, maximum=MAX_PLAINTEXT_SIZE), maximum=MAX_PLAINTEXT_SIZE), scope_key, "snapshot", context)
    record = _sign("snapshot", {**context, "sealed": sealed}, master_private_key)
    verify_snapshot(record, policy, pinned_key)
    return record


def verify_snapshot(record: Any, policy: Any, pinned_key: bytes, *, minimum_sequence: int = 0,
                    expected_parent_hash: str | None = None) -> dict:
    p = verify_policy(policy, pinned_key)
    body = _verify(record, "snapshot", pinned_key)
    _fields(body, _CONTEXT_FIELDS | {"sequence", "parent_hash", "sealed"})
    _check_context(body, policy, p)
    _uint(body["sequence"], 1)
    _uint(minimum_sequence)
    _hash(body["parent_hash"], True)
    _hash(expected_parent_hash, True)
    if (body["sequence"] == 1) != (body["parent_hash"] is None):
        _fail("invalid snapshot parent")
    if body["sequence"] <= max(minimum_sequence, p["checkpoint_sequence"]):
        raise ReplayError("snapshot below trusted checkpoint")
    if body["sequence"] - p["checkpoint_sequence"] > MAX_EPOCH_PUBLICATIONS:
        raise ReplayError("scope epoch publication limit reached")
    if expected_parent_hash is not None and body["parent_hash"] != expected_parent_hash:
        raise ReplayError("snapshot does not extend trusted parent")
    if body["sequence"] == p["checkpoint_sequence"] + 1 and body["parent_hash"] != p["checkpoint_hash"]:
        raise ReplayError("snapshot does not extend policy checkpoint")
    _validate_sealed(body["sealed"], False, MAX_PLAINTEXT_SIZE)
    return body


def open_snapshot(record: Any, policy: Any, pinned_key: bytes, scope_key: bytes, *, minimum_sequence: int = 0,
                  expected_parent_hash: str | None = None) -> dict:
    body = verify_snapshot(record, policy, pinned_key, minimum_sequence=minimum_sequence, expected_parent_hash=expected_parent_hash)
    context = {k: v for k, v in body.items() if k != "sealed"}
    return parse_record(_open(body["sealed"], scope_key, "snapshot", context, maximum=MAX_PLAINTEXT_SIZE), maximum=MAX_PLAINTEXT_SIZE)


def wrap_scope_key(scope_key: bytes, policy: Any, pinned_key: bytes, master_private_key: bytes, device_id: str) -> dict:
    p = verify_policy(policy, pinned_key)
    _master(master_private_key, pinned_key)
    grant = authorize_grant(p, device_id, "read")
    context = {**_context(policy, p), "device_id": device_id, "grant_id": grant["grant_id"],
               "generation": grant["generation"], "recipient_public_key": grant["agreement_public_key"], "grant_hash": canonical_hash(grant)}
    return _sign("scope-key-wrap", {**context, "sealed": _hybrid_seal(_key(scope_key), decode_key(grant["agreement_public_key"]), "scope-key-wrap", context)}, master_private_key)


def verify_scope_key_wrap(record: Any, policy: Any, pinned_key: bytes, device_id: str | None = None,
                          *, expected_device_id: str | None = None) -> dict:
    p = verify_policy(policy, pinned_key)
    body = _verify(record, "scope-key-wrap", pinned_key, maximum=16 * 1024)
    if device_id is not None and expected_device_id is not None and device_id != expected_device_id:
        raise AuthorizationError("scope key recipient mismatch")
    device_id = expected_device_id or device_id or body.get("device_id")
    grant = authorize_grant(p, device_id, "read")
    _fields(body, _CONTEXT_FIELDS | {"device_id", "grant_id", "generation", "recipient_public_key", "grant_hash", "sealed"})
    _check_context(body, policy, p)
    expected = {"device_id": device_id, "grant_id": grant["grant_id"], "generation": grant["generation"],
                "recipient_public_key": grant["agreement_public_key"], "grant_hash": canonical_hash(grant)}
    if any(body[k] != v for k, v in expected.items()):
        raise AuthorizationError("scope key recipient mismatch")
    _validate_sealed(body["sealed"], True, 32)
    return body


def unwrap_scope_key(record: Any, policy: Any, pinned_key: bytes, device_id: str, device_private_key: bytes) -> bytes:
    body = verify_scope_key_wrap(record, policy, pinned_key, device_id)
    if agreement_public_key(device_private_key) != decode_key(body["recipient_public_key"]):
        raise AuthorizationError("scope key recipient mismatch")
    return _key(_hybrid_open(body["sealed"], device_private_key, "scope-key-wrap", {k: v for k, v in body.items() if k != "sealed"}, maximum=32))


def build_create(payload: dict, policy: Any, pinned_key: bytes, device_id: str, device_private_key: bytes, *, request_id: str) -> dict:
    p = verify_policy(policy, pinned_key)
    grant = authorize_grant(p, device_id, "create")
    _id(request_id)
    if signing_public_key(device_private_key) != decode_key(grant["signing_public_key"]):
        raise AuthorizationError("contributor signing identity mismatch")
    context = {**_context(policy, p), "device_id": device_id, "grant_id": grant["grant_id"], "generation": grant["generation"],
               "request_id": request_id, "operation": "create", "inbox_public_key": p["inbox_public_key"]}
    payload = validate_create_payload(payload)
    data = canonical_bytes(payload, maximum=MAX_CREATE_SIZE)
    return _sign("create", {**context, "sealed": _hybrid_seal(data, decode_key(p["inbox_public_key"]), "create", context)}, device_private_key)


def verify_create(record: Any, policy: Any, pinned_key: bytes, *, current_policy: Any = None) -> dict:
    p = verify_policy(policy, pinned_key)
    obj = parse_record(record, maximum=2 * MAX_CREATE_SIZE)
    if type(obj.get("payload")) is not dict:
        _fail()
    candidate = obj["payload"]
    _fields(candidate, _CONTEXT_FIELDS | {"device_id", "grant_id", "generation", "request_id", "operation", "inbox_public_key", "sealed"})
    _id(candidate["grant_id"])
    _uint(candidate["generation"], 1)
    grant = authorize_grant(p, candidate["device_id"], "create", grant_id=candidate["grant_id"], generation=candidate["generation"])
    body = _verify(obj, "create", decode_key(grant["signing_public_key"]), maximum=2 * MAX_CREATE_SIZE)
    _check_context(body, policy, p)
    _id(body["request_id"])
    if body["operation"] != "create" or body["inbox_public_key"] != p["inbox_public_key"]:
        raise AuthorizationError("invalid create operation or inbox")
    if current_policy is not None:
        current = verify_policy(current_policy, pinned_key, expected_scope_id=p["scope_id"], expected_vault_id=p["vault_id"], minimum_version=p["version"], minimum_epoch=p["epoch"])
        active = authorize_grant(current, body["device_id"], "create", grant_id=body["grant_id"], generation=body["generation"])
        if active != grant or current["inbox_public_key"] != body["inbox_public_key"]:
            raise AuthorizationError("create grant is no longer active")
    _validate_sealed(body["sealed"], True, MAX_CREATE_SIZE)
    return body


def open_create(record: Any, policy: Any, pinned_key: bytes, inbox_private_key: bytes, *, current_policy: Any = None) -> dict:
    body = verify_create(record, policy, pinned_key, current_policy=current_policy)
    if agreement_public_key(inbox_private_key) != decode_key(body["inbox_public_key"]):
        raise AuthorizationError("master inbox identity mismatch")
    context = {k: v for k, v in body.items() if k != "sealed"}
    return validate_create_payload(parse_record(_hybrid_open(body["sealed"], inbox_private_key, "create", context, maximum=MAX_CREATE_SIZE), maximum=MAX_CREATE_SIZE))


def build_receipt(submission: Any, policy: Any, pinned_key: bytes, master_private_key: bytes, *, status: str,
                  canonical_entry_id: str | None = None, revision: int = 0) -> dict:
    body = verify_create(submission, policy, pinned_key)
    _master(master_private_key, pinned_key)
    context = {k: body[k] for k in _CONTEXT_FIELDS | {"device_id", "grant_id", "generation", "request_id"}}
    payload = {**context, "submission_hash": canonical_hash(parse_record(submission)), "status": status,
               "canonical_entry_id": canonical_entry_id, "revision": revision}
    record = _sign("receipt", payload, master_private_key)
    verify_receipt(record, submission, policy, pinned_key)
    return record


def verify_receipt(record: Any, submission: Any, policy: Any, pinned_key: bytes) -> dict:
    source = verify_create(submission, policy, pinned_key)
    body = _verify(record, "receipt", pinned_key, maximum=16 * 1024)
    fields = _CONTEXT_FIELDS | {"device_id", "grant_id", "generation", "request_id"}
    _fields(body, fields | {"submission_hash", "status", "canonical_entry_id", "revision"})
    if any(body[k] != source[k] for k in fields) or body["submission_hash"] != canonical_hash(parse_record(submission)):
        raise AuthenticationError("receipt submission binding mismatch")
    if body["status"] not in ("accepted", "published", "conflict", "rejected", "quarantined"):
        _fail("invalid receipt status")
    _uint(body["revision"])
    if body["status"] in ("accepted", "published"):
        _id(body["canonical_entry_id"])
        _uint(body["revision"], 1)
    elif body["canonical_entry_id"] is not None or body["revision"] != 0:
        _fail("invalid unsuccessful receipt")
    return body


def validate_create_payload(payload: Any) -> dict:
    """Validate transport-level create schema; importer also validates Entry semantics."""
    payload = parse_record(payload, maximum=MAX_CREATE_SIZE)
    _fields(payload, {"schema_version", "entry", "secret", "passphrase"})
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
        _fail("unsupported create schema")
    entry = payload["entry"]
    _fields(entry, {"name", "type", "fields", "tags", "note", "refs"})
    for key in ("name", "type", "note"):
        if type(entry[key]) is not str or len(entry[key]) > (65536 if key == "note" else 256):
            _fail("invalid create metadata")
    if not entry["name"] or not entry["type"]:
        _fail("invalid create metadata")
    if type(entry["fields"]) is not dict or type(entry["refs"]) is not list:
        _fail("invalid create metadata")
    if type(entry["tags"]) is not list or len(entry["tags"]) > 128 or any(type(t) is not str or len(t) > 256 for t in entry["tags"]):
        _fail("invalid create tags")
    for key in ("secret", "passphrase"):
        if payload[key] is not None and (type(payload[key]) is not str or len(payload[key]) > 512 * 1024):
            _fail("invalid create secret type or size")
    return payload


def build_revocation(policy: Any, pinned_key: bytes, master_private_key: bytes, *, device_id: str) -> dict:
    p = verify_policy(policy, pinned_key)
    _master(master_private_key, pinned_key)
    grant = authorize_grant(p, device_id, "read")
    return _sign("revocation", {**_context(policy, p), "device_id": device_id,
                               "grant_id": grant["grant_id"], "generation": grant["generation"]}, master_private_key)


def verify_revocation(record: Any, policy: Any, pinned_key: bytes) -> dict:
    p = verify_policy(policy, pinned_key)
    body = _verify(record, "revocation", pinned_key, maximum=16 * 1024)
    _fields(body, _CONTEXT_FIELDS | {"device_id", "grant_id", "generation"})
    _check_context(body, policy, p)
    _id(body["grant_id"])
    _uint(body["generation"], 1)
    authorize_grant(p, body["device_id"], "read", grant_id=body["grant_id"], generation=body["generation"])
    return body


def _endpoint(value: Any) -> None:
    if type(value) is not str or not value or len(value) > 2048 or any(ch.isspace() or ord(ch) < 32 or ch == "\\" for ch in value):
        _fail("invalid invitation endpoint")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
        if (parsed.scheme not in ("http", "https") or not hostname or
                parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment):
            _fail("invalid invitation endpoint")
        if port is not None and not 1 <= port <= 65535:
            _fail("invalid invitation endpoint")
        if parsed.scheme == "http":
            host = hostname.rstrip(".").lower()
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                loopback = host == "localhost" or host.endswith(".localhost")
            if not loopback:
                _fail("invitation endpoint requires HTTPS")
    except ValueError:
        raise ValidationError("invalid invitation endpoint") from None


def build_invitation(policy: Any, pinned_key: bytes, master_private_key: bytes, *,
                     invite_id: str, expires_at: int, endpoint: str) -> dict:
    p = verify_policy(policy, pinned_key)
    _master(master_private_key, pinned_key)
    _id(invite_id)
    _uint(expires_at, 1)
    _endpoint(endpoint)
    return _sign("invitation", {**_context(policy, p), "invite_id": invite_id,
                                "expires_at": expires_at, "endpoint": endpoint}, master_private_key)


def verify_invitation(record: Any, policy: Any, pinned_key: bytes, *, now: int) -> dict:
    p = verify_policy(policy, pinned_key)
    body = _verify(record, "invitation", pinned_key, maximum=16 * 1024)
    _fields(body, _CONTEXT_FIELDS | {"invite_id", "expires_at", "endpoint"})
    _check_context(body, policy, p)
    _id(body["invite_id"])
    _uint(body["expires_at"], 1)
    _uint(now)
    _endpoint(body["endpoint"])
    if body["expires_at"] <= now:
        raise ReplayError("invitation expired")
    return body


_ENROLLMENT_REQUEST_FIELDS = _CONTEXT_FIELDS | {"invitation_hash", "request_id", "device_id", "signing_public_key",
                                              "agreement_public_key", "token_hash", "role", "challenge"}


def build_enrollment_request(invitation: Any, source_policy: Any, pin: bytes, device_signing_private: bytes, *,
                             device_id: str, agreement_public_key: bytes, token_hash: str, role: str,
                             request_id: str, challenge: bytes, now: int) -> dict:
    source = verify_policy(source_policy, pin)
    verify_invitation(invitation, source_policy, pin, now=now)
    body = {**_context(source_policy, source), "invitation_hash": canonical_hash(parse_record(invitation)),
            "request_id": request_id, "device_id": device_id,
            "signing_public_key": encode_key(signing_public_key(device_signing_private)),
            "agreement_public_key": encode_key(agreement_public_key), "token_hash": token_hash,
            "role": role, "challenge": encode_key(challenge)}
    record = _sign("enrollment-request", body, device_signing_private)
    verify_enrollment_request(record, invitation, source_policy, pin, now=now)
    return record


def verify_enrollment_request(record: Any, invitation: Any, source_policy: Any, pin: bytes, *, now: int) -> dict:
    source = verify_policy(source_policy, pin)
    verify_invitation(invitation, source_policy, pin, now=now)
    candidate = parse_record(record, maximum=16 * 1024)
    body = candidate.get("payload")
    _fields(body, _ENROLLMENT_REQUEST_FIELDS)
    body = _verify(candidate, "enrollment-request", decode_key(body["signing_public_key"]), maximum=16 * 1024)
    _check_context(body, source_policy, source)
    if body["invitation_hash"] != canonical_hash(parse_record(invitation)):
        raise AuthenticationError("enrollment invitation mismatch")
    _id(body["device_id"])
    _id(body["request_id"])
    decode_key(body["agreement_public_key"])
    decode_key(body["challenge"])
    _hash(body["token_hash"])
    if body["role"] not in ("reader", "contributor"):
        _fail("invalid enrollment role")
    if body["device_id"] == source["master_device_id"] or body["signing_public_key"] == source["master_public_key"]:
        raise AuthorizationError("master identity cannot enroll as recipient")
    if body["agreement_public_key"] == source["inbox_public_key"] or body["token_hash"] == source["master_token_hash"]:
        raise AuthorizationError("master authentication cannot be delegated")
    return body


def _enrollment_answer_context(request: Any, invitation: Any, source_policy: Any, current_policy: Any, pin: bytes,
                               snapshot: Any, wrap: Any, now: int) -> dict:
    requested = verify_enrollment_request(request, invitation, source_policy, pin, now=now)
    source = verify_policy(source_policy, pin)
    current = verify_policy(current_policy, pin, expected_scope_id=source["scope_id"], expected_vault_id=source["vault_id"],
                            minimum_version=source["version"] + 1, minimum_epoch=source["epoch"] + 1)
    grant = authorize_grant(current, requested["device_id"], "read")
    if any(grant[k] != requested[k] for k in ("signing_public_key", "agreement_public_key", "token_hash", "role")):
        raise AuthorizationError("enrollment grant does not match request")
    # Enrollment is a fresh grant, never the reuse of a grant in the invitation policy.
    if any(g["grant_id"] == grant["grant_id"] for g in source["grants"]):
        raise AuthorizationError("enrollment requires a fresh grant")
    publication = verify_snapshot(snapshot, current_policy, pin)
    verify_scope_key_wrap(wrap, current_policy, pin, expected_device_id=requested["device_id"])
    return {**_context(current_policy, current), "request_hash": canonical_hash(parse_record(request)),
            "invitation_hash": canonical_hash(parse_record(invitation)), "challenge": requested["challenge"],
            "device_id": requested["device_id"], "grant_id": grant["grant_id"], "generation": grant["generation"],
            "snapshot_hash": canonical_hash(parse_record(snapshot)), "sequence": publication["sequence"],
            "wrap_hash": canonical_hash(parse_record(wrap))}


def build_enrollment_answer(request: Any, invitation: Any, source_policy: Any, current_policy: Any, pin: bytes,
                            master_private: bytes, *, snapshot: Any, wrap: Any, now: int, expires_at: int) -> dict:
    _master(master_private, pin)
    _uint(expires_at, 1)
    _uint(now)
    if expires_at <= now:
        raise ReplayError("enrollment answer expired")
    context = _enrollment_answer_context(request, invitation, source_policy, current_policy, pin, snapshot, wrap, now)
    expires_at = min(expires_at, verify_invitation(invitation, source_policy, pin, now=now)["expires_at"])
    return _sign("enrollment-answer", {**context, "expires_at": expires_at}, master_private)


def verify_enrollment_answer(answer: Any, request: Any, invitation: Any, source_policy: Any, current_policy: Any,
                             pin: bytes, *, snapshot: Any, wrap: Any, now: int) -> dict:
    context = _enrollment_answer_context(request, invitation, source_policy, current_policy, pin, snapshot, wrap, now)
    body = _verify(answer, "enrollment-answer", pin, maximum=16 * 1024)
    _fields(body, set(context) | {"expires_at"})
    if any(body[k] != v for k, v in context.items()):
        raise AuthenticationError("enrollment answer context mismatch")
    _uint(body["expires_at"], 1)
    if body["expires_at"] <= now or body["expires_at"] > verify_invitation(invitation, source_policy, pin, now=now)["expires_at"]:
        raise ReplayError("enrollment answer expired or exceeds invitation validity")
    return body
