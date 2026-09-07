"""Encrypted transport for the existing, signed KK3 enrollment ceremony.

The copied code carries a random 256-bit encryption key and the master pin.
The relay receives a domain-separated authentication token, never this key.
Local UIs compare the signed request fingerprint before approving a device.
"""
from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys_keeper import project_protocol as wire
from keys_keeper.backend import Sealed
from keys_keeper.project_client import ProjectClient, _id

MAX_PACKET = 24 * 1024 * 1024
PREFIX = "kk-connect-1."


class PairingError(RuntimeError):
    pass


def _encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(value, *, maximum=MAX_PACKET):
    if not isinstance(value, str) or len(value) > maximum:
        raise PairingError("Invalid connection data")
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, UnicodeError):
        raise PairingError("Invalid connection data") from None
    if _encode(raw) != value:
        raise PairingError("Invalid connection data")
    return raw


def token(key: bytes) -> str:
    if len(key) != 32:
        raise PairingError("Invalid connection key")
    return hashlib.sha256(b"keys-keeper/pairing/auth/v1\0" + key).hexdigest()


def make_code(endpoint, scope_id, pair_id, key, fingerprint):
    value = {"endpoint": endpoint, "scope_id": _id(scope_id), "pair_id": _id(pair_id),
             "key": _encode(key), "fingerprint": fingerprint}
    return PREFIX + _encode(wire.canonical_bytes(value))


def parse_code(code):
    if not isinstance(code, str) or len(code) > 4096 or not code.strip().startswith(PREFIX):
        raise PairingError("Paste the connection code from your main computer")
    try:
        value = wire.parse_record(_decode(code.strip()[len(PREFIX):], maximum=4096), maximum=4096)
        if set(value) != {"endpoint", "scope_id", "pair_id", "key", "fingerprint"}:
            raise ValueError()
        _id(value["scope_id"])
        _id(value["pair_id"])
        key = _decode(value["key"], maximum=43)
        if len(key) != 32 or len(value["fingerprint"]) != 64 or any(c not in "0123456789abcdef" for c in value["fingerprint"]):
            raise ValueError()
        ProjectClient(base_url=value["endpoint"])
        return value
    except (ValueError, TypeError, RuntimeError):
        raise PairingError("Invalid connection code") from None


def seal(key, pair_id, slot, value):
    nonce = secrets.token_bytes(12)
    aad = f"keys-keeper/pairing/v1/{_id(pair_id)}/{slot}".encode()
    return _encode(nonce + AESGCM(key).encrypt(nonce, wire.canonical_bytes(value, maximum=16 * 1024 * 1024), aad))


def open_packet(key, pair_id, slot, packet):
    raw = _decode(packet)
    aad = f"keys-keeper/pairing/v1/{_id(pair_id)}/{slot}".encode()
    try:
        return wire.parse_record(AESGCM(key).decrypt(raw[:12], raw[12:], aad), maximum=16 * 1024 * 1024)
    except (ValueError, InvalidTag, wire.ProtocolError):
        raise PairingError("Connection data could not be verified") from None


def comparison(fingerprint):
    return " ".join(fingerprint[i:i + 4].upper() for i in range(0, 24, 4))


class PairingClient(ProjectClient):
    def _request(self, method, path, **kwargs):
        kwargs.setdefault("include_device", False)
        return super()._request(method, path, **kwargs)


def client(endpoint, key):
    return PairingClient(base_url=endpoint, token=Sealed(token(key)))


def route(scope_id, pair_id=None, slot=None):
    path = f"/v2/scopes/{_id(scope_id)}/pairings"
    if pair_id is not None:
        path += "/" + _id(pair_id)
    if slot is not None:
        if slot not in {"request", "response"}:
            raise PairingError("Invalid connection operation")
        path += "/" + slot
    return path
