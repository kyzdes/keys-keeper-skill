"""Independent wire decoding, with no production serialization/KDF helpers.

Written by the integration reviewer, separately from the protocol author.
This cross-implementation check is not a claim of external cryptographic audit.
"""
import base64
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DOMAIN = b"keys-keeper/KK3-projects-v1/"


def serialize(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def hkdf(shared, salt, info, length=32):
    # RFC 5869 sections 2.2 and 2.3, using stdlib HMAC instead of production HKDF.
    prk = hmac.digest(salt, shared, "sha256")
    output, previous = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        output += previous
    return output[:length]


def verify_record(record, public_key):
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    message = DOMAIN + b"signature/" + record["kind"].encode() + b"\0" + serialize(unsigned)
    Ed25519PublicKey.from_public_bytes(public_key).verify(decode(record["signature"]), message)
    return record["payload"]


def decrypt_wrap(record, private):
    body = record["payload"]
    context = {k: v for k, v in body.items() if k != "sealed"}
    sealed = body["sealed"]
    ephemeral = decode(sealed["ephemeral_public_key"])
    shared = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(ephemeral))
    key = hkdf(shared, decode(sealed["salt"]), DOMAIN + b"kdf/scope-key-wrap\0" + ephemeral + serialize(context))
    return AESGCM(key).decrypt(decode(sealed["nonce"]), decode(sealed["ciphertext"]),
                               DOMAIN + b"aead/scope-key-wrap\0" + serialize(context))


@pytest.fixture
def vector():
    return json.loads((Path(__file__).parent / "fixtures/project_protocol/vector.json").read_text())


def test_independent_hkdf_matches_rfc5869_a1():
    assert hkdf(bytes([11]) * 22, bytes(range(13)), bytes(range(240, 250)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")


def test_independent_decoder_checks_existing_signature_wrap_and_snapshot(vector):
    pin = decode(vector["pin"])
    for name in ("policy", "wrap", "snapshot"):
        verify_record(vector[name], pin)
    key = decrypt_wrap(vector["wrap"], bytes([4]) * 32)
    assert key == bytes([7]) * 32
    snapshot = vector["snapshot"]
    assert hashlib.sha256(serialize(snapshot)).hexdigest() == vector["snapshot_hash"]
    context = {k: v for k, v in snapshot["payload"].items() if k != "sealed"}
    sealed = snapshot["payload"]["sealed"]
    plaintext = AESGCM(key).decrypt(decode(sealed["nonce"]), decode(sealed["ciphertext"]),
                                    DOMAIN + b"aead/snapshot\0" + serialize(context))
    assert plaintext == b'{"entries":[]}'


def test_production_accepts_wrap_emitted_by_independent_encoder(vector):
    from keys_keeper import project_protocol as production
    record = deepcopy(vector["wrap"])
    context = {k: v for k, v in record["payload"].items() if k != "sealed"}
    private = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    ephemeral = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    shared = private.exchange(X25519PublicKey.from_public_bytes(decode(context["recipient_public_key"])))
    salt, nonce = bytes(range(32, 64)), bytes(range(12))
    key = hkdf(shared, salt, DOMAIN + b"kdf/scope-key-wrap\0" + ephemeral + serialize(context))
    encrypted = AESGCM(key).encrypt(nonce, bytes([7]) * 32, DOMAIN + b"aead/scope-key-wrap\0" + serialize(context))
    record["payload"] = {**context, "sealed": {"ephemeral_public_key": encode(ephemeral),
        "salt": encode(salt), "nonce": encode(nonce), "ciphertext": encode(encrypted)}}
    unsigned = {k: v for k, v in record.items() if k != "signature"}
    record["signature"] = encode(Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).sign(
        DOMAIN + b"signature/scope-key-wrap\0" + serialize(unsigned)))
    assert production.unwrap_scope_key(record, vector["policy"], decode(vector["pin"]),
        vector["device_id"], bytes([4]) * 32) == bytes([7]) * 32


def test_independent_checks_detect_type_confusion_and_context_swap(vector):
    forged = deepcopy(vector["wrap"])
    forged["kind"] = "snapshot"
    with pytest.raises(InvalidSignature):
        verify_record(forged, decode(vector["pin"]))
    forged = deepcopy(vector["wrap"])
    forged["payload"]["scope_id"] = "ffffffff-ffff-4fff-8fff-ffffffffffff"
    with pytest.raises(InvalidTag):
        decrypt_wrap(forged, bytes([4]) * 32)
