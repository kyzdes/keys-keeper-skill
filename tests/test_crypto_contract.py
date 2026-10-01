"""Independent KK1 compatibility checks with the real 600,000-round KDF.

Fixtures are synthetic bytes; no user backend, file, vault or secret is read.
"""
import hashlib

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys_keeper import crypto


PASSWORD = "synthetic-compatibility-🔑"
PLAINTEXT = b"\x00binary\xff\n" + "synthetic-кириллица".encode()
MAGIC = b"KK1\x00"
ITERATIONS = 600_000


@pytest.fixture(scope="module")
def production_blob():
    return crypto.encrypt_blob(PLAINTEXT, password=PASSWORD)


def independent_key(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=32)


def test_independent_decoder_accepts_production_kk1_and_pins_kdf_parameters(production_blob):
    assert production_blob[:4] == MAGIC
    key = independent_key(PASSWORD, production_blob[4:20])
    assert AESGCM(key).decrypt(production_blob[20:32], production_blob[32:], MAGIC) == PLAINTEXT


def test_production_decoder_accepts_independently_encoded_kk1():
    salt, nonce = bytes(range(16)), bytes(range(12))
    key = independent_key(PASSWORD, salt)
    blob = MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, PLAINTEXT, MAGIC)
    assert crypto.decrypt_blob(blob, password=PASSWORD) == PLAINTEXT


def test_repeated_encryption_uses_fresh_salt_and_nonce(production_blob):
    another = crypto.encrypt_blob(PLAINTEXT, password=PASSWORD)
    assert another[4:20] != production_blob[4:20]
    assert another[20:32] != production_blob[20:32]
    assert another[32:] != production_blob[32:]


@pytest.mark.parametrize("component", ["magic", "salt", "nonce", "ciphertext", "tag", "truncate"])
def test_modified_components_never_return_plaintext(production_blob, component):
    modified = bytearray(production_blob)
    if component == "truncate":
        modified.pop()
    else:
        position = {"magic": 3, "salt": 4, "nonce": 20, "ciphertext": 32, "tag": -1}[component]
        modified[position] ^= 1
    with pytest.raises(crypto.BadPassword) as caught:
        crypto.decrypt_blob(bytes(modified), password=PASSWORD)
    assert PASSWORD not in str(caught.value)
    assert "synthetic" not in str(caught.value)
