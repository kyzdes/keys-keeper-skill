"""AES-256-GCM with PBKDF2-HMAC-SHA256 for keys-keeper export blobs.

File format (binary):
  4 bytes : magic "KK1\\0"  (version byte = 0)
  16 bytes : salt
  12 bytes : nonce
  N bytes  : ciphertext + 16-byte GCM tag (combined by AESGCM)
"""
from __future__ import annotations
import os
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class BadPassword(RuntimeError):
    pass


_MAGIC = b"KK1\x00"
_KDF_ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_blob(data: bytes, *, password: str) -> bytes:
    blob, _key = _encrypt_blob_with_key(data, password=password)
    return blob


def _encrypt_blob_with_key(data: bytes, *, password: str) -> tuple[bytes, bytes]:
    """Return the new blob and its key for a process-local journal cache only."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, data, _MAGIC)
    return _MAGIC + salt + nonce + ct, key


def decrypt_blob(blob: bytes, *, password: str) -> bytes:
    salt = _blob_salt(blob)
    key = _derive_key(password, salt)
    return _decrypt_blob_with_key(blob, key=key)


def _blob_salt(blob: bytes) -> bytes:
    """Validate the fixed header and GCM tag before considering a cached key."""
    if len(blob) < 48 or blob[:4] != _MAGIC:
        raise BadPassword("not a keys-keeper export blob")
    return blob[4:20]


def _decrypt_blob_with_key(blob: bytes, *, key: bytes) -> bytes:
    _blob_salt(blob)
    nonce = blob[20:32]
    ct = blob[32:]
    try:
        return AESGCM(key).decrypt(nonce, ct, _MAGIC)
    except Exception as ex:
        raise BadPassword("password incorrect or file corrupted") from ex
