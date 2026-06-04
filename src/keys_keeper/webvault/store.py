"""Accounts + sessions for the web vault.

Zero-knowledge auth split: the browser derives an auth-hash `AH` from the
passphrase via PBKDF2 with a per-account salt (a DIFFERENT salt than the blob),
and sends `AH` (over TLS) to log in. We store only `scrypt(AH)` — a one-way
image that lets us verify membership but is useless for decrypting the vault
(the blob key is `PBKDF2(passphrase, blob.salt)`, derived only in the browser).

stdlib only (`hashlib.scrypt`, `hmac`, `secrets`) — keeps the zero-dep promise.
Accounts persist to a JSON file; sessions live in memory with an idle timeout.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass
from hashlib import scrypt
from pathlib import Path

# scrypt work factors (n*r*128 bytes ≈ 16 MiB at these settings).
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def _scrypt(auth_hash_hex: str, salt: bytes) -> bytes:
    return scrypt(bytes.fromhex(auth_hash_hex), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                  p=_SCRYPT_P, dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM)


class AccountError(RuntimeError):
    pass


@dataclass
class Account:
    uid: str
    prefix: str            # S3 key namespace for this account's vault
    auth_salt: str         # hex — the per-account PBKDF2 salt the BROWSER uses for AH
    auth_iters: int        # PBKDF2 iterations for AH (browser must match)
    scrypt_salt: str       # hex — server-side salt for storing scrypt(AH)
    scrypt_hash: str       # hex — scrypt(AH) (what we actually persist)


class AccountStore:
    """JSON-backed account registry. All secrets here are one-way (scrypt of an
    auth-hash); there is no plaintext passphrase or vault key anywhere."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def _read(self) -> dict:
        if not self.path.exists():
            return {"accounts": {}}
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {"accounts": {}}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    def exists(self, uid: str) -> bool:
        return uid in self._read()["accounts"]

    def get(self, uid: str) -> Account | None:
        rec = self._read()["accounts"].get(uid)
        return Account(**rec) if rec else None

    def register(self, *, uid: str, prefix: str, auth_salt: str, auth_iters: int,
                 auth_hash: str) -> Account:
        if not uid or not uid.replace("-", "").replace("_", "").replace("@", "").replace(".", "").isalnum():
            raise AccountError("invalid uid")
        with self._lock:
            data = self._read()
            if uid in data["accounts"]:
                raise AccountError("account already exists")
            scrypt_salt = secrets.token_bytes(16)
            acct = Account(
                uid=uid, prefix=prefix, auth_salt=auth_salt, auth_iters=int(auth_iters),
                scrypt_salt=scrypt_salt.hex(),
                scrypt_hash=_scrypt(auth_hash, scrypt_salt).hex(),
            )
            data["accounts"][uid] = acct.__dict__
            self._write(data)
            return acct

    def verify(self, uid: str, auth_hash: str) -> bool:
        acct = self.get(uid)
        if acct is None:
            # constant-ish work even for unknown users (don't leak existence by timing)
            _scrypt("00" * 32, secrets.token_bytes(16))
            return False
        try:
            got = _scrypt(auth_hash, bytes.fromhex(acct.scrypt_salt))
        except ValueError:
            return False
        return hmac.compare_digest(got.hex(), acct.scrypt_hash)


@dataclass
class _Session:
    uid: str
    expires: float


class SessionStore:
    """In-memory sessions with idle timeout. Tokens are 256-bit random."""

    def __init__(self, idle_sec: int = 15 * 60):
        self.idle_sec = idle_sec
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def create(self, uid: str) -> str:
        token = secrets.token_hex(32)
        with self._lock:
            self._sessions[token] = _Session(uid, time.time() + self.idle_sec)
        return token

    def resolve(self, token: str | None) -> str | None:
        """Return the uid for a live token (refreshing its idle window), else None."""
        if not token:
            return None
        with self._lock:
            s = self._sessions.get(token)
            now = time.time()
            if s is None or s.expires < now:
                self._sessions.pop(token, None)
                return None
            s.expires = now + self.idle_sec
            return s.uid

    def destroy(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)
