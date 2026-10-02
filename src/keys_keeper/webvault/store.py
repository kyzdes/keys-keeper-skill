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
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import scrypt
from pathlib import Path

from keys_keeper.private_files import (
    PrivateFileError, atomic_write_bytes as _atomic_write_bytes, secure_read as _secure_read,
)

# scrypt work factors (n*r*128 bytes ≈ 16 MiB at these settings).
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024

# Bound concurrent scrypt work: each call transiently allocates ~16 MiB, so an
# unauthenticated flood of /auth/login + /auth/register could otherwise spawn
# unbounded large allocations and exhaust memory. A module-level semaphore caps
# how many scrypt computations run at once; excess requests block briefly (and
# the per-IP rate limiter in the server sheds the real flood before it gets here).
_SCRYPT_CONCURRENCY = max(2, min(8, (os.cpu_count() or 2)))
_scrypt_gate = threading.Semaphore(_SCRYPT_CONCURRENCY)
_MAX_ACCOUNTS = 10_000
_MAX_ACCOUNTS_BYTES = 16 * 1024 * 1024
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def _scrypt(auth_hash_hex: str, salt: bytes) -> bytes:
    with _scrypt_gate:
        return scrypt(bytes.fromhex(auth_hash_hex), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R,
                      p=_SCRYPT_P, dklen=_SCRYPT_DKLEN, maxmem=_SCRYPT_MAXMEM)


class AccountError(RuntimeError):
    pass


class AccountStoreError(AccountError):
    """The existing registry cannot safely be read or replaced."""


class SessionCapacityError(AccountError):
    pass


def _valid_uid(uid: object) -> bool:
    return (isinstance(uid, str) and 0 < len(uid) <= 128
            and uid.replace("-", "").replace("_", "").replace("@", "").replace(".", "").isalnum())


def _valid_account(record: object, uid: str) -> bool:
    if not isinstance(record, dict) or set(record) != set(Account.__dataclass_fields__):
        return False
    prefix = record["prefix"]
    return (record["uid"] == uid and _valid_uid(uid)
            and isinstance(prefix, str) and 0 < len(prefix) <= 1024
            and "\\" not in prefix and all(p not in {"", ".", ".."} for p in prefix.split("/"))
            and type(record["auth_iters"]) is int and 600_000 <= record["auth_iters"] < 2**31
            and all(isinstance(record[k], str) and pattern.fullmatch(record[k])
                    for k, pattern in (("auth_salt", _HEX32), ("scrypt_salt", _HEX32),
                                       ("scrypt_hash", _HEX64))))


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
        self._initialized = False

    def _read(self) -> dict:
        try:
            raw = _secure_read(self.path, max_bytes=_MAX_ACCOUNTS_BYTES)
        except FileNotFoundError:
            if not self._initialized:
                return {"accounts": {}}
            raise AccountStoreError("account registry unavailable") from None
        except (PrivateFileError, OSError):
            raise AccountStoreError("account registry unavailable") from None
        try:
            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate member")
                    result[key] = value
                return result
            data = json.loads(raw, object_pairs_hook=pairs)
            if (not isinstance(data, dict) or set(data) != {"accounts"}
                    or not isinstance(data["accounts"], dict)
                    or len(data["accounts"]) > _MAX_ACCOUNTS
                    or any(not _valid_account(rec, uid) for uid, rec in data["accounts"].items())):
                raise ValueError("invalid registry")
        except (ValueError, UnicodeError, RecursionError):
            raise AccountStoreError("account registry invalid") from None
        self._initialized = True
        return data

    def _write(self, data: dict) -> None:
        try:
            encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
            if len(encoded) > _MAX_ACCOUNTS_BYTES:
                raise AccountStoreError("account registry capacity exceeded")
            _atomic_write_bytes(self.path, encoded)
        except (PrivateFileError, OSError):
            raise AccountStoreError("account registry unavailable") from None
        self._initialized = True

    def exists(self, uid: str) -> bool:
        return uid in self._read()["accounts"]

    def get(self, uid: str) -> Account | None:
        rec = self._read()["accounts"].get(uid)
        return Account(**rec) if rec else None

    def register(self, *, uid: str, prefix: str, auth_salt: str, auth_iters: int,
                 auth_hash: str) -> Account:
        if not _valid_uid(uid):
            raise AccountError("invalid uid")
        if (not isinstance(auth_salt, str) or not _HEX32.fullmatch(auth_salt)
                or not isinstance(auth_hash, str) or not _HEX64.fullmatch(auth_hash)
                or type(auth_iters) is not int or not 600_000 <= auth_iters < 2**31):
            raise AccountError("invalid authentication parameters")
        if (not isinstance(prefix, str) or not 0 < len(prefix) <= 1024 or "\\" in prefix
                or any(p in {"", ".", ".."} for p in prefix.split("/"))):
            raise AccountError("invalid account prefix")
        with self._lock:
            data = self._read()
            if uid in data["accounts"]:
                raise AccountError("account already exists")
            if len(data["accounts"]) >= _MAX_ACCOUNTS:
                raise AccountError("account registry capacity exceeded")
            scrypt_salt = secrets.token_bytes(16)
            acct = Account(
                uid=uid, prefix=prefix, auth_salt=auth_salt, auth_iters=auth_iters,
                scrypt_salt=scrypt_salt.hex(),
                scrypt_hash=_scrypt(auth_hash, scrypt_salt).hex(),
            )
            data["accounts"][uid] = acct.__dict__
            self._write(data)
            return acct

    def verify(self, uid: str, auth_hash: str) -> bool:
        if not _valid_uid(uid) or not isinstance(auth_hash, str) or not _HEX64.fullmatch(auth_hash):
            return False
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

    def __init__(self, idle_sec: int = 15 * 60, *, max_sessions: int = 4096):
        if type(max_sessions) is not int or max_sessions < 1:
            raise ValueError("max_sessions must be a positive integer")
        self.idle_sec = idle_sec
        self.max_sessions = max_sessions
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        # Entries are ordered by their last refresh; monotonic expiry preserves
        # that order. Abandoned tokens are reclaimed without a full-table scan.
        while self._sessions:
            token, session = next(iter(self._sessions.items()))
            if session.expires > now:
                break
            self._sessions.pop(token)

    def create(self, uid: str) -> str:
        token = secrets.token_hex(32)
        with self._lock:
            now = time.monotonic()
            self._expire(now)
            if len(self._sessions) >= self.max_sessions:
                raise SessionCapacityError("session capacity exceeded")
            self._sessions[token] = _Session(uid, now + self.idle_sec)
        return token

    def resolve(self, token: str | None) -> str | None:
        """Return the uid for a live token (refreshing its idle window), else None."""
        if not token:
            return None
        with self._lock:
            now = time.monotonic()
            self._expire(now)
            s = self._sessions.get(token)
            if s is None:
                self._sessions.pop(token, None)
                return None
            s.expires = now + self.idle_sec
            self._sessions.move_to_end(token)
            return s.uid

    def destroy(self, token: str | None) -> None:
        if token:
            with self._lock:
                self._sessions.pop(token, None)
