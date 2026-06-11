"""Encrypted-file keychain backend for headless Linux (no Secret Service).

A bare Ubuntu *server* has no D-Bus session and no keyring daemon, so the
`secret-tool` path is unavailable exactly where this tool is most useful. This
backend stores every secret in a single AES-256-GCM blob at `paths.secrets_enc`,
unlocked by the `KEYS_KEEPER_MASTER_KEY` environment variable.

It reuses the same crypto primitive as `keys export` (`crypto.encrypt_blob` /
`decrypt_blob` — AES-256-GCM + PBKDF2-HMAC-SHA256, 600k iterations) and the same
cross-platform advisory lock as `MetadataStore`. No new dependencies (the file
backend rides on the existing `cryptography` dep — consistent with D-014).

Storage model: the plaintext is a JSON object mapping `account -> value`. The
whole map is decrypted once per process on first access (one PBKDF2), cached in
memory, and re-encrypted + atomically rewritten on every mutation.
"""
from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from typing import Iterator

from keys_keeper import crypto
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper._locking import lock_exclusive, unlock

_MASTER_ENV = "KEYS_KEEPER_MASTER_KEY"


class EncryptedFileBackend(KeychainBackend):
    """All secrets in one AES-256-GCM file, unlocked by KEYS_KEEPER_MASTER_KEY.

    The `service` argument is accepted for parity with the other backends (so
    tests can isolate namespaces) but only affects the in-memory cache key, not
    the file location — each KEYS_KEEPER_HOME has exactly one `secrets.enc`.
    """

    def __init__(self, *, service: str = "keys-keeper"):
        self.service = service
        self.paths = Paths()
        self._cache: dict[str, str] | None = None

    # ---- master key ----

    def _password(self) -> str:
        pw = os.environ.get(_MASTER_ENV)
        if not pw:
            raise KeychainError(
                f"{_MASTER_ENV} is not set. On a headless host without a desktop "
                f"keyring, keys-keeper encrypts secrets in a file unlocked by this "
                f"variable. Set it (e.g. `export {_MASTER_ENV}=...`), or install a "
                f"Secret Service keyring (libsecret-tools) for the OS-native backend."
            )
        return pw

    # ---- load / persist ----

    def _decrypt_file(self) -> dict[str, str]:
        """Read + decrypt the secrets file fresh from disk (no cache)."""
        path = self.paths.secrets_enc
        if not path.exists():
            return {}
        blob = path.read_bytes()
        try:
            plaintext = crypto.decrypt_blob(blob, password=self._password())
        except crypto.BadPassword as ex:
            raise KeychainError(
                f"cannot decrypt {path.name}: {ex}. Wrong {_MASTER_ENV}?"
            ) from ex
        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as ex:
            raise KeychainError(f"corrupt secrets file {path.name}: {ex}") from ex
        if not isinstance(data, dict):
            # The blob authenticated (GCM) but isn't our {account: value} map —
            # that's real corruption, not an empty store. Refuse rather than
            # silently treating it as empty and overwriting on the next write.
            raise KeychainError(f"corrupt secrets file {path.name}: not an object")
        return data

    def _load(self) -> dict[str, str]:
        """Cached decrypt for read-only callers (get / list_ids).

        Mutations do NOT use this — they re-read under the lock (see _mutate),
        so a stale cache can never clobber another process's concurrent write.
        """
        if self._cache is None:
            self._cache = self._decrypt_file()
        return self._cache

    @contextmanager
    def _mutate(self) -> Iterator[dict[str, str]]:
        """Lock → re-read from disk → yield mutable dict → encrypt + atomic write.

        Mirrors store.MetadataStore._locked_write: the read-modify-write is fully
        inside the exclusive lock, so concurrent `keys` processes serialize and
        never lose each other's updates. The lock lives on a separate file so the
        atomic rename of secrets.enc doesn't invalidate the lock fd.
        """
        # 0700 even when this is the process's first filesystem touch, so the
        # encrypted store's parent dir is never created world-readable.
        ensure_private_dir(self.paths.root)
        lock_path = self.paths.root / "secrets.lock"
        lock_fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            lock_exclusive(lock_fd)
            data = self._decrypt_file()   # fresh read under the lock, not the cache
            yield data
            plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
            blob = crypto.encrypt_blob(plaintext, password=self._password())
            self._atomic_write_bytes(blob)
            self._cache = data
        finally:
            unlock(lock_fd)
            os.close(lock_fd)

    def _atomic_write_bytes(self, blob: bytes) -> None:
        # temp file in the same dir -> fsync -> os.replace (atomic on POSIX/NTFS).
        target = self.paths.secrets_enc
        fd, tmp_path = tempfile.mkstemp(dir=self.paths.root, prefix=".secrets.", suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, target)
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass

    # ---- KeychainBackend interface ----

    def get(self, account: str) -> Sealed:
        data = self._load()
        if account not in data:
            raise KeychainError(f"secret not found: {account}")
        return Sealed(data[account])

    def set(self, account: str, value: str) -> None:
        with self._mutate() as data:
            data[account] = value

    def delete(self, account: str) -> None:
        with self._mutate() as data:
            data.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self._load().keys())
