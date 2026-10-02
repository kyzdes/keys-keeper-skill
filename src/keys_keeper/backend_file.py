"""Encrypted-file keychain backend for headless Linux (no Secret Service).

A bare Ubuntu *server* has no D-Bus session and no keyring daemon, so the
`secret-tool` path is unavailable exactly where this tool is most useful. This
backend stores every secret in a single AES-256-GCM blob at `paths.secrets_enc`.
Legacy master callers may unlock it with `KEYS_KEEPER_MASTER_KEY`; isolated
profiles use an explicit owner-only password file or inherited file descriptor.

It reuses the same crypto primitive as `keys export` (`crypto.encrypt_blob` /
`decrypt_blob` — AES-256-GCM + PBKDF2-HMAC-SHA256, 600k iterations) and the same
cross-platform advisory lock as `MetadataStore`. No new dependencies (the file
backend rides on the existing `cryptography` dep — consistent with D-014).

Storage model: the plaintext is a JSON object mapping `account -> value`. Each
read authenticates fresh ciphertext. One current salt/key pair stays inside
this backend object; unchanged mutations do not encrypt or rewrite the map.
"""
from __future__ import annotations

import json
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from keys_keeper import crypto
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed, SecretNotFound, SecretUnavailable
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper.private_files import (
    PrivateFileError, atomic_write_bytes, open_private_file, secure_read,
)
from keys_keeper._locking import lock_exclusive, unlock

_MASTER_ENV = "KEYS_KEEPER_MASTER_KEY"
_MAX_PASSWORD_BYTES = 64 * 1024
_MAX_BLOB_BYTES = 64 * 1024 * 1024


class EncryptedFileBackend(KeychainBackend):
    """All secrets in one AES-256-GCM file under explicitly selected paths."""

    def __init__(
        self,
        *,
        service: str = "keys-keeper",
        paths: Paths | None = None,
        password_file: Path | None = None,
        password_fd: int | None = None,
        allow_env_password: bool = True,
    ):
        if password_file is not None and password_fd is not None:
            raise ValueError("password_file and password_fd are mutually exclusive")
        if password_fd is not None and (not isinstance(password_fd, int) or password_fd < 0):
            raise ValueError("password_fd must be a non-negative file descriptor")
        self.service = service
        self.paths = paths or Paths()
        self.password_file = Path(password_file) if password_file is not None else None
        self.password_fd = password_fd
        self.allow_env_password = allow_env_password
        self._password_cache: Sealed | None = None
        self._derived_key_cache: tuple[bytes, bytes] | None = None
        self._cache_identity = self._identity()

    def __getstate__(self):
        raise TypeError("file backend contains process-local unlocking material")

    def _identity(self):
        return (self.service, self.paths.root.resolve(),
                self.password_file.resolve() if self.password_file is not None else None,
                self.password_fd, self.allow_env_password)

    def _bind_identity(self):
        identity = self._identity()
        if identity != self._cache_identity:
            self._password_cache = None
            self._derived_key_cache = None
            self._cache_identity = identity

    # ---- master key ----

    def _password(self) -> str:
        if self._password_cache is not None:
            return self._password_cache.unseal()
        if self.password_file is not None:
            raw = self._read_password_file(self.password_file)
            source = "explicit unlock source"
        elif self.password_fd is not None:
            raw = self._read_password_fd(self.password_fd)
            source = "explicit unlock source"
        elif self.allow_env_password:
            value = os.environ.get(_MASTER_ENV)
            raw = value.encode("utf-8") if value else b""
            source = _MASTER_ENV
        else:
            raise KeychainError(
                "profile file backend has no explicit unlock source; provision its "
                "owner-only password file or pass an inherited descriptor"
            )
        raw = raw[:-1] if raw.endswith(b"\n") else raw
        raw = raw[:-1] if raw.endswith(b"\r") else raw
        if not raw:
            raise KeychainError(f"{source} is missing or empty")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise SecretUnavailable("file backend unlock source is not valid UTF-8") from None
        self._password_cache = Sealed(value)
        return value

    @staticmethod
    def _validate_password_stat(info: os.stat_result) -> None:
        if not stat.S_ISREG(info.st_mode):
            raise KeychainError("file backend unlock source must be a regular file")
        if os.name == "posix":
            if info.st_uid != os.getuid():
                raise KeychainError("file backend unlock source must be owned by this user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise KeychainError(
                    "file backend unlock source permissions must be 0600 or stricter"
                )

    @classmethod
    def _read_password_file(cls, path: Path) -> bytes:
        try:
            return secure_read(path, max_bytes=_MAX_PASSWORD_BYTES)
        except (PrivateFileError, OSError):
            raise SecretUnavailable(
                "file backend unlock source must be a bounded private regular non-symlink file; "
                "safe ownership and permissions are required"
            ) from None

    @classmethod
    def _read_password_fd(cls, source_fd: int) -> bytes:
        try:
            fd = os.dup(source_fd)
        except OSError as ex:
            raise KeychainError("cannot duplicate file backend unlock descriptor") from ex
        try:
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                cls._validate_password_stat(info)
                if os.name == "nt":
                    from keys_keeper.windows_file_security import validate_fd
                    try:
                        validate_fd(fd)
                    except OSError:
                        raise SecretUnavailable("file backend unlock descriptor is not private") from None
            return cls._bounded_read(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _bounded_read(fd: int) -> bytes:
        chunks: list[bytes] = []
        remaining = _MAX_PASSWORD_BYTES + 1
        try:
            while remaining:
                chunk = os.read(fd, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        except OSError as ex:
            raise KeychainError("cannot read file backend unlock source") from ex
        raw = b"".join(chunks)
        if len(raw) > _MAX_PASSWORD_BYTES:
            raise KeychainError("file backend unlock source is too large")
        return raw

    # ---- load / persist ----

    def _decrypt_file(self) -> dict[str, str]:
        """Read fresh ciphertext and authenticate it even when its salt is cached."""
        self._bind_identity()
        path = self.paths.secrets_enc
        try:
            blob = self._secure_read_blob(path)
            salt = crypto._blob_salt(blob)
            cached = self._derived_key_cache
            key = cached[1] if cached is not None and cached[0] == salt else crypto._derive_key(self._password(), salt)
            plaintext = crypto._decrypt_blob_with_key(blob, key=key)
            data = json.loads(plaintext.decode("utf-8"))
            if not isinstance(data, dict) or not all(
                isinstance(account, str) and isinstance(value, str) for account, value in data.items()
            ):
                raise KeychainError("corrupt encrypted secrets entry map")
        except FileNotFoundError:
            self._derived_key_cache = None
            return {}
        except (crypto.BadPassword, ValueError, UnicodeError, RecursionError):
            self._derived_key_cache = None
            raise SecretUnavailable(
                f"cannot decrypt {path.name}: password incorrect or file corrupted"
            ) from None
        except Exception:
            self._derived_key_cache = None
            raise
        self._derived_key_cache = (salt, key)
        return data

    @staticmethod
    def _secure_read_blob(path: Path) -> bytes:
        try:
            return secure_read(path, max_bytes=_MAX_BLOB_BYTES)
        except FileNotFoundError:
            raise
        except PrivateFileError as ex:
            # Shared file errors contain only fixed metadata diagnostics.
            raise SecretUnavailable(str(ex)) from None
        except OSError:
            raise SecretUnavailable("cannot open encrypted secrets file") from None

    def _load(self) -> dict[str, str]:
        return self._decrypt_file()

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
        try:
            lock_fd = open_private_file(lock_path, os.O_RDWR | os.O_CREAT)
        except (PrivateFileError, OSError):
            raise SecretUnavailable("cannot open encrypted secrets lock") from None
        try:
            lock_exclusive(lock_fd)
            try:
                original = self._decrypt_file()
                data = dict(original)
                yield data
                if data == original:
                    return
                if not all(isinstance(account, str) and isinstance(value, str) for account, value in data.items()):
                    raise KeychainError("invalid encrypted secrets entry map")
                plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
                if len(plaintext) + 48 > _MAX_BLOB_BYTES:
                    raise KeychainError("encrypted secrets file exceeds size limit")
                blob, key = crypto._encrypt_blob_with_key(plaintext, password=self._password())
                self._atomic_write_bytes(blob)
                self._derived_key_cache = (crypto._blob_salt(blob), key)
            finally:
                unlock(lock_fd)
        finally:
            os.close(lock_fd)

    def _atomic_write_bytes(self, blob: bytes) -> None:
        atomic_write_bytes(self.paths.secrets_enc, blob)

    # ---- KeychainBackend interface ----

    def get(self, account: str) -> Sealed:
        try:
            data = self._load()
        except SecretUnavailable:
            raise
        except KeychainError:
            raise SecretUnavailable("encrypted secrets provider unavailable") from None
        if account not in data:
            raise SecretNotFound(f"secret not found: {account}")
        return Sealed(data[account])

    def set(self, account: str, value: str) -> None:
        with self._mutate() as data:
            data[account] = value

    def delete(self, account: str) -> None:
        with self._mutate() as data:
            data.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self._load().keys())
