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

Storage model: the plaintext is a JSON object mapping `account -> value`. The
whole map is decrypted once per process on first access (one PBKDF2), cached in
memory, and re-encrypted + atomically rewritten on every mutation.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from keys_keeper import crypto
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper._locking import lock_exclusive, unlock

_MASTER_ENV = "KEYS_KEEPER_MASTER_KEY"
_MAX_PASSWORD_BYTES = 64 * 1024


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
        self._cache: dict[str, str] | None = None
        self._password_cache: Sealed | None = None

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
        except UnicodeDecodeError as ex:
            raise KeychainError("file backend unlock source is not valid UTF-8") from ex
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
            before = path.lstat()
        except OSError as ex:
            raise KeychainError("cannot open file backend unlock source") from ex
        if stat.S_ISLNK(before.st_mode):
            raise KeychainError("file backend unlock source must not be a symlink")
        cls._validate_password_stat(before)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as ex:
            raise KeychainError("cannot open file backend unlock source") from ex
        try:
            opened = os.fstat(fd)
            cls._validate_password_stat(opened)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise KeychainError("file backend unlock source changed while opening")
            return cls._bounded_read(fd)
        finally:
            os.close(fd)

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
        """Read + decrypt the secrets file fresh from disk (no cache)."""
        path = self.paths.secrets_enc
        if not path.exists():
            return {}
        blob = self._secure_read_blob(path)
        try:
            plaintext = crypto.decrypt_blob(blob, password=self._password())
        except crypto.BadPassword as ex:
            raise KeychainError(
                f"cannot decrypt {path.name}: password incorrect or file corrupted"
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
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in data.items()):
            raise KeychainError(f"corrupt secrets file {path.name}: invalid entry map")
        return data

    @staticmethod
    def _secure_read_blob(path: Path) -> bytes:
        try:
            before = path.lstat()
        except OSError as ex:
            raise KeychainError("cannot inspect encrypted secrets file") from ex
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise KeychainError("encrypted secrets file must be a regular non-symlink file")
        if os.name == "posix":
            if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
                raise KeychainError("encrypted secrets file has unsafe ownership or permissions")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(path, flags)
        except OSError as ex:
            raise KeychainError("cannot open encrypted secrets file") from ex
        try:
            opened = os.fstat(fd)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                raise KeychainError("encrypted secrets file changed while opening")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                return stream.read()
        finally:
            os.close(fd)

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
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            lock_fd = os.open(lock_path, flags, 0o600)
        except OSError as ex:
            raise KeychainError("cannot open encrypted secrets lock") from ex
        try:
            info = os.fstat(lock_fd)
            if not stat.S_ISREG(info.st_mode):
                raise KeychainError("encrypted secrets lock must be a regular file")
            if os.name == "posix":
                if info.st_uid != os.getuid():
                    raise KeychainError("encrypted secrets lock must be owned by this user")
                os.fchmod(lock_fd, 0o600)
            lock_exclusive(lock_fd)
            try:
                data = self._decrypt_file()   # fresh read under the lock, not the cache
                yield data
                plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
                blob = crypto.encrypt_blob(plaintext, password=self._password())
                self._atomic_write_bytes(blob)
                self._cache = data
            finally:
                unlock(lock_fd)
        finally:
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
