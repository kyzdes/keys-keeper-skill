"""Bounded private durable-file IO; standard library only, no crypto dependency."""
from __future__ import annotations

import errno
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from uuid import uuid4

from keys_keeper.paths import ensure_private_dir


class PrivateFileError(RuntimeError):
    """A durable file does not satisfy ownership/type/size/race requirements."""


class PrivateFileCommitError(PrivateFileError):
    """Publication committed but parent fsync failed; callers must not retry."""
    committed = True


_DEFAULT_MAX_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PrivateFileState:
    """One bounded read for optimistic replacement; payload never appears in repr."""
    path: Path
    data: bytes = field(repr=False)
    identity: tuple[int, int] | None
    mode: int | None
    fingerprint: tuple[int, int, int] | None
    max_bytes: int
    require_private: bool


def _fingerprint(info: os.stat_result) -> tuple[int, int, int]:
    return info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _validate_file(info: os.stat_result, *, require_private: bool) -> None:
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise PrivateFileError("refusing non-regular or symlink durable state file")
    if os.name == "posix":
        if info.st_uid != os.geteuid() or (require_private and stat.S_IMODE(info.st_mode) & 0o077):
            raise PrivateFileError("durable state file has unsafe ownership or permissions")


def _open_read(path: Path, flags: int) -> int:
    if os.name == "nt":
        from keys_keeper.windows_file_security import open_read
        return open_read(path)
    return os.open(path, flags)


def secure_read_state(path: Path, *, max_bytes: int | None = None,
                      require_private: bool = True, missing_ok: bool = False) -> PrivateFileState:
    """Read bounded bytes without following the final link or blocking on a FIFO.

    The opened descriptor remains authoritative. A read changed in place is
    rejected; replacement also compares fresh bytes and timestamps. These are
    optimistic conflict checks, not exclusion of noncooperative writers between
    the final check and rename. Callers requiring isolation use a shared lock.
    """
    path = Path(path)
    maximum = _DEFAULT_MAX_BYTES if max_bytes is None else max_bytes
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer")
    try:
        before = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return PrivateFileState(path, b"", None, None, None, maximum, require_private)
        raise
    except OSError as ex:
        raise PrivateFileError("cannot inspect durable state file") from ex
    _validate_file(before, require_private=require_private)
    if before.st_size > maximum:
        raise PrivateFileError("durable state file exceeds size limit")
    # Windows CRT descriptors default to text mode.  Ciphertext can contain
    # CRLF and CTRL-Z bytes, so os.read() must use an explicitly binary fd.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        fd = _open_read(path, flags)
    except OSError as ex:
        raise PrivateFileError("cannot open durable state file") from ex
    try:
        opened = os.fstat(fd)
        _validate_file(opened, require_private=require_private)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PrivateFileError("durable state file changed while opening")
        if os.name == "nt":
            from keys_keeper.windows_file_security import validate_fd
            validate_fd(fd, require_private=require_private)
        if opened.st_size > maximum:
            raise PrivateFileError("durable state file exceeds size limit")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            size = min(1024 * 1024, remaining)
            chunk = os.read(fd, size)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        result = b"".join(chunks)
        if len(result) > maximum:
            raise PrivateFileError("durable state file exceeds size limit")
        after = os.fstat(fd)
        if _fingerprint(opened) != _fingerprint(after):
            raise PrivateFileError("durable state file changed while reading")
        return PrivateFileState(path, result, (opened.st_dev, opened.st_ino),
                                stat.S_IMODE(opened.st_mode), _fingerprint(opened),
                                maximum, require_private)
    except OSError as ex:
        raise PrivateFileError("cannot safely read durable state file") from ex
    finally:
        os.close(fd)


def secure_read(path: Path, *, max_bytes: int | None = None, require_private: bool = True) -> bytes:
    return secure_read_state(path, max_bytes=max_bytes, require_private=require_private).data


def open_private_file(path: Path, flags: int) -> int:
    """Owner-private append/create descriptor for audit and lock streams.

    Truncation occurs only after descriptor validation. Windows existing ACLs
    must already satisfy the private policy; existing directories are unaffected.
    """
    path = Path(path)
    if os.name == "nt":
        from keys_keeper.windows_file_security import open_private_file as native_open
        return native_open(path, flags)
    fd = os.open(path, (flags & ~os.O_TRUNC) | getattr(os, "O_NONBLOCK", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        _validate_file(os.fstat(fd), require_private=False)
        os.fchmod(fd, 0o600)
        if flags & os.O_TRUNC:
            os.ftruncate(fd, 0)
        return fd
    except BaseException:
        os.close(fd)
        raise


def create_private_temp(parent: Path, *, prefix: str = ".keys-", suffix: str = ".tmp",
                        mode: int = 0o600) -> tuple[int, Path]:
    """Create an owner-private tempfile before writing any secret payload."""
    if mode & ~0o600:
        raise ValueError("private file mode cannot grant group/other access")
    if os.name == "nt":
        from keys_keeper.windows_file_security import create_private_file
        for _ in range(64):
            candidate = Path(parent) / f"{prefix}{uuid4().hex}{suffix}"
            try:
                return create_private_file(candidate), candidate
            except FileExistsError:
                continue
        raise PrivateFileError("cannot allocate a private temporary file")
    fd, name = tempfile.mkstemp(dir=parent, prefix=prefix, suffix=suffix)
    try:
        os.fchmod(fd, mode)
    except BaseException:
        os.close(fd)
        os.unlink(name)
        raise
    return fd, Path(name)


def _check_expected(expected: PrivateFileState) -> None:
    try:
        current = secure_read_state(expected.path, max_bytes=expected.max_bytes,
                                    require_private=expected.require_private, missing_ok=True)
    except (OSError, PrivateFileError) as ex:
        raise PrivateFileError("target changed before write") from ex
    if (current.identity != expected.identity or current.fingerprint != expected.fingerprint
            or current.mode != expected.mode or current.data != expected.data):
        raise PrivateFileError("target changed before write")


def atomic_write_bytes(path: Path, data: bytes, *, sync_parent=None,
                       replace_existing: bool = True, expected: PrivateFileState | None = None,
                       ensure_parent_private: bool = True, mode: int = 0o600) -> None:
    """Publish a complete private file; optional state rejects read/write conflicts.

    User-chosen export/sink directories use ensure_parent_private=False: their
    permissions are never altered. Private temp security is independent of the
    parent. Missing expected targets use create-only publication even when the
    caller requested replacement, so a competing newly created file survives.
    """
    path = Path(path)
    if expected is not None and expected.path != path:
        raise ValueError("expected state belongs to a different file")
    if ensure_parent_private:
        ensure_private_dir(path.parent)
    else:
        parent = path.parent.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode)
                or getattr(parent, "st_file_attributes", 0) & 0x400):
            raise PrivateFileError("target parent must be a non-symlink directory")
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        _validate_file(existing, require_private=False)
        if os.name == "nt":
            from keys_keeper.windows_file_security import validate_path
            validate_path(path, require_private=ensure_parent_private)
    if existing is not None and not replace_existing:
        raise FileExistsError(errno.EEXIST, "durable state file already exists", path)
    fd, temporary = create_private_temp(path.parent, prefix=f".{path.name}.", mode=mode)
    try:
        cleanup_failed = False
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if expected is not None:
            _check_expected(expected)
        if replace_existing and (expected is None or expected.identity is not None):
            os.replace(temporary, path)
        else:
            # Publish a completely written same-directory inode without ever
            # replacing a first backup created concurrently after preflight.
            os.link(temporary, path)
            try:
                os.unlink(temporary)
            except OSError:
                cleanup_failed = True
        try:
            (sync_parent or fsync_parent)(path.parent)
        except OSError as ex:
            raise PrivateFileCommitError("file committed but directory durability check failed") from ex
        if cleanup_failed:
            raise PrivateFileCommitError("file committed but temporary cleanup failed")
    except BaseException:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def fsync_parent(directory: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError as ex:
        if directory_fsync_unsupported(ex):
            return
        raise
    try:
        os.fsync(fd)
    except OSError as ex:
        if not directory_fsync_unsupported(ex):
            raise
    finally:
        os.close(fd)


def directory_fsync_unsupported(error: OSError) -> bool:
    unsupported = {errno.EINVAL, errno.ENOSYS}
    for name in ("ENOTSUP", "EOPNOTSUPP"):
        value = getattr(errno, name, None)
        if value is not None:
            unsupported.add(value)
    return error.errno in unsupported
