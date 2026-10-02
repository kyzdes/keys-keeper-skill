"""Bounded private durable-file IO; standard library only, no crypto dependency."""
from __future__ import annotations

import errno
import os
import stat
import tempfile
from pathlib import Path

from keys_keeper.paths import ensure_private_dir


class PrivateFileError(RuntimeError):
    """A durable file does not satisfy ownership/type/size/race requirements."""


def secure_read(path: Path, *, max_bytes: int | None = None, require_private: bool = True) -> bytes:
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer")
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as ex:
        raise PrivateFileError("cannot inspect durable state file") from ex
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PrivateFileError("durable state file must be a regular non-symlink file")
    if os.name == "posix":
        if before.st_uid != os.getuid() or (require_private and stat.S_IMODE(before.st_mode) & 0o077):
            raise PrivateFileError("durable state file has unsafe ownership or permissions")
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
        fd = os.open(path, flags)
    except OSError as ex:
        raise PrivateFileError("cannot open durable state file") from ex
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise PrivateFileError("durable state file must be a regular non-symlink file")
        if os.name == "posix":
            if opened.st_uid != os.getuid() or (require_private and stat.S_IMODE(opened.st_mode) & 0o077):
                raise PrivateFileError("durable state file has unsafe ownership or permissions")
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise PrivateFileError("durable state file changed while opening")
        if max_bytes is not None and opened.st_size > max_bytes:
            raise PrivateFileError("durable state file exceeds size limit")
        chunks: list[bytes] = []
        remaining = None if max_bytes is None else max_bytes + 1
        while remaining is None or remaining:
            size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = os.read(fd, size)
            if not chunk:
                break
            chunks.append(chunk)
            if remaining is not None:
                remaining -= len(chunk)
        result = b"".join(chunks)
        if max_bytes is not None and len(result) > max_bytes:
            raise PrivateFileError("durable state file exceeds size limit")
        return result
    finally:
        os.close(fd)


def atomic_write_bytes(path: Path, data: bytes, *, sync_parent=None, replace_existing: bool = True) -> None:
    ensure_private_dir(path.parent)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise PrivateFileError("refusing to replace a symlink durable state file")
    if existing is not None and not replace_existing:
        raise FileExistsError(errno.EEXIST, "durable state file already exists", path)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        if replace_existing:
            os.replace(temporary, path)
        else:
            # Publish a completely written same-directory inode without ever
            # replacing a first backup created concurrently after preflight.
            os.link(temporary, path)
            os.unlink(temporary)
        (sync_parent or fsync_parent)(path.parent)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
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
