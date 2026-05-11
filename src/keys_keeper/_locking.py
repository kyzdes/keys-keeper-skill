"""Cross-platform exclusive file locking.

POSIX: fcntl.flock (advisory, file-descriptor scoped).
Windows: msvcrt.locking (mandatory, byte-range scoped).

flock locks the whole file abstractly; msvcrt.locking locks a byte range.
On Windows we lock byte 0 — that requires the file to have at least 1 byte
(behaviour on empty files is inconsistent across Windows versions), so we
idempotently write a sentinel byte before locking. LK_LOCK is the blocking
variant with internal retry (~1s × 10 attempts).
"""
from __future__ import annotations
import os
import sys

if sys.platform == "win32":
    import msvcrt

    def lock_exclusive(fd: int) -> None:
        os.lseek(fd, 0, 0)
        try:
            os.write(fd, b"L")
        except OSError:
            pass
        os.lseek(fd, 0, 0)
        msvcrt.locking(fd, msvcrt.LK_LOCK, 1)

    def unlock(fd: int) -> None:
        os.lseek(fd, 0, 0)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def lock_exclusive(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
