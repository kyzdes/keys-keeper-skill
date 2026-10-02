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
import errno
import math
import time


def _bounded_acquire(acquire, timeout):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
        raise ValueError("invalid lock timeout")
    deadline = time.monotonic() + timeout
    while True:
        try:
            acquire()
            return
        except OSError as ex:
            if ex.errno not in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("exclusive lock is busy") from None
            time.sleep(min(0.05, remaining))

if sys.platform == "win32":
    import msvcrt

    def lock_exclusive(fd: int, *, timeout=None) -> None:
        os.lseek(fd, 0, 0)
        if os.fstat(fd).st_size == 0:
            try:
                os.write(fd, b"L")
            except OSError:
                pass
        os.lseek(fd, 0, 0)
        if timeout is None:
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
        else:
            def acquire():
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            _bounded_acquire(acquire, timeout)

    def unlock(fd: int) -> None:
        os.lseek(fd, 0, 0)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def lock_exclusive(fd: int, *, timeout=None) -> None:
        if timeout is None:
            fcntl.flock(fd, fcntl.LOCK_EX)
        else:
            _bounded_acquire(lambda: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB), timeout)

    def unlock(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)
