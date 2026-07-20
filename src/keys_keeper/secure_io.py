"""Race-aware filesystem primitives for plaintext secret sinks."""
from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path


class SecureFileError(RuntimeError):
    """A target cannot safely be used as a plaintext secret sink."""


@dataclass(frozen=True)
class SecureTextState:
    path: Path
    text: str
    identity: tuple[int, int] | None
    mode: int | None


def _validate_regular_file(path: Path, st: os.stat_result) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise SecureFileError(f"refusing symlink target: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise SecureFileError(f"refusing non-regular target: {path}")
    if os.name == "posix" and st.st_uid != os.geteuid():
        raise SecureFileError(f"refusing target not owned by current user: {path}")


def read_secure_text(
    path: Path,
    *,
    missing_ok: bool,
    encoding: str = "utf-8",
) -> SecureTextState:
    """Read a regular user-owned file without following the final symlink.

    The returned identity is checked again by ``replace_secure_text`` so a
    target swapped between the read and write is rejected.
    """
    path = Path(path)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return SecureTextState(path=path, text="", identity=None, mode=None)
        raise SecureFileError(f"target does not exist: {path}")
    except OSError as ex:
        raise SecureFileError(f"cannot inspect target {path}: {ex}") from ex

    _validate_regular_file(path, before)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags)
    except OSError as ex:
        raise SecureFileError(f"cannot safely open target {path}: {ex}") from ex
    try:
        opened = os.fstat(fd)
        _validate_regular_file(path, opened)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise SecureFileError(f"target changed while opening: {path}")
        with os.fdopen(fd, "r", encoding=encoding) as handle:
            fd = -1
            text = handle.read()
    except (OSError, UnicodeError) as ex:
        raise SecureFileError(f"cannot read target {path}: {ex}") from ex
    finally:
        if fd >= 0:
            os.close(fd)

    return SecureTextState(
        path=path,
        text=text,
        identity=(opened.st_dev, opened.st_ino),
        mode=stat.S_IMODE(opened.st_mode),
    )


def _check_unchanged(state: SecureTextState) -> None:
    try:
        current = os.lstat(state.path)
    except FileNotFoundError:
        if state.identity is None:
            return
        raise SecureFileError(f"target disappeared before write: {state.path}")
    except OSError as ex:
        raise SecureFileError(f"cannot re-check target {state.path}: {ex}") from ex

    if state.identity is None:
        raise SecureFileError(f"target appeared before write: {state.path}")
    _validate_regular_file(state.path, current)
    if (current.st_dev, current.st_ino) != state.identity:
        raise SecureFileError(f"target changed before write: {state.path}")


def _fsync_parent_best_effort(path: Path) -> None:
    """Persist the directory entry where the platform supports it.

    The destination has already been atomically replaced when this runs.  A
    directory-fsync failure must therefore not be reported as a failed write:
    callers might retry and act on a false rollback assumption.
    """
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        fd = os.open(path.parent, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        # Some filesystems do not implement directory fsync.  The atomic
        # replacement still succeeded; crash durability is best-effort there.
        return


def replace_secure_text(
    state: SecureTextState,
    text: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Atomically replace a previously inspected plaintext sink.

    New files are mode 0600 on POSIX. Existing files lose all group/other
    access while preserving a stricter owner mode such as 0400.
    """
    path = state.path
    parent = path.parent
    if not parent.is_dir():
        raise SecureFileError(f"target parent is not a directory: {parent}")

    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=parent
        )
    except OSError as ex:
        raise SecureFileError(f"cannot create secure temporary file for {path}: {ex}") from ex

    tmp = Path(tmp_name)
    try:
        final_mode = 0o600 if state.mode is None else state.mode & 0o600
        if os.name == "posix":
            os.fchmod(fd, final_mode)
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            fd = -1
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())

        _check_unchanged(state)
        os.replace(tmp, path)
        _fsync_parent_best_effort(path)
    except SecureFileError:
        raise
    except (OSError, UnicodeError) as ex:
        raise SecureFileError(f"cannot securely replace target {path}: {ex}") from ex
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
