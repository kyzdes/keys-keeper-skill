"""Bounded plaintext sinks using the shared private-file policy."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from keys_keeper import private_files


class SecureFileError(RuntimeError):
    """A target cannot safely be used as a plaintext secret sink."""


DEFAULT_MAX_TEXT_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class SecureTextState:
    path: Path
    text: str = field(repr=False)
    identity: tuple[int, int] | None
    mode: int | None
    _bytes_state: private_files.PrivateFileState = field(repr=False)


def read_secure_text(path: Path, *, missing_ok: bool, encoding: str = "utf-8",
                     max_bytes: int = DEFAULT_MAX_TEXT_BYTES) -> SecureTextState:
    """Read a bounded regular user-owned target, without following its final link.

    Existing templates may have public permissions. Publication makes the new
    sink private; it never changes permissions on a user-selected directory.
    """
    path = Path(path)
    try:
        state = private_files.secure_read_state(path, max_bytes=max_bytes,
                                                require_private=False, missing_ok=missing_ok)
        return SecureTextState(path, state.data.decode(encoding), state.identity,
                               state.mode, state)
    except UnicodeError:
        raise SecureFileError("target text has invalid encoding") from None
    except (OSError, private_files.PrivateFileError) as ex:
        raise SecureFileError(f"cannot securely read target {path}: {ex}") from ex


def _fsync_parent_best_effort(directory: Path) -> None:
    # The rename already committed. Avoid reporting a false rollback that could
    # trigger a second secret operation on unsupported/transient directory fsync.
    try:
        private_files.fsync_parent(directory)
    except OSError:
        pass


def replace_secure_text(state: SecureTextState, text: str, *, encoding: str = "utf-8") -> None:
    """Atomically publish a private sink, rejecting observed concurrent changes.

    A fresh bounded read compares bytes, size and modification/change times,
    including same-inode writes. This is optimistic conflict detection; an
    uncooperative writer can still race after the check. For exclusive mutation,
    callers must arrange a shared lock. Newly appearing targets are never lost.
    """
    try:
        data = text.encode(encoding)
        if len(data) > state._bytes_state.max_bytes:
            raise SecureFileError("plaintext sink exceeds size limit")
        mode = 0o600 if state.mode is None else state.mode & 0o600
        private_files.atomic_write_bytes(state.path, data, expected=state._bytes_state,
                                         mode=mode, ensure_parent_private=False,
                                         sync_parent=_fsync_parent_best_effort)
    except SecureFileError:
        raise
    except UnicodeError:
        raise SecureFileError("target text cannot be encoded") from None
    except (OSError, private_files.PrivateFileError) as ex:
        raise SecureFileError(f"cannot securely replace target {state.path}: {ex}") from ex
