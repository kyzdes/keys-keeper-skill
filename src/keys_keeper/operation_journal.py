"""Durable encrypted state for bounded local operations.

The journal records recoverable stages inside one explicit profile.  It does
not make a metadata store and an OS credential backend one crash-atomic system;
higher-level handlers must make each durable stage idempotent and decide how to
complete or close it during recovery.
"""
from __future__ import annotations

import errno
import json
import os
import re
import stat
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Iterator, Mapping
from uuid import UUID, uuid4

from keys_keeper import crypto
from keys_keeper._locking import lock_exclusive, unlock
from keys_keeper.backend import Sealed
from keys_keeper.paths import Paths, _canonical_uuid, ensure_private_dir


_SCHEMA = 1
_TOKEN = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
_POINTER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PENDING_INDEX_SCHEMA = 1
_PENDING_INDEX_NAME = "pending-index.json"
_MAX_JOURNAL_BYTES = 160 * 1024 * 1024
_MAX_INDEX_BYTES = 1024 * 1024


class JournalError(RuntimeError):
    """A journal record cannot be safely read, written, or recovered."""


class JournalNotFound(JournalError):
    pass


@dataclass(frozen=True)
class OperationRecord:
    operation_id: UUID
    kind: str
    stage: str
    status: str
    created_at: str
    updated_at: str
    state: Mapping[str, object] = field(repr=False)
    result: Mapping[str, object] | None = field(default=None, repr=False)
    error_code: str | None = None

    @property
    def finished(self) -> bool:
        return self.status in {"completed", "failed"}


PasswordProvider = Callable[[], str | bytes | Sealed]
RecoveryHandler = Callable[[OperationRecord], Mapping[str, object] | None]


class OperationJournal:
    """Encrypted, atomic, replayable records under one profile's Paths."""

    def __init__(self, *, paths: Paths, password_provider: PasswordProvider):
        if not callable(password_provider):
            raise TypeError("password_provider must be callable")
        self.paths = paths
        self._password_provider = password_provider
        self._password_cache: Sealed | None = None
        self._thread_lock = threading.RLock()
        self._lock_depth = 0

    @contextmanager
    def locked(self) -> Iterator["OperationJournal"]:
        """Hold this journal's process and profile lock across a local mutation.

        Calls through the same instance are reentrant, which lets a coordinator
        serialize journal, backend, and metadata steps without opening a second
        flock descriptor. Distinct journal instances must never be nested.
        """
        with self._thread_lock:
            if self._lock_depth:
                self._lock_depth += 1
                try:
                    yield self
                finally:
                    self._lock_depth -= 1
                return
            with profile_lock(self.paths):
                self._lock_depth = 1
                try:
                    yield self
                finally:
                    self._lock_depth = 0

    def begin(
        self,
        kind: str,
        *,
        state: Mapping[str, object] | None = None,
        operation_id: UUID | str | None = None,
    ) -> OperationRecord:
        kind = _validate_token(kind, "operation kind")
        op_id = uuid4() if operation_id is None else _canonical_uuid(
            operation_id, field_name="operation_id"
        )
        now = _now()
        record = OperationRecord(
            operation_id=op_id,
            kind=kind,
            stage="prepared",
            status="pending",
            created_at=now,
            updated_at=now,
            state=_freeze_mapping(state),
        )
        with self.locked():
            if self._record_path(op_id).exists():
                raise JournalError("operation_id already exists")
            # Publish a metadata-only pending marker first.  A process death
            # between this write and the encrypted record therefore fails
            # closed instead of allowing a projection to miss an operation
            # whose durable preparation may have started.
            self._add_pending_unlocked(op_id, kind)
            try:
                self._write_unlocked(record)
            except BaseException:
                self._remove_pending_unlocked(op_id)
                raise
        return record

    def read(self, operation_id: UUID | str) -> OperationRecord:
        op_id = _canonical_uuid(operation_id, field_name="operation_id")
        with self.locked():
            return self._read_unlocked(op_id)

    def stage(
        self,
        operation_id: UUID | str,
        stage: str,
        *,
        state: Mapping[str, object] | None = None,
    ) -> OperationRecord:
        op_id = _canonical_uuid(operation_id, field_name="operation_id")
        stage = _validate_token(stage, "operation stage")
        with self.locked():
            current = self._read_unlocked(op_id)
            if current.finished:
                raise JournalError("cannot advance a closed operation")
            updated = replace(
                current,
                stage=stage,
                updated_at=_now(),
                state=current.state if state is None else _freeze_mapping(state),
            )
            self._write_unlocked(updated)
            return updated

    def finish(
        self,
        operation_id: UUID | str,
        *,
        result: Mapping[str, object] | None = None,
    ) -> OperationRecord:
        return self._close(operation_id, status="completed", result=result)

    def fail(self, operation_id: UUID | str, *, error_code: str) -> OperationRecord:
        error_code = _validate_token(error_code, "error code")
        return self._close(operation_id, status="failed", error_code=error_code)

    def _close(
        self,
        operation_id: UUID | str,
        *,
        status: str,
        result: Mapping[str, object] | None = None,
        error_code: str | None = None,
    ) -> OperationRecord:
        op_id = _canonical_uuid(operation_id, field_name="operation_id")
        with self.locked():
            current = self._read_unlocked(op_id)
            if current.finished:
                if current.status == status:
                    # Reconcile a crash after the terminal encrypted record was
                    # durable but before its metadata-only marker was removed.
                    self._remove_pending_unlocked(op_id)
                    return current
                raise JournalError("operation is already closed")
            updated = replace(
                current,
                stage="finished" if status == "completed" else "failed",
                status=status,
                updated_at=_now(),
                result=None if result is None else _freeze_mapping(result),
                error_code=error_code,
            )
            self._write_unlocked(updated)
            self._remove_pending_unlocked(op_id)
            return updated

    def list_unfinished(self) -> list[OperationRecord]:
        with self.locked():
            if not self.paths.operations_dir.exists():
                return []
            records: list[OperationRecord] = []
            for path in sorted(self.paths.operations_dir.glob("*.enc")):
                try:
                    op_id = _canonical_uuid(path.stem, field_name="operation_id")
                except ValueError as ex:
                    raise JournalError("invalid journal filename") from ex
                record = self._read_unlocked(op_id)
                if not record.finished:
                    records.append(record)
            return records

    def pending_refs(self, *, kind: str | None = None) -> tuple[dict[str, str], ...]:
        """Read the metadata-only pending index through this reentrant lock."""
        if kind is not None:
            kind = _validate_token(kind, "operation kind")
        with self.locked():
            entries = _read_pending_index(self.paths)
        if kind is not None:
            entries = [item for item in entries if item["kind"] == kind]
        return tuple(dict(item) for item in entries)

    def recover(self, handlers: Mapping[str, RecoveryHandler]) -> list[OperationRecord]:
        """Replay pending records once, closing handler failures safely.

        Handlers run without the profile lock and must be idempotent.  A missing
        handler leaves its record pending for a component that understands it.
        Exception text is never persisted because it may contain secret data.
        """
        recovered: list[OperationRecord] = []
        for record in self.list_unfinished():
            handler = handlers.get(record.kind)
            if handler is None:
                continue
            try:
                result = handler(record)
                recovered.append(self.finish(record.operation_id, result=result))
            except Exception:
                recovered.append(self.fail(record.operation_id, error_code="recovery_error"))
        return recovered

    def _password(self) -> str:
        if self._password_cache is not None:
            return self._password_cache.unseal()
        try:
            supplied = self._password_provider()
        except Exception:
            raise JournalError("journal key provider failed") from None
        if isinstance(supplied, Sealed):
            value = supplied.unseal()
        elif isinstance(supplied, bytes):
            if not supplied:
                raise JournalError("journal key is empty")
            value = "key-bytes:" + supplied.hex()
        elif isinstance(supplied, str):
            value = supplied
        else:
            raise JournalError("journal key provider returned an unsupported type")
        if not value:
            raise JournalError("journal key is empty")
        self._password_cache = Sealed(value)
        return value

    def _record_path(self, operation_id: UUID) -> Path:
        return self.paths.operations_dir / f"{operation_id}.enc"

    def _pending_index_path(self) -> Path:
        return self.paths.operations_dir / _PENDING_INDEX_NAME

    def _add_pending_unlocked(self, operation_id: UUID, kind: str) -> None:
        entries = _read_pending_index(self.paths)
        identifier = str(operation_id)
        if any(item["operation_id"] == identifier for item in entries):
            raise JournalError("operation_id already exists in pending index")
        entries.append({"operation_id": identifier, "kind": kind})
        _write_pending_index(self.paths, entries)

    def _remove_pending_unlocked(self, operation_id: UUID) -> None:
        entries = _read_pending_index(self.paths)
        identifier = str(operation_id)
        kept = [item for item in entries if item["operation_id"] != identifier]
        if len(kept) != len(entries):
            _write_pending_index(self.paths, kept)

    def _write_unlocked(self, record: OperationRecord) -> None:
        data = {
            "schema": _SCHEMA,
            "operation_id": str(record.operation_id),
            "kind": record.kind,
            "stage": record.stage,
            "status": record.status,
            "created_at": record.created_at,
            "updated_at": record.updated_at,
            "state": dict(record.state),
            "result": None if record.result is None else dict(record.result),
            "error_code": record.error_code,
        }
        try:
            plaintext = json.dumps(
                data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as ex:
            raise JournalError("journal state is not JSON serializable") from ex
        blob = crypto.encrypt_blob(plaintext, password=self._password())
        _atomic_write_bytes(self._record_path(record.operation_id), blob)

    def _read_unlocked(self, operation_id: UUID) -> OperationRecord:
        path = self._record_path(operation_id)
        try:
            blob = _secure_read(path, max_bytes=_MAX_JOURNAL_BYTES)
        except FileNotFoundError as ex:
            raise JournalNotFound("journal operation not found") from ex
        try:
            plaintext = crypto.decrypt_blob(blob, password=self._password())
            raw = json.loads(plaintext.decode("utf-8"))
        except (crypto.BadPassword, UnicodeDecodeError, ValueError) as ex:
            raise JournalError("cannot decrypt or decode journal record") from ex
        return _decode_record(raw, expected_id=operation_id)


@contextmanager
def profile_lock(paths: Paths) -> Iterator[None]:
    """Acquire the single mutation lock for one explicit profile.

    Callers must not nest raw profile locks. Use ``OperationJournal.locked``
    when journal methods participate in the same local mutation. Network I/O
    must happen after releasing it.
    """
    ensure_private_dir(paths.root)
    ensure_private_dir(paths.locks_dir)
    lock_path = paths.locks_dir / "profile.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as ex:
        raise JournalError("cannot open profile lock") from ex
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise JournalError("profile lock must be a regular file")
        if os.name == "posix":
            if info.st_uid != os.getuid():
                raise JournalError("profile lock must be owned by this user")
            os.fchmod(fd, 0o600)
        lock_exclusive(fd)
        try:
            yield
        finally:
            unlock(fd)
    finally:
        os.close(fd)


def pending_operation_refs(paths: Paths, *, kind: str | None = None) -> tuple[dict[str, str], ...]:
    """Return metadata-only durable pending references for one profile.

    The index never contains operation state or values.  It is intentionally
    readable without the journal key so publication composition can fail
    closed before it obtains secret material.
    """
    if kind is not None:
        kind = _validate_token(kind, "operation kind")
    with profile_lock(paths):
        entries = _read_pending_index(paths)
    if kind is not None:
        entries = [item for item in entries if item["kind"] == kind]
    return tuple(dict(item) for item in entries)


def _read_pending_index(paths: Paths) -> list[dict[str, str]]:
    path = paths.operations_dir / _PENDING_INDEX_NAME
    try:
        raw = _secure_read(path, max_bytes=_MAX_INDEX_BYTES)
    except FileNotFoundError:
        return []
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as ex:
        raise JournalError("pending operation index is corrupt") from ex
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "operations"}
        or value["schema"] != _PENDING_INDEX_SCHEMA
        or not isinstance(value["operations"], list)
    ):
        raise JournalError("pending operation index is corrupt")
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in value["operations"]:
        if not isinstance(item, dict) or set(item) != {"operation_id", "kind"}:
            raise JournalError("pending operation index is corrupt")
        try:
            operation_id = _canonical_uuid(item["operation_id"], field_name="operation_id")
            operation_kind = _validate_token(item["kind"], "operation kind")
        except (TypeError, ValueError) as ex:
            raise JournalError("pending operation index is corrupt") from ex
        identifier = str(operation_id)
        if identifier in seen:
            raise JournalError("pending operation index is corrupt")
        seen.add(identifier)
        entries.append({"operation_id": identifier, "kind": operation_kind})
    return entries


def _write_pending_index(paths: Paths, entries: list[dict[str, str]]) -> None:
    encoded = json.dumps(
        {"schema": _PENDING_INDEX_SCHEMA, "operations": entries},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    _atomic_write_bytes(paths.operations_dir / _PENDING_INDEX_NAME, encoded)


def write_active_generation(paths: Paths, generation_id: str) -> None:
    """Atomically switch the plaintext pointer after a generation is verified."""
    if not isinstance(generation_id, str) or not _POINTER.fullmatch(generation_id):
        raise ValueError("generation_id must be a safe opaque identifier")
    if generation_id in {".", ".."}:
        raise ValueError("generation_id must be a safe opaque identifier")
    with profile_lock(paths):
        _atomic_write_bytes(paths.active_generation, (generation_id + "\n").encode("ascii"))


def read_active_generation(paths: Paths) -> str | None:
    with profile_lock(paths):
        try:
            raw = _secure_read(paths.active_generation, max_bytes=256)
        except FileNotFoundError:
            return None
    try:
        value = raw.decode("ascii").rstrip("\n")
    except UnicodeDecodeError as ex:
        raise JournalError("active generation pointer is corrupt") from ex
    if not _POINTER.fullmatch(value) or value in {".", ".."}:
        raise JournalError("active generation pointer is corrupt")
    return value


def _decode_record(raw: object, *, expected_id: UUID) -> OperationRecord:
    if not isinstance(raw, dict) or raw.get("schema") != _SCHEMA:
        raise JournalError("unknown or invalid journal schema")
    try:
        operation_id = _canonical_uuid(raw["operation_id"], field_name="operation_id")
        kind = _validate_token(raw["kind"], "operation kind")
        stage = _validate_token(raw["stage"], "operation stage")
        status = raw["status"]
        created_at = raw["created_at"]
        updated_at = raw["updated_at"]
        state = raw["state"]
        result = raw.get("result")
        error_code = raw.get("error_code")
    except (KeyError, TypeError, ValueError) as ex:
        raise JournalError("invalid journal record") from ex
    if operation_id != expected_id:
        raise JournalError("journal record identity mismatch")
    if not isinstance(status, str) or status not in {"pending", "completed", "failed"}:
        raise JournalError("invalid journal status")
    if not isinstance(created_at, str) or not isinstance(updated_at, str):
        raise JournalError("invalid journal timestamp")
    if not isinstance(state, dict) or (result is not None and not isinstance(result, dict)):
        raise JournalError("invalid journal state")
    if error_code is not None:
        error_code = _validate_token(error_code, "error code")
    return OperationRecord(
        operation_id=operation_id,
        kind=kind,
        stage=stage,
        status=status,
        created_at=created_at,
        updated_at=updated_at,
        state=MappingProxyType(dict(state)),
        result=None if result is None else MappingProxyType(dict(result)),
        error_code=error_code,
    )


def _freeze_mapping(value: Mapping[str, object] | None) -> Mapping[str, object]:
    if value is None:
        return MappingProxyType({})
    if not isinstance(value, Mapping):
        raise TypeError("operation state must be a mapping")
    return MappingProxyType(dict(value))


def _validate_token(value: object, label: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase safe token")
    return value


def _secure_read(path: Path, *, max_bytes: int | None = None) -> bytes:
    if max_bytes is not None and (
        isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0
    ):
        raise ValueError("max_bytes must be a non-negative integer")
    try:
        before = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as ex:
        raise JournalError("cannot inspect durable state file") from ex
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise JournalError("durable state file must be a regular non-symlink file")
    if os.name == "posix":
        if before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077:
            raise JournalError("durable state file has unsafe ownership or permissions")
    # Windows CRT descriptors default to text mode.  Ciphertext can contain
    # CRLF and CTRL-Z bytes, so os.read() must use an explicitly binary fd.
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        fd = os.open(path, flags)
    except OSError as ex:
        raise JournalError("cannot open durable state file") from ex
    try:
        opened = os.fstat(fd)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise JournalError("durable state file changed while opening")
        if max_bytes is not None and opened.st_size > max_bytes:
            raise JournalError("durable state file exceeds size limit")
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
            raise JournalError("durable state file exceeds size limit")
        return result
    finally:
        os.close(fd)


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    ensure_private_dir(path.parent)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise JournalError("refusing to replace a symlink durable state file")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        _fsync_parent(path.parent)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _fsync_parent(directory: Path) -> None:
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError as ex:
        if _directory_fsync_unsupported(ex):
            return
        raise
    try:
        os.fsync(fd)
    except OSError as ex:
        if not _directory_fsync_unsupported(ex):
            raise
    finally:
        os.close(fd)


def _directory_fsync_unsupported(error: OSError) -> bool:
    unsupported = {errno.EINVAL, errno.ENOSYS}
    for name in ("ENOTSUP", "EOPNOTSUPP"):
        value = getattr(errno, name, None)
        if value is not None:
            unsupported.add(value)
    return error.errno in unsupported


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
