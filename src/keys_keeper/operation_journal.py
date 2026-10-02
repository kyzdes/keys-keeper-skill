"""Durable encrypted state for bounded local operations.

The journal records recoverable stages inside one explicit profile.  It does
not make a metadata store and an OS credential backend one crash-atomic system;
higher-level handlers must make each durable stage idempotent and decide how to
complete or close it during recovery.
"""
from __future__ import annotations

import json
import os
import re
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Iterator, Mapping
from uuid import UUID, uuid4

from keys_keeper import crypto, private_files
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
_MAX_RECOVERY_RECORDS = 10_000
_MAX_RECOVERY_BYTES = 512 * 1024 * 1024
_RECEIPTS_NAME = "terminal-receipts.kk1"
_MAX_RECEIPTS = 64
_MAX_RECEIPTS_BYTES = 1024 * 1024
_MAX_MIGRATION_RECORDS = _MAX_RECOVERY_RECORDS + _MAX_RECEIPTS
_MAX_MIGRATION_BYTES = _MAX_RECOVERY_BYTES + _MAX_JOURNAL_BYTES
_JOURNAL_TEMP = re.compile(
    r"\.(?:([a-f0-9-]{36})\.enc|terminal-receipts\.kk1|pending-index\.json)"
    r"\.[A-Za-z0-9_-]{1,64}\.tmp\Z"
)


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


def _record_data(record: OperationRecord) -> dict:
    return {"schema": _SCHEMA, "operation_id": str(record.operation_id),
            "kind": record.kind, "stage": record.stage, "status": record.status,
            "created_at": record.created_at, "updated_at": record.updated_at,
            "state": dict(record.state),
            "result": None if record.result is None else dict(record.result),
            "error_code": record.error_code}


class OperationJournal:
    """Encrypted, atomic, replayable records under one profile's Paths."""

    def __init__(self, *, paths: Paths, password_provider: PasswordProvider):
        if not callable(password_provider):
            raise TypeError("password_provider must be callable")
        self.paths = paths
        self._password_provider = password_provider
        self._password_cache: Sealed | None = None
        # A live journal already retains its unlocking material. Keep at most
        # one derived key for this instance's currently read record salt to
        # avoid repeated PBKDF2 work. Never serialize, log, or share this cache;
        # every read still loads fresh file bytes and authenticates with GCM.
        self._derived_key_cache: tuple[bytes, bytes] | None = None
        self._receipt_key_cache: tuple[bytes, bytes] | None = None
        self._thread_lock = threading.RLock()
        self._lock_depth = 0

    def __getstate__(self) -> None:
        raise TypeError("operation journal contains process-local unlocking material")

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
            if self._record_path(op_id).exists() or any(
                item.operation_id == op_id for item in self._read_receipts_unlocked()
            ):
                raise JournalError("operation_id already exists")
            # Key creation/authorization precedes the pending marker. Dying
            # during reserved-key initialization cannot strand an operation
            # whose recovery image has never been prepared.
            self._password()
            # Publish a metadata-only pending marker first.  A process death
            # between this write and the encrypted record therefore fails
            # closed instead of allowing a projection to miss an operation
            # whose durable preparation may have started.
            self._add_pending_unlocked(op_id, kind)
            try:
                self._write_unlocked(record)
            except BaseException:
                # A parent-fsync error may follow a committed atomic replace.
                # Keep its marker whenever any record object was published;
                # recovery must inspect it instead of treating preparation as
                # rolled back. Only a definitely absent image is safe to clear.
                try:
                    self._record_path(op_id).lstat()
                except FileNotFoundError:
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
                    if self._record_path(op_id).exists():
                        self._archive_finished_unlocked(current)
                    else:
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
            # Reject an unsupported result before terminalization or clearing
            # its recovery marker. Also authenticate the existing ledger before
            # any durable state change, so corruption cannot strand this close.
            _receipt_payload([updated])
            self._read_receipts_unlocked()
            self._write_unlocked(updated)
            self._archive_finished_unlocked(updated)
            return updated

    def list_unfinished(self) -> list[OperationRecord]:
        """Authenticate active state and compact a bounded legacy/crash tail.

        The cheap migration preflight runs before any KDF. Finished history is
        retained as at most64 small encrypted receipts, never before/after state.
        Unindexed pending records are still discovered and consume active caps.
        """
        with self.locked():
            try:
                snapshot, paths = self._recovery_snapshot(migration=True)
                pending = _read_pending_index(self.paths)
                if len(pending) > _MAX_RECOVERY_RECORDS:
                    raise JournalError("journal recovery scan exceeds resource limit")
                receipts = self._read_receipts_unlocked()
                records, terminal, active_bytes = [], [], 0
                by_id = {str(item.operation_id): item for item in receipts}
                for path in paths:
                    record = self._read_unlocked(UUID(path.stem))
                    by_id[str(record.operation_id)] = record
                    if record.finished:
                        _receipt_payload([record])
                        terminal.append(record)
                    else:
                        records.append(record)
                        active_bytes += path.lstat().st_size
                        if len(records) > _MAX_RECOVERY_RECORDS or active_bytes > _MAX_RECOVERY_BYTES:
                            raise JournalError("journal recovery scan exceeds resource limit")
                # No writes or deletion occur until every legacy record and the
                # unchanged directory have been authenticated/inspected.
                if self._recovery_snapshot(migration=True)[0] != snapshot:
                    raise JournalError("journal directory changed during recovery scan")
                for item in pending:
                    record = by_id.get(item["operation_id"])
                    if record is None or record.kind != item["kind"]:
                        raise JournalError("pending index references unavailable operation state")
                finished_ids = {identifier for identifier, record in by_id.items() if record.finished}
                kept = [item for item in pending if item["operation_id"] not in finished_ids]
                orphan_temps = [] if snapshot is None else [
                    self.paths.operations_dir / item[0] for item in snapshot[-1]
                    if item[0].endswith(".tmp")
                ]
                if terminal:
                    receipt_map = {str(item.operation_id): item for item in receipts}
                    receipt_map.update({str(item.operation_id): item for item in terminal})
                    ordered = sorted(receipt_map.values(), key=lambda item: (item.updated_at, str(item.operation_id)))
                    self._write_receipts_unlocked(ordered)
                if kept != pending:
                    _write_pending_index(self.paths, kept)
                if terminal or orphan_temps:
                    # Receipt durability and index cleanup precede removal.
                    for record in terminal:
                        self._record_path(record.operation_id).unlink()
                    # Atomic writes killed before replace can leave encrypted
                    # image temps. All durable state was just authenticated;
                    # under the profile lock no valid writer owns these temps.
                    # Missing/invalid indexed state fails before this cleanup.
                    for path in orphan_temps:
                        path.unlink()
                    private_files.fsync_parent(self.paths.operations_dir)
                return records
            except OSError:
                raise JournalError("journal directory unavailable during recovery scan") from None

    def _read_receipts_unlocked(self) -> list[OperationRecord]:
        try:
            blob = _secure_read(self.paths.operations_dir / _RECEIPTS_NAME,
                                max_bytes=_MAX_RECEIPTS_BYTES)
        except FileNotFoundError:
            return []
        try:
            salt = crypto._blob_salt(blob)
            cached = self._receipt_key_cache
            key = cached[1] if cached is not None and cached[0] == salt else crypto._derive_key(self._password(), salt)
            raw = json.loads(crypto._decrypt_blob_with_key(blob, key=key))
            if (not isinstance(raw, dict) or set(raw) != {"schema", "kind", "records"}
                    or raw["schema"] != 1 or raw["kind"] != "terminal_receipts"
                    or not isinstance(raw["records"], list) or len(raw["records"]) > _MAX_RECEIPTS):
                raise ValueError("invalid receipts")
            result = []
            seen = set()
            for value in raw["records"]:
                if not isinstance(value, dict):
                    raise ValueError("invalid receipt")
                identifier = _canonical_uuid(value.get("operation_id"), field_name="operation_id")
                item = _decode_record(value, expected_id=identifier)
                if not item.finished or item.state or identifier in seen:
                    raise ValueError("invalid receipt")
                _receipt_payload([item])
                seen.add(identifier)
                result.append(item)
        except (crypto.BadPassword, UnicodeError, ValueError, JournalError, TypeError):
            self._receipt_key_cache = None
            raise JournalError("terminal operation receipts are corrupt") from None
        self._receipt_key_cache = (salt, key)
        return result

    def _write_receipts_unlocked(self, records: list[OperationRecord]) -> None:
        records = records[-_MAX_RECEIPTS:]
        while True:
            try:
                plaintext = _receipt_payload(records)
                break
            except JournalError:
                if len(records) <= 1:
                    raise
                records = records[1:]
        blob, key = crypto._encrypt_blob_with_key(plaintext, password=self._password())
        _atomic_write_bytes(self.paths.operations_dir / _RECEIPTS_NAME, blob)
        self._receipt_key_cache = (crypto._blob_salt(blob), key)

    def _archive_finished_unlocked(self, record: OperationRecord) -> None:
        if not record.finished:
            raise JournalError("cannot archive a pending operation")
        records = [item for item in self._read_receipts_unlocked()
                   if item.operation_id != record.operation_id]
        records.append(record)
        self._write_receipts_unlocked(records)
        # Crash before deletion leaves an authenticated terminal active record.
        # A receipt is durable before its pending marker/recovery image goes away.
        self._remove_pending_unlocked(record.operation_id)
        try:
            self._record_path(record.operation_id).unlink()
        except FileNotFoundError:
            pass
        private_files.fsync_parent(self.paths.operations_dir)

    def _recovery_snapshot(self, *, migration: bool = False):
        """Cheap no-follow/type/owner/resource preflight; never derives a key."""
        try:
            directory = self.paths.operations_dir.lstat()
        except FileNotFoundError:
            return None, ()
        if (not stat.S_ISDIR(directory.st_mode) or stat.S_ISLNK(directory.st_mode)
                or getattr(directory, "st_file_attributes", 0) & 0x400):
            raise JournalError("journal directory must be a non-symlink directory")
        if os.name == "posix" and (directory.st_uid != os.geteuid() or directory.st_mode & 0o077):
            raise JournalError("journal directory has unsafe ownership or permissions")
        if os.name == "nt":
            from keys_keeper.windows_file_security import validate_path
            validate_path(self.paths.operations_dir, directory=True)
        entries, total, operation_files = [], 0, 0
        maximum_records = _MAX_MIGRATION_RECORDS if migration else _MAX_RECOVERY_RECORDS
        maximum_bytes = _MAX_MIGRATION_BYTES if migration else _MAX_RECOVERY_BYTES
        with os.scandir(self.paths.operations_dir) as iterator:
            for item in iterator:
                bookkeeping = item.name in {_PENDING_INDEX_NAME, _RECEIPTS_NAME}
                if not bookkeeping:
                    operation_files += 1
                    if operation_files > maximum_records:
                        raise JournalError("journal recovery scan exceeds resource limit")
                temporary = _JOURNAL_TEMP.fullmatch(item.name)
                if not (bookkeeping or temporary or item.name.endswith(".enc")):
                    continue
                try:
                    if item.name.endswith(".enc"):
                        _canonical_uuid(item.name[:-4], field_name="operation_id")
                    elif temporary and temporary.group(1):
                        _canonical_uuid(temporary.group(1), field_name="operation_id")
                except ValueError:
                    raise JournalError("invalid journal filename") from None
                info = item.stat(follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & 0x400):
                    raise JournalError("journal record must be a regular non-symlink file")
                if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
                    raise JournalError("journal record has unsafe ownership or permissions")
                if os.name == "nt":
                    validate_path(self.paths.operations_dir / item.name)
                if not bookkeeping:
                    total += info.st_size
                maximum_file = (_MAX_INDEX_BYTES if item.name == _PENDING_INDEX_NAME else
                                _MAX_RECEIPTS_BYTES if item.name == _RECEIPTS_NAME else _MAX_JOURNAL_BYTES)
                if total > maximum_bytes or info.st_size > maximum_file:
                    raise JournalError("journal recovery scan exceeds resource limit")
                entries.append((item.name, info.st_dev, info.st_ino, info.st_size,
                                info.st_mtime_ns, info.st_ctime_ns, info.st_mode))
        entries.sort()
        stamp = (directory.st_dev, directory.st_ino, directory.st_mtime_ns,
                 directory.st_ctime_ns, tuple(entries))
        return stamp, tuple(self.paths.operations_dir / item[0] for item in entries if item[0].endswith(".enc"))

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

        Handlers run without the profile lock and must be idempotent. Before
        raising they must finish compensating any partial effects: failure
        closes the operation and erases its recovery images. A missing handler
        leaves its record pending for a component that understands it. Persist
        failures after a successful handler propagate without marking failure.
        Exception text is never persisted because it may contain secret data.
        """
        recovered: list[OperationRecord] = []
        for record in self.list_unfinished():
            handler = handlers.get(record.kind)
            if handler is None:
                continue
            try:
                result = handler(record)
            except Exception:
                recovered.append(self.fail(record.operation_id, error_code="recovery_error"))
            else:
                recovered.append(self.finish(record.operation_id, result=result))
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
        if len(entries) >= _MAX_RECOVERY_RECORDS:
            raise JournalError("journal recovery scan exceeds resource limit")
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
        data = _record_data(record)
        try:
            plaintext = json.dumps(
                data, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError, RecursionError):
            raise JournalError("journal state is not JSON serializable") from None
        # The fixed KK1 header/tag adds 48 bytes. Refuse a state that this
        # journal could not read back, before spending PBKDF2 or replacing it.
        if len(plaintext) + 48 > _MAX_JOURNAL_BYTES:
            raise JournalError("journal record exceeds size limit")
        blob, key = crypto._encrypt_blob_with_key(plaintext, password=self._password())
        _atomic_write_bytes(self._record_path(record.operation_id), blob)
        # Only a successful durable local write replaces the previous key.
        self._derived_key_cache = (crypto._blob_salt(blob), key)

    def _read_unlocked(self, operation_id: UUID) -> OperationRecord:
        path = self._record_path(operation_id)
        try:
            blob = _secure_read(path, max_bytes=_MAX_JOURNAL_BYTES)
        except FileNotFoundError as ex:
            for record in self._read_receipts_unlocked():
                if record.operation_id == operation_id:
                    return record
            raise JournalNotFound("journal operation not found") from ex
        return self._decode_blob_unlocked(operation_id, blob)

    def _decode_blob_unlocked(self, operation_id: UUID, blob: bytes) -> OperationRecord:
        try:
            salt = crypto._blob_salt(blob)
            cached = self._derived_key_cache
            if cached is not None and cached[0] == salt:
                key = cached[1]
            else:
                key = crypto._derive_key(self._password(), salt)
            plaintext = crypto._decrypt_blob_with_key(blob, key=key)
            raw = json.loads(plaintext.decode("utf-8"))
        except (crypto.BadPassword, UnicodeDecodeError, ValueError) as ex:
            self._derived_key_cache = None
            raise JournalError("cannot decrypt or decode journal record") from ex
        try:
            record = _decode_record(raw, expected_id=operation_id)
        except (JournalError, ValueError):
            self._derived_key_cache = None
            raise
        self._derived_key_cache = (salt, key)
        return record


@contextmanager
def profile_lock(paths: Paths, *, timeout=None) -> Iterator[None]:
    """Acquire the single mutation lock for one explicit profile.

    Callers must not nest raw profile locks. Use ``OperationJournal.locked``
    when journal methods participate in the same local mutation. Network I/O
    must happen after releasing it.
    Automatic metadata callers may supply a finite timeout; journal/storage
    callers retain the existing blocking behavior by default.
    """
    ensure_private_dir(paths.root)
    ensure_private_dir(paths.locks_dir)
    lock_path = paths.locks_dir / "profile.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = private_files.open_private_file(lock_path, flags)
    except (OSError, private_files.PrivateFileError) as ex:
        raise JournalError("cannot open profile lock") from ex
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise JournalError("profile lock must be a regular file")
        if os.name == "posix":
            if info.st_uid != os.getuid():
                raise JournalError("profile lock must be owned by this user")
            os.fchmod(fd, 0o600)
        lock_exclusive(fd, timeout=timeout)
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
    if len(encoded) > _MAX_INDEX_BYTES:
        raise JournalError("pending operation index exceeds size limit")
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


def _receipt_payload(records: list[OperationRecord]) -> bytes:
    try:
        payload = {"schema": 1, "kind": "terminal_receipts", "records": [
            _record_data(replace(record, state=_freeze_mapping({}))) for record in records
        ]}
        plaintext = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise JournalError("terminal operation result is not JSON serializable") from None
    if len(plaintext) + 48 > _MAX_RECEIPTS_BYTES:
        raise JournalError("terminal operation result exceeds receipt limit")
    return plaintext


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


def _secure_read(path: Path, *, max_bytes: int | None = None, require_private: bool = True) -> bytes:
    try:
        return private_files.secure_read(path, max_bytes=max_bytes, require_private=require_private)
    except private_files.PrivateFileError as ex:
        raise JournalError(str(ex)) from ex


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    try:
        private_files.atomic_write_bytes(path, data, sync_parent=_fsync_parent)
    except private_files.PrivateFileError as ex:
        raise JournalError(str(ex)) from ex


def _fsync_parent(directory: Path) -> None:
    private_files.fsync_parent(directory)


def _directory_fsync_unsupported(error: OSError) -> bool:
    return private_files.directory_fsync_unsupported(error)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
