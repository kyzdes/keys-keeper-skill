"""Metadata store backed by a JSON file with atomic writes + exclusive lock."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from keys_keeper._locking import lock_exclusive, unlock
from keys_keeper.models import Entry, ValidationError, now_iso, validate_tombstone
from keys_keeper.project_models import CatalogState, CatalogValidationError, Folder, new_catalog_id
from keys_keeper.paths import Paths, ensure_private_dir

# v2 (2026-06): adds a top-level `tombstones` list so deletes propagate through
# S3 sync instead of being resurrected by an older peer snapshot. See sync.py.
SCHEMA_VERSION = 2
CATALOG_SCHEMA_VERSION = 3


class StoreError(RuntimeError):
    pass


class NameConflict(StoreError):
    pass


class NotFound(StoreError):
    pass


def _normalize_v3_entries(records: list[dict]) -> None:
    """Give legacy-style Entry writers safe, explicit v3 catalog defaults."""
    for record in records:
        record.setdefault("folder_id", None)
        record.setdefault("distribution", "local_only")
        record.setdefault("provenance", {"source": "local"})
        record.setdefault("content_revision", str(uuid.uuid4()))


def _validate_v3_data(data: dict) -> None:
    allowed = {"schema_version", "entries", "tombstones", "catalog"}
    if set(data) != allowed:
        raise StoreError("schema-v3 metadata contains unknown or missing top-level fields")
    if data.get("schema_version") != CATALOG_SCHEMA_VERSION:
        raise StoreError("schema-v3 metadata has an invalid schema_version")
    records = data.get("entries")
    if not isinstance(records, list):
        raise StoreError("schema-v3 entries must be a list")
    try:
        entries = [
            Entry.from_untrusted_dict(record, allow_project_fields=True)
            for record in records
        ]
        tombstones = [validate_tombstone(record) for record in data.get("tombstones", [])]
        if len({entry.id for entry in entries}) != len(entries):
            raise ValidationError("schema-v3 metadata contains duplicate entry ids")
        catalog = CatalogState.from_dict(data.get("catalog"), entry_ids={entry.id for entry in entries})
    except (ValidationError, CatalogValidationError) as ex:
        raise StoreError(f"invalid schema-v3 catalog metadata: {ex}") from ex
    if len({item["id"] for item in tombstones}) != len(tombstones):
        raise StoreError("invalid schema-v3 catalog metadata: duplicate tombstone id")
    folder_ids = {folder.id for folder in catalog.folders}
    for entry in entries:
        if entry.folder_id is not None and entry.folder_id not in folder_ids:
            raise StoreError("invalid schema-v3 catalog metadata: entry folder_id refers to a missing folder")


def _metadata_revision(data: dict) -> str:
    revision_data = {
        "schema_version": data.get("schema_version", SCHEMA_VERSION),
        "entries": data.get("entries", []),
        "tombstones": data.get("tombstones", []),
    }
    # Keep schema-v1/v2 revision bytes exactly as they were. Catalog metadata is
    # part of the revision once an explicit v3 migration has happened.
    if revision_data["schema_version"] >= CATALOG_SCHEMA_VERSION:
        revision_data["catalog"] = data.get("catalog", {})
    canonical = json.dumps(
        revision_data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@dataclass(frozen=True)
class MetadataSnapshot:
    entries: list[Entry]
    tombstones: list[dict]
    revision: str


class MetadataTransaction:
    """Mutable metadata view held under ``MetadataStore``'s write lock.

    The application service uses this boundary to keep multi-entry metadata
    changes atomic while it coordinates compensating secret-backend writes.
    Nothing is persisted when the surrounding context exits with an error.
    """

    def __init__(self, data: dict):
        self._data = data
        self._schema_version = data.get("schema_version", SCHEMA_VERSION)
        self._records_by_slot: dict[int, dict] = {}
        self._slot_by_name: dict[str, int] = {}
        self._slot_by_id: dict[str, int] = {}
        self._order: list[int] = []
        self._next_slot = 0
        self._reset_entries(data["entries"])

    def list(self) -> list[Entry]:
        return [
            Entry.from_dict(self._records_by_slot[slot])
            for slot in self._order
            if slot in self._records_by_slot
        ]

    def get_by_name(self, name: str) -> Entry | None:
        slot = self._slot_by_name.get(name)
        if slot is None:
            return None
        return Entry.from_dict(self._records_by_slot[slot])

    def get_by_id(self, id_: str) -> Entry | None:
        slot = self._slot_by_id.get(id_)
        if slot is None:
            return None
        return Entry.from_dict(self._records_by_slot[slot])

    def add(self, entry: Entry) -> None:
        if entry.name in self._slot_by_name:
            raise NameConflict(
                f"entry with name {entry.name!r} already exists "
                f"(use --replace to overwrite or --rename to pick a new name)"
            )
        if entry.id in self._slot_by_id:
            raise NameConflict(f"entry with id {entry.id!r} already exists")
        self._append_record(entry.to_dict())

    def update(self, entry: Entry) -> None:
        slot = self._slot_by_id.get(entry.id)
        if slot is None:
            raise NotFound(f"no entry with id {entry.id}")
        conflict_slot = self._slot_by_name.get(entry.name)
        if conflict_slot is not None and conflict_slot != slot:
            raise NameConflict(f"entry with name {entry.name!r} already exists")

        previous = self._records_by_slot[slot]
        previous_name = previous["name"]
        self._records_by_slot[slot] = entry.to_dict()
        if previous_name != entry.name:
            del self._slot_by_name[previous_name]
            self._slot_by_name[entry.name] = slot

    def replace_by_name(self, entry: Entry) -> None:
        slot = self._slot_by_name.get(entry.name)
        if slot is None:
            self.add(entry)
            return

        previous = self._records_by_slot[slot]
        previous_id = previous["id"]
        conflict_slot = self._slot_by_id.get(entry.id)
        if conflict_slot is not None and conflict_slot != slot:
            raise NameConflict(f"entry with id {entry.id!r} already exists")

        self._records_by_slot[slot] = entry.to_dict()
        if previous_id != entry.id:
            del self._slot_by_id[previous_id]
            self._slot_by_id[entry.id] = slot

    def delete_by_name(self, name: str) -> Entry:
        slot = self._slot_by_name.get(name)
        if slot is None:
            raise NotFound(f"no entry with name {name!r}")
        record = self._records_by_slot.pop(slot)
        del self._slot_by_name[record["name"]]
        del self._slot_by_id[record["id"]]
        entry = Entry.from_dict(record)
        self._data.setdefault("tombstones", []).append(
            {"id": entry.id, "name": entry.name, "deleted_at": now_iso()}
        )
        return entry

    def replace_all(self, entries: list[Entry], tombstones: list[dict]) -> None:
        self._reset_entries([entry.to_dict() for entry in entries])
        self._data["tombstones"] = list(tombstones)

    def prune_tombstones_before(self, horizon_ts: str) -> int:
        tombstones = self._data.get("tombstones", [])
        kept = [
            tombstone
            for tombstone in tombstones
            if tombstone["deleted_at"] >= horizon_ts
        ]
        self._data["tombstones"] = kept
        return len(tombstones) - len(kept)

    def revision(self) -> str:
        data = dict(self._data)
        data["entries"] = self._materialize_entries()
        return _metadata_revision(data)

    def catalog_state(self) -> dict:
        """Detached catalog data suitable for a coordinated metadata mutation."""
        if self._schema_version < CATALOG_SCHEMA_VERSION:
            raise StoreError("project catalog requires explicit schema-v3 migration")
        return json.loads(json.dumps(self._data["catalog"], ensure_ascii=False))

    def set_catalog_state(self, state: dict) -> None:
        """Validate and set catalog metadata within this same transaction."""
        if self._schema_version < CATALOG_SCHEMA_VERSION:
            raise StoreError("project catalog requires explicit schema-v3 migration")
        CatalogState.from_dict(state, entry_ids=set(self._slot_by_id))
        self._data["catalog"] = json.loads(json.dumps(state, ensure_ascii=False))

    def _append_record(self, record: dict) -> None:
        slot = self._next_slot
        self._next_slot += 1
        self._records_by_slot[slot] = record
        self._slot_by_name.setdefault(record["name"], slot)
        self._slot_by_id.setdefault(record["id"], slot)
        self._order.append(slot)

    def _reset_entries(self, records: list[dict]) -> None:
        self._records_by_slot.clear()
        self._slot_by_name.clear()
        self._slot_by_id.clear()
        self._order.clear()
        self._next_slot = 0
        for record in records:
            self._append_record(record)

    def _materialize_entries(self) -> list[dict]:
        return [
            self._records_by_slot[slot]
            for slot in self._order
            if slot in self._records_by_slot
        ]

    def _commit(self) -> None:
        self._data["entries"] = self._materialize_entries()
        if self._schema_version >= CATALOG_SCHEMA_VERSION:
            _normalize_v3_entries(self._data["entries"])
            _validate_v3_data(self._data)


class MetadataStore:
    """JSON-backed metadata store. All write ops acquire an exclusive flock
    on a sibling lock file to coordinate cross-process writes.
    """

    def __init__(self, paths: Paths):
        self.paths = paths
        self._lock_path = paths.root / "data.lock"

    # ---------- public API ----------

    def list(self) -> list[Entry]:
        data = self._read()
        return [Entry.from_dict(d) for d in data["entries"]]

    def get_by_name(self, name: str) -> Entry | None:
        for e in self.list():
            if e.name == name:
                return e
        return None

    def get_by_id(self, id_: str) -> Entry | None:
        for e in self.list():
            if e.id == id_:
                return e
        return None

    def add(self, entry: Entry) -> None:
        with self._locked_write() as data:
            for d in data["entries"]:
                if d["name"] == entry.name:
                    raise NameConflict(
                        f"entry with name {entry.name!r} already exists "
                        f"(use --replace to overwrite or --rename to pick a new name)"
                    )
                if d["id"] == entry.id:
                    raise NameConflict(f"entry with id {entry.id!r} already exists")
            data["entries"].append(entry.to_dict())

    def update(self, entry: Entry) -> None:
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["id"] == entry.id:
                    data["entries"][i] = entry.to_dict()
                    return
            raise NotFound(f"no entry with id {entry.id}")

    def replace_by_name(self, entry: Entry) -> None:
        """Used for --replace: overwrites by name even if id differs."""
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["name"] == entry.name:
                    if any(
                        other["id"] == entry.id and other["name"] != entry.name
                        for other in data["entries"]
                    ):
                        raise NameConflict(f"entry with id {entry.id!r} already exists")
                    data["entries"][i] = entry.to_dict()
                    return
            if any(d["id"] == entry.id for d in data["entries"]):
                raise NameConflict(f"entry with id {entry.id!r} already exists")
            data["entries"].append(entry.to_dict())

    def delete_by_name(self, name: str) -> Entry:
        with self._locked_write() as data:
            for i, d in enumerate(data["entries"]):
                if d["name"] == name:
                    entry = Entry.from_dict(data["entries"].pop(i))
                    # Soft-delete: record a tombstone so the deletion survives a
                    # round-trip through an older peer's snapshot (F10/F18).
                    data.setdefault("tombstones", []).append(
                        {"id": entry.id, "name": entry.name, "deleted_at": now_iso()}
                    )
                    return entry
            raise NotFound(f"no entry with name {name!r}")

    def tombstones(self) -> list[dict]:
        """Soft-delete records: [{'id', 'name', 'deleted_at'}]. Read-only copy."""
        return list(self._read().get("tombstones", []))

    def catalog_state(self) -> dict:
        """Return a detached, validated v3 catalog without changing disk state."""
        data = self._read()
        if data.get("schema_version", SCHEMA_VERSION) < CATALOG_SCHEMA_VERSION:
            raise StoreError("project catalog requires explicit schema-v3 migration")
        return json.loads(json.dumps(data["catalog"], ensure_ascii=False))

    def migrate_catalog_v3(self, *, expected_revision: str | None = None) -> dict:
        """Explicitly and atomically migrate legacy metadata to catalog schema v3.

        Reading a v1/v2 vault never calls this method.  The pre-catalog file is
        copied once while the metadata lock is held, before its first v3 write.
        """
        with self._locked_write() as data:
            current = data.get("schema_version", SCHEMA_VERSION)
            if expected_revision is not None:
                if not isinstance(expected_revision, str) or len(expected_revision) != 64:
                    raise StoreError("catalog migration expected_revision is invalid")
                if _metadata_revision(data) != expected_revision:
                    raise StoreError("catalog migration source changed after verified backup")
            if current == CATALOG_SCHEMA_VERSION:
                return json.loads(json.dumps(data["catalog"], ensure_ascii=False))
            if current != SCHEMA_VERSION:
                raise StoreError("catalog migration requires a supported legacy schema")
            backup = self.paths.root / f"data.v{SCHEMA_VERSION}.json.bak"
            if self.paths.data_json.exists() and not backup.exists():
                shutil.copy2(self.paths.data_json, backup)
            unsorted = Folder(id=new_catalog_id(), name="Unsorted", parent_id=None, position=0)
            for record in data["entries"]:
                record["folder_id"] = unsorted.id
                record["distribution"] = "local_only"
                record["provenance"] = {"source": "legacy_migration"}
                record["content_revision"] = str(uuid.uuid4())
            data["catalog"] = CatalogState(folders=[unsorted]).to_dict()
            data["schema_version"] = CATALOG_SCHEMA_VERSION
            _validate_v3_data(data)
            return json.loads(json.dumps(data["catalog"], ensure_ascii=False))

    def snapshot(self) -> MetadataSnapshot:
        """Read entries, tombstones, and their revision under one lock."""
        ensure_private_dir(self.paths.root)
        lock_fd = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            lock_exclusive(lock_fd)
            data = self._read()
            return MetadataSnapshot(
                entries=[Entry.from_dict(record) for record in data["entries"]],
                tombstones=list(data.get("tombstones", [])),
                revision=_metadata_revision(data),
            )
        finally:
            unlock(lock_fd)
            os.close(lock_fd)

    def apply_merge(self, entries: list[Entry], tombstones: list[dict]) -> None:
        """Atomically replace the whole metadata set (entries + tombstones).

        Used by the sync engine after it has computed the merged state and
        written the corresponding secrets to the keychain. One `_locked_write`
        keeps the swap atomic under the same flock as every other mutation
        (N6/N8) — an interrupted apply leaves the prior consistent file intact.
        """
        with self._locked_write() as data:
            data["entries"] = [e.to_dict() for e in entries]
            data["tombstones"] = list(tombstones)

    def prune_tombstones_before(self, horizon_ts: str) -> int:
        """Remove expired tombstones without replacing concurrent entries."""
        with self.transaction() as tx:
            return tx.prune_tombstones_before(horizon_ts)

    @contextmanager
    def transaction(self) -> Iterator[MetadataTransaction]:
        """Hold one metadata lock across an application-level mutation.

        This is intentionally a small public facade over ``_locked_write`` so
        callers never depend on the JSON representation. If the caller raises,
        ``_locked_write`` skips its atomic commit.
        """
        with self._locked_write() as data:
            tx = MetadataTransaction(data)
            yield tx
            tx._commit()

    # ---------- internal ----------

    def _read(self) -> dict:
        if not self.paths.data_json.exists():
            return {"schema_version": SCHEMA_VERSION, "entries": [], "tombstones": []}
        raw = self.paths.data_json.read_text()
        if not raw.strip():
            return {"schema_version": SCHEMA_VERSION, "entries": [], "tombstones": []}
        data = json.loads(raw)
        sv = data.get("schema_version", 0)
        if sv > CATALOG_SCHEMA_VERSION:
            raise StoreError(
                f"data.json schema_version={sv} is newer than this CLI supports "
                f"({CATALOG_SCHEMA_VERSION}); upgrade keys-keeper"
            )
        if sv < SCHEMA_VERSION:
            data = self._migrate(data, sv)
        data.setdefault("tombstones", [])
        if data.get("schema_version") == CATALOG_SCHEMA_VERSION:
            _validate_v3_data(data)
        return data

    def _migrate(self, data: dict, from_version: int) -> dict:
        # Back up the pre-migration file ONCE (guarded by existence), so the
        # lock-free reads that call _read() don't re-copy on every call. The
        # actual v2 persistence happens on the next _locked_write.
        bak = self.paths.root / f"data.v{from_version}.json.bak"
        if self.paths.data_json.exists() and not bak.exists():
            shutil.copy2(self.paths.data_json, bak)
        # 1 -> 2: introduce the tombstones container (lossless; entries unchanged).
        if from_version < 2:
            data.setdefault("tombstones", [])
        data["schema_version"] = SCHEMA_VERSION
        return data

    @contextmanager
    def _locked_write(self) -> Iterator[dict]:
        """Acquire exclusive lock, read, yield mutable dict, write atomically."""
        # 0700 even when a store write is the process's first filesystem touch
        # (before paths.ensure()), so data.json's parent is never world-readable.
        ensure_private_dir(self.paths.root)
        # Lock on a separate file so we can rename data.json atomically without
        # invalidating the lock fd. On Windows the mode bits are ignored; the
        # lock file holds no secrets so this is acceptable.
        lock_fd = os.open(self._lock_path, os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            lock_exclusive(lock_fd)
            data = self._read()
            yield data
            if data.get("schema_version", SCHEMA_VERSION) >= CATALOG_SCHEMA_VERSION:
                _normalize_v3_entries(data["entries"])
                _validate_v3_data(data)
            self._atomic_write(data)
        finally:
            unlock(lock_fd)
            os.close(lock_fd)

    def _atomic_write(self, data: dict) -> None:
        # Backup the current good file (if any) before overwriting.
        if self.paths.data_json.exists():
            shutil.copy2(self.paths.data_json, self.paths.data_json_bak)
        # Write to temp file in same dir, then rename.
        fd, tmp_path = tempfile.mkstemp(
            dir=self.paths.root, prefix=".data.", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, sort_keys=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_path, self.paths.data_json)
        except Exception:
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            raise
