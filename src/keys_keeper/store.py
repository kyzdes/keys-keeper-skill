"""Metadata store backed by a JSON file with atomic writes + exclusive lock."""
from __future__ import annotations
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterator
from contextlib import contextmanager

from keys_keeper._locking import lock_exclusive, unlock
from keys_keeper.models import Entry, EntryType, now_iso
from keys_keeper.paths import Paths, ensure_private_dir


# v2 (2026-06): adds a top-level `tombstones` list so deletes propagate through
# S3 sync instead of being resurrected by an older peer snapshot. See sync.py.
SCHEMA_VERSION = 2


class StoreError(RuntimeError):
    pass


class NameConflict(StoreError):
    pass


class NotFound(StoreError):
    pass


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
                    data["entries"][i] = entry.to_dict()
                    return
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

    # ---------- internal ----------

    def _read(self) -> dict:
        if not self.paths.data_json.exists():
            return {"schema_version": SCHEMA_VERSION, "entries": [], "tombstones": []}
        raw = self.paths.data_json.read_text()
        if not raw.strip():
            return {"schema_version": SCHEMA_VERSION, "entries": [], "tombstones": []}
        data = json.loads(raw)
        sv = data.get("schema_version", 0)
        if sv > SCHEMA_VERSION:
            raise StoreError(
                f"data.json schema_version={sv} is newer than this CLI supports "
                f"({SCHEMA_VERSION}); upgrade keys-keeper"
            )
        if sv < SCHEMA_VERSION:
            data = self._migrate(data, sv)
        data.setdefault("tombstones", [])
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
