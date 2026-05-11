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
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths


SCHEMA_VERSION = 1


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
                    return Entry.from_dict(data["entries"].pop(i))
            raise NotFound(f"no entry with name {name!r}")

    # ---------- internal ----------

    def _read(self) -> dict:
        if not self.paths.data_json.exists():
            return {"schema_version": SCHEMA_VERSION, "entries": []}
        raw = self.paths.data_json.read_text()
        if not raw.strip():
            return {"schema_version": SCHEMA_VERSION, "entries": []}
        data = json.loads(raw)
        sv = data.get("schema_version", 0)
        if sv > SCHEMA_VERSION:
            raise StoreError(
                f"data.json schema_version={sv} is newer than this CLI supports "
                f"({SCHEMA_VERSION}); upgrade keys-keeper"
            )
        if sv < SCHEMA_VERSION:
            data = self._migrate(data, sv)
        return data

    def _migrate(self, data: dict, from_version: int) -> dict:
        # No older versions exist yet; reserved for future schema bumps.
        # Keep a backup on any migration.
        bak = self.paths.root / f"data.v{from_version}.json.bak"
        if self.paths.data_json.exists():
            shutil.copy2(self.paths.data_json, bak)
        data["schema_version"] = SCHEMA_VERSION
        return data

    @contextmanager
    def _locked_write(self) -> Iterator[dict]:
        """Acquire exclusive lock, read, yield mutable dict, write atomically."""
        self.paths.root.mkdir(parents=True, exist_ok=True)
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
