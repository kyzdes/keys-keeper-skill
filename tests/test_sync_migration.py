"""Phase 0 — data.json schema v1->v2 migration + tombstone soft-delete.

Pure metadata-store behaviour; no keychain or network. Cross-platform.
"""
import json
import pytest

from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, SCHEMA_VERSION, StoreError
from keys_keeper.models import Entry, EntryType


def _write_raw(paths: Paths, data: dict) -> None:
    paths.ensure()
    paths.data_json.write_text(json.dumps(data))


def _v1_file(paths: Paths) -> dict:
    e = Entry.new(name="api-one", type=EntryType.API_KEY).to_dict()
    data = {"schema_version": 1, "entries": [e]}  # NOTE: no "tombstones" key
    _write_raw(paths, data)
    return data


def test_F11_v1_migrates_to_v2_lossless_with_backup(kk_home):
    paths = Paths()
    _v1_file(paths)
    store = MetadataStore(paths)

    # Pure read migrates in memory and preserves the entry.
    entries = store.list()
    assert [e.name for e in entries] == ["api-one"]
    assert store.tombstones() == []

    # A write persists v2 to disk.
    store.add(Entry.new(name="api-two", type=EntryType.API_KEY))
    on_disk = json.loads(paths.data_json.read_text())
    assert on_disk["schema_version"] == SCHEMA_VERSION == 2
    assert "tombstones" in on_disk and on_disk["tombstones"] == []
    assert sorted(e["name"] for e in on_disk["entries"]) == ["api-one", "api-two"]
    # Pre-migration backup exists and still reads as v1.
    bak = paths.root / "data.v1.json.bak"
    assert bak.exists()
    assert json.loads(bak.read_text())["schema_version"] == 1


def test_F11_migration_is_idempotent(kk_home):
    paths = Paths()
    _v1_file(paths)
    store = MetadataStore(paths)
    store.add(Entry.new(name="api-two", type=EntryType.API_KEY))  # persists v2
    # Second read of an already-v2 file: no error, no schema change.
    again = MetadataStore(paths)
    assert len(again.list()) == 2
    assert json.loads(paths.data_json.read_text())["schema_version"] == 2


def test_F10_delete_records_tombstone(kk_home):
    paths = Paths()
    store = MetadataStore(paths)
    e = Entry.new(name="doomed", type=EntryType.API_KEY)
    store.add(e)
    removed = store.delete_by_name("doomed")
    assert removed.id == e.id
    assert store.get_by_name("doomed") is None  # gone from live set
    ts = store.tombstones()
    assert len(ts) == 1
    assert ts[0]["id"] == e.id
    assert ts[0]["name"] == "doomed"
    assert ts[0]["deleted_at"].endswith("Z")  # ISO-8601 UTC


def test_F12_future_schema_is_refused_and_writes_nothing(kk_home):
    paths = Paths()
    _write_raw(paths, {"schema_version": SCHEMA_VERSION + 1, "entries": [], "tombstones": []})
    before = paths.data_json.read_text()
    store = MetadataStore(paths)
    with pytest.raises(StoreError):
        store.list()
    assert paths.data_json.read_text() == before  # untouched


def test_apply_merge_replaces_entries_and_tombstones(kk_home):
    paths = Paths()
    store = MetadataStore(paths)
    store.add(Entry.new(name="keep-me", type=EntryType.API_KEY))
    new_entries = [Entry.new(name="merged-in", type=EntryType.API_KEY)]
    new_tombstones = [{"id": "kk:dead", "name": "old", "deleted_at": "2026-06-03T00:00:00Z"}]
    store.apply_merge(new_entries, new_tombstones)
    assert [e.name for e in store.list()] == ["merged-in"]
    assert store.tombstones() == new_tombstones
