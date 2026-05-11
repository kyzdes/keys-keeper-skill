import json
import os
import threading
import time
import pytest
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, NameConflict, NotFound, SCHEMA_VERSION


@pytest.fixture
def store(kk_home):
    paths = Paths()
    paths.ensure()
    return MetadataStore(paths)


def test_initial_load_returns_empty_when_no_file(store):
    assert store.list() == []


def test_add_and_list(store):
    e = Entry.new(name="ok-1", type=EntryType.API_KEY, fields={})
    store.add(e)
    listed = store.list()
    assert len(listed) == 1
    assert listed[0].name == "ok-1"


def test_add_persists_to_disk(store, kk_home):
    e = Entry.new(name="ok-2", type=EntryType.API_KEY, fields={})
    store.add(e)
    # New store instance reads from disk
    paths = Paths()
    store2 = MetadataStore(paths)
    assert store2.get_by_name("ok-2") is not None


def test_add_rejects_duplicate_name(store):
    store.add(Entry.new(name="dup", type=EntryType.API_KEY, fields={}))
    with pytest.raises(NameConflict):
        store.add(Entry.new(name="dup", type=EntryType.API_KEY, fields={}))


def test_get_by_name_returns_none_for_missing(store):
    assert store.get_by_name("nope") is None


def test_get_by_name_finds_existing(store):
    store.add(Entry.new(name="findme", type=EntryType.API_KEY, fields={}))
    e = store.get_by_name("findme")
    assert e is not None
    assert e.name == "findme"


def test_update_replaces_entry(store):
    e = Entry.new(name="upd", type=EntryType.API_KEY, fields={})
    store.add(e)
    e.tags = ["new-tag"]
    store.update(e)
    assert store.get_by_name("upd").tags == ["new-tag"]


def test_delete_removes_entry(store):
    store.add(Entry.new(name="del", type=EntryType.API_KEY, fields={}))
    store.delete_by_name("del")
    assert store.get_by_name("del") is None


def test_delete_missing_raises(store):
    with pytest.raises(NotFound):
        store.delete_by_name("never-existed")


def test_atomic_write_creates_backup(store, kk_home):
    e1 = Entry.new(name="first", type=EntryType.API_KEY, fields={})
    store.add(e1)
    e2 = Entry.new(name="second", type=EntryType.API_KEY, fields={})
    store.add(e2)
    paths = Paths()
    assert paths.data_json.exists()
    assert paths.data_json_bak.exists()


def test_schema_version_written(store):
    paths = Paths()
    store.add(Entry.new(name="x-test", type=EntryType.API_KEY, fields={}))
    raw = json.loads(paths.data_json.read_text())
    assert raw["schema_version"] == SCHEMA_VERSION


def test_concurrent_writes_serialize(store, kk_home):
    """Two threads adding different entries must both succeed without losing one."""
    paths = Paths()
    errors = []

    def add_many(prefix: str):
        try:
            local_store = MetadataStore(paths)
            for i in range(5):
                local_store.add(
                    Entry.new(name=f"{prefix}-{i}", type=EntryType.API_KEY, fields={})
                )
        except Exception as ex:
            errors.append(ex)

    t1 = threading.Thread(target=add_many, args=("a",))
    t2 = threading.Thread(target=add_many, args=("b",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert errors == []
    final = MetadataStore(paths)
    names = {e.name for e in final.list()}
    assert names == {f"a-{i}" for i in range(5)} | {f"b-{i}" for i in range(5)}
