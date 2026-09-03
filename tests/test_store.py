import json
import threading

import pytest

from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.store import SCHEMA_VERSION, MetadataStore, NameConflict, NotFound


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


def test_add_rejects_duplicate_id_even_when_name_differs(store):
    first = Entry.new(name="id-first", type=EntryType.API_KEY, fields={})
    second = Entry.new(name="id-second", type=EntryType.API_KEY, fields={})
    second.id = first.id
    store.add(first)

    with pytest.raises(NameConflict, match="entry with id"):
        store.add(second)

    assert [entry.name for entry in store.list()] == [first.name]


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
        except Exception as ex:  # noqa: BLE001 -- surface thread failures in test
            errors.append(ex)

    t1 = threading.Thread(target=add_many, args=("a",))
    t2 = threading.Thread(target=add_many, args=("b",))
    t1.start(); t2.start()
    t1.join(); t2.join()

    assert errors == []
    final = MetadataStore(paths)
    names = {e.name for e in final.list()}
    assert names == {f"a-{i}" for i in range(5)} | {f"b-{i}" for i in range(5)}


def test_tombstone_prune_serializes_with_concurrent_entry_add(
    store,
    monkeypatch,
):
    expired = Entry.new(name="expired", type=EntryType.API_KEY, fields={})
    store.add(expired)
    store.delete_by_name(expired.name)

    atomic_write_entered = threading.Event()
    release_atomic_write = threading.Event()
    writer_started = threading.Event()
    writer_finished = threading.Event()
    errors = []
    original_atomic_write = store._atomic_write

    def blocked_atomic_write(data):
        atomic_write_entered.set()
        if not release_atomic_write.wait(timeout=2):
            raise TimeoutError("test did not release tombstone GC commit")
        original_atomic_write(data)

    monkeypatch.setattr(store, "_atomic_write", blocked_atomic_write)

    def prune():
        try:
            store.prune_tombstones_before("9999-01-01T00:00:00Z")
        except Exception as ex:  # noqa: BLE001 -- surface thread failures in test
            errors.append(ex)

    def add_concurrently():
        try:
            writer_started.set()
            MetadataStore(Paths()).add(
                Entry.new(name="concurrent", type=EntryType.API_KEY, fields={})
            )
        except Exception as ex:  # noqa: BLE001 -- surface thread failures in test
            errors.append(ex)
        finally:
            writer_finished.set()

    prune_thread = threading.Thread(target=prune)
    writer_thread = threading.Thread(target=add_concurrently)
    prune_thread.start()
    try:
        assert atomic_write_entered.wait(timeout=2)
        writer_thread.start()
        assert writer_started.wait(timeout=2)
        assert not writer_finished.wait(timeout=0.05)
    finally:
        release_atomic_write.set()
    prune_thread.join(timeout=2)
    writer_thread.join(timeout=2)

    assert not prune_thread.is_alive()
    assert not writer_thread.is_alive()
    assert errors == []
    final = MetadataStore(Paths())
    assert [entry.name for entry in final.list()] == ["concurrent"]
    assert final.tombstones() == []


def test_transaction_indexes_reject_duplicate_name_and_id(store):
    first = Entry.new(name="indexed-first", type=EntryType.API_KEY, fields={})
    duplicate_name = Entry.new(
        name=first.name,
        type=EntryType.API_KEY,
        fields={},
    )
    duplicate_id = Entry.new(
        name="indexed-second",
        type=EntryType.API_KEY,
        fields={},
    )
    duplicate_id.id = first.id

    with store.transaction() as tx:
        tx.add(first)
        with pytest.raises(NameConflict) as name_error:
            tx.add(duplicate_name)
        assert str(name_error.value) == (
            "entry with name 'indexed-first' already exists "
            "(use --replace to overwrite or --rename to pick a new name)"
        )
        with pytest.raises(NameConflict) as id_error:
            tx.add(duplicate_id)
        assert str(id_error.value) == f"entry with id {first.id!r} already exists"

    assert [entry.id for entry in store.list()] == [first.id]


def test_transaction_update_rename_preserves_order_and_entry_isolation(store):
    first = Entry.new(name="rename-first", type=EntryType.API_KEY, fields={})
    middle = Entry.new(name="rename-middle", type=EntryType.API_KEY, fields={})
    last = Entry.new(name="rename-last", type=EntryType.API_KEY, fields={})
    with store.transaction() as tx:
        for entry in (first, middle, last):
            tx.add(entry)

    with store.transaction() as tx:
        renamed = tx.get_by_id(middle.id)
        assert renamed is not None
        renamed.name = "rename-new"
        tx.update(renamed)

        assert tx.get_by_name("rename-middle") is None
        assert tx.get_by_name("rename-new").id == middle.id
        assert [entry.name for entry in tx.list()] == [
            "rename-first",
            "rename-new",
            "rename-last",
        ]

        detached = tx.get_by_id(middle.id)
        detached.tags.append("not-persisted")
        assert tx.get_by_id(middle.id).tags == []

        conflict = tx.get_by_id(middle.id)
        conflict.name = first.name
        with pytest.raises(
            NameConflict,
            match="entry with name 'rename-first' already exists",
        ):
            tx.update(conflict)
        assert tx.get_by_id(middle.id).name == "rename-new"

    assert [entry.name for entry in store.list()] == [
        "rename-first",
        "rename-new",
        "rename-last",
    ]


def test_transaction_replace_updates_id_index_without_moving_entry(store):
    first = Entry.new(name="replace-first", type=EntryType.API_KEY, fields={})
    middle = Entry.new(name="replace-middle", type=EntryType.API_KEY, fields={})
    last = Entry.new(name="replace-last", type=EntryType.API_KEY, fields={})
    with store.transaction() as tx:
        for entry in (first, middle, last):
            tx.add(entry)

    replacement = Entry.new(
        name=middle.name,
        type=EntryType.API_KEY,
        fields={},
    )
    conflict = Entry.new(
        name=first.name,
        type=EntryType.API_KEY,
        fields={},
    )
    conflict.id = last.id

    with store.transaction() as tx:
        tx.replace_by_name(replacement)
        assert tx.get_by_id(middle.id) is None
        assert tx.get_by_id(replacement.id).name == middle.name
        assert [entry.id for entry in tx.list()] == [
            first.id,
            replacement.id,
            last.id,
        ]
        with pytest.raises(NameConflict) as error:
            tx.replace_by_name(conflict)
        assert str(error.value) == f"entry with id {last.id!r} already exists"

    assert [entry.id for entry in store.list()] == [
        first.id,
        replacement.id,
        last.id,
    ]


def test_transaction_delete_keeps_order_and_new_add_appends(store):
    first = Entry.new(name="delete-first", type=EntryType.API_KEY, fields={})
    middle = Entry.new(name="delete-middle", type=EntryType.API_KEY, fields={})
    last = Entry.new(name="delete-last", type=EntryType.API_KEY, fields={})
    appended = Entry.new(name="delete-appended", type=EntryType.API_KEY, fields={})
    with store.transaction() as tx:
        for entry in (first, middle, last):
            tx.add(entry)

    with store.transaction() as tx:
        deleted = tx.delete_by_name(middle.name)
        assert deleted.id == middle.id
        assert tx.get_by_name(middle.name) is None
        assert tx.get_by_id(middle.id) is None
        tx.add(appended)
        assert [entry.name for entry in tx.list()] == [
            first.name,
            last.name,
            appended.name,
        ]
        with pytest.raises(NotFound) as error:
            tx.delete_by_name("delete-missing")
        assert str(error.value) == "no entry with name 'delete-missing'"

    assert [entry.name for entry in store.list()] == [
        first.name,
        last.name,
        appended.name,
    ]
    assert [(item["id"], item["name"]) for item in store.tombstones()] == [
        (middle.id, middle.name)
    ]


def test_transaction_rollback_commit_and_serialized_bytes_are_stable(store):
    base = Entry.new(name="transaction-base", type=EntryType.API_KEY, fields={})
    store.add(base)
    before_rollback = Paths().data_json.read_bytes()

    with pytest.raises(RuntimeError, match="abort transaction"):
        with store.transaction() as tx:
            tx.delete_by_name(base.name)
            tx.add(
                Entry.new(
                    name="transaction-rolled-back",
                    type=EntryType.API_KEY,
                    fields={},
                )
            )
            raise RuntimeError("abort transaction")

    assert Paths().data_json.read_bytes() == before_rollback
    assert [entry.id for entry in store.list()] == [base.id]
    assert store.tombstones() == []

    committed = Entry.new(
        name="transaction-committed",
        type=EntryType.API_KEY,
        fields={},
    )
    with store.transaction() as tx:
        tx.add(committed)

    committed_bytes = Paths().data_json.read_bytes()
    with store.transaction() as tx:
        assert tx.get_by_name(base.name).id == base.id
        assert tx.get_by_id(committed.id).name == committed.name
        tx.revision()

    assert Paths().data_json.read_bytes() == committed_bytes
    assert json.loads(committed_bytes) == {
        "schema_version": SCHEMA_VERSION,
        "entries": [base.to_dict(), committed.to_dict()],
        "tombstones": [],
    }
