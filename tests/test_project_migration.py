import json

import pytest

from keys_keeper.models import Entry, EntryType, ValidationError, validate_snapshot_payload
from keys_keeper.paths import Paths
from keys_keeper.store import CATALOG_SCHEMA_VERSION, MetadataStore, StoreError


def test_catalog_migration_is_explicit_lossless_and_private(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    original = Entry.new(name="legacy-key", type=EntryType.API_KEY)
    store.add(original)
    before = paths.data_json.read_text()

    # A normal read must not create a v3 catalog or rewrite v2 metadata.
    assert store.list()[0].id == original.id
    assert paths.data_json.read_text() == before

    store.migrate_catalog_v3()
    raw = json.loads(paths.data_json.read_text())
    assert raw["schema_version"] == CATALOG_SCHEMA_VERSION
    assert json.loads((paths.root / "data.v2.json.bak").read_text())["schema_version"] == 2
    migrated = store.list()[0]
    assert migrated.id == original.id
    assert migrated.distribution == "local_only"
    assert migrated.folder_id == raw["catalog"]["folders"][0]["id"]
    assert migrated.content_revision is not None


def test_interrupted_catalog_migration_leaves_legacy_file_unchanged(kk_home, monkeypatch):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    store.add(Entry.new(name="legacy-key", type=EntryType.API_KEY))
    before = paths.data_json.read_text()

    def interrupted(_data):
        raise OSError("simulated interruption before replace")

    monkeypatch.setattr(store, "_atomic_write", interrupted)
    with pytest.raises(OSError, match="simulated interruption"):
        store.migrate_catalog_v3()
    assert paths.data_json.read_text() == before


def test_catalog_migration_rejects_a_change_after_backup_revision(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    store.add(Entry.new(name="first", type=EntryType.API_KEY))
    backed_up_revision = store.snapshot().revision
    store.add(Entry.new(name="changed-after-backup", type=EntryType.API_KEY))

    with pytest.raises(StoreError, match="source changed"):
        store.migrate_catalog_v3(expected_revision=backed_up_revision)
    assert json.loads(paths.data_json.read_text())["schema_version"] == 2


def test_schema_v3_rejects_invalid_references_and_legacy_snapshot_roundtrip(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    entry = Entry.new(name="legacy-key", type=EntryType.API_KEY)
    store.add(entry)
    store.migrate_catalog_v3()
    raw = json.loads(paths.data_json.read_text())
    raw["entries"][0]["folder_id"] = "11111111-1111-4111-8111-111111111111"
    paths.data_json.write_text(json.dumps(raw))
    with pytest.raises(StoreError, match="folder_id refers"):
        MetadataStore(paths).list()

    with pytest.raises(ValidationError, match="unsupported snapshot schema_version"):
        validate_snapshot_payload({"schema_version": 3, "entries": [], "tombstones": []})


def test_v3_normalizes_a_legacy_entry_writer_to_private_defaults(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    created = Entry.new(name="normal-writer", type=EntryType.API_KEY)
    store.add(created)
    raw = json.loads(paths.data_json.read_text())
    record = next(item for item in raw["entries"] if item["id"] == created.id)
    assert record["folder_id"] is None
    assert record["distribution"] == "local_only"
    assert record["provenance"] == {"source": "local"}
    assert record["content_revision"]
