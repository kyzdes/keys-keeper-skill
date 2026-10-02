"""Integrity regressions shared by standalone and project master profiles."""
from __future__ import annotations

import os

import pytest

from _sync_fakes import FakeBackend
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.project_runtime import _ReadBackend
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore, StoreError


@pytest.mark.parametrize("schema", [2, 3])
@pytest.mark.parametrize("writer", ["store", "service"])
def test_referenced_name_cannot_change_identity(tmp_path, schema, writer):
    store = MetadataStore(Paths(tmp_path / "synthetic-vault"))
    if schema == 3:
        store.migrate_catalog_v3()
    backend = FakeBackend()
    service = VaultService(store, backend)
    key = Entry.new(name="original-key", type=EntryType.API_KEY)
    service.create_entry(key, secrets=SecretInput(value="synthetic-original"))
    server = Entry.new(name="dependent-server", type=EntryType.SERVER,
                       fields={"host": "example.test", "user": "tester", "auth": "ssh_key"},
                       refs=[{"role": "ssh_key", "name": key.name}])
    service.create_entry(server)
    before = store.snapshot().revision
    changed = store.get_by_id(key.id)
    changed.name = "renamed-key"
    with pytest.raises(StoreError, match="referenced"):
        if writer == "store":
            store.update(changed)
        else:
            service.update_entry(changed, secrets=SecretInput(value="synthetic-replacement"))
    assert store.snapshot().revision == before
    assert store.get_by_name("original-key").id == key.id
    assert backend.get(key.id).unseal() == "synthetic-original"
    assert store.get_by_id(server.id).refs == [{"role": "ssh_key", "name": "original-key"}]
    assert not service.master_mutations.has_pending


@pytest.mark.parametrize("data", [b"", b" \n\t"])
def test_existing_empty_metadata_is_never_a_new_vault(tmp_path, data):
    paths = Paths(tmp_path / "synthetic-vault")
    paths.ensure()
    paths.data_json.write_bytes(data)
    if os.name == "posix":
        paths.data_json.chmod(0o600)
    store = MetadataStore(paths)
    with pytest.raises(StoreError, match="empty"):
        store.list()
    with pytest.raises(StoreError, match="empty"):
        store.add(Entry.new(name="must-not-persist", type=EntryType.API_KEY))
    assert paths.data_json.read_bytes() == data


def test_read_backend_uses_one_coherent_generation_and_next_operation_refreshes():
    class View:
        def __init__(self):
            self.generation = {"a": "synthetic-old-a", "b": "synthetic-old-b"}
            self.reads = 0

        def _read(self):
            self.reads += 1
            return [], dict(self.generation)

    view = View()
    operation = _ReadBackend(view)
    assert operation.list_ids() == ["a", "b"]
    assert operation.get("a").unseal() == "synthetic-old-a"
    view.generation = {"a": "synthetic-new-a", "b": "synthetic-new-b"}
    assert operation.get("b").unseal() == "synthetic-old-b"
    assert view.reads == 1
    assert _ReadBackend(view).get("a").unseal() == "synthetic-new-a"
