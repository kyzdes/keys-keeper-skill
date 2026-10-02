"""Independent adversarial checks of the shared durable mutation boundary."""
from __future__ import annotations

import pytest

from _sync_fakes import FakeBackend
from keys_keeper.master_journal import MasterMutationManager, MasterRecoveryRequired
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


def components(tmp_path, schema):
    paths = Paths(tmp_path / "synthetic-vault")
    store = MetadataStore(paths)
    if schema == 3:
        store.migrate_catalog_v3()
    backend = FakeBackend()
    journal = OperationJournal(paths=paths, password_provider=lambda: "synthetic-journal-key")
    manager = MasterMutationManager(store, backend, journal)
    return store, backend, journal, manager, VaultService(store, backend, master_mutations=manager)


@pytest.mark.parametrize("schema", [2, 3])
@pytest.mark.parametrize("invalid", ["metadata", "secret"])
def test_invalid_single_mutation_never_leaves_unrecoverable_pending_state(tmp_path, schema, invalid):
    store, backend, journal, manager, service = components(tmp_path, schema)
    entry = Entry.new(name="synthetic-key", type=EntryType.API_KEY)
    value = "synthetic-value"
    if invalid == "metadata":
        entry.name = "invalid NAME"
    else:
        value = 123
    with pytest.raises((ValidationError, MasterRecoveryRequired, ValueError, TypeError)):
        service.create_entry(entry, secrets=SecretInput(value=value))
    assert not manager.has_pending, "invalid caller input must not poison recovery"
    assert journal.list_unfinished() == []
    assert store.list() == []
    assert entry.id not in backend.d


@pytest.mark.parametrize("schema", [2, 3])
def test_postcommit_metadata_race_cannot_become_trusted_after_revision(tmp_path, schema, monkeypatch):
    store, backend, _journal, manager, service = components(tmp_path, schema)
    entry = Entry.new(name="synthetic-key", type=EntryType.API_KEY)
    original = manager._commit_record

    def unrelated_commit(operation_id):
        # A metadata-only writer can acquire data.lock after the transaction
        # releases it, even while this manager still owns its profile lock.
        store.delete_by_name(entry.name)
        return original(operation_id)

    monkeypatch.setattr(manager, "_commit_record", unrelated_commit)
    with pytest.raises(MasterRecoveryRequired):
        service.create_entry(entry, secrets=SecretInput(value="synthetic-value"))
    assert manager.has_pending, "a divergent after image must not be declared applied"
    assert store.get_by_id(entry.id) is None


@pytest.mark.parametrize("schema", [2, 3])
@pytest.mark.parametrize("type_,fields", [
    (EntryType.API_KEY, {}),
    (EntryType.SSH_KEY, {"public_key": "ssh-ed25519 synthetic"}),
    (EntryType.NOTE, {"secret_body": True}),
    (EntryType.SERVER, {"host": "synthetic.example", "user": "root", "auth": "password"}),
])
def test_required_primary_secret_missing_is_rejected_before_durable_preparation(tmp_path, schema, type_, fields):
    store, backend, journal, manager, service = components(tmp_path, schema)
    entry = Entry.new(name="synthetic-secret-entry", type=type_, fields=fields)
    with pytest.raises((ValidationError, MasterRecoveryRequired, ValueError)):
        service.create_entry(entry)
    assert not manager.has_pending and journal.list_unfinished() == []
    assert store.list() == [] and entry.id not in backend.d


@pytest.mark.parametrize("schema", [2, 3])
def test_public_note_does_not_require_a_primary_secret(tmp_path, schema):
    store, backend, _journal, manager, service = components(tmp_path, schema)
    entry = Entry.new(name="synthetic-public-note", type=EntryType.NOTE,
                      fields={"secret_body": False, "body": "public"})
    service.create_entry(entry)
    assert store.get_by_id(entry.id).fields == {"secret_body": False, "body": "public"}
    assert entry.id not in backend.d and not manager.has_pending


@pytest.mark.parametrize("schema", [2, 3])
def test_known_existing_primary_can_be_adopted_without_rewriting_it(tmp_path, schema):
    store, backend, _journal, manager, service = components(tmp_path, schema)
    entry = Entry.new(name="synthetic-existing-key", type=EntryType.API_KEY)
    backend.set(entry.id, "synthetic-existing")
    service.create_entry(entry)
    assert store.get_by_id(entry.id) is not None
    assert backend.get(entry.id).unseal() == "synthetic-existing"
    assert not manager.has_pending
