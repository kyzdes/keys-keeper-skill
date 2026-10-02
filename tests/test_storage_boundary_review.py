"""Independent regressions for the shared metadata mutation boundary.

Every fixture is synthetic and isolated; no OS credential backend is opened.
"""
from __future__ import annotations

import copy
import json
import uuid

import pytest

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.master_journal import MASTER_MUTATION_KIND, MasterMutationManager, MasterRecoveryRequired
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.operation_journal import JournalError, OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.private_files import atomic_write_bytes
from keys_keeper.service import SecretInput
from keys_keeper.store import MetadataStore, NameConflict, StoreError


class _MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values = {}
        self.writes = []

    def get(self, account):
        if account not in self.values:
            raise KeychainError("synthetic account is absent")
        return Sealed(self.values[account])

    def list_ids(self):
        return list(self.values)

    def set(self, account, value):
        self.writes.append(("set", account))
        self.values[account] = value

    def delete(self, account):
        self.writes.append(("delete", account))
        self.values.pop(account, None)


def _components(tmp_path, *, catalog=False):
    store = MetadataStore(Paths(tmp_path / "profile"))
    if catalog:
        store.migrate_catalog_v3()
    backend = _MemoryBackend()
    journal = OperationJournal(paths=store.paths,
                               password_provider=lambda: b"synthetic-review-journal-key")
    return store, backend, journal, MasterMutationManager(store, backend, journal)


@pytest.mark.parametrize("schema,duplicate", [(2, "id"), (2, "name"), (3, "name")])
def test_metadata_parser_rejects_ambiguous_persisted_identities(tmp_path, schema, duplicate):
    store, _backend, _journal, _manager = _components(tmp_path)
    store.add(Entry.new(name="original", type=EntryType.API_KEY))
    if schema == 3:
        store.migrate_catalog_v3()
    data = store._read()
    other = copy.deepcopy(data["entries"][0])
    other["name" if duplicate == "id" else "id"] = (
        "different-name" if duplicate == "id" else str(uuid.uuid4())
    )
    data["entries"].append(other)
    original = json.dumps(data).encode("utf-8")
    atomic_write_bytes(store.paths.data_json, original)

    with pytest.raises(StoreError):
        store.snapshot()

    assert store.paths.data_json.read_bytes() == original


@pytest.mark.parametrize("defect", ["rename_collision", "create_id_collision", "missing_folder"])
def test_single_entry_feasibility_is_proved_before_journal_or_backend(tmp_path, monkeypatch, defect):
    store, backend, journal, manager = _components(tmp_path, catalog=True)
    original = Entry.new(name="original", type=EntryType.API_KEY)
    store.add(original)
    backend.values[original.id] = "synthetic-original"
    before = store.snapshot().revision

    def forbidden_begin(*_args, **_kwargs):
        pytest.fail("invalid metadata reached the durable journal boundary")

    monkeypatch.setattr(journal, "begin", forbidden_begin)
    if defect == "rename_collision":
        occupied = Entry.new(name="occupied", type=EntryType.API_KEY)
        store.add(occupied)
        before = store.snapshot().revision
        candidate = store.get_by_id(original.id)
        candidate.name = occupied.name
        operation = manager.update_entry
        expected = NameConflict
    else:
        candidate = Entry.new(name="candidate", type=EntryType.API_KEY)
        operation = manager.create_entry
        expected = StoreError
        if defect == "create_id_collision":
            candidate.id = original.id
            expected = (StoreError, MasterRecoveryRequired)
        else:
            candidate.folder_id = str(uuid.uuid4())

    with pytest.raises(expected):
        operation(candidate, secrets=SecretInput(value="synthetic-new"))

    assert backend.writes == []
    assert backend.values == {original.id: "synthetic-original"}
    assert store.snapshot().revision == before


def test_recovery_rejects_invalid_after_catalog_before_backend_side_effect(tmp_path):
    store, backend, journal, manager = _components(tmp_path, catalog=True)
    candidate = Entry.new(name="invalid-recovery", type=EntryType.API_KEY)
    candidate.folder_id = str(uuid.uuid4())
    catalog = store.catalog_state()
    state = manager._state(
        action="create", before_revision=store.snapshot().revision,
        entry_before=None, entry_after=candidate,
        dependents_before=[], dependents_after=[],
        catalog_before=catalog, catalog_after=catalog,
        accounts_after={candidate.id: {"present": True, "value": "synthetic-new"}},
    )
    record = journal.begin(MASTER_MUTATION_KIND, state=state)

    with pytest.raises(StoreError):
        manager.recover()

    assert backend.writes == []
    assert backend.values == {}
    assert not journal.read(record.operation_id).finished
    assert manager.has_pending


def test_recovery_rejects_missing_required_secret_before_metadata_publication(tmp_path):
    store, backend, journal, manager = _components(tmp_path)
    before = store.snapshot().revision
    candidate = Entry.new(name="credential-without-secret", type=EntryType.API_KEY)
    state = manager._state(
        action="create", before_revision=before,
        entry_before=None, entry_after=candidate,
        dependents_before=[], dependents_after=[],
        catalog_before=None, catalog_after=None, accounts_after={},
    )
    record = journal.begin(MASTER_MUTATION_KIND, state=state)

    with pytest.raises(ValidationError):
        manager.recover()

    assert backend.writes == []
    assert store.snapshot().revision == before
    assert not journal.read(record.operation_id).finished
    assert manager.has_pending


def test_manager_recovery_resource_preflight_precedes_indexed_decrypt_and_backend(tmp_path, monkeypatch):
    store, backend, journal, manager = _components(tmp_path)
    candidate = Entry.new(name="indexed-mutation", type=EntryType.API_KEY)
    state = manager._state(
        action="create", before_revision=store.snapshot().revision,
        entry_before=None, entry_after=candidate,
        dependents_before=[], dependents_after=[],
        catalog_before=None, catalog_after=None,
        accounts_after={candidate.id: {"present": True, "value": "synthetic-new"}},
    )
    journal.begin(MASTER_MUTATION_KIND, state=state)
    monkeypatch.setattr("keys_keeper.operation_journal._MAX_MIGRATION_RECORDS", 0)

    def forbidden_read(*_args, **_kwargs):
        pytest.fail("indexed ciphertext decrypted before directory resource preflight")

    monkeypatch.setattr(journal, "read", forbidden_read)
    with pytest.raises(JournalError):
        manager.recover()

    assert backend.writes == []
    assert backend.values == {}


def test_allowed_legacy_optional_fields_survive_backup_roundtrip(tmp_path):
    from keys_keeper.project_backup import create_master_backup, inspect_backup, restore_backup

    store, backend, journal, _manager = _components(tmp_path)
    candidate = Entry.new(name="legacy-optional-fields", type=EntryType.API_KEY)
    raw = candidate.to_dict()
    del raw["tags"]
    atomic_write_bytes(store.paths.data_json, json.dumps({
        "schema_version": 2, "entries": [raw], "tombstones": [],
    }).encode("utf-8"))
    backend.values[candidate.id] = "synthetic-secret"
    before = store.snapshot().revision
    destination = tmp_path / "legacy-backup.enc"

    manifest = create_master_backup(store, backend, journal=journal,
                                    destination=destination, password="synthetic-backup")
    assert inspect_backup(destination, password="synthetic-backup") == manifest
    recovered = restore_backup(destination, password="synthetic-backup",
                               recovery_root=tmp_path / "recovered",
                               recovery_password="synthetic-recovery")
    assert recovered.metadata_store().snapshot().revision == before
    assert recovered.open_master_backend("synthetic-recovery").get(candidate.id).unseal() == "synthetic-secret"


def test_explicit_update_can_repair_legacy_note_field_without_automatic_migration(tmp_path):
    store, backend, _journal, manager = _components(tmp_path)
    candidate = Entry.new(name="legacy-note", type=EntryType.NOTE,
                          fields={"secret_body": False, "body": "synthetic-note"})
    raw = candidate.to_dict()
    raw["fields"]["secret_body"] = "false"
    atomic_write_bytes(store.paths.data_json, json.dumps({
        "schema_version": 2, "entries": [raw], "tombstones": [],
    }).encode("utf-8"))
    repaired = store.get_by_id(candidate.id)
    assert repaired.fields["secret_body"] == "false"
    repaired.fields["secret_body"] = False

    manager.update_entry(repaired)

    assert store.get_by_id(candidate.id).fields["secret_body"] is False
    assert backend.writes == []
