"""Optimistic secret preimages and complete replacement use the durable boundary."""
from __future__ import annotations

from copy import deepcopy

import pytest

from keys_keeper.backend import KeychainError, SecretAccessDenied
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.paths import Paths
from keys_keeper.service import ConcurrentMutation, SecretInput, VaultService
from keys_keeper.store import MetadataStore
from test_service import FaultBackend


@pytest.fixture
def vault(tmp_path):
    store = MetadataStore(Paths(tmp_path / "synthetic"))
    backend = FaultBackend()
    service = VaultService(store, backend)
    entry = Entry.new(name="key", type=EntryType.SSH_KEY,
                      fields={"public_key": "ssh-ed25519 synthetic"})
    service.create_entry(entry, secrets=SecretInput(value="old", passphrase="old-passphrase"))
    return store, backend, service, entry


@pytest.mark.parametrize("kind", ["secret", "passphrase", "delete", "empty-to-absent", "absent-to-empty"])
def test_snapshot_account_race_rejected_before_journal_or_mutation(vault, monkeypatch, kind):
    store, backend, service, entry = vault
    account = entry.id if kind == "secret" else entry.id + ":passphrase"
    if kind == "empty-to-absent":
        backend.values[account] = ""
    if kind == "absent-to-empty":
        backend.values.pop(account)
    old = ({"present": True, "value": backend.values[account]}
           if account in backend.values else {"present": False})
    snapshot = store.snapshot()
    changed = deepcopy(entry)
    if kind == "secret":
        service.update_entry(changed, secrets=SecretInput(value="fresh"))
    elif kind == "empty-to-absent":
        service.update_entry(changed, secrets=SecretInput(value="old", mode="replace"))
    else:
        service.update_entry(changed, secrets=SecretInput(passphrase="" if kind == "absent-to-empty" else "fresh"))
    assert snapshot.revision == store.snapshot().revision
    metadata_before = store.paths.data_json.read_bytes()
    accounts_before = dict(backend.values)
    monkeypatch.setattr(service.master_mutations.journal, "begin",
                        lambda *_a, **_kw: pytest.fail("stale snapshot must not begin a journal"))
    with pytest.raises(ConcurrentMutation, match="local secrets changed"):
        service.apply_snapshot(snapshot.entries, snapshot.tombstones,
                               secret_writes={} if kind == "delete" else {account: "remote"},
                               secret_deletes=[account] if kind == "delete" else [],
                               expected_revision=snapshot.revision,
                               expected_accounts={account: old})
    assert store.paths.data_json.read_bytes() == metadata_before
    assert backend.values == accounts_before
    assert not service.master_mutations.has_pending


@pytest.mark.parametrize("expected", [{}, {"unrelated": {"present": False}},
                                     {"placeholder": {"present": 1}},
                                     {"placeholder": {"present": False, "value": ""}},
                                     {"placeholder": {"present": True}}])
def test_snapshot_preconditions_require_exact_valid_account_images(vault, monkeypatch, expected):
    store, backend, service, entry = vault
    expected = {entry.id if k == "placeholder" else k: v for k, v in expected.items()}
    snapshot = store.snapshot()
    before = dict(backend.values)
    monkeypatch.setattr(service.master_mutations.journal, "begin",
                        lambda *_a, **_kw: pytest.fail("invalid preimages must not begin a journal"))
    with pytest.raises(ValueError, match="snapshot account preconditions"):
        service.apply_snapshot(snapshot.entries, snapshot.tombstones,
                               secret_writes={entry.id: "remote"}, secret_deletes=[],
                               expected_revision=snapshot.revision, expected_accounts=expected)
    assert backend.values == before


def test_snapshot_preimage_read_denial_is_not_absence(vault, monkeypatch):
    store, backend, service, entry = vault
    snapshot = store.snapshot()
    original_get = backend.get

    def denied(account):
        if account == entry.id:
            raise SecretAccessDenied("synthetic read denial")
        return original_get(account)

    monkeypatch.setattr(backend, "get", denied)
    monkeypatch.setattr(service.master_mutations.journal, "begin",
                        lambda *_a, **_kw: pytest.fail("denied read must not begin a journal"))
    with pytest.raises(SecretAccessDenied):
        service.apply_snapshot(snapshot.entries, snapshot.tombstones,
                               secret_writes={entry.id: "remote"}, secret_deletes=[],
                               expected_revision=snapshot.revision,
                               expected_accounts={entry.id: {"present": True, "value": "old"}})
    assert backend.values[entry.id] == "old"


@pytest.mark.parametrize("schema", [2, 3])
@pytest.mark.parametrize("mode,value,passphrase,expected_value,expected_passphrase", [
    ("patch", None, None, "old", "old-passphrase"),
    ("patch", "", "", "", ""),
    ("replace", "restored", None, "restored", None),
    ("replace", "", "", "", ""),
    ("replace", "restored", "new-passphrase", "restored", "new-passphrase"),
])
def test_secret_patch_and_replace_matrix(vault, schema, mode, value, passphrase,
                                        expected_value, expected_passphrase):
    store, backend, service, entry = vault
    if schema == 3:
        store.migrate_catalog_v3()
    service.create_entry(deepcopy(entry), replace=True,
                         secrets=SecretInput(value=value, passphrase=passphrase, mode=mode))
    assert backend.values[entry.id] == expected_value
    if expected_passphrase is None:
        assert entry.id + ":passphrase" not in backend.values
    else:
        assert backend.values[entry.id + ":passphrase"] == expected_passphrase
    assert store.schema_version == schema
    assert not service.master_mutations.has_pending


def test_replacement_can_create_optional_account_after_absence(vault):
    store, backend, service, entry = vault
    service.update_entry(deepcopy(entry), secrets=SecretInput(value="old", mode="replace"))
    assert entry.id + ":passphrase" not in backend.values
    service.update_entry(deepcopy(entry), secrets=SecretInput(value="new", passphrase="", mode="replace"))
    assert backend.values[entry.id + ":passphrase"] == ""


@pytest.mark.parametrize("schema", [2, 3])
def test_replacement_cannot_delete_required_secret_before_begin(vault, monkeypatch, schema):
    store, backend, service, entry = vault
    if schema == 3:
        store.migrate_catalog_v3()
    before = dict(backend.values)
    metadata = store.paths.data_json.read_bytes()
    monkeypatch.setattr(service.master_mutations.journal, "begin",
                        lambda *_a, **_kw: pytest.fail("incomplete replacement must not begin a journal"))
    with pytest.raises(ValidationError, match="requires a secret"):
        service.update_entry(store.get_by_id(entry.id), secrets=SecretInput(mode="replace"))
    assert backend.values == before
    assert store.paths.data_json.read_bytes() == metadata


@pytest.mark.parametrize("schema", [2, 3])
def test_replacement_restores_secret_and_deleted_passphrase_on_failure(vault, schema):
    store, backend, service, entry = vault
    if schema == 3:
        store.migrate_catalog_v3()
    before = dict(backend.values)
    metadata = store.paths.data_json.read_bytes()
    backend.fail_after = ("delete", entry.id + ":passphrase")
    changed = store.get_by_id(entry.id)
    changed.note = "replacement"
    with pytest.raises(KeychainError, match="injected delete failure"):
        service.update_entry(changed, secrets=SecretInput(value="restored", mode="replace"))
    assert backend.values == before
    assert store.paths.data_json.read_bytes() == metadata
    assert not service.master_mutations.has_pending


def test_secret_input_rejects_unknown_mode():
    with pytest.raises(ValueError, match="mode must be patch or replace"):
        SecretInput(mode="replace-maybe")
