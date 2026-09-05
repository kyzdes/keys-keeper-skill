from __future__ import annotations

import pytest

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.master_journal import MasterMutationManager
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_service import ProjectService
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore
from keys_keeper.sync import LegacyCatalogSyncError, build_snapshot_payload


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}
        self.get_calls = 0

    def get(self, account: str) -> Sealed:
        self.get_calls += 1
        if account not in self.values:
            raise KeychainError("missing")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


def _env(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    backend = MemoryBackend()
    service = VaultService(store, backend)
    entry = Entry.new(name="catalog-key", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="synthetic"))
    store.migrate_catalog_v3()
    journal = OperationJournal(
        paths=paths, password_provider=lambda: b"project-service-test-key"
    )
    service = VaultService(
        store,
        backend,
        master_mutations=MasterMutationManager(store, backend, journal),
    )
    projects = ProjectService(store)
    project = projects.create_project("alice", "Alice")
    scope = projects.create_scope(project.id)
    projects.set_entry_distribution(entry.id, "project_allowed")
    projects.assign(scope.id, entry.id)
    return store, backend, service, projects, entry, scope


def test_v3_secret_update_bumps_content_revision_and_preserves_catalog_attributes(kk_home):
    store, backend, service, projects, entry, scope = _env(kk_home)
    before = store.get_by_id(entry.id)
    replacement = Entry.new(name=entry.name, type=EntryType.API_KEY)
    service.create_entry(replacement, replace=True, secrets=SecretInput(value="replacement"))
    after = store.get_by_id(entry.id)
    assert after.id == entry.id
    assert after.folder_id == before.folder_id
    assert after.distribution == "project_allowed"
    assert after.provenance == before.provenance
    assert after.content_revision != before.content_revision
    assert backend.values[entry.id] == "replacement"
    catalog = store.catalog_state()
    assert catalog["bindings"][0]["scope_id"] == scope.id
    assert catalog["publication_intents"][-1] == {
        "scope_id": scope.id, "entry_id": entry.id, "reason": "entry_replaced",
        "desired_content_revision": after.content_revision,
    }


def test_v3_secret_only_update_bumps_revision_and_queues_bound_scope(kk_home):
    store, backend, service, _projects, entry, scope = _env(kk_home)
    before = store.get_by_id(entry.id)
    old_revision = before.content_revision
    service.update_entry(before, secrets=SecretInput(value="rotated"))
    after = store.get_by_id(entry.id)
    assert after.content_revision != old_revision
    assert backend.values[entry.id] == "rotated"
    assert store.catalog_state()["publication_intents"][-1]["scope_id"] == scope.id
    assert store.catalog_state()["publication_intents"][-1]["reason"] == "entry_updated"


def test_v3_delete_removes_bindings_marks_intent_and_keeps_dedup(kk_home):
    store, _backend, service, _projects, entry, scope = _env(kk_home)
    service.delete_entry(entry.id)
    catalog = store.catalog_state()
    assert catalog["bindings"] == []
    assert {item["scope_id"] for item in catalog["publication_intents"] if item["reason"] == "entry_deleted"} == {scope.id}
    assert {item["entry_id"] for item in catalog["dedup"] if item["reason"] == "entry_deleted"} == {entry.id}


def test_legacy_snapshot_refuses_v3_before_any_secret_backend_access(kk_home):
    store, backend, _service, _projects, _entry, _scope = _env(kk_home)
    with pytest.raises(LegacyCatalogSyncError, match="disabled"):
        build_snapshot_payload(store, backend)
    assert backend.get_calls == 0
