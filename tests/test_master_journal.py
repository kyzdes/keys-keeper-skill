from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.master_journal import (
    MASTER_MUTATION_KIND,
    MasterMutationManager,
    MasterMutationRequired,
    MasterRecoveryRequired,
    assert_no_pending,
    projection_guard,
)
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_service import ProjectService
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


JOURNAL_KEY = b"durable-master-journal-key-32!!"


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []

    def get(self, account: str) -> Sealed:
        if account not in self.values:
            raise KeychainError("missing")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.calls.append(("set", account))
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.calls.append(("delete", account))
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


def _durable(tmp_path):
    paths = Paths(tmp_path / "master")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    journal = OperationJournal(paths=paths, password_provider=lambda: JOURNAL_KEY)
    manager = MasterMutationManager(store, backend, journal)
    return paths, store, backend, journal, manager, VaultService(
        store, backend, master_mutations=manager
    )


def test_schema3_requires_durable_manager_but_legacy_behavior_remains(tmp_path):
    legacy = MetadataStore(Paths(tmp_path / "legacy"))
    backend = MemoryBackend()
    entry = Entry.new(name="legacy-entry", type=EntryType.API_KEY)
    VaultService(legacy, backend).create_entry(
        entry, secrets=SecretInput(value="synthetic")
    )
    assert backend.get(entry.id).unseal() == "synthetic"

    catalog = MetadataStore(Paths(tmp_path / "catalog"))
    catalog.migrate_catalog_v3()
    with pytest.raises(MasterMutationRequired, match="durable"):
        VaultService(catalog, MemoryBackend()).create_entry(
            Entry.new(name="catalog-entry", type=EntryType.API_KEY),
            secrets=SecretInput(value="synthetic"),
        )


def test_durable_update_is_in_place_and_delete_preserves_catalog_intent(tmp_path):
    _paths, store, backend, _journal, manager, service = _durable(tmp_path)
    entry = Entry.new(name="shared-entry", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="first"))
    projects = ProjectService(store)
    project = projects.create_project("durable", "Durable")
    scope = projects.create_scope(project.id)
    projects.set_entry_distribution(entry.id, "project_allowed")
    projects.assign(scope.id, entry.id)

    changed = store.get_by_id(entry.id)
    previous_revision = changed.content_revision
    changed.name = "renamed-entry"
    service.update_entry(changed, secrets=SecretInput(value="second"))
    assert backend.get(entry.id).unseal() == "second"
    assert ("delete", entry.id) not in backend.calls
    assert store.get_by_id(entry.id).content_revision != previous_revision
    assert not manager.has_pending

    dependent = Entry.new(
        name="dependent-server",
        type=EntryType.SERVER,
        fields={"host": "example.test", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": "renamed-entry"}],
    )
    service.create_entry(dependent)
    service.delete_entry(entry.id, cascade=True)
    catalog = store.catalog_state()
    assert store.get_by_id(entry.id) is None
    assert store.get_by_id(dependent.id).refs == []
    assert any(
        item.get("entry_id") == entry.id and item.get("reason") == "entry_deleted"
        for item in catalog["dedup"]
    )
    assert not manager.has_pending


def test_pending_marker_blocks_projection_without_journal_key(tmp_path):
    paths, _store, _backend, journal, manager, _service = _durable(tmp_path)
    record = journal.begin(MASTER_MUTATION_KIND, state={"synthetic": True})
    with pytest.raises(MasterRecoveryRequired, match="recovery required"):
        assert_no_pending(paths)
    with pytest.raises(MasterRecoveryRequired, match="recovery required"):
        manager.assert_projection_ready()
    with pytest.raises(MasterRecoveryRequired, match="recovery required"):
        with projection_guard(paths):
            pytest.fail("pending mutation must prevent projection")
    journal.fail(record.operation_id, error_code="test_closed")
    assert_no_pending(paths)


def _password_file(paths: Paths) -> None:
    paths.backend_password_file.parent.mkdir(parents=True, exist_ok=True)
    paths.backend_password_file.write_text("backend-password", encoding="utf-8")
    if os.name == "posix":
        paths.backend_password_file.chmod(0o600)


def _file_components(paths: Paths):
    backend = EncryptedFileBackend(
        paths=paths,
        password_file=paths.backend_password_file,
        allow_env_password=False,
    )
    journal = OperationJournal(paths=paths, password_provider=lambda: JOURNAL_KEY)
    store = MetadataStore(paths)
    manager = MasterMutationManager(store, backend, journal)
    service = VaultService(store, backend, master_mutations=manager)
    return store, backend, journal, manager, service


def _run_child(paths: Paths, script_body: str) -> subprocess.CompletedProcess:
    script = f"""
import os
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.master_journal import MasterMutationManager
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore
paths = Paths(os.environ['MASTER_ROOT'])
{script_body}
"""
    environment = os.environ.copy()
    environment.update(
        MASTER_ROOT=str(paths.root),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    return subprocess.run([sys.executable, "-c", script], env=environment, check=False)


def test_process_exit_after_backend_write_recovers_secret_and_metadata(tmp_path):
    paths = Paths(tmp_path / "master")
    MetadataStore(paths).migrate_catalog_v3()
    _password_file(paths)
    result = _run_child(
        paths,
        """
class StopBackend(EncryptedFileBackend):
    def set(self, account, value):
        super().set(account, value)
        os._exit(73)
backend = StopBackend(paths=paths, password_file=paths.backend_password_file, allow_env_password=False)
journal = OperationJournal(paths=paths, password_provider=lambda: b'durable-master-journal-key-32!!')
manager = MasterMutationManager(MetadataStore(paths), backend, journal)
VaultService(manager.store, backend, master_mutations=manager).create_entry(
    Entry.new(name='crash-created', type=EntryType.API_KEY),
    secrets=SecretInput(value='SYNTHETIC-CRASH-SECRET'),
)
""",
    )
    assert result.returncode == 73
    store, backend, journal, manager, _service = _file_components(paths)
    assert manager.has_pending
    encrypted = next(paths.operations_dir.glob("*.enc")).read_bytes()
    assert b"SYNTHETIC-CRASH-SECRET" not in encrypted
    recovered = manager.recover()
    entry = store.get_by_name("crash-created")
    assert len(recovered) == 1 and entry is not None
    assert backend.get(entry.id).unseal() == "SYNTHETIC-CRASH-SECRET"
    assert not manager.has_pending


def test_process_exit_after_metadata_commit_recovers_without_duplicate(tmp_path):
    paths = Paths(tmp_path / "master")
    MetadataStore(paths).migrate_catalog_v3()
    _password_file(paths)
    result = _run_child(
        paths,
        """
class StopJournal(OperationJournal):
    def stage(self, operation_id, stage, **kwargs):
        if stage == 'metadata_committed':
            os._exit(74)
        return super().stage(operation_id, stage, **kwargs)
backend = EncryptedFileBackend(paths=paths, password_file=paths.backend_password_file, allow_env_password=False)
journal = StopJournal(paths=paths, password_provider=lambda: b'durable-master-journal-key-32!!')
manager = MasterMutationManager(MetadataStore(paths), backend, journal)
VaultService(manager.store, backend, master_mutations=manager).create_entry(
    Entry.new(name='commit-created', type=EntryType.API_KEY),
    secrets=SecretInput(value='SYNTHETIC-COMMIT-SECRET'),
)
""",
    )
    assert result.returncode == 74
    store, backend, _journal, manager, _service = _file_components(paths)
    assert len(store.list()) == 1 and manager.has_pending
    manager.recover()
    assert len(store.list()) == 1
    assert backend.get(store.list()[0].id).unseal() == "SYNTHETIC-COMMIT-SECRET"
    assert not manager.has_pending


def test_process_exit_during_delete_recovers_cascade_forward(tmp_path):
    paths = Paths(tmp_path / "master")
    MetadataStore(paths).migrate_catalog_v3()
    _password_file(paths)
    store, _backend, _journal, _manager, service = _file_components(paths)
    parent = Entry.new(name="delete-parent", type=EntryType.API_KEY)
    service.create_entry(
        parent,
        secrets=SecretInput(value="main", passphrase="passphrase"),
    )
    child = Entry.new(
        name="delete-child",
        type=EntryType.SERVER,
        fields={"host": "example.test", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": parent.name}],
    )
    service.create_entry(child)
    result = _run_child(
        paths,
        f"""
class StopBackend(EncryptedFileBackend):
    def delete(self, account):
        super().delete(account)
        os._exit(75)
backend = StopBackend(paths=paths, password_file=paths.backend_password_file, allow_env_password=False)
journal = OperationJournal(paths=paths, password_provider=lambda: b'durable-master-journal-key-32!!')
manager = MasterMutationManager(MetadataStore(paths), backend, journal)
VaultService(manager.store, backend, master_mutations=manager).delete_entry({parent.id!r}, cascade=True)
""",
    )
    assert result.returncode == 75
    store, backend, _journal, manager, _service = _file_components(paths)
    manager.recover()
    assert store.get_by_id(parent.id) is None
    assert store.get_by_id(child.id).refs == []
    assert parent.id not in backend.list_ids()
    assert parent.id + ":passphrase" not in backend.list_ids()
