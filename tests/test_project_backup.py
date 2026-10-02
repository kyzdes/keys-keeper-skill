from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

import pytest

from keys_keeper import crypto
from keys_keeper import project_backup as backup_module
from keys_keeper import private_files
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.master_journal import (
    MASTER_MUTATION_KIND, MASTER_UNLOCK_ACCOUNT, MasterMutationManager,
    compose_master_mutations,
)
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_backup import (
    BACKUP_SCHEMA_VERSION,
    ProjectBackupCommitError,
    ProjectBackupError,
    create_master_backup,
    create_replica_backup,
    inspect_backup,
    restore_backup,
)
from keys_keeper.project_replica import ReplicaStore
from keys_keeper.project_service import ProjectService
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}
        self.denied: set[str] = set()

    def get(self, account: str) -> Sealed:
        if account in self.denied:
            raise KeychainError("denied")
        if account not in self.values:
            raise KeychainError("missing")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


def _journal(paths: Paths) -> OperationJournal:
    return OperationJournal(paths=paths, password_provider=lambda: b"runtime-key")


def test_backup_reader_uses_binary_descriptor(tmp_path, monkeypatch):
    path = tmp_path / "backup.enc"
    ciphertext = b"header\r\nbody\x1a\r\ntail"
    path.write_bytes(ciphertext)
    if os.name == "posix":
        path.chmod(0o600)
    real_open = private_files._open_read
    binary_flag = getattr(os, "O_BINARY", getattr(os, "O_NONBLOCK", 0x4))
    seen = []
    monkeypatch.setattr(backup_module.os, "O_BINARY", binary_flag, raising=False)

    def recording_open(target, flags):
        seen.append(flags)
        return real_open(target, flags)

    monkeypatch.setattr(private_files, "_open_read", recording_open)
    assert backup_module._secure_read(path) == ciphertext
    assert seen and seen[0] & binary_flag


def _checkpoint(scope_id: str, vault_id: str) -> dict:
    return {
        "scope_id": scope_id,
        "vault_id": vault_id,
        "epoch": 1,
        "policy_version": 1,
        "policy_hash": "2" * 64,
        "sequence": 1,
        "parent_hash": None,
        "snapshot_hash": "1" * 64,
    }


def _replica_payload(scope_id: str) -> dict:
    return {
        "schema_version": 1,
        "scope_id": scope_id,
        "source_revision": "a" * 64,
        "entries": [{
            "id": "kk:" + str(uuid4()),
            "name": "replica-entry",
            "type": "api_key",
            "fields": {},
            "tags": [],
            "note": "",
            "refs": [],
            "created_at": "2026-09-05T10:00:00Z",
            "updated_at": "2026-09-05T10:00:00Z",
            "secret": "SYNTHETIC-REPLICA-SECRET",
            "passphrase": None,
        }],
    }


def test_schema3_master_backup_round_trip_is_complete_and_recovery_only(tmp_path):
    paths = Paths(tmp_path / "source")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    backend.set("kk:project-runtime-key", "SYNTHETIC-RUNTIME-KEY")
    journal = _journal(paths)
    manager = MasterMutationManager(store, backend, journal)
    service = VaultService(store, backend, master_mutations=manager)
    entry = Entry.new(name="backup-entry", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-BACKUP-SECRET"))
    projects = ProjectService(store)
    project = projects.create_project("backup", "Backup")
    scope = projects.create_scope(project.id)
    projects.set_entry_distribution(entry.id, "project_allowed")
    projects.assign(scope.id, entry.id)
    state = {
        "registry": {"master": {"mode": "master"}},
        "scopes": {scope.id: {"checkpoint": "3" * 64}},
    }

    destination = tmp_path / "master.kk3"
    manifest = create_master_backup(
        store,
        backend,
        journal=journal,
        destination=destination,
        password="backup-password",
        project_state=state,
    )
    assert manifest.schema_version == BACKUP_SCHEMA_VERSION
    assert manifest.kind == "master" and manifest.entry_count == 1
    assert b"SYNTHETIC-BACKUP-SECRET" not in destination.read_bytes()
    if os.name == "posix":
        assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert inspect_backup(destination, password="backup-password") == manifest

    recovered = restore_backup(
        destination,
        password="backup-password",
        recovery_root=tmp_path / "recovered",
        recovery_password="recovery-password",
    )
    marker = json.loads((recovered.paths.root / "recovery-only").read_text())
    assert marker["mode"] == "recovery_only"
    assert marker["status"] == "restored"
    assert marker["activation"] == "requires_trusted_history_verification"
    restored_store = recovered.metadata_store()
    assert restored_store.snapshot().revision == store.snapshot().revision
    assert restored_store.catalog_state() == store.catalog_state()
    restored_backend = recovered.open_master_backend("recovery-password")
    assert restored_backend.get(entry.id).unseal() == "SYNTHETIC-BACKUP-SECRET"
    assert restored_backend.get("kk:project-runtime-key").unseal() == "SYNTHETIC-RUNTIME-KEY"
    assert recovered.project_state("recovery-password") == state


def test_master_backup_aborts_on_missing_or_denied_required_secret(tmp_path):
    paths = Paths(tmp_path / "source")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    entry = Entry.new(name="required-entry", type=EntryType.API_KEY)
    store.add(entry)
    backend = MemoryBackend()
    backend.set("kk:project-runtime-key", "runtime")
    destination = tmp_path / "must-not-exist.kk3"
    with pytest.raises(ProjectBackupError, match="required entry secret"):
        create_master_backup(
            store,
            backend,
            journal=_journal(paths),
            destination=destination,
            password="backup-password",
        )
    assert not destination.exists()

    backend.set(entry.id, "synthetic")
    backend.denied.add(entry.id)
    with pytest.raises(ProjectBackupError, match="cannot read entry secret"):
        create_master_backup(
            store,
            backend,
            journal=_journal(paths),
            destination=destination,
            password="backup-password",
        )
    assert not destination.exists()


def test_schema2_pre_migration_backup_round_trip(tmp_path):
    paths = Paths(tmp_path / "legacy")
    store = MetadataStore(paths)
    backend = MemoryBackend()
    entry = Entry.new(name="legacy-backup", type=EntryType.API_KEY)
    VaultService(store, backend).create_entry(
        entry, secrets=SecretInput(value="SYNTHETIC-LEGACY-SECRET")
    )
    destination = tmp_path / "legacy.kk3"
    create_master_backup(
        store,
        backend,
        journal=_journal(paths),
        destination=destination,
        password="backup-password",
        project_state={"pre_migration": True},
    )
    recovered = restore_backup(
        destination,
        password="backup-password",
        recovery_root=tmp_path / "legacy-recovered",
        recovery_password="recovery-password",
    )
    assert recovered.metadata_store().get_by_id(entry.id).name == entry.name
    assert recovered.open_master_backend("recovery-password").get(entry.id).unseal() == "SYNTHETIC-LEGACY-SECRET"


@pytest.mark.parametrize("service_accounts", [None, ()])
def test_schema2_durable_backup_restores_journal_key_and_accepts_new_mutation(
    tmp_path, service_accounts,
):
    store, backend = MetadataStore(Paths(tmp_path / "source")), MemoryBackend()
    service = VaultService(store, backend)
    original = Entry.new(name="durable-original", type=EntryType.API_KEY)
    service.create_entry(original, secrets=SecretInput(value="SYNTHETIC-ORIGINAL"))
    manager = service.master_mutations
    assert manager is not None
    source_key = backend.get(MASTER_UNLOCK_ACCOUNT).unseal()
    assert manager.journal.paths.operations_dir.joinpath("terminal-receipts.kk1").exists()
    assert store._read()["schema_version"] == 2

    destination = tmp_path / "durable-master.kk3"
    create_master_backup(store, backend, journal=manager.journal,
                         destination=destination, password="backup-password",
                         service_accounts=service_accounts)
    recovered = restore_backup(destination, password="backup-password",
                               recovery_root=tmp_path / "recovered",
                               recovery_password="recovery-password")
    marker_path = recovered.paths.root / "recovery-only"
    marker = marker_path.read_bytes()
    restored_store = recovered.metadata_store()
    restored_backend = recovered.open_master_backend("recovery-password")
    assert restored_backend.get(MASTER_UNLOCK_ACCOUNT).unseal() == source_key
    restored_manager = compose_master_mutations(restored_store, restored_backend)
    # Recovery authenticates the restored encrypted receipt ledger. A missing
    # runtime key would otherwise create a new key and strand these receipts.
    assert restored_manager.recover() == []
    assert not restored_manager.has_pending
    assert restored_backend.get(original.id).unseal() == "SYNTHETIC-ORIGINAL"
    new_entry = Entry.new(name="durable-after-restore", type=EntryType.API_KEY)
    VaultService(restored_store, restored_backend, master_mutations=restored_manager).create_entry(
        new_entry, secrets=SecretInput(value="SYNTHETIC-AFTER-RESTORE"),
    )
    assert restored_store.get_by_id(new_entry.id).name == new_entry.name
    assert restored_backend.get(new_entry.id).unseal() == "SYNTHETIC-AFTER-RESTORE"
    assert restored_manager.recover() == []
    # Exercising the isolated manager is not activation of a recovery profile.
    assert marker_path.read_bytes() == marker
    assert json.loads(marker)["mode"] == "recovery_only"


def test_backup_directory_fsync_failure_reports_committed_publication(tmp_path, monkeypatch):
    store, backend = MetadataStore(Paths(tmp_path / "source")), MemoryBackend()
    entry = Entry.new(name="committed-backup", type=EntryType.API_KEY)
    service = VaultService(store, backend)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-SECRET"))
    destination = tmp_path / "published.kk3"

    def failed_parent_sync(_parent):
        raise OSError("SYNTHETIC-UNTRUSTED-DIAGNOSTIC")

    monkeypatch.setattr(backup_module, "_fsync_parent", failed_parent_sync)
    with pytest.raises(ProjectBackupCommitError) as failed:
        create_master_backup(store, backend, journal=service.master_mutations.journal,
                             destination=destination, password="backup-password")
    assert failed.value.committed is True
    assert "SYNTHETIC" not in str(failed.value)
    assert b"SYNTHETIC-SECRET" not in destination.read_bytes()
    assert inspect_backup(destination, password="backup-password").entry_count == 1


def test_backup_existing_destination_fails_before_secret_access(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "source")
    store, backend = MetadataStore(paths), MemoryBackend()
    destination = tmp_path / "existing.kk3"
    destination.write_bytes(b"previous-backup")

    def forbidden_access(*_args):
        raise AssertionError("existing destination must be rejected before provider access")

    monkeypatch.setattr(backend, "get", forbidden_access)
    monkeypatch.setattr(backend, "list_ids", forbidden_access)
    with pytest.raises(ProjectBackupError, match="destination already exists"):
        create_master_backup(store, backend, journal=_journal(paths),
                             destination=destination, password="backup-password")
    assert destination.read_bytes() == b"previous-backup"


def test_backup_competing_destination_is_preserved(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "source")
    store, backend = MetadataStore(paths), MemoryBackend()
    destination = tmp_path / "raced.kk3"
    encrypt = backup_module.crypto.encrypt_blob

    def competing_backup(plaintext, *, password):
        blob = encrypt(plaintext, password=password)
        destination.write_bytes(b"competing-backup")
        return blob

    monkeypatch.setattr(backup_module.crypto, "encrypt_blob", competing_backup)
    with pytest.raises(ProjectBackupError, match="destination already exists"):
        create_master_backup(store, backend, journal=_journal(paths),
                             destination=destination, password="backup-password")
    assert destination.read_bytes() == b"competing-backup"


@pytest.mark.parametrize("fault", ["required-absent", "authority-missing", "authority-absent", "service-collision", "manifest-revision"])
def test_restore_rejects_authenticated_incomplete_secret_maps_before_writing(tmp_path, fault):
    paths = Paths(tmp_path / "source")
    store, backend = MetadataStore(paths), MemoryBackend()
    service = VaultService(store, backend)
    entry = Entry.new(name="complete-backup", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-SECRET"))
    destination = tmp_path / "tampered.kk3"
    create_master_backup(store, backend, journal=service.master_mutations.journal,
                         destination=destination, password="backup-password")
    bundle = json.loads(crypto.decrypt_blob(destination.read_bytes(), password="backup-password"))
    payload = bundle["payload"]
    if fault == "required-absent":
        payload["entry_secrets"][entry.id] = {"present": False}
    elif fault == "authority-missing":
        payload["service_secrets"].pop(MASTER_UNLOCK_ACCOUNT)
    elif fault == "authority-absent":
        payload["service_secrets"][MASTER_UNLOCK_ACCOUNT] = {"present": False}
    elif fault == "service-collision":
        payload["service_secrets"][entry.id] = {"present": True, "value": "SYNTHETIC-OVERRIDE"}
    else:
        bundle["manifest"]["metadata_revision"] = "0" * 64
    # Keep authentication and the content hash valid: this tests the actual
    # backup contract, not detection of a damaged encrypted byte stream.
    bundle["manifest"]["content_hash"] = hashlib.sha256(backup_module._canonical_bytes(payload)).hexdigest()
    destination.write_bytes(crypto.encrypt_blob(backup_module._canonical_bytes(bundle), password="backup-password"))
    target = tmp_path / "must-not-be-created"
    with pytest.raises(ProjectBackupError):
        restore_backup(destination, password="backup-password", recovery_root=target,
                       recovery_password="recovery-password")
    assert not target.exists()


def test_backup_validates_legacy_metadata_before_encrypting_or_publishing(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "legacy")
    store, backend = MetadataStore(paths), MemoryBackend()
    entry = Entry.new(name="legacy-invalid-note", type=EntryType.NOTE,
                      fields={"secret_body": False, "body": "synthetic body"})
    store.add(entry)
    data = json.loads(paths.data_json.read_text(encoding="utf-8"))
    data["entries"][0]["fields"]["secret_body"] = "False"
    paths.data_json.write_text(json.dumps(data), encoding="utf-8")
    backend.set(entry.id, "SYNTHETIC-SECRET")
    monkeypatch.setattr(backup_module.crypto, "encrypt_blob",
                        lambda *_a, **_kw: pytest.fail("invalid metadata was encrypted"))
    destination = tmp_path / "must-not-exist.kk3"
    with pytest.raises(ProjectBackupError, match="invalid master backup metadata"):
        create_master_backup(store, backend, journal=_journal(paths),
                             destination=destination, password="backup-password")
    assert not destination.exists()


@pytest.mark.parametrize("kind", ["symlink", "directory", "fifo", "symlink-parent"])
def test_backup_refuses_unsafe_targets_without_following_or_replacing(tmp_path, kind):
    store, backend = MetadataStore(Paths(tmp_path / "source")), MemoryBackend()
    entry = Entry.new(name="unsafe-target", type=EntryType.API_KEY)
    service = VaultService(store, backend)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-SECRET"))
    destination = tmp_path / "unsafe.kk3"
    preserved = tmp_path / "preserved"
    preserved.write_bytes(b"previous-file")
    if kind == "symlink":
        try:
            destination.symlink_to(preserved)
        except OSError:
            pytest.skip("symlinks require platform support")
    elif kind == "directory":
        destination.mkdir()
    elif kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO requires POSIX")
        os.mkfifo(destination)
    else:
        actual_parent = tmp_path / "actual-parent"
        actual_parent.mkdir()
        linked_parent = tmp_path / "linked-parent"
        try:
            linked_parent.symlink_to(actual_parent, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks require platform support")
        destination = linked_parent / "unsafe.kk3"
    with pytest.raises(ProjectBackupError):
        create_master_backup(store, backend, journal=service.master_mutations.journal,
                             destination=destination, password="backup-password")
    assert preserved.read_bytes() == b"previous-file"
    if kind == "symlink":
        assert destination.is_symlink()
    elif kind == "directory":
        assert destination.is_dir()
    elif kind == "fifo":
        assert stat.S_ISFIFO(destination.lstat().st_mode)
    else:
        assert not (actual_parent / "unsafe.kk3").exists()


def test_master_backup_refuses_pending_mutation(tmp_path):
    paths = Paths(tmp_path / "master")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    backend.set("kk:project-runtime-key", "runtime")
    journal = _journal(paths)
    operation = journal.begin(MASTER_MUTATION_KIND, state={"synthetic": True})
    with pytest.raises(ProjectBackupError, match="recovery is required"):
        create_master_backup(
            store,
            backend,
            journal=journal,
            destination=tmp_path / "blocked.kk3",
            password="backup-password",
        )
    journal.fail(operation.operation_id, error_code="test_closed")


def test_process_exit_during_restore_stays_recovery_only_and_resumes(tmp_path):
    paths = Paths(tmp_path / "source")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    backend.set("kk:project-runtime-key", "SYNTHETIC-RUNTIME-KEY")
    manager = MasterMutationManager(store, backend, _journal(paths))
    service = VaultService(store, backend, master_mutations=manager)
    entry = Entry.new(name="interrupted-restore", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-RESTORE-SECRET"))
    backup = tmp_path / "interrupted.kk3"
    create_master_backup(
        store,
        backend,
        journal=manager.journal,
        destination=backup,
        password="backup-password",
    )
    recovered_root = tmp_path / "partial-recovery"
    child = r'''
import os
from pathlib import Path
import keys_keeper.project_backup as project_backup

original = project_backup._file_backend
class StopAfterWrite:
    def __init__(self, backend):
        self.backend = backend
    def set(self, account, value):
        self.backend.set(account, value)
        os._exit(76)
def stopping_backend(paths, password):
    return StopAfterWrite(original(paths, password))
project_backup._file_backend = stopping_backend
project_backup.restore_backup(
    Path(os.environ["BACKUP_FILE"]),
    password=os.environ["BACKUP_PASSWORD"],
    recovery_root=Path(os.environ["RECOVERY_ROOT"]),
    recovery_password=os.environ["RECOVERY_PASSWORD"],
)
'''
    environment = os.environ.copy()
    environment.update(
        BACKUP_FILE=str(backup),
        BACKUP_PASSWORD="backup-password",
        RECOVERY_ROOT=str(recovered_root),
        RECOVERY_PASSWORD="recovery-password",
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    result = subprocess.run(
        [sys.executable, "-c", child], env=environment, check=False
    )
    assert result.returncode == 76
    marker = json.loads((recovered_root / "recovery-only").read_text())
    assert marker["status"] == "restore_in_progress"

    recovered = restore_backup(
        backup,
        password="backup-password",
        recovery_root=recovered_root,
        recovery_password="recovery-password",
        resume=True,
    )
    marker = json.loads((recovered_root / "recovery-only").read_text())
    assert marker["status"] == "restored"
    restored_backend = recovered.open_master_backend("recovery-password")
    assert restored_backend.get(entry.id).unseal() == "SYNTHETIC-RESTORE-SECRET"
    assert restored_backend.get("kk:project-runtime-key").unseal() == "SYNTHETIC-RUNTIME-KEY"


def test_concurrent_fresh_restores_cannot_interleave_one_recovery_root(
    tmp_path, monkeypatch
):
    paths = Paths(tmp_path / "source")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    backend.set("kk:project-runtime-key", "SYNTHETIC-RUNTIME-KEY")
    entry = Entry.new(name="serialized-restore", type=EntryType.API_KEY)
    manager = MasterMutationManager(store, backend, _journal(paths))
    VaultService(store, backend, master_mutations=manager).create_entry(
        entry, secrets=SecretInput(value="SYNTHETIC-RESTORE-SECRET")
    )
    source = tmp_path / "serialized.kk3"
    create_master_backup(
        store,
        backend,
        journal=manager.journal,
        destination=source,
        password="backup-password",
    )

    entered = threading.Event()
    release = threading.Event()
    original_write = backup_module._atomic_write
    write_calls = 0
    write_calls_lock = threading.Lock()

    def paused_first_marker(path, data):
        nonlocal write_calls
        if path.name == "recovery-only":
            with write_calls_lock:
                write_calls += 1
                first_marker = write_calls == 1
            if first_marker:
                entered.set()
                assert release.wait(5)
        return original_write(path, data)

    monkeypatch.setattr(backup_module, "_atomic_write", paused_first_marker)
    target = tmp_path / "single-recovery-root"

    def run_restore():
        return restore_backup(
            source,
            password="backup-password",
            recovery_root=target,
            recovery_password="recovery-password",
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run_restore)
        assert entered.wait(5)
        second = pool.submit(run_restore)
        release.set()
        recovered = first.result(timeout=10)
        with pytest.raises(ProjectBackupError, match="new and empty"):
            second.result(timeout=10)

    assert recovered.metadata_store().get_by_id(entry.id) is not None
    assert (
        recovered.open_master_backend("recovery-password").get(entry.id).unseal()
        == "SYNTHETIC-RESTORE-SECRET"
    )
    marker = json.loads((target / "recovery-only").read_text())
    assert marker["backup_hash"] == recovered.manifest.content_hash
    assert marker["status"] == "restored"


def test_replica_backup_round_trip_preserves_generation_and_outbox(tmp_path):
    scope_id, vault_id = str(uuid4()), str(uuid4())
    source = ReplicaStore(
        paths=Paths(tmp_path / "replica"), password_provider=lambda: b"replica-key"
    )
    payload = _replica_payload(scope_id)
    checkpoint = _checkpoint(scope_id, vault_id)
    source.install(payload, checkpoint)
    state = {
        "mode": "replica",
        "outbox": [{"request_id": str(uuid4()), "status": "local_pending"}],
    }
    destination = tmp_path / "replica.kk3"
    create_replica_backup(
        source,
        destination=destination,
        password="backup-password",
        project_state=state,
    )
    assert b"SYNTHETIC-REPLICA-SECRET" not in destination.read_bytes()
    recovered = restore_backup(
        destination,
        password="backup-password",
        recovery_root=tmp_path / "replica-recovered",
        recovery_password="recovery-password",
    )
    assert recovered.replica_store("recovery-password").load() == (payload, checkpoint)
    assert recovered.project_state("recovery-password") == state


def test_backup_schema_rejects_unknown_fields_without_partial_restore(tmp_path):
    scope_id, vault_id = str(uuid4()), str(uuid4())
    source = ReplicaStore(
        paths=Paths(tmp_path / "replica"), password_provider=lambda: b"replica-key"
    )
    source.install(_replica_payload(scope_id), _checkpoint(scope_id, vault_id))
    destination = tmp_path / "replica.kk3"
    create_replica_backup(
        source, destination=destination, password="backup-password"
    )
    raw = json.loads(
        crypto.decrypt_blob(destination.read_bytes(), password="backup-password")
    )
    raw["payload"]["unknown_extension"] = {"must": "not disappear"}
    destination.write_bytes(
        crypto.encrypt_blob(
            json.dumps(raw, sort_keys=True, separators=(",", ":")).encode(),
            password="backup-password",
        )
    )
    destination.chmod(0o600)
    target = tmp_path / "must-remain-empty"
    with pytest.raises(ProjectBackupError, match="invalid replica backup fields"):
        restore_backup(
            destination,
            password="backup-password",
            recovery_root=target,
            recovery_password="recovery-password",
        )
    assert not target.exists()
