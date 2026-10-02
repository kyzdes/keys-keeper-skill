"""Resource rejection preserves previously durable synthetic state."""
import sys
from types import SimpleNamespace

import pytest

from keys_keeper import operation_journal as journal, project_models, project_replica
from keys_keeper.paths import Paths
from keys_keeper.refs import RefCycleError, detect_cycles
from keys_keeper import store
from keys_keeper import project_backup


def test_deep_reference_graph_accepts_chain_and_shared_dag_then_rejects_backedge():
    size = 3000
    entries = [SimpleNamespace(name=f"entry-{i}", refs=([{"name": f"entry-{i + 1}"}]
               if i + 1 < size else [])) for i in range(size)]
    # A second root points into an already completed branch; it is a DAG.
    entries.append(SimpleNamespace(name="shared-root", refs=[{"name": "entry-1500"},
                                                            {"name": "missing"}]))
    detect_cycles(entries)
    entries[size - 1].refs = [{"name": "entry-1500"}]
    with pytest.raises(RefCycleError, match="cycle"):
        detect_cycles(entries)


def test_folder_chain_validation_has_linear_work_and_detects_late_cycle():
    size = 3000
    # Count executed validator lines, not wall time; CPU contention cannot make
    # this test flaky, and a quadratic ancestry walk must exceed the budget.
    folders = [SimpleNamespace(id=str(i), parent_id=str(i + 1) if i + 1 < size else None)
               for i in range(size)]
    lines = [0]
    code = project_models._validate_folder_cycles.__code__
    def count(frame, event, arg):
        if event == "line" and frame.f_code is code:
            lines[0] += 1
            if lines[0] > size * 20:
                raise AssertionError("folder ancestry traversal is not linear")
        return count
    previous = sys.gettrace()
    try:
        sys.settrace(count)
        project_models._validate_folder_cycles(folders)
    finally:
        sys.settrace(previous)
    folders[-1].parent_id = str(size // 2)
    with pytest.raises(project_models.CatalogValidationError, match="cycle"):
        project_models._validate_folder_cycles(folders)


def test_oversized_journal_update_preserves_ciphertext_and_pending_index(tmp_path, monkeypatch):
    instance = journal.OperationJournal(paths=Paths(tmp_path / "profile"), password_provider=lambda: "test-only")
    record = instance.begin("test_operation", state={"small": True})
    path = instance._record_path(record.operation_id)
    original = path.read_bytes()
    index = instance._pending_index_path().read_bytes()
    monkeypatch.setattr(journal, "_MAX_JOURNAL_BYTES", len(original) + 20)
    monkeypatch.setattr(journal.crypto, "_derive_key", lambda *args: pytest.fail("oversized update ran KDF"))
    with pytest.raises(journal.JournalError, match="size limit"):
        instance.stage(record.operation_id, "next", state={"large": "x" * 1000})
    assert path.read_bytes() == original
    assert instance._pending_index_path().read_bytes() == index
    assert instance.read(record.operation_id).state == {"small": True}


def test_pending_index_bound_refuses_new_operation_before_kdf(tmp_path, monkeypatch):
    instance = journal.OperationJournal(paths=Paths(tmp_path / "profile"), password_provider=lambda: "test-only")
    monkeypatch.setattr(journal, "_MAX_INDEX_BYTES", 32)
    monkeypatch.setattr(journal.crypto, "_derive_key", lambda *args: pytest.fail("full index ran KDF"))
    with pytest.raises(journal.JournalError, match="index exceeds"):
        instance.begin("test_operation")
    assert not instance._pending_index_path().exists()
    assert not list(instance.paths.operations_dir.glob("*.enc"))


@pytest.mark.parametrize("kind", ["generation", "pointer"])
def test_replica_oversized_files_refused_before_read_or_password(tmp_path, monkeypatch, kind):
    paths = Paths(tmp_path / "profile")
    digest = "a" * 64
    journal._atomic_write_bytes(paths.active_generation, (digest + "\n").encode())
    journal._atomic_write_bytes(paths.generations_dir / f"{digest}.enc", b"x" * 129)
    if kind == "pointer":
        journal._atomic_write_bytes(paths.active_generation, b"x" * 257)
    monkeypatch.setattr(project_replica, "_MAX_GENERATION_BYTES", 128)
    real_read = journal.os.read
    def guarded_read(fd, size):
        if journal.os.fstat(fd).st_size > 128:
            pytest.fail("oversized ciphertext/pointer allocated before rejection")
        return real_read(fd, size)
    monkeypatch.setattr(journal.os, "read", guarded_read)
    replica = project_replica.ReplicaStore(paths=paths, password_provider=lambda: pytest.fail("oversized file unlocked"))
    with pytest.raises(project_replica.ReplicaError):
        replica.load()


@pytest.mark.parametrize("kind", ["oversized", "symlink", "fifo"])
def test_metadata_unsafe_sources_refused_before_io(tmp_path, monkeypatch, kind):
    paths = Paths(tmp_path / "profile")
    paths.ensure()
    if kind == "oversized":
        paths.data_json.write_bytes(b"x" * 129)
        monkeypatch.setattr(store, "_MAX_METADATA_BYTES", 128)
    elif kind == "symlink":
        target = tmp_path / "unrelated"
        target.write_bytes(b'{"schema_version":2,"entries":[]}')
        try:
            paths.data_json.symlink_to(target)
        except OSError:
            pytest.skip("symlinks unavailable")
    else:
        if not hasattr(journal.os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        journal.os.mkfifo(paths.data_json, 0o600)
    monkeypatch.setattr(journal.os, "read", lambda *args: pytest.fail("unsafe metadata was read"))
    with pytest.raises(store.StoreError, match="unavailable"):
        store.MetadataStore(paths).list()


def test_oversized_metadata_write_keeps_existing_file(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "profile")
    paths.ensure()
    metadata = store.MetadataStore(paths)
    metadata._atomic_write({"schema_version": 2, "entries": [], "tombstones": []})
    original = paths.data_json.read_bytes()
    monkeypatch.setattr(store, "_MAX_METADATA_BYTES", len(original) + 20)
    with pytest.raises(store.StoreError, match="size limit"):
        metadata._atomic_write({"schema_version": 2, "entries": [{"large": "x" * 1000}], "tombstones": []})
    assert paths.data_json.read_bytes() == original


def test_metadata_backup_symlink_never_modifies_unrelated_target(tmp_path):
    paths = Paths(tmp_path / "profile")
    paths.ensure()
    metadata = store.MetadataStore(paths)
    original = {"schema_version": 2, "entries": [], "tombstones": []}
    metadata._atomic_write(original)
    target = tmp_path / "unrelated"
    target.write_bytes(b"protected-target")
    try:
        paths.data_json_bak.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    before = paths.data_json.read_bytes()
    with pytest.raises(store.StoreError, match="backup"):
        metadata._atomic_write({**original, "extra": True})
    assert target.read_bytes() == b"protected-target"
    assert paths.data_json.read_bytes() == before


def _empty_master_backup_payload():
    metadata = {"schema_version": 2, "entries": [], "tombstones": []}
    revision = store.MetadataTransaction(metadata).revision()
    return {
        "kind": "master",
        "metadata": {**metadata, "revision": revision, "catalog": None},
        "entry_secrets": {}, "service_secrets": {},
        "project_state": {}, "journal_files": {},
    }


def test_backup_envelope_bound_stops_before_kdf_or_partial_file(tmp_path, monkeypatch):
    payload = _empty_master_backup_payload()
    monkeypatch.setattr(project_backup, "_MAX_BACKUP_BYTES",
                        len(project_backup._canonical_bytes(payload)) + 49)
    monkeypatch.setattr(project_backup.crypto, "_derive_key", lambda *args: pytest.fail("unreadable backup derived key"))
    target = tmp_path / "backup.enc"
    with pytest.raises(project_backup.ProjectBackupError, match="size limit"):
        project_backup._write_bundle(target, "synthetic-key", payload, payload["metadata"]["revision"])
    assert not target.exists()


def test_backup_raw_payload_bound_precedes_deep_validation(tmp_path, monkeypatch):
    payload = _empty_master_backup_payload()
    monkeypatch.setattr(project_backup, "_MAX_BACKUP_BYTES", 128)
    monkeypatch.setattr(project_backup, "_validate_payload", lambda *args, **kwargs:
                        pytest.fail("oversized payload reached deep state validation"))
    target = tmp_path / "backup.enc"
    with pytest.raises(project_backup.ProjectBackupError, match="size limit"):
        project_backup._write_bundle(target, "synthetic-key", payload, payload["metadata"]["revision"])
    assert not target.exists()


def test_backup_producer_still_validates_small_output_before_password_or_publication(tmp_path, monkeypatch):
    payload = {"kind": "master", "metadata": {"entries": []}}
    target = tmp_path / "missing-parent" / "backup.enc"
    monkeypatch.setattr(project_backup, "_password", lambda *args:
                        pytest.fail("invalid producer output requested its password"))
    monkeypatch.setattr(project_backup.crypto, "encrypt_blob", lambda *args, **kwargs:
                        pytest.fail("invalid producer output started encryption"))

    with pytest.raises(project_backup.ProjectBackupError, match="invalid master backup fields"):
        project_backup._write_bundle(target, "synthetic-key", payload, None)

    assert not target.parent.exists()


def test_replica_envelope_bound_stops_before_password_or_pointer(tmp_path, monkeypatch):
    from uuid import uuid4
    scope, vault = str(uuid4()), str(uuid4())
    payload = {"schema_version": 1, "scope_id": scope, "source_revision": "a" * 64, "entries": []}
    checkpoint = {"scope_id": scope, "vault_id": vault, "epoch": 1, "policy_version": 1,
                  "policy_hash": "b" * 64, "sequence": 1, "parent_hash": None, "snapshot_hash": "c" * 64}
    monkeypatch.setattr(project_replica, "_MAX_GENERATION_BYTES", 128)
    replica = project_replica.ReplicaStore(paths=Paths(tmp_path / "replica"),
                                         password_provider=lambda: pytest.fail("unreadable generation unlocked"))
    with pytest.raises(project_replica.ReplicaError, match="size limit"):
        replica.install(payload, checkpoint)
    assert not replica.paths.active_generation.exists()
