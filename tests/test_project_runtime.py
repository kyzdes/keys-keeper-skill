"""User-level project composition with synthetic credentials and a real relay."""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from keys_keeper import project_protocol as wire
from keys_keeper.backend import Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.project_runtime import ProjectRuntime, RuntimeErrorSafe, write_bundle
from keys_keeper.project_service import ProjectService
from keys_keeper.project_replica import ReplicaReadOnlyError
from keys_keeper.service import SecretInput
from keys_keeper.store import MetadataStore
from keys_keeper.sync_server import SyncServerApp
from test_project_sync_e2e import FakeBackend, _running


@pytest.fixture
def configured(tmp_path):
    paths = Paths(tmp_path / "master")
    backend = FakeBackend()
    store = MetadataStore(paths)
    for name in ("project-key", "private-canary"):
        entry = Entry.new(name=name, type=EntryType.API_KEY)
        store.add(entry)
        backend.set(entry.id, "synthetic-" + name)
    store.migrate_catalog_v3()
    catalog = ProjectService(store)
    project = catalog.create_project("alpha", "Alpha")
    scope = catalog.create_scope(project.id, "default")
    key = store.get_by_name("project-key")
    catalog.set_entry_distribution(key.id, "project_allowed")
    catalog.assign(scope.id, key.id)
    app = SyncServerApp(tmp_path / "relay.sqlite", "runtime-admin")
    with _running(app) as endpoint:
        runtime = ProjectRuntime(paths, backend)
        info = runtime.initialize(scope.id, endpoint, admin_token=Sealed("runtime-admin"))
        yield runtime, backend, scope, info


def _connect(tmp_path, configured):
    runtime, backend, scope, info = configured
    runtime.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invite = runtime.invite(scope.id)
    worker = ProjectRuntime(Paths(tmp_path / "worker"), backend_factory=lambda: pytest.fail("worker constructed master backend"))
    joined = worker.join(invite, fingerprint=info["fingerprint"])
    request = joined["request_bundle"]
    fingerprint = wire.canonical_hash(request["request"])
    answer = runtime.approve(request, fingerprint=fingerprint)
    assert runtime.approve(request, fingerprint=fingerprint) == answer
    worker.finish(joined["profile_id"], answer)
    return worker, joined, answer


def test_enrollment_create_use_sync_and_revoke(tmp_path, configured):
    master, backend, scope, _ = configured
    with pytest.raises(RuntimeErrorSafe, match="backup"):
        master.invite(scope.id)
    worker, joined, answer = _connect(tmp_path, configured)
    context = worker.context()
    assert context.kind == "replica"
    assert [e.name for e in context.store.list()] == ["project-key"]
    key = context.store.get_by_name("project-key")
    assert context.backend.get(key.id).unseal() == "synthetic-project-key"
    entry = Entry.new(name="from-worker", type=EntryType.API_KEY)
    pending = context.service.create_entry(entry, secrets=SecretInput(value="synthetic-worker-value"))
    assert context.backend.get(pending.id).unseal() == "synthetic-worker-value"
    with pytest.raises(ReplicaReadOnlyError):
        context.service.create_entry(entry, secrets=SecretInput(value="overwrite"), replace=True)
    with pytest.raises(ReplicaReadOnlyError):
        context.backend.set(key.id, "overwrite")
    worker.sync()
    master.sync(scope.id)
    worker.sync()
    imported = master.master_store.get_by_name("from-worker")
    assert imported is not None
    assert backend.get(imported.id).unseal() == "synthetic-worker-value"
    assert len([e for e in worker.context().store.list() if e.name == "from-worker"]) == 1
    assert worker.context().store.get_by_name("private-canary") is None
    master.master(master.registry.resolve(scope.id)).revoke(answer["request"]["payload"]["device_id"])
    with pytest.raises(Exception):
        worker.sync()


def test_bad_selectors_never_construct_backend_and_preview_is_metadata_only(configured):
    runtime, backend, scope, _ = configured
    backend.gets.clear()
    with pytest.raises(RuntimeErrorSafe):
        runtime.context("unknown/default")
    assert backend.gets == []
    scoped = runtime.context(scope.id)
    assert [e.name for e in scoped.store.list()] == ["project-key"]
    assert backend.gets == []


def test_wrong_pin_repeated_invite_and_bundle_substitution_fail(tmp_path, configured):
    master, _, scope, info = configured
    master.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invite = master.invite(scope.id)
    worker = ProjectRuntime(Paths(tmp_path / "worker"), backend_factory=lambda: pytest.fail("master backend"))
    with pytest.raises(RuntimeErrorSafe, match="fingerprint"):
        worker.join(invite, fingerprint="0" * 64)
    joined = worker.join(invite, fingerprint=info["fingerprint"])
    with pytest.raises(RuntimeErrorSafe, match="finish"):
        worker.context()
    request = joined["request_bundle"]
    answer = master.approve(request, fingerprint=wire.canonical_hash(request["request"]))
    other = ProjectRuntime(Paths(tmp_path / "other"))
    second = other.join(invite, fingerprint=info["fingerprint"])
    with pytest.raises(RuntimeErrorSafe, match="consumed"):
        master.approve(second["request_bundle"], fingerprint=wire.canonical_hash(second["request_bundle"]["request"]))
    with pytest.raises(RuntimeErrorSafe, match="request"):
        other.finish(second["profile_id"], answer)


def test_restore_marker_blocks_all_runtime_access(tmp_path):
    root = tmp_path / "restore"
    root.mkdir()
    (root / "recovery-only").write_text("{}")
    runtime = ProjectRuntime(Paths(root), backend_factory=lambda: pytest.fail("backend"))
    with pytest.raises(RuntimeErrorSafe, match="recovery"):
        runtime.context()
    blocked_calls = [
        lambda: runtime.master_backend,
        lambda: runtime.status(),
        lambda: runtime.initialize("00000000-0000-4000-8000-000000000000", "https://relay.example", admin_token=Sealed("token")),
        lambda: runtime.preview("master"),
        lambda: runtime.backup("master", tmp_path / "blocked.enc", "password"),
        lambda: runtime.invite("master"),
        lambda: runtime.join({}, fingerprint="0" * 64),
        lambda: runtime.approve({}, fingerprint="0" * 64),
        lambda: runtime.finish("master", {}),
        lambda: runtime.sync(),
        lambda: runtime.watch(None, cycles=1, sleep=lambda _value: None),
    ]
    for call in blocked_calls:
        with pytest.raises(RuntimeErrorSafe, match="recovery"):
            call()


def test_broken_recovery_marker_symlink_blocks_runtime(tmp_path):
    root = tmp_path / "restore-symlink"
    root.mkdir()
    (root / "recovery-only").symlink_to(root / "missing-marker")
    runtime = ProjectRuntime(Paths(root), backend_factory=lambda: pytest.fail("backend"))
    with pytest.raises(RuntimeErrorSafe, match="recovery"):
        runtime.status()


def test_interrupted_join_reuses_reserved_profile_and_request(tmp_path, configured, monkeypatch):
    master, _backend, scope, info = configured
    master.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invitation = master.invite(scope.id)
    worker = ProjectRuntime(Paths(tmp_path / "worker"), backend_factory=lambda: pytest.fail("master backend"))
    original_put = worker.registry.put
    calls = 0

    def stop_before_registry(item, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic interruption")
        return original_put(item, **kwargs)

    monkeypatch.setattr(worker.registry, "put", stop_before_registry)
    with pytest.raises(OSError, match="interruption"):
        worker.join(invitation, fingerprint=info["fingerprint"])
    first_state_file = next((worker.paths.profiles_dir).glob("*/state/operations/*.enc"))
    first_state = first_state_file.read_bytes()
    joined = worker.join(invitation, fingerprint=info["fingerprint"])
    assert first_state_file.read_bytes() == first_state
    assert worker.registry.resolve(joined["profile_id"])["status"] == "pending"


def test_interrupted_initialize_reuses_orphaned_authority(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "master")
    backend = FakeBackend()
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    catalog = ProjectService(store)
    project = catalog.create_project("alpha", "Alpha")
    scope = catalog.create_scope(project.id, "default")
    runtime = ProjectRuntime(paths, backend)
    app = SyncServerApp(tmp_path / "relay.sqlite", "runtime-admin")
    original_put = runtime.registry.put
    calls = 0

    def stop_before_registry(item, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic interruption")
        return original_put(item, **kwargs)

    monkeypatch.setattr(runtime.registry, "put", stop_before_registry)
    with _running(app) as endpoint:
        with pytest.raises(OSError, match="interruption"):
            runtime.initialize(
                scope.id, endpoint, admin_token=Sealed("runtime-admin")
            )
        record = next(
            (paths.root / "project-sync" / scope.id / "state" / "operations").glob(
                "*.enc"
            )
        )
        orphaned = record.read_bytes()
        result = runtime.initialize(
            scope.id, endpoint, admin_token=Sealed("runtime-admin")
        )

    assert record.read_bytes() == orphaned
    assert runtime.registry.resolve(scope.id)["status"] == "active"
    assert result["scope_id"] == scope.id


def test_active_finish_replay_preserves_concurrent_outbox(tmp_path, configured):
    worker, joined, answer = _connect(tmp_path, configured)
    context = worker.context()
    context.service.create_entry(
        Entry.new(name="preserved-pending", type=EntryType.API_KEY),
        secrets=SecretInput(value="synthetic-pending"),
    )
    item = worker.registry.resolve(joined["profile_id"])
    before = worker.state(item).load()["outbox"]
    replay = worker.finish(joined["profile_id"], answer)
    assert replay["status"] == "active"
    assert worker.state(item).load()["outbox"] == before


def test_concurrent_approvals_preserve_both_grants(tmp_path, configured):
    master, _backend, scope, info = configured
    master.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invitations = [master.invite(scope.id), master.invite(scope.id)]
    requests = []
    for index, invitation in enumerate(invitations):
        worker = ProjectRuntime(Paths(tmp_path / f"worker-{index}"))
        joined = worker.join(invitation, fingerprint=info["fingerprint"])
        requests.append(joined["request_bundle"])

    def approve(request):
        return master.approve(
            request, fingerprint=wire.canonical_hash(request["request"])
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        answers = list(pool.map(approve, requests))
    assert len(answers) == 2
    state = master.state(master.registry.resolve(scope.id)).load()
    grants = wire.verify_policy(state["policy"], wire.decode_key(state["pin"]))["grants"]
    assert {grant["device_id"] for grant in grants} == {
        request["request"]["payload"]["device_id"] for request in requests
    }


def test_cached_approval_is_withheld_after_local_revocation(tmp_path, configured):
    master, _backend, scope, info = configured
    master.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invitation = master.invite(scope.id)
    worker = ProjectRuntime(Paths(tmp_path / "worker"))
    joined = worker.join(invitation, fingerprint=info["fingerprint"])
    request = joined["request_bundle"]
    fingerprint = wire.canonical_hash(request["request"])
    answer = master.approve(request, fingerprint=fingerprint)
    device_id = answer["request"]["payload"]["device_id"]
    master.master(master.registry.resolve(scope.id)).request_revoke(device_id)

    with pytest.raises(RuntimeErrorSafe, match="no longer active"):
        master.approve(request, fingerprint=fingerprint)


def test_status_masks_corrupt_encrypted_state(configured):
    runtime, _backend, scope, _info = configured
    state = runtime.state(runtime.registry.resolve(scope.id))
    record = next(state.paths.operations_dir.glob("*.enc"))
    record.write_bytes(b"corrupt-encrypted-state")

    result = runtime.status(scope.id)
    assert result["delivery"] == "unavailable"
    assert "error" not in result
    assert "checkpoint" not in result
    assert "recipients" not in result
    assert "outbox" not in result


def test_public_bundle_contains_no_device_private_keys_or_bearer(tmp_path, configured):
    worker, joined, answer = _connect(tmp_path, configured)
    state = worker.state(worker.registry.resolve(joined["profile_id"])).load()
    path = tmp_path / "request.json"
    write_bundle(path, joined["request_bundle"])
    text = path.read_text()
    for field in ("token", "signing_private", "agreement_private"):
        assert state[field] not in text
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    with pytest.raises(RuntimeErrorSafe):
        write_bundle(path, answer)
