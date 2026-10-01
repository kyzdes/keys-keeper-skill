"""User-level project composition with synthetic credentials and a real relay."""
from __future__ import annotations

import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

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


@pytest.fixture(autouse=True)
def isolated_automatic_worker_boundary(monkeypatch):
    # Runtime fixtures inject synthetic backends; execute their operation in
    # place while separate supervisor tests prove hard process cancellation.
    monkeypatch.setattr(ProjectRuntime, "_run_auto_sync", lambda self, item: self.sync(item["id"]))


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


def test_first_join_rejects_tombstoned_master_root_without_mutating_it(
    tmp_path, configured
):
    master, _backend, scope, info = configured
    master.backup("master", tmp_path / "recovery.enc", "synthetic-recovery-password")
    invitation = master.invite(scope.id)

    paths = Paths(tmp_path / "worker")
    store = MetadataStore(paths)
    old = Entry.new(name="deleted-before-enrollment", type=EntryType.API_KEY)
    store.add(old)
    store.delete_by_name(old.name)
    before = paths.data_json.read_bytes()
    worker = ProjectRuntime(
        paths,
        backend_factory=lambda: pytest.fail("master backend constructed"),
    )

    with pytest.raises(RuntimeErrorSafe, match="clean Keys Keeper root"):
        worker.join(invitation, fingerprint=info["fingerprint"])

    assert paths.data_json.read_bytes() == before
    assert not (paths.root / "profile-registry.json").exists()
    assert not paths.pending_dir.exists()
    assert not paths.profiles_dir.exists()

    artifact_paths = Paths(tmp_path / "worker-with-config")
    artifact_paths.root.mkdir()
    artifact_paths.config_toml.write_text("[sync]\nenabled = false\n")
    artifact_worker = ProjectRuntime(
        artifact_paths,
        backend_factory=lambda: pytest.fail("master backend constructed"),
    )
    with pytest.raises(RuntimeErrorSafe, match="clean Keys Keeper root"):
        artifact_worker.join(invitation, fingerprint=info["fingerprint"])
    assert artifact_paths.config_toml.read_text() == "[sync]\nenabled = false\n"
    assert not (artifact_paths.root / "profile-registry.json").exists()


def test_worker_master_backend_rejected_before_cached_backend_is_returned(
    tmp_path, configured
):
    worker, _joined, _answer = _connect(tmp_path, configured)
    cached_backend = object()
    worker._backend = cached_backend

    with pytest.raises(RuntimeErrorSafe, match="worker root"):
        _ = worker.master_backend
    assert worker._backend is cached_backend


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


def _watch_profile():
    scope_id = str(uuid4())
    return {"id": scope_id, "kind": "master_scope", "scope_id": scope_id,
            "vault_id": str(uuid4()), "device_id": str(uuid4()),
            "project": "daily-fixture", "environment": "test",
            "endpoint": "https://relay.example", "status": "active"}


def _watch_runtime(tmp_path):
    runtime = ProjectRuntime(Paths(tmp_path), backend_factory=lambda: pytest.fail("watch unlocked real backend"))
    item = _watch_profile()
    runtime.registry.put(item)
    return runtime, item


def test_watch_legacy_interval_sleeps_for_a_day_and_never_retries(tmp_path, monkeypatch):
    runtime, item = _watch_runtime(tmp_path)
    attempts, sleeps, reports = [], [], []

    def failed_sync(selector):
        attempts.append(selector)
        raise ValueError("SYNTHETIC-ERROR-MUST-NOT-APPEAR")

    monkeypatch.setattr(runtime, "sync", failed_sync)
    runtime.watch(item["id"], interval=60, cycles=2, clock=lambda: 1000,
                  sleep=sleeps.append, report=reports.append)

    assert attempts == [item["id"]]
    assert sleeps == [86400]
    assert reports[0]["profiles"][0]["error"] == "operation_failed"
    assert reports[1]["profiles"][0]["status"] == "deferred"
    assert "SYNTHETIC-ERROR" not in json.dumps(reports)


def test_watch_claim_survives_restart_and_enforces_rolling_24_hours(tmp_path, monkeypatch):
    runtime, item = _watch_runtime(tmp_path)
    attempts, reports = [], []
    monkeypatch.setattr(runtime, "sync", lambda selector: attempts.append(selector))
    runtime.watch(item["id"], cycles=1, clock=lambda: 1000.5)
    marker = tmp_path / "project-watch-schedule" / item["id"] / "last-attempt.json"
    before = marker.read_bytes()

    restarted = ProjectRuntime(Paths(tmp_path), backend_factory=lambda: pytest.fail("deferred watch unlocked backend"))
    monkeypatch.setattr(restarted, "sync", lambda selector: attempts.append(selector))
    monkeypatch.setattr(restarted, "state", lambda _item: pytest.fail("deferred watch decrypted project state"))
    restarted.watch(item["id"], interval=5, cycles=1, clock=lambda: 87400.4, report=reports.append)
    assert attempts == [item["id"]]
    assert marker.read_bytes() == before
    assert reports[0]["profiles"][0]["status"] == "deferred"
    restarted.watch(item["id"], interval=5, cycles=1, clock=lambda: 87400.5)
    assert attempts == [item["id"], item["id"]]
    assert marker.read_bytes() != before
    if os.name == "posix":
        assert marker.stat().st_mode & 0o077 == 0


def test_parallel_watchers_claim_one_daily_attempt(tmp_path):
    runtime, item = _watch_runtime(tmp_path)
    other = ProjectRuntime(Paths(tmp_path))
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda worker: worker._claim_auto_sync(item, 1000), [runtime, other]))
    assert sorted(claimed for claimed, _due in claims) == [False, True]


def test_watch_runs_next_pass_only_when_a_full_day_has_elapsed(tmp_path, monkeypatch):
    runtime, item = _watch_runtime(tmp_path)
    clock_value, attempts, sleeps = [1000.0], [], []
    monkeypatch.setattr(runtime, "sync", lambda _selector: attempts.append(clock_value[0]))

    def advance(seconds):
        sleeps.append(seconds)
        clock_value[0] += seconds

    runtime.watch(item["id"], interval=60, cycles=3, clock=lambda: clock_value[0], sleep=advance)
    assert attempts == [1000, 87400, 173800]
    assert sleeps == [86400, 86400]


@pytest.mark.parametrize("marker_bytes", [
    b"null", b"[]", b"not json", b'{"schema_version":true,"last_attempt":1}',
    b'{"schema_version":1,"last_attempt":true}',
    b'{"schema_version":1,"last_attempt":-1}',
    b'{"schema_version":1,"last_attempt":NaN}',
])
def test_invalid_watch_marker_fails_closed_without_sync(tmp_path, monkeypatch, marker_bytes):
    runtime, item = _watch_runtime(tmp_path)
    runtime._claim_auto_sync(item, 1000)
    marker = tmp_path / "project-watch-schedule" / item["id"] / "last-attempt.json"
    marker.write_bytes(marker_bytes)
    reports = []
    monkeypatch.setattr(runtime, "sync", lambda _selector: pytest.fail("invalid timing metadata permitted expensive work"))
    runtime.watch(item["id"], cycles=1, clock=lambda: 999999, report=reports.append)
    assert reports[0]["profiles"][0]["error"] == "schedule_unavailable"
    assert marker.read_bytes() == marker_bytes


def test_manual_sync_runs_immediately_after_daily_watch(tmp_path, monkeypatch):
    runtime, item = _watch_runtime(tmp_path)
    calls = []

    class SyntheticMaster:
        def receive(self):
            calls.append("receive")
            return {"status": "idle"}

        def publish(self):
            calls.append("publish")
            return {"status": "unchanged"}

    monkeypatch.setattr(runtime, "master", lambda _item: SyntheticMaster())
    runtime.watch(item["id"], cycles=1, clock=lambda: 1000)
    marker = tmp_path / "project-watch-schedule" / item["id"] / "last-attempt.json"
    before = marker.read_bytes()
    for _ in range(2):
        assert runtime.sync(item["id"])["publish"]["status"] == "unchanged"
    assert calls == ["receive", "publish"] * 3
    assert marker.read_bytes() == before


def test_watch_profiles_have_independent_daily_claims(tmp_path, monkeypatch):
    runtime, first = _watch_runtime(tmp_path)
    second = _watch_profile()
    runtime.registry.put(second)
    runtime._claim_auto_sync(first, 1000)
    calls, reports = [], []
    monkeypatch.setattr(runtime, "sync", lambda selector: calls.append(selector))
    runtime.watch(None, cycles=1, clock=lambda: 2000, report=reports.append)
    assert calls == [second["id"]]
    assert [result["status"] for result in reports[0]["profiles"]] == ["deferred", "synced"]


def test_auto_entry_and_watch_share_daily_claim(tmp_path, monkeypatch):
    runtime, item = _watch_runtime(tmp_path)
    attempts = []
    monkeypatch.setattr(runtime, "sync", lambda *_args: attempts.append("work"))
    assert runtime.auto_sync(item["scope_id"], clock=lambda: 1000)["status"] == "synced"
    runtime.watch(item["id"], interval=5, cycles=1, clock=lambda: 1001)
    assert runtime.auto_sync(item["id"], clock=lambda: 2000)["status"] == "deferred"
    assert attempts == ["work"]


def test_profile_identity_changes_do_not_reset_scope_claim_and_legacy_is_preserved(tmp_path):
    from keys_keeper.auto_schedule import claim_auto_sync
    runtime, item = _watch_runtime(tmp_path)
    item = {**item, "id": str(uuid4()), "kind": "replica"}
    legacy = Paths(tmp_path / "project-watch-schedule" / item["id"])
    claim_auto_sync(legacy, 1000)
    assert runtime._claim_auto_sync(item, 1001) == (False, 87400)
    shared = tmp_path / "project-watch-schedule" / item["scope_id"] / "last-attempt.json"
    assert json.loads(shared.read_bytes())["last_attempt"] == 1000
    item["id"] = str(uuid4())
    assert runtime._claim_auto_sync(item, 87400 - 0.01) == (False, 87400)
    assert runtime._claim_auto_sync(item, 87400) == (True, 173800)


def test_automatic_timeout_consumes_slot_and_manual_sync_remains_immediate(tmp_path, monkeypatch):
    from keys_keeper.auto_worker import AutoWorkerError
    runtime, item = _watch_runtime(tmp_path)
    calls = []
    def timeout(_item):
        calls.append("automatic")
        raise AutoWorkerError("operation_timed_out")
    monkeypatch.setattr(runtime, "_run_auto_sync", timeout)
    assert runtime.auto_sync(item["id"], clock=lambda: 1000) == {"status": "failed", "error": "operation_timed_out"}
    assert runtime.auto_sync(item["id"], clock=lambda: 1001)["status"] == "deferred"
    monkeypatch.setattr(runtime, "sync", lambda *_args: calls.append("manual"))
    runtime.sync(item["id"])
    assert calls == ["automatic", "manual"]


def test_actual_supervised_project_worker_uses_only_synthetic_replica(tmp_path, configured):
    from keys_keeper.auto_worker import run_auto_worker
    worker, joined, _answer = _connect(tmp_path, configured)
    run_auto_worker("project", worker.paths, joined["profile_id"], timeout=10)
    context = worker.context(joined["profile_id"])
    assert context.kind == "replica"
    assert [entry.name for entry in context.store.list()] == ["project-key"]


def test_runtime_state_cache_uses_immutable_identity_and_defensive_copy(tmp_path, monkeypatch):
    runtime = ProjectRuntime(Paths(tmp_path))
    item = _watch_profile()
    monkeypatch.setattr(runtime, "_profile_password", lambda profile: profile["scope_id"])
    original_id = item["scope_id"]
    first = runtime.state(item)
    assert runtime.state(dict(item)) is first
    item["scope_id"] = str(uuid4())
    assert first.journal._password_provider() == original_id
    assert runtime.state(item) is not first
    same_identity = dict(item, project="renamed", status="pending")
    assert runtime.state(same_identity) is runtime.state(item)


def test_runtime_state_cache_is_bounded_and_profile_local(tmp_path):
    runtime = ProjectRuntime(Paths(tmp_path))
    first_item = _watch_profile()
    first = runtime.state(first_item)
    others = [runtime.state(_watch_profile()) for _ in range(32)]
    assert len(runtime._states) == 32
    assert all(other is not first for other in others)
    assert runtime.state(first_item) is not first
    assert ProjectRuntime(Paths(tmp_path)).state(first_item) is not first


@pytest.mark.parametrize("field", ["vault_id", "device_id", "endpoint"])
def test_runtime_state_cache_does_not_cross_profile_identity_changes(tmp_path, field):
    runtime = ProjectRuntime(Paths(tmp_path))
    item = _watch_profile()
    state = runtime.state(item)
    changed = dict(item)
    changed[field] = "https://other.example" if field == "endpoint" else str(uuid4())
    assert runtime.state(changed) is not state


def test_reused_runtime_state_reads_external_journal_updates(tmp_path, monkeypatch):
    item = _watch_profile()
    runtime = ProjectRuntime(Paths(tmp_path))
    other = ProjectRuntime(Paths(tmp_path))
    for worker in (runtime, other):
        monkeypatch.setattr(worker, "_profile_password", lambda _profile: "synthetic-cache-password")
    state = runtime.state(item)
    identity = {"scope_id": item["scope_id"], "vault_id": item["vault_id"], "mode": "master"}
    state.save({**identity, "revision": 1})
    assert state.load() == {**identity, "revision": 1}
    other.state(item).save({**identity, "revision": 2})
    assert runtime.state(dict(item)) is state
    assert state.load() == {**identity, "revision": 2}


def test_cli_watch_defaults_daily_but_accepts_legacy_interval():
    from keys_keeper.cli import build_parser

    parser = build_parser()
    assert parser.parse_args(["project-sync", "watch"]).interval == 86400
    legacy = parser.parse_args(["project-sync", "watch", "--scope", "fixture/test", "--interval", "60"])
    assert legacy.scope == "fixture/test"
    assert legacy.interval == 60
