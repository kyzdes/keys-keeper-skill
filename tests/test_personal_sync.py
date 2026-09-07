"""Real HTTP + SQLite + encrypted local replicas; no real OS credentials."""
from __future__ import annotations

import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from keys_keeper import api, pairing, project_protocol as wire
from keys_keeper.backend import Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.personal_sync import PersonalSync, read_settings
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_replica import ReplicaReadOnlyError
from keys_keeper.project_runtime import ProjectRuntime, RuntimeErrorSafe
from keys_keeper.project_service import ProjectService
from keys_keeper.service import SecretInput
from keys_keeper.store import MetadataStore
from keys_keeper.sync_server import SyncServerApp
from keys_keeper.sync_vps_client import VpsAuthenticationError, VpsConflictError, VpsInviteExpiredError
from test_project_sync_e2e import FakeBackend, _running


@pytest.fixture
def personal(tmp_path):
    paths = Paths(tmp_path / "master")
    backend = FakeBackend()
    store = MetadataStore(paths)
    for name in ("relay-admin", "private-key", "project-key"):
        entry = Entry.new(name=name, type=EntryType.API_KEY)
        store.add(entry)
        backend.set(entry.id, "test-admin-token" if name == "relay-admin" else "synthetic-" + name)
    store.migrate_catalog_v3()
    catalog = ProjectService(store)
    project = catalog.create_project("existing", "Existing project")
    scope = catalog.create_scope(project.id, "prod")
    catalog.set_entry_distribution(store.get_by_name("project-key").id, "project_allowed")
    catalog.assign(scope.id, store.get_by_name("project-key").id)
    existing = store.catalog_state()
    app = SyncServerApp(tmp_path / "relay.sqlite3", "test-admin-token")
    with _running(app) as endpoint:
        runtime = ProjectRuntime(paths, backend)
        manager = PersonalSync(paths, runtime)
        manager.setup(endpoint=endpoint, admin_token_entry="relay-admin", name="Main Mac", all_keys=True)
        yield manager, runtime, backend, endpoint, scope, existing, app


def _worker(tmp_path, personal):
    manager, runtime, backend, endpoint, scope, existing, app = personal
    worker = PersonalSync(Paths(tmp_path / "windows"))
    invitation = manager.invite()
    joined = worker.join(code=invitation["code"], name="Windows PC")
    request = manager.pending()[0]
    assert request["comparison_code"] == joined["comparison_code"]
    manager.approve(pair_id=request["pair_id"], fingerprint=request["fingerprint"])
    assert worker.poll_worker()["status"] == "active"
    return worker, invitation, request


def test_all_current_and_future_keys_without_widening_project_scopes(tmp_path, personal):
    manager, master, backend, endpoint, scope, before, app = personal
    worker, invitation, request = _worker(tmp_path, personal)
    context = ProjectRuntime(worker.paths).context()
    assert context.kind == "replica"
    assert {e.name for e in context.store.list()} == {"relay-admin", "private-key", "project-key"}
    assert master.master_store.get_by_name("private-key").distribution == "local_only"
    assert master.master_store.catalog_state()["bindings"] == before["bindings"]
    from keys_keeper.project_projection import preview_scope
    assert [e["name"] for e in preview_scope(master.master_store, scope.id)["entries"]] == ["project-key"]
    fresh = Entry.new(name="new-mac-key", type=EntryType.API_KEY, tags=["personal"], note="Keep my note", fields={"service": "example"})
    master.context().service.create_entry(fresh, secrets=SecretInput(value="synthetic-new-mac"))
    manager.sync(); worker.sync()
    copied = context.store.get_by_name("new-mac-key")
    assert copied.note == "Keep my note" and copied.tags == ["personal"] and copied.fields["service"] == "example"
    assert context.backend.get(copied.id).unseal() == "synthetic-new-mac"
    assert master.master_store.get_by_id(fresh.id).distribution == "local_only"
    assert master.master_store.catalog_state()["bindings"] == before["bindings"]
    assert manager.status()["devices"][0]["name"] == "Windows PC"
    # Relay sees neither the pairing encryption key nor any vault plaintext.
    with app._connect() as db:
        rows = db.execute("SELECT * FROM kk3_pairings").fetchall()
    serialized = json.dumps([dict(r) for r in rows])
    assert "synthetic-" not in serialized and pairing.parse_code(invitation["code"])["key"] not in serialized


def test_worker_adds_once_but_cannot_overwrite_or_select_master(tmp_path, personal, monkeypatch, capsys):
    manager, master, backend, *_ = personal
    worker, _, _ = _worker(tmp_path, personal)
    root = ProjectRuntime(worker.paths)
    context = root.context()
    entry = Entry.new(name="from-windows", type=EntryType.API_KEY)
    context.service.create_entry(entry, secrets=SecretInput(value="synthetic-windows"))
    worker.sync(); manager.sync(); worker.sync(); manager.sync(); worker.sync()
    assert len([e for e in master.master_store.list() if e.name == "from-windows"]) == 1
    assert context.store.get_by_name("from-windows") is not None
    from keys_keeper import cli
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(worker.paths.root))
    assert cli.main(["list"]) == 0
    output = capsys.readouterr().out
    assert "from-windows" in output and "synthetic-" not in output
    with pytest.raises(ReplicaReadOnlyError):
        context.service.create_entry(entry, secrets=SecretInput(value="overwrite"), replace=True)
    with pytest.raises(RuntimeErrorSafe):
        root.context("master")
    with pytest.raises(RuntimeErrorSafe):
        _ = root.master_backend
    grant = manager.status()["devices"][0]
    manager.revoke(grant["device_id"])
    with pytest.raises(VpsAuthenticationError):
        worker.sync()


def test_wrong_fingerprint_never_grants_and_interrupted_join_resumes(tmp_path, personal, monkeypatch):
    manager, *_ = personal
    invitation = manager.invite()
    worker = PersonalSync(Paths(tmp_path / "windows"))
    original = worker._upload_request
    monkeypatch.setattr(worker, "_upload_request", lambda *args: (_ for _ in ()).throw(ConnectionError()))
    with pytest.raises(ConnectionError):
        worker.join(code=invitation["code"], name="Windows")
    assert worker.status()["state"] == "pending"
    assert ProjectRuntime(worker.paths).context().store.list() == []
    monkeypatch.setattr(worker, "_upload_request", original)
    worker.join(code=invitation["code"], name="Windows")
    request = manager.pending()[0]
    with pytest.raises(RuntimeErrorSafe, match="fingerprint"):
        manager.approve(pair_id=request["pair_id"], fingerprint="0" * 64)
    assert not manager.status()["devices"]
    manager.approve(pair_id=request["pair_id"], fingerprint=request["fingerprint"])
    worker.watch(cycles=1)
    assert worker.status()["state"] == "active"


def test_code_tampering_expiry_and_mailbox_authentication(tmp_path, personal):
    manager, runtime, backend, endpoint, scope, before, app = personal
    invitation = manager.invite()
    value = pairing.parse_code(invitation["code"])
    key = wire.decode_key(value["key"])
    path = pairing.route(value["scope_id"], value["pair_id"])
    with pytest.raises(VpsAuthenticationError):
        ProjectClient(base_url=endpoint, token=Sealed("wrong-token"))._request("GET", path)
    mailbox = pairing.client(endpoint, key)._request("GET", path)
    with pytest.raises(pairing.PairingError):
        pairing.open_packet(key, value["pair_id"], "response", mailbox["invitation"])
    worker = PersonalSync(Paths(tmp_path / "windows"))
    wrong_pin = pairing.make_code(endpoint, value["scope_id"], value["pair_id"], key, "0" * 64)
    with pytest.raises(RuntimeErrorSafe, match="fingerprint"):
        worker.join(code=wrong_pin, name="Windows")
    assert read_settings(worker.paths) is None
    app._clock = lambda: time.time() + 1000
    with pytest.raises(VpsInviteExpiredError):
        pairing.client(endpoint, key)._request("GET", path)


def test_a_second_worker_cannot_replace_first_claim(tmp_path, personal):
    manager, *_ = personal
    invitation = manager.invite()
    one = PersonalSync(Paths(tmp_path / "one"))
    two = PersonalSync(Paths(tmp_path / "two"))
    one.join(code=invitation["code"], name="First PC")
    with pytest.raises(VpsConflictError):
        two.join(code=invitation["code"], name="Second PC")
    assert manager.pending()[0]["name"] == "First PC"


def test_setup_requires_all_keys_and_preserves_existing_worker_vault(tmp_path, personal):
    manager, master, backend, endpoint, *_ = personal
    with pytest.raises(RuntimeErrorSafe, match="Confirm"):
        manager.setup(endpoint=endpoint, admin_token_entry="relay-admin", name="Mac")
    worker = PersonalSync(Paths(tmp_path / "existing-worker"))
    old = Entry.new(name="keep-this", type=EntryType.API_KEY)
    worker.root.master_store.add(old)
    with pytest.raises(RuntimeErrorSafe, match="empty"):
        worker.join(code=manager.invite()["code"], name="Windows")
    assert worker.root.master_store.get_by_id(old.id) is not None
    assert read_settings(worker.paths) is None


class Handler:
    def _send_json(self, status, value):
        self.status, self.value = status, value


def test_local_api_never_returns_pairing_material_in_status(tmp_path, personal):
    manager, runtime, *_ = personal
    invitation = manager.invite()
    for action in ("status", "pending"):
        handler = Handler()
        api.handle_api(handler, paths=manager.paths, method="GET", path="/api/personal-sync/" + action, body=None, runtime=runtime)
        assert handler.status == 200
        serialized = json.dumps(handler.value)
        assert "synthetic-" not in serialized and invitation["code"] not in serialized
        assert pairing.parse_code(invitation["code"])["key"] not in serialized
    handler = Handler()
    api.handle_api(handler, paths=manager.paths, method="GET", path="/api/personal-sync/status?profile=master", body=None, runtime=runtime)
    assert handler.status == 403


def test_setup_retry_does_not_duplicate_scope(personal):
    manager, master, backend, endpoint, *_ = personal
    original = read_settings(manager.paths)["scope_id"]
    manager.setup(endpoint=endpoint, admin_token_entry="relay-admin", name="Main Mac", all_keys=True)
    assert read_settings(manager.paths)["scope_id"] == original
    assert len(master.registry.list()) == 1


def test_lost_approval_upload_retries_same_encrypted_response(tmp_path, personal, monkeypatch):
    manager, *_ = personal
    worker = PersonalSync(Paths(tmp_path / "worker"))
    worker.join(code=manager.invite()["code"], name="Windows")
    request = manager.pending()[0]
    original = manager._flush_responses
    monkeypatch.setattr(manager, "_flush_responses", lambda *args: (_ for _ in ()).throw(ConnectionError()))
    with pytest.raises(ConnectionError):
        manager.approve(pair_id=request["pair_id"], fingerprint=request["fingerprint"])
    assert worker.poll_worker()["status"] == "pending"
    monkeypatch.setattr(manager, "_flush_responses", original)
    manager.sync()
    assert worker.poll_worker()["status"] == "active"
    assert len(manager.status()["devices"]) == 1


def test_cancel_pending_connection_preserves_identity_and_allows_new_code(tmp_path, personal):
    manager, *_ = personal
    worker = PersonalSync(Paths(tmp_path / "worker"))
    worker.join(code=manager.invite()["code"], name="Windows")
    abandoned = worker.runtime().paths.root
    assert worker.cancel_pending() == {"status": "cancelled"}
    assert abandoned.exists()
    assert not worker.status()["configured"]
    worker.join(code=manager.invite()["code"], name="Windows retry")
    request = next(r for r in manager.pending() if r["name"] == "Windows retry")
    manager.approve(pair_id=request["pair_id"], fingerprint=request["fingerprint"])
    worker.poll_worker()
    with pytest.raises(RuntimeErrorSafe):
        worker.cancel_pending()


def test_parallel_join_reuses_one_local_device(tmp_path, personal):
    manager, *_ = personal
    invitation = manager.invite()
    paths = Paths(tmp_path / "parallel-worker")
    def join(_):
        return PersonalSync(paths).join(code=invitation["code"], name="Windows")
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(join, range(2)))
    assert results[0] == results[1]
    assert len(list((paths.root / "personal-replicas").iterdir())) == 1
    assert len(manager.pending()) == 1
