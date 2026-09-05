"""KK3 end-to-end paths over the real HTTP relay and SQLite database.

Every credential here is generated per test and the in-memory backend prevents
any interaction with a user keychain.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import secrets
import threading
from uuid import uuid4

import pytest

from keys_keeper import project_protocol as protocol
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_replica import ReplicaStore
from keys_keeper.project_service import ProjectService
from keys_keeper.project_sync import (
    ProjectMaster,
    ProjectReplica,
    ProjectState,
    ProjectSyncError,
    new_master_state,
)
from keys_keeper.store import MetadataStore
from keys_keeper.sync_server import SyncServerApp, create_http_server
from keys_keeper.sync_vps_client import VpsAuthenticationError


_ADMIN = "e2e-admin-bootstrap-token"


def _id() -> str:
    return str(uuid4())


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class FakeBackend(KeychainBackend):
    """Test-only backend that records which scoped accounts were read."""

    def __init__(self):
        self.values: dict[str, str] = {}
        self.gets: list[str] = []

    def get(self, account: str) -> Sealed:
        self.gets.append(account)
        if account not in self.values:
            raise KeychainError("fixture account is absent")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


@contextmanager
def _running(app):
    server = create_http_server(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _identity(role: str = "reader", generation: int = 1) -> dict:
    signing_private = protocol.generate_key()
    agreement_private = protocol.generate_key()
    token = secrets.token_urlsafe(32)
    grant = {
        "grant_id": _id(),
        "generation": generation,
        "device_id": _id(),
        "role": role,
        "signing_public_key": protocol.encode_key(
            protocol.signing_public_key(signing_private)
        ),
        "agreement_public_key": protocol.encode_key(
            protocol.agreement_public_key(agreement_private)
        ),
        "token_hash": _token_hash(token),
    }
    return {
        "token": token,
        "signing_private": signing_private,
        "agreement_private": agreement_private,
        "grant": grant,
    }


def _add(store: MetadataStore, backend: FakeBackend, name: str) -> Entry:
    entry = Entry.new(name=name, type=EntryType.API_KEY)
    store.add(entry)
    backend.set(entry.id, f"fixture-{name}")
    return entry


def _replica_state(master: ProjectState, endpoint: str, identity: dict) -> dict:
    latest = master.load()
    # A checkpoint means an installed generation. The pin/policy below are the
    # onboarding trust anchor; checkpoint=None deliberately causes first pull.
    return {
        "mode": "replica",
        "scope_id": latest["scope_id"],
        "vault_id": latest["vault_id"],
        "endpoint": endpoint,
        "device_id": identity["grant"]["device_id"],
        "token": identity["token"],
        "pin": latest["pin"],
        "signing_private": protocol.encode_key(identity["signing_private"]),
        "agreement_private": protocol.encode_key(identity["agreement_private"]),
        "policy": latest["policy"],
        "checkpoint": None,
        "used_grants": list(latest["used_grants"]),
        "outbox": [],
    }


def _new_master(tmp_path, scope, endpoint: str, store, backend: FakeBackend) -> tuple[ProjectState, ProjectMaster]:
    state = ProjectState(Paths(tmp_path), lambda: b"x" * 32)
    state.save(new_master_state(scope.id, scope.vault_id, endpoint))
    ProjectClient(base_url=endpoint, token=Sealed(_ADMIN)).create_scope(state.load()["policy"])
    return state, ProjectMaster(state, store, backend)


def _new_replica(tmp_path, master: ProjectState, endpoint: str, identity: dict) -> tuple[ProjectState, ReplicaStore, ProjectReplica]:
    # Profile state and generations use separate private roots.  Pull holds the
    # profile journal lock while ReplicaStore atomically switches generations.
    state = ProjectState(Paths(tmp_path / "state"), lambda: b"y" * 32)
    state.save(_replica_state(master, endpoint, identity))
    store = ReplicaStore(paths=Paths(tmp_path / "generation"), password_provider=lambda: b"y" * 32)
    return state, store, ProjectReplica(state, store)


@pytest.fixture
def two_scopes(tmp_path):
    master_paths = Paths(tmp_path / "master-vault")
    store = MetadataStore(master_paths)
    backend = FakeBackend()
    entries = {name: _add(store, backend, name) for name in ("a-key", "b-key", "shared-key", "private-key")}
    store.migrate_catalog_v3()
    catalog = ProjectService(store)
    alpha = catalog.create_project("alpha", "Alpha")
    beta = catalog.create_project("beta", "Beta")
    scope_a = catalog.create_scope(alpha.id, "test")
    scope_b = catalog.create_scope(beta.id, "test")
    for name in ("a-key", "b-key", "shared-key"):
        catalog.set_entry_distribution(entries[name].id, "project_allowed")
    catalog.assign(scope_a.id, entries["a-key"].id)
    catalog.assign(scope_a.id, entries["shared-key"].id)
    catalog.assign(scope_b.id, entries["b-key"].id)
    catalog.assign(scope_b.id, entries["shared-key"].id)

    app = SyncServerApp(tmp_path / "relay.sqlite3", _ADMIN, clock=lambda: 1_800_000_000)
    with _running(app) as endpoint:
        yield {
            "tmp_path": tmp_path,
            "store": store,
            "backend": backend,
            "catalog": catalog,
            "entries": entries,
            "scope_a": scope_a,
            "scope_b": scope_b,
            "endpoint": endpoint,
            "app": app,
        }


def test_two_scope_projection_create_once_and_no_name_overwrite(two_scopes):
    env = two_scopes
    reader_a, reader_b, contributor = _identity(), _identity(), _identity("contributor")
    a_state, master_a = _new_master(env["tmp_path"] / "master-a", env["scope_a"], env["endpoint"], env["store"], env["backend"])
    b_state, master_b = _new_master(env["tmp_path"] / "master-b", env["scope_b"], env["endpoint"], env["store"], env["backend"])
    assert master_a.publish(grants=[reader_a["grant"], contributor["grant"]])["count"] == 2
    assert master_b.publish(grants=[reader_b["grant"]])["count"] == 2

    _, a_store, a_replica = _new_replica(env["tmp_path"] / "reader-a", a_state, env["endpoint"], reader_a)
    _, b_store, b_replica = _new_replica(env["tmp_path"] / "reader-b", b_state, env["endpoint"], reader_b)
    assert a_replica.pull() == {"status": "applied", "sequence": 1, "count": 2}
    assert b_replica.pull() == {"status": "applied", "sequence": 1, "count": 2}
    assert {entry.name for entry in a_store.metadata_store().list()} == {"a-key", "shared-key"}
    assert {entry.name for entry in b_store.metadata_store().list()} == {"b-key", "shared-key"}
    assert env["entries"]["private-key"].id not in env["backend"].gets

    _, contributor_store, contributor_replica = _new_replica(
        env["tmp_path"] / "contributor", a_state, env["endpoint"], contributor
    )
    contributor_replica.pull()
    with pytest.raises(ProjectSyncError, match="already exists"):
        contributor_replica.create(_create_payload("shared-key"))
    created = contributor_replica.create(_create_payload("remote-key"))
    assert created["status"] == "local_pending"
    assert contributor_replica.submit() == {"processed": 1, "pending": 1}
    assert master_a.receive() == {"processed": 1, "outcomes": {"accepted": 1}}
    assert master_a.publish()["count"] == 3
    assert contributor_replica.pull()["count"] == 3
    assert contributor_replica.submit() == {"processed": 1, "pending": 0}
    assert contributor_replica.submit() == {"processed": 0, "pending": 0}
    assert env["store"].get_by_name("remote-key") is not None
    assert len([entry for entry in env["store"].list() if entry.name == "remote-key"]) == 1
    assert master_a.receive() == {"processed": 0, "outcomes": {}}
    with pytest.raises(ProjectSyncError, match="already exists"):
        contributor_replica.create(_create_payload("remote-key"))
    assert contributor_store.metadata_store().get_by_name("remote-key") is not None


def _create_payload(name: str) -> dict:
    return {
        "schema_version": 1,
        "entry": {"name": name, "type": "api_key", "fields": {}, "tags": [], "note": "", "refs": []},
        "secret": f"fixture-{name}",
        "passphrase": None,
    }


class _LostFirstPublish:
    def __init__(self, client):
        self.client = client
        self.lose_response = True

    def publish(self, *args, **kwargs):
        result = self.client.publish(*args, **kwargs)
        if self.lose_response:
            self.lose_response = False
            raise OSError("synthetic response loss")
        return result

    def __getattr__(self, name):
        return getattr(self.client, name)


def test_publish_resume_rotation_history_and_revoked_create_denied(two_scopes):
    env = two_scopes
    former_contributor, newcomer = _identity("contributor"), _identity()
    state, _ = _new_master(env["tmp_path"] / "master-a", env["scope_a"], env["endpoint"], env["store"], env["backend"])
    lossy = _LostFirstPublish(ProjectClient(base_url=env["endpoint"], token=Sealed(state.load()["token"]), device_id=state.load()["device_id"]))
    master = ProjectMaster(state, env["store"], env["backend"], client=lossy)
    with pytest.raises(OSError, match="response loss"):
        master.publish(grants=[former_contributor["grant"]])
    assert state.load()["pending"] is not None
    assert master.publish(grants=[former_contributor["grant"]])["status"] == "unchanged"
    first = state.load()
    old_policy, old_snapshot = first["policy"], first["checkpoint"]["snapshot_hash"]
    assert old_policy["payload"]["version"] == 2

    _, _, old_replica = _new_replica(env["tmp_path"] / "former-contributor", state, env["endpoint"], former_contributor)
    old_replica.pull()
    old_replica.create(_create_payload("revoked-create"))

    assert master.publish(grants=[former_contributor["grant"], newcomer["grant"]])["status"] == "published"
    latest = state.load()
    assert latest["policy"]["payload"]["parent_policy_hash"] == protocol.canonical_hash(old_policy)
    assert latest["policy"]["payload"]["epoch"] == old_policy["payload"]["epoch"] + 1
    _, _, newcomer_replica = _new_replica(env["tmp_path"] / "new-reader", state, env["endpoint"], newcomer)
    assert newcomer_replica.pull()["status"] == "applied"
    remote = ProjectClient(base_url=env["endpoint"], token=Sealed(newcomer["token"]), device_id=newcomer["grant"]["device_id"])
    old_record = remote.snapshot(env["scope_a"].id, old_snapshot)["record"]
    current = remote.state(env["scope_a"].id)
    newest_key = protocol.unwrap_scope_key(
        current["wrap"], current["policy"], protocol.decode_key(latest["pin"]), newcomer["grant"]["device_id"], newcomer["agreement_private"]
    )
    with pytest.raises(protocol.AuthenticationError):
        protocol.open_snapshot(old_record, old_policy, protocol.decode_key(latest["pin"]), newest_key)

    enrolled_policy = latest["policy"]
    assert master.revoke(former_contributor["grant"]["device_id"])["status"] == "revoked"
    with pytest.raises(VpsAuthenticationError):
        old_replica.submit()
    with pytest.raises(VpsAuthenticationError):
        ProjectClient(base_url=env["endpoint"], token=Sealed(former_contributor["token"]), device_id=former_contributor["grant"]["device_id"]).state(env["scope_a"].id)
    latest = state.load()
    assert latest["policy"]["payload"]["parent_policy_hash"] == protocol.canonical_hash(enrolled_policy)
    assert all(grant["device_id"] != former_contributor["grant"]["device_id"] for grant in latest["policy"]["payload"]["grants"])
    assert {former_contributor["grant"]["grant_id"], newcomer["grant"]["grant_id"]} <= {
        grant["grant_id"] for grant in latest["used_grants"]
    }
    with env["app"]._connect() as connection:
        history = connection.execute(
            "SELECT grant_id FROM kk3_grants WHERE scope_id=?",
            (env["scope_a"].id,),
        ).fetchall()
        operations = connection.execute(
            "SELECT COUNT(*) FROM kk3_operations WHERE scope_id=?",
            (env["scope_a"].id,),
        ).fetchone()[0]
    assert {row["grant_id"] for row in history} == {
        former_contributor["grant"]["grant_id"], newcomer["grant"]["grant_id"]
    }
    # Retry after the synthetic response loss used the same operation id.
    assert operations == 3


class _HiddenRevocation:
    """Hostile relay wrapper omitting blocks and lying about block success."""
    def __init__(self, client, state):
        self.client, self.state_store = client, state
        self.publications = []

    def _unlocked(self):
        assert self.state_store.journal._lock_depth == 0, "state lock held during HTTP"

    def state(self, *args):
        self._unlocked()
        result = self.client.state(*args)
        result["revocations"] = []
        return result

    def block(self, *args):
        self._unlocked()
        return {"status": "blocked", "rekey": "pending"}

    def publish(self, *args, **kwargs):
        self._unlocked()
        self.publications.append(kwargs)
        return self.client.publish(*args, **kwargs)

    def __getattr__(self, name):
        target = getattr(self.client, name)
        def call(*args, **kwargs):
            self._unlocked()
            return target(*args, **kwargs)
        return call


def _configured_contributor(env):
    member = _identity("contributor")
    state, master = _new_master(env["tmp_path"] / "master-durable", env["scope_a"], env["endpoint"], env["store"], env["backend"])
    master.publish(grants=[member["grant"]])
    _, replica_store, replica = _new_replica(env["tmp_path"] / "replica-durable", state, env["endpoint"], member)
    replica.pull()
    return member, state, master, replica


def test_local_revoke_survives_fake_relay_success_rekey_failure_and_restart(two_scopes, monkeypatch):
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    replica.create(_create_payload("blocked-pending"))
    replica.submit()
    ordinary = master.client(state.load())
    hostile = _HiddenRevocation(ordinary, state)
    master._client_override = hostile
    old_key = protocol.decode_key(state.load()["scope_key"])
    original_get = env["backend"].get
    monkeypatch.setattr(env["backend"], "get", lambda *a: (_ for _ in ()).throw(KeychainError("synthetic locked backend")))
    with pytest.raises(Exception, match="secret access failed"):
        master.revoke(member["grant"]["device_id"])
    assert state.load()["local_revocations"][0]["record"]["payload"]["grant_id"] == member["grant"]["grant_id"]
    monkeypatch.setattr(env["backend"], "get", original_get)
    restarted_state = ProjectState(state.paths, lambda: b"x" * 32)
    hostile.state_store = restarted_state
    restarted = ProjectMaster(restarted_state, env["store"], env["backend"], client=hostile)
    assert restarted.receive() == {"processed": 1, "outcomes": {"quarantined": 1}}
    assert env["store"].get_by_name("blocked-pending") is None
    assert restarted.publish()["status"] == "published"
    current = restarted_state.load()
    assert current["policy"]["payload"]["grants"] == []
    assert current["local_revocations"]
    remote = ordinary.state(current["scope_id"])
    with pytest.raises(protocol.AuthenticationError):
        protocol.open_snapshot(remote["snapshot"], remote["policy"], protocol.decode_key(current["pin"]), old_key)


def test_revoked_lost_response_pending_reconciles_without_reissue(two_scopes):
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    ordinary = master.client(state.load())
    lossy = _LostFirstPublish(ordinary)
    master._client_override = lossy
    with pytest.raises(OSError):
        master.publish(force=True)
    revoked_pending = state.load()["pending"]["request"]
    hostile = _HiddenRevocation(ordinary, state)
    master._client_override = hostile
    master.request_revoke(member["grant"]["device_id"])
    assert master.publish()["status"] == "published"
    assert len(hostile.publications) == 1
    assert hostile.publications[0]["operation_id"] != revoked_pending["operation_id"]
    assert hostile.publications[0]["policy"]["payload"]["grants"] == []


def test_uncertain_revoked_pending_stops_without_retransmission(two_scopes):
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    ordinary = master.client(state.load())
    class FailedBeforeSend(_HiddenRevocation):
        def publish(self, *args, **kwargs):
            self.publications.append(kwargs)
            raise OSError("synthetic uncertain transport")
    failed = FailedBeforeSend(ordinary, state)
    master._client_override = failed
    with pytest.raises(OSError):
        master.publish(force=True)
    master.request_revoke(member["grant"]["device_id"])
    with pytest.raises(ProjectSyncError, match="outcome is uncertain"):
        master.publish()
    assert len(failed.publications) == 1
    assert state.load()["pending"] is not None


def test_local_revoke_survives_real_process_exit(two_scopes):
    import subprocess
    import sys
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    script = """import os,sys
from keys_keeper.paths import Paths
from keys_keeper.project_sync import ProjectState, ProjectMaster
state=ProjectState(Paths(sys.argv[1]),lambda:b'x'*32)
ProjectMaster(state,None,None).request_revoke(sys.argv[2])
os._exit(73)
"""
    result = subprocess.run([sys.executable, "-c", script, str(state.paths.root), member["grant"]["device_id"]], timeout=30, capture_output=True)
    assert result.returncode == 73
    restarted = ProjectState(state.paths, lambda: b"x" * 32)
    assert restarted.load()["local_revocations"][0]["record"]["payload"]["grant_id"] == member["grant"]["grant_id"]
    recovered_master = ProjectMaster(restarted, env["store"], env["backend"])
    assert recovered_master.publish()["status"] == "published"
    assert restarted.load()["policy"]["payload"]["grants"] == []


def test_network_job_does_not_block_local_revoke(two_scopes):
    from concurrent.futures import ThreadPoolExecutor
    import time
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    ordinary = master.client(state.load())
    entered, release = threading.Event(), threading.Event()
    class Paused(_HiddenRevocation):
        def state(self, *args):
            self._unlocked()
            entered.set()
            assert release.wait(10)
            return super().state(*args)
    paused = Paused(ordinary, state)
    master._client_override = paused
    with ThreadPoolExecutor(max_workers=1) as pool:
        job = pool.submit(master.publish, force=True)
        assert entered.wait(5)
        try:
            started = time.monotonic()
            assert master.request_revoke(member["grant"]["device_id"])["status"] == "blocked"
            assert time.monotonic() - started < 2
        finally:
            release.set()
        assert job.result(timeout=20)["status"] == "published"
    assert paused.publications[-1]["policy"]["payload"]["grants"] == []


def test_trusted_onboarding_checkpoint_does_not_skip_initial_install(two_scopes):
    env = two_scopes
    member, master_state, master, _ = _configured_contributor(env)
    state, store, replica = _new_replica(env["tmp_path"] / "onboarding", master_state, env["endpoint"], member)
    data = state.load()
    data.update(trusted_checkpoint=master_state.load()["checkpoint"], applied_checkpoint=None, checkpoint=None, used_grants=[])
    state.save(data)
    assert replica.pull()["status"] == "applied"
    assert store.metadata_store().list()
    after = state.load()
    assert after["trusted_checkpoint"] == after["applied_checkpoint"] == after["checkpoint"]
    assert member["grant"]["grant_id"] in {g["grant_id"] for g in after["used_grants"]}
    assert replica.pull()["status"] == "unchanged"


def test_startup_import_recovery_precedes_network_queue_with_local_authorization(two_scopes, monkeypatch):
    from keys_keeper.project_importer import ProjectImporter
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    master.request_revoke(member["grant"]["device_id"])
    called = []
    original = ProjectImporter.recover
    def recover(importer, *, current_policy, revoked_grant_ids=()):
        assert member["grant"]["grant_id"] in revoked_grant_ids
        assert current_policy == state.load()["policy"]
        called.append("recover")
        return original(importer, current_policy=current_policy, revoked_grant_ids=revoked_grant_ids)
    monkeypatch.setattr(ProjectImporter, "recover", recover)
    ordinary = master.client(state.load())
    class Checked(_HiddenRevocation):
        def pending(self, *args):
            self._unlocked()
            assert called == ["recover"]
            return self.client.pending(*args)
    master._client_override = Checked(ordinary, state)
    assert master.receive()["processed"] == 0


def test_observed_signed_revocation_stays_denied_when_relay_later_omits_it(two_scopes):
    env = two_scopes
    member, master_state, master, replica = _configured_contributor(env)
    source = master_state.load()
    revocation = protocol.build_revocation(source["policy"], protocol.decode_key(source["pin"]), protocol.decode_key(source["signing_private"]), device_id=member["grant"]["device_id"])
    ordinary = replica.client(replica.state.load())
    class Omission(_HiddenRevocation):
        show = True
        def state(self, *args):
            result = super().state(*args)
            result["revocations"] = [revocation] if self.show else []
            return result
    hostile = Omission(ordinary, replica.state)
    replica._client_override = hostile
    with pytest.raises(ProjectSyncError, match="grant revoked"):
        replica.pull()
    assert replica.state.load()["local_revocations"]
    hostile.show = False
    with pytest.raises(ProjectSyncError, match="grant revoked"):
        replica.pull()
    with pytest.raises(ProjectSyncError, match="grant revoked"):
        replica.create(_create_payload("must-not-create"))


def test_offline_replica_installs_verified_snapshot_gap(two_scopes):
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    before = replica.state.load()["applied_checkpoint"]
    master.publish(force=True)
    master.publish(force=True)
    assert replica.pull()["sequence"] == before["sequence"] + 2
    assert replica.state.load()["applied_checkpoint"]["snapshot_hash"] == state.load()["checkpoint"]["snapshot_hash"]


def test_history_byte_budget_stops_before_unbounded_chain_fetch(two_scopes, monkeypatch):
    env = two_scopes
    member, state, master, replica = _configured_contributor(env)
    checkpoint = replica.state.load()["checkpoint"]
    monkeypatch.setattr("keys_keeper.project_sync.MAX_HISTORY_BYTES", 64)
    with pytest.raises(ProjectSyncError, match="history byte budget exceeded"):
        replica.pull()
    assert replica.state.load()["checkpoint"] == checkpoint


def test_publication_intent_ack_retry_and_metadata_only_unchanged(two_scopes, monkeypatch):
    e = two_scopes
    state, master = _new_master(e["tmp_path"] / "queue-master", e["scope_a"], e["endpoint"], e["store"], e["backend"])
    master.publish()
    assert e["catalog"].capture_publications(e["scope_a"].id) == {}
    e["backend"].gets.clear()
    assert master.publish()["status"] == "unchanged"
    assert e["backend"].gets == []

    entry = e["entries"]["a-key"].id
    e["catalog"].unassign(e["scope_a"].id, entry)
    captured = e["catalog"].capture_publications(e["scope_a"].id)
    client = master.client(state.load())
    real_publish = client.publish
    dispatched = []
    def change_during_http(*args, **kwargs):
        dispatched.append(kwargs["operation_id"])
        result = real_publish(*args, **kwargs)
        if len(dispatched) == 1:
            e["catalog"].assign(e["scope_a"].id, entry)
        return result
    monkeypatch.setattr(client, "publish", change_during_http)
    master._client_override = client
    real_save = state.save
    def crash_after_ack(data):
        if data.get("pending") is None and data.get("checkpoint", {}).get("sequence") == 2:
            raise RuntimeError("synthetic process interruption after metadata ACK")
        return real_save(data)
    monkeypatch.setattr(state, "save", crash_after_ack)
    with pytest.raises(RuntimeError, match="synthetic process interruption"):
        master.publish()
    assert state.load()["pending"]["publication_revisions"] == captured
    intents = e["catalog"].publication_intents(scope_id=e["scope_a"].id)
    intent = next(i for i in intents if i["entry_id"] == entry)
    assert intent["applied_revision"] == captured[entry] < intent["desired_revision"]
    monkeypatch.setattr(state, "save", real_save)
    # Process restart repeats the identical prepared operation, then publishes
    # the newer desired state. Replaying ACK cannot consume the newer revision.
    restarted = ProjectMaster(ProjectState(state.paths, lambda: b"x" * 32), e["store"], e["backend"], client=client)
    restarted.publish()
    assert dispatched[0] == dispatched[1]
    assert len(set(dispatched)) == 2
    assert restarted.state.load()["checkpoint"]["sequence"] == 3
    assert e["catalog"].capture_publications(e["scope_a"].id) == {}


def test_epoch_budget_automatically_rotates_key(two_scopes, monkeypatch):
    e = two_scopes
    monkeypatch.setattr(protocol, "MAX_EPOCH_PUBLICATIONS", 2)
    state, master = _new_master(e["tmp_path"] / "epoch-master", e["scope_a"], e["endpoint"], e["store"], e["backend"])
    master.publish()
    initial = state.load()
    master.publish(force=True)
    assert state.load()["scope_key"] == initial["scope_key"]
    master.publish(force=True)
    latest = state.load()
    assert latest["scope_key"] != initial["scope_key"]
    assert latest["policy"]["payload"]["epoch"] == initial["policy"]["payload"]["epoch"] + 1
    assert latest["policy"]["payload"]["checkpoint_sequence"] == 2
    assert latest["checkpoint"]["sequence"] == 3


def test_atomic_add_grants_from_distinct_engines_preserves_both(two_scopes):
    from concurrent.futures import ThreadPoolExecutor
    e = two_scopes
    state, first = _new_master(e["tmp_path"] / "grant-master", e["scope_a"], e["endpoint"], e["store"], e["backend"])
    first.publish()
    second = ProjectMaster(ProjectState(state.paths, lambda: b"x" * 32), e["store"], e["backend"])
    a, b = _identity(), _identity()
    with ThreadPoolExecutor(max_workers=2) as pool:
        calls = [pool.submit(engine.add_grant, member["grant"]) for engine, member in ((first, a), (second, b))]
        for call in calls:
            assert call.result(timeout=30)["status"] == "published"
    grants = state.load()["policy"]["payload"]["grants"]
    assert {g["grant_id"] for g in grants} == {a["grant"]["grant_id"], b["grant"]["grant_id"]}
    assert first.add_grant(a["grant"])["status"] == "unchanged"
    first.request_revoke(a["grant"]["device_id"])
    with pytest.raises(ProjectSyncError, match="active project grant"):
        first.add_grant(a["grant"])
