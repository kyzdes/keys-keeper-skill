"""Fast adversarial trust-state checks, without a credential backend."""
from copy import deepcopy

import pytest

from keys_keeper import project_protocol as p
from keys_keeper.project_sync import ProjectSyncError, _checkpoint, _verified_remote
from test_project_protocol import env


class RelayView:
    def __init__(self, policy, snapshot, policies=()):
        self.result = {"policy": policy, "snapshot": snapshot, "head_hash": p.canonical_hash(snapshot),
                       "sequence": snapshot["payload"]["sequence"], "wrap": None, "revocations": []}
        self.policies = {p.canonical_hash(record): record for record in policies}

    def state(self, scope_id):
        return deepcopy(self.result)

    def policy(self, scope_id, digest):
        return {"record": self.policies[digest]}


def state_for(e, snapshot):
    return {"policy": e["policy"], "scope_id": e["payload"]["scope_id"], "vault_id": e["payload"]["vault_id"],
            "pin": p.encode_key(e["pin"]), "checkpoint": _checkpoint(snapshot), "used_grants": []}


def test_known_policy_seeds_grant_history_before_retirement_and_regrant(env):
    e = env
    first = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    removed = p.sign_policy({**e["payload"], "version": 2, "epoch": 2, "parent_policy_hash": p.canonical_hash(e["policy"]),
                            "checkpoint_sequence": 1, "checkpoint_hash": p.canonical_hash(first), "grants": []}, e["master"])
    reused = p.sign_policy({**removed["payload"], "version": 3, "epoch": 3, "parent_policy_hash": p.canonical_hash(removed),
                           "grants": e["payload"]["grants"]}, e["master"])
    latest = p.build_snapshot({}, reused, e["pin"], e["master"], p.generate_key(), sequence=2, parent_hash=p.canonical_hash(first))
    relay = RelayView(reused, latest, [removed, e["policy"]])
    with pytest.raises(ProjectSyncError, match="retired project grant was reused"):
        _verified_remote(relay, state_for(e, first))


def test_relay_head_sequence_cannot_override_signed_trusted_head(env):
    e = env
    first = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    relay = RelayView(e["policy"], first)
    relay.result["sequence"] = 999
    with pytest.raises(ProjectSyncError, match="HEAD sequence mismatch"):
        _verified_remote(relay, state_for(e, first))


@pytest.mark.parametrize("bad", [None, "untrusted", [], {"payload": []}, {"payload": {"policy_hash": {}}}])
def test_malformed_relay_revocation_never_reaches_unsafe_lookup(env, bad):
    e = env
    first = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    relay = RelayView(e["policy"], first)
    relay.result["revocations"] = [bad]
    with pytest.raises(ProjectSyncError):
        _verified_remote(relay, state_for(e, first))


def test_durable_replica_revoke_blocks_queued_resubmission_before_http(env):
    from contextlib import nullcontext
    from keys_keeper.project_sync import ProjectReplica
    from test_project_protocol import submit
    e = env
    record = submit(e)
    state = {"policy": e["policy"], "scope_id": e["payload"]["scope_id"], "vault_id": e["payload"]["vault_id"],
             "pin": p.encode_key(e["pin"]), "device_id": e["grant"]["device_id"],
             "local_revocations": [{"policy": e["policy"], "record": p.build_revocation(e["policy"], e["pin"], e["master"], device_id=e["grant"]["device_id"])}],
             "outbox": [{"status": "local_pending", "submission": record, "source_policy": e["policy"]}]}
    class State:
        locked = job_locked = staticmethod(nullcontext)
        def load(self):
            return deepcopy(state)
    class NoHTTP:
        def __getattr__(self, name):
            raise AssertionError("revoked outbox reached HTTP")
    with pytest.raises(ProjectSyncError, match="project grant revoked"):
        ProjectReplica(State(), None, client=NoHTTP()).submit()


@pytest.mark.parametrize("status", ["published", "conflict", "rejected", "quarantined", "local_pending", "uploaded", "accepted"])
def test_terminal_outbox_history_does_not_reserve_a_free_entry_name(env, status):
    from contextlib import nullcontext
    from keys_keeper.project_sync import ProjectReplica
    from test_project_protocol import creation
    e = env
    payload = creation()
    data = {"policy": e["policy"], "scope_id": e["payload"]["scope_id"], "vault_id": e["payload"]["vault_id"],
            "pin": p.encode_key(e["pin"]), "device_id": e["grant"]["device_id"], "signing_private": p.encode_key(e["signing"]),
            "outbox": [{"request_id": "retained-history", "status": status, "payload": payload}]}
    class State:
        locked = staticmethod(nullcontext)
        def load(self):
            return deepcopy(data)
        def save(self, current):
            data.clear()
            data.update(deepcopy(current))
    class InstalledEmpty:
        def metadata_store(self):
            return self
        def get_by_name(self, name):
            return None
    replica = ProjectReplica(State(), InstalledEmpty())
    if status in {"local_pending", "uploaded", "accepted"}:
        with pytest.raises(ProjectSyncError, match="pending entry name already exists"):
            replica.create(payload)
        assert len(data["outbox"]) == 1
    else:
        result = replica.create(payload)
        assert result["request_id"] != "retained-history"
        assert result["status"] == "local_pending"
        assert len(data["outbox"]) == 2
        assert data["outbox"][0]["status"] == status
