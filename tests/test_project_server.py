"""KK3 relay integration: real HTTP, real SQLite, synthetic credentials only."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import http.client
import json
from pathlib import Path
import secrets
import sqlite3
import threading
from uuid import uuid4

import pytest

from keys_keeper import project_protocol as p, project_server as relay
from keys_keeper.backend import Sealed
from keys_keeper.project_client import ProjectClient
from keys_keeper.sync_server import SyncServerApp, create_http_server
from keys_keeper.sync_vps_client import VpsAuthenticationError, VpsConflictError, VpsProtocolError, VpsValidationError

ADMIN = "synthetic-admin-bootstrap-token"
CANARY = "SYNTHETIC-PROJECT-SECRET-CANARY"


def uid():
    return str(uuid4())


def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()


def identity(role="contributor", generation=1):
    sign, agree = p.generate_key(), p.generate_key()
    token = secrets.token_urlsafe(32)
    grant = {"grant_id": uid(), "generation": generation, "device_id": uid(), "role": role,
             "signing_public_key": p.encode_key(p.signing_public_key(sign)),
             "agreement_public_key": p.encode_key(p.agreement_public_key(agree)), "token_hash": digest(token)}
    return {"sign": sign, "agree": agree, "token": token, "grant": grant}


def auth(device_id, token):
    return {"Authorization": f"Bearer {token}", "X-Device-ID": device_id}


@contextmanager
def running(app):
    server = create_http_server(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


def request(address, method, path, *, body=None, headers=None):
    headers = dict(headers or {})
    if isinstance(body, dict):
        body = json.dumps(body, separators=(",", ":")).encode()
        headers.setdefault("Content-Type", "application/json")
    connection = http.client.HTTPConnection(*address, timeout=10)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


class Scope:
    def __init__(self, address):
        self.address = address
        self.master, self.inbox, self.key = [p.generate_key() for _ in range(3)]
        self.pin = p.signing_public_key(self.master)
        self.master_device = uid()
        self.token = secrets.token_urlsafe(32)
        self.scope_id, self.vault_id = uid(), uid()
        self.base = f"/v2/scopes/{self.scope_id}"
        self.headers = auth(self.master_device, self.token)
        self.genesis = p.sign_policy({"scope_id": self.scope_id, "vault_id": self.vault_id,
            "version": 1, "epoch": 1, "master_device_id": self.master_device,
            "master_token_hash": digest(self.token), "master_public_key": p.encode_key(self.pin),
            "inbox_public_key": p.encode_key(p.agreement_public_key(self.inbox)),
            "parent_policy_hash": None, "checkpoint_sequence": 0, "checkpoint_hash": None, "grants": []}, self.master)
        self.policy = self.genesis
        self.head, self.sequence = None, 0
        assert request(address, "POST", "/v2/scopes", body={"policy": self.genesis}, headers={"Authorization": f"Bearer {ADMIN}"})[0] == 201

    def call(self, method, suffix, *, body=None, headers=None):
        return request(self.address, method, self.base + suffix, body=body, headers=self.headers if headers is None else headers)

    def transaction(self, *, policy=None):
        policy = self.policy if policy is None else policy
        snapshot = p.build_snapshot({"entries": [{"synthetic": CANARY}]}, policy, self.pin, self.master,
                                    self.key, sequence=self.sequence + 1, parent_hash=self.head)
        wraps = [p.wrap_scope_key(self.key, policy, self.pin, self.master, g["device_id"]) for g in policy["payload"]["grants"]]
        return {"operation_id": uid(), "expected_head_hash": self.head, "policy": policy, "snapshot": snapshot, "wraps": wraps}

    def publish(self, *, policy=None):
        tx = self.transaction(policy=policy)
        status, result = self.call("POST", "/publish", body=tx)
        assert status == 201, result
        self.policy = tx["policy"]
        self.head, self.sequence = result["head_hash"], result["sequence"]
        return tx

    def changed_policy(self, grants, *, epoch_delta=1):
        return p.sign_policy({**self.policy["payload"], "grants": grants,
            "version": self.policy["payload"]["version"] + 1,
            "epoch": self.policy["payload"]["epoch"] + epoch_delta,
            "parent_policy_hash": p.canonical_hash(self.policy),
            "checkpoint_sequence": self.sequence, "checkpoint_hash": self.head}, self.master)

    def enroll(self, *members):
        self.key = p.generate_key()
        return self.publish(policy=self.changed_policy([m["grant"] for m in members]))

    def submission(self, member, *, policy=None, request_id=None):
        payload = {"schema_version": 1, "entry": {"name": "synthetic", "type": "token", "fields": {}, "tags": [], "note": "", "refs": []},
                   "secret": CANARY, "passphrase": None}
        return p.build_create(payload, policy or self.policy, self.pin, member["grant"]["device_id"], member["sign"], request_id=request_id or uid())

    def member_headers(self, member):
        return auth(member["grant"]["device_id"], member["token"])

    def client(self, member=None):
        return ProjectClient(base_url=f"http://{self.address[0]}:{self.address[1]}",
            token=Sealed(self.token if member is None else member["token"]),
            device_id=self.master_device if member is None else member["grant"]["device_id"])


@pytest.fixture
def setup(tmp_path):
    app = SyncServerApp(tmp_path / "relay.sqlite3", ADMIN, clock=lambda: 1_800_000_000)
    with running(app) as address:
        scope = Scope(address)
        scope.publish()
        contributor, reader = identity(), identity("reader")
        scope.enroll(contributor, reader)
        yield app, scope, contributor, reader


def test_bootstrap_pin_admin_and_retry_survive_head_changes(setup):
    app, s, contributor, reader = setup
    assert request(s.address, "POST", "/v2/scopes", body={"policy": s.genesis})[0] == 401
    status, result = request(s.address, "POST", "/v2/scopes", body={"policy": s.genesis}, headers={"Authorization": f"Bearer {ADMIN}"})
    assert status == 200 and result == {"scope_id": s.scope_id}
    forged_genesis = p.sign_policy({**s.genesis["payload"], "master_token_hash": "a" * 64}, s.master)
    assert request(s.address, "POST", "/v2/scopes", body={"policy": forged_genesis}, headers={"Authorization": f"Bearer {ADMIN}"})[0] == 409
    assert request(s.address, "POST", "/v2/scopes", body={"policy": s.policy}, headers={"Authorization": f"Bearer {ADMIN}"})[0] == 422


def test_complete_role_matrix_and_scope_isolation(setup):
    app, s, contributor, reader = setup
    other = Scope(s.address)
    other.publish()
    snapshot_hash = s.head
    for member in (contributor, reader):
        headers = s.member_headers(member)
        status, state = s.call("GET", "/state", headers=headers)
        assert status == 200
        assert state["wrap"]["payload"]["device_id"] == member["grant"]["device_id"]
        assert p.unwrap_scope_key(state["wrap"], state["policy"], s.pin, member["grant"]["device_id"], member["agree"]) == s.key
        assert s.call("GET", f"/policies/{p.canonical_hash(s.policy)}", headers=headers)[0] == 200
        assert s.call("GET", f"/snapshots/{snapshot_hash}", headers=headers)[0] == 200
        assert s.call("GET", "/submissions", headers=headers)[0] == 403
        assert s.call("POST", "/publish", body=s.transaction(), headers=headers)[0] == 403
        revoke = p.build_revocation(s.policy, s.pin, s.master, device_id=contributor["grant"]["device_id"])
        assert s.call("POST", "/revoke", body={"revocation": revoke}, headers=headers)[0] == 403
        assert other.call("GET", "/state", headers=headers)[0] == 403
        assert other.call("GET", f"/snapshots/{other.head}", headers=headers)[0] == 403
        assert other.call("GET", f"/policies/{p.canonical_hash(other.policy)}", headers=headers)[0] == 403
    submission = s.submission(contributor)
    assert s.call("POST", "/submissions", body={"submission": submission}, headers=s.member_headers(reader))[0] == 403
    assert s.call("POST", "/submissions", body={"submission": submission}, headers=s.member_headers(contributor))[0] == 201
    request_id = submission["payload"]["request_id"]
    assert s.call("GET", f"/submissions/{request_id}", headers=s.member_headers(reader))[0] == 404
    receipt = p.build_receipt(submission, s.policy, s.pin, s.master, status="accepted", canonical_entry_id=uid(), revision=1)
    assert s.call("POST", f"/submissions/{request_id}/receipt", body={"receipt": receipt}, headers=s.member_headers(contributor))[0] == 403
    for member in (contributor, reader):
        assert s.call("GET", "/state", headers=auth(member["grant"]["device_id"], "wrong-token"))[0] == 401
    assert s.call("GET", "/state", headers={})[0] == 401
    assert s.call("GET", "/state", headers=auth(s.master_device, "wrong-token"))[0] == 401


def test_publish_atomic_cas_idempotency_concurrent_and_fault_rollback(setup):
    app, s, contributor, reader = setup
    tx = s.transaction()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: s.call("POST", "/publish", body=tx), range(2)))
    assert sorted(status for status, _ in results) == [200, 201]
    assert results[0][1] == results[1][1]
    assert s.call("POST", "/publish", body={**tx, "operation_id": uid()})[0] == 409
    assert s.call("POST", "/publish", body={**tx, "expected_head_hash": "a" * 64})[0] == 409
    s.head, s.sequence = results[0][1]["head_hash"], results[0][1]["sequence"]
    next_tx = s.transaction()
    missing = {**next_tx, "wraps": next_tx["wraps"][:1]}
    assert s.call("POST", "/publish", body=missing)[0] == 422
    assert s.call("GET", "/state")[1]["head_hash"] == s.head
    assert s.call("POST", "/publish", body=next_tx)[0] == 201  # failed operation did not reserve its id
    assert s.call("POST", "/publish", body=tx)[0] == 200  # retry after a newer HEAD
    with app._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM kk3_operations WHERE scope_id=?", (s.scope_id,)).fetchone()[0] == 4


def test_history_epoch_enrollment_does_not_grant_old_key(setup):
    app, s, contributor, reader = setup
    old_policy, old_key, old_hash = s.policy, s.key, s.head
    newcomer = identity()
    s.enroll(contributor, reader, newcomer)
    state = s.client(newcomer).state(s.scope_id)
    new_key = p.unwrap_scope_key(state["wrap"], state["policy"], s.pin, newcomer["grant"]["device_id"], newcomer["agree"])
    assert new_key != old_key
    old_snapshot = s.client(newcomer).snapshot(s.scope_id, old_hash)["record"]
    with pytest.raises(p.AuthenticationError):
        p.open_snapshot(old_snapshot, old_policy, s.pin, new_key)
    assert p.open_snapshot(old_snapshot, old_policy, s.pin, old_key)["entries"]
    changed = s.changed_policy([contributor["grant"], reader["grant"]], epoch_delta=0)
    assert s.call("POST", "/publish", body=s.transaction(policy=changed))[0] == 403


def test_grant_history_no_reuse_across_removal_restart(setup):
    app, s, contributor, reader = setup
    removed_grant = deepcopy(contributor["grant"])
    s.enroll(reader)
    for attempted in (removed_grant, {**removed_grant, "grant_id": uid()}):
        attempted_policy = s.changed_policy([attempted, reader["grant"]])
        status, result = s.call("POST", "/publish", body=s.transaction(policy=attempted_policy))
        assert status == 409 and "reused" in result["error"]["code"]
    new_grant = {**removed_grant, "grant_id": uid(), "generation": 2}
    contributor["grant"] = new_grant
    s.enroll(contributor, reader)
    restarted = SyncServerApp(app.database, ADMIN)
    with running(restarted) as address:
        assert request(address, "GET", s.base + "/state", headers=s.member_headers(contributor))[0] == 200
        with restarted._connect() as connection:
            assert connection.execute("SELECT COUNT(*) FROM kk3_grants WHERE scope_id=? AND device_id=?", (s.scope_id, new_grant["device_id"])).fetchone()[0] == 2


def test_immediate_block_durable_retry_then_crypto_rekey(setup):
    app, s, contributor, reader = setup
    old_policy, old_key = s.policy, s.key
    record = p.build_revocation(s.policy, s.pin, s.master, device_id=contributor["grant"]["device_id"])
    for _ in range(2):
        assert s.call("POST", "/revoke", body={"revocation": record}) == (200, {"status": "blocked", "rekey": "pending"})
    assert s.call("GET", "/state", headers=s.member_headers(contributor))[0] == 403
    assert s.call("GET", f"/snapshots/{s.head}", headers=s.member_headers(contributor))[0] == 403
    assert s.call("GET", "/state")[1]["revocations"] == [record]
    assert s.call("POST", "/publish", body=s.transaction())[0] == 409
    s.enroll(reader)
    assert s.call("POST", "/revoke", body={"revocation": record}) == (200, {"status": "blocked", "rekey": "complete"})
    state = s.call("GET", "/state")[1]
    assert state["revocations"] == []
    with pytest.raises(p.AuthenticationError):
        p.open_snapshot(state["snapshot"], state["policy"], s.pin, old_key)
    restarted = SyncServerApp(app.database, ADMIN)
    with running(restarted) as address:
        assert request(address, "GET", s.base + "/state", headers=s.member_headers(contributor))[0] == 403
    with app._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM kk3_blocks WHERE scope_id=?", (s.scope_id,)).fetchone()[0] == 1


def test_old_policy_submission_queue_retry_immutability_and_current_grant(setup):
    app, s, contributor, reader = setup
    old_policy = s.policy
    record = s.submission(contributor)
    request_id = record["payload"]["request_id"]
    s.key = p.generate_key()
    s.publish(policy=s.changed_policy([contributor["grant"], reader["grant"]]))
    for expected in (201, 200):
        assert s.call("POST", "/submissions", body={"submission": record}, headers=s.member_headers(contributor))[0] == expected
    changed = s.submission(contributor, policy=old_policy, request_id=request_id)
    assert s.call("POST", "/submissions", body={"submission": changed}, headers=s.member_headers(contributor))[0] == 409
    items = s.client().pending(s.scope_id)["items"]
    assert items == [{"submission": record, "policy_hash": p.canonical_hash(old_policy)}]
    assert p.open_create(items[0]["submission"], old_policy, s.pin, s.inbox, current_policy=s.policy)["secret"] == CANARY
    assert s.client(contributor).submission(s.scope_id, request_id)["receipt"] is None
    old_grant = contributor["grant"]
    s.enroll(reader)
    contributor["grant"] = {**old_grant, "grant_id": uid(), "generation": 2}
    s.enroll(contributor, reader)
    assert s.call("POST", "/submissions", body={"submission": record}, headers=s.member_headers(contributor))[0] == 403


def test_receipts_accepted_published_durable_monotonic_and_binding(setup):
    app, s, contributor, reader = setup
    policy = s.policy
    record = s.submission(contributor)
    request_id = record["payload"]["request_id"]
    s.client(contributor).submit(s.scope_id, record)
    entry_id = uid()
    accepted = p.build_receipt(record, policy, s.pin, s.master, status="accepted", canonical_entry_id=entry_id, revision=3)
    published = p.build_receipt(record, policy, s.pin, s.master, status="published", canonical_entry_id=entry_id, revision=4)
    assert s.client().acknowledge(s.scope_id, request_id, accepted)["status"] == "recorded"
    assert s.client().pending(s.scope_id)["items"] == []
    assert s.client().acknowledge(s.scope_id, request_id, published)["status"] == "recorded"
    assert s.client().acknowledge(s.scope_id, request_id, accepted)["status"] == "recorded"
    assert s.client(contributor).submission(s.scope_id, request_id)["receipt"] == published
    for wrong in (p.build_receipt(record, policy, s.pin, s.master, status="published", canonical_entry_id=uid(), revision=5),
                  p.build_receipt(record, policy, s.pin, s.master, status="rejected")):
        assert s.call("POST", f"/submissions/{request_id}/receipt", body={"receipt": wrong})[0] == 409
    forged = p._sign("receipt", accepted["payload"], contributor["sign"])
    assert s.call("POST", f"/submissions/{request_id}/receipt", body={"receipt": forged})[0] == 422


def test_revoke_blocks_pending_acceptance_but_not_existing_acceptance_publication(setup):
    app, s, contributor, reader = setup
    old_policy = s.policy
    first, second = s.submission(contributor), s.submission(contributor)
    for record in (first, second):
        s.client(contributor).submit(s.scope_id, record)
    entry_id = uid()
    receipt = p.build_receipt(first, old_policy, s.pin, s.master, status="accepted", canonical_entry_id=entry_id, revision=1)
    s.client().acknowledge(s.scope_id, first["payload"]["request_id"], receipt)
    revocation = p.build_revocation(old_policy, s.pin, s.master, device_id=contributor["grant"]["device_id"])
    s.client().block(s.scope_id, revocation)
    late = p.build_receipt(second, old_policy, s.pin, s.master, status="accepted", canonical_entry_id=uid(), revision=2)
    assert s.call("POST", f"/submissions/{second['payload']['request_id']}/receipt", body={"receipt": late})[0] == 403
    s.enroll(reader)
    published = p.build_receipt(first, old_policy, s.pin, s.master, status="published", canonical_entry_id=entry_id, revision=3)
    assert s.client().acknowledge(s.scope_id, first["payload"]["request_id"], published)["status"] == "recorded"
    quarantine = p.build_receipt(second, old_policy, s.pin, s.master, status="quarantined")
    assert s.client().acknowledge(s.scope_id, second["payload"]["request_id"], quarantine)["status"] == "recorded"


def test_queue_count_byte_rate_quotas_preserve_retry_and_fairness(setup, monkeypatch):
    app, s, contributor, reader = setup
    second = identity()
    s.enroll(contributor, reader, second)
    monkeypatch.setattr(relay, "MAX_DEVICE_PENDING", 1)
    first = s.submission(contributor)
    assert s.call("POST", "/submissions", body={"submission": first}, headers=s.member_headers(contributor))[0] == 201
    assert s.call("POST", "/submissions", body={"submission": first}, headers=s.member_headers(contributor))[0] == 200
    assert s.call("POST", "/submissions", body={"submission": s.submission(contributor)}, headers=s.member_headers(contributor))[0] == 429
    assert s.call("POST", "/submissions", body={"submission": s.submission(second)}, headers=s.member_headers(second))[0] == 201
    monkeypatch.setattr(relay, "MAX_DEVICE_PENDING", 100)
    monkeypatch.setattr(relay, "MAX_SCOPE_PENDING", 2)
    assert s.call("POST", "/submissions", body={"submission": s.submission(second)}, headers=s.member_headers(second))[1]["error"]["code"] == "queue_full"
    monkeypatch.setattr(relay, "MAX_SCOPE_PENDING", 1000)
    monkeypatch.setattr(relay, "MAX_SCOPE_PENDING_BYTES", 1)
    assert s.call("POST", "/submissions", body={"submission": s.submission(second)}, headers=s.member_headers(second))[0] == 429
    monkeypatch.setattr(relay, "MAX_SCOPE_PENDING_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(relay, "MAX_CREATES_PER_MINUTE", 1)
    assert s.call("POST", "/submissions", body={"submission": s.submission(second)}, headers=s.member_headers(second))[1]["error"]["code"] == "rate_limited"
    assert len(s.client().pending(s.scope_id)["items"]) == 2


def test_hostile_request_json_bounded_types_and_no_secret_leaks(setup, capsys):
    app, s, contributor, reader = setup
    bad_policies = [{"policy": {"payload": []}}, {"policy": {"payload": {"master_public_key": []}}}, {"policy": {"payload": CANARY}}]
    for body in bad_policies:
        status, result = request(s.address, "POST", "/v2/scopes", body=body, headers={"Authorization": f"Bearer {ADMIN}"})
        assert status == 422
        assert CANARY not in json.dumps(result)
    valid = s.submission(contributor)
    for bad in ([1], {**valid, "payload": []}, {**valid, "payload": {"policy_hash": {CANARY: 1}}}):
        status, result = s.call("POST", "/submissions", body={"submission": bad}, headers=s.member_headers(contributor))
        assert status == 422
        assert CANARY not in json.dumps(result)
    for bad in (b'{"x":1,"x":2}', ('{"x":' + '[' * 1500 + '0' + ']' * 1500 + '}').encode()):
        status, result = request(s.address, "POST", s.base + "/publish", body=bad, headers={**s.headers, "Content-Type": "application/json"})
        assert status in (400, 422)
    for bad in ({"payload": []}, {"payload": {"device_id": {CANARY: 1}}}):
        assert s.call("POST", f"/submissions/{uid()}/receipt", body={"receipt": bad})[0] == 422
    for suffix in ("/state?x=1", "/state?token=" + CANARY):
        status, response = s.call("GET", suffix)
        assert status == 400 and CANARY not in json.dumps(response)
    assert s.call("PUT", "/publish", body={})[0] == 405
    assert s.call("POST", "/publish", body={"value": 1.0})[0] == 422
    assert s.call("GET", "/unknown")[0] == 404
    assert CANARY not in capsys.readouterr().err


def test_relay_persistence_only_ciphertexts_and_public_metadata(setup):
    app, s, contributor, reader = setup
    s.client(contributor).submit(s.scope_id, s.submission(contributor))
    with app._connect() as connection:
        # Include every persisted row and checkpoint WAL before byte inspection.
        dump = "\n".join(connection.iterdump())
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    for secret in (CANARY, s.token, contributor["token"], reader["token"], ADMIN):
        assert secret not in dump
        assert secret.encode() not in Path(app.database).read_bytes()
    restarted = SyncServerApp(app.database, ADMIN)
    with running(restarted) as address:
        status, state = request(address, "GET", s.base + "/state", headers=s.member_headers(contributor))
        assert status == 200 and state["sequence"] == s.sequence
        status, pending = request(address, "GET", s.base + "/submissions", headers=s.headers)
        assert status == 200 and len(pending["items"]) == 1


def test_project_client_safe_types_and_exact_http_contract(setup, monkeypatch):
    app, s, contributor, reader = setup
    client = s.client(contributor)
    assert client.state(s.scope_id)["sequence"] == s.sequence
    with pytest.raises(VpsAuthenticationError):
        client.pending(s.scope_id)
    with pytest.raises(VpsValidationError):
        client.state("../../" + CANARY)
    with pytest.raises(VpsValidationError):
        client.submit(s.scope_id, {"secret": object()})
    assert contributor["token"] not in repr(client)
    monkeypatch.setattr("keys_keeper.sync_vps_client.VpsSyncClient._request", lambda *a, **k: [1, 2])
    with pytest.raises(VpsProtocolError):
        client.state(s.scope_id)


def test_policy_and_grant_rollback_on_invalid_transaction_wraps(setup):
    app, s, contributor, reader = setup
    newcomer = identity()
    policy = s.changed_policy([contributor["grant"], reader["grant"], newcomer["grant"]])
    tx = s.transaction(policy=policy)
    assert s.call("POST", "/publish", body={**tx, "wraps": tx["wraps"][:-1]})[0] == 422
    assert s.call("GET", "/state")[1]["policy"] == s.policy
    with app._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM kk3_grants WHERE scope_id=? AND grant_id=?", (s.scope_id, newcomer["grant"]["grant_id"])).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM kk3_policies WHERE scope_id=? AND hash=?", (s.scope_id, p.canonical_hash(policy))).fetchone()[0] == 0
    assert s.call("POST", "/publish", body=tx)[0] == 201


def test_request_byte_limit_and_duplicate_auth_headers(setup, monkeypatch):
    app, s, contributor, reader = setup
    monkeypatch.setattr("keys_keeper.sync_server.MAX_REQUEST_BODY", 1024)
    assert s.call("POST", "/publish", body={"value": "x" * 2048})[0] == 413
    connection = http.client.HTTPConnection(*s.address, timeout=5)
    try:
        connection.putrequest("GET", s.base + "/state")
        connection.putheader("Authorization", "Bearer " + s.token)
        connection.putheader("Authorization", "Bearer " + contributor["token"])
        connection.putheader("X-Device-ID", s.master_device)
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 400
        assert json.loads(response.read())["error"]["code"] == "ambiguous_authentication"
    finally:
        connection.close()


def test_signature_forgery_wrong_scope_publication_and_submission(setup):
    app, s, contributor, reader = setup
    tx = s.transaction()
    forged = {**tx, "snapshot": p._sign("snapshot", tx["snapshot"]["payload"], contributor["sign"])}
    assert s.call("POST", "/publish", body=forged)[0] == 422
    modified_body = {**tx["snapshot"]["payload"], "scope_id": uid()}
    forged = {**tx, "snapshot": p._sign("snapshot", modified_body, s.master)}
    assert s.call("POST", "/publish", body=forged)[0] == 403
    submission = s.submission(contributor)
    forged = p._sign("create", {**submission["payload"], "operation": "update"}, contributor["sign"])
    assert s.call("POST", "/submissions", body={"submission": forged}, headers=s.member_headers(contributor))[0] == 403
    forged = p._sign("create", submission["payload"], reader["sign"])
    assert s.call("POST", "/submissions", body={"submission": forged}, headers=s.member_headers(contributor))[0] == 422
    assert s.call("GET", "/state")[1]["head_hash"] == s.head
    assert s.client().pending(s.scope_id)["items"] == []


def test_total_storage_byte_and_record_quotas_are_atomic_with_control_reserve(setup):
    from dataclasses import replace
    app, s, contributor, reader = setup
    other = Scope(s.address)
    other.publish()
    service = app.project_relay
    with app._connect() as connection:
        used, records = service.storage_usage(connection, s.scope_id)
    service.limits = replace(service.limits, scope_bytes=used + 100)
    tx = s.transaction()
    status, error = s.call("POST", "/publish", body=tx)
    assert status == 429 and error["error"]["code"] == "storage_full"
    assert s.call("GET", "/state")[1]["head_hash"] == s.head
    other.publish()
    submission = s.submission(contributor)
    assert s.call("POST", "/submissions", body={"submission": submission}, headers=s.member_headers(contributor))[0] == 429
    assert s.client().pending(s.scope_id)["items"] == []
    # Normal history quota cannot consume reserved immediate-revocation space.
    revoke = p.build_revocation(s.policy, s.pin, s.master, device_id=contributor["grant"]["device_id"])
    assert s.client().block(s.scope_id, revoke)["rekey"] == "pending"
    assert s.call("GET", "/state", headers=s.member_headers(contributor))[0] == 403
    service.limits = replace(service.limits, scope_bytes=512 * 1024 * 1024, scope_records=records)
    assert s.call("POST", "/publish", body=s.transaction())[0] == 409  # blocked grant first
    policy = s.changed_policy([reader["grant"]])
    assert s.call("POST", "/publish", body=s.transaction(policy=policy))[0] == 201  # removal uses reserve
    with app._connect() as connection:
        used_all, _ = service.storage_usage(connection)
    service.limits = replace(service.limits, scope_records=20_000, relay_bytes=used_all + 100)
    assert other.call("POST", "/publish", body=other.transaction())[0] == 429


def test_storage_record_quota_rolls_back_inserted_submission(setup):
    from dataclasses import replace
    app, s, contributor, reader = setup
    with app._connect() as connection:
        _, records = app.project_relay.storage_usage(connection, s.scope_id)
    app.project_relay.limits = replace(app.project_relay.limits, scope_records=records)
    record = s.submission(contributor)
    assert s.call("POST", "/submissions", body={"submission": record}, headers=s.member_headers(contributor))[0] == 429
    with app._connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM kk3_submissions WHERE scope_id=?", (s.scope_id,)).fetchone()[0] == 0
    app.project_relay.limits = replace(app.project_relay.limits, scope_records=records + 1)
    assert s.call("POST", "/submissions", body={"submission": record}, headers=s.member_headers(contributor))[0] == 201
    assert s.call("POST", "/submissions", body={"submission": record}, headers=s.member_headers(contributor))[0] == 200


def test_bounded_slots_and_authentication_precede_reading_body(setup):
    from contextlib import ExitStack
    app, s, contributor, reader = setup
    with ExitStack() as stack:
        for _ in range(app.project_relay.limits.concurrent_requests):
            stack.enter_context(app.project_relay.request_slot())
        status, response = s.call("GET", "/state")
        assert status == 429 and response["error"]["code"] == "relay_busy"
    assert s.call("GET", "/state")[0] == 200
    for headers, expected in (({}, 401), (s.headers, 413)):
        connection = http.client.HTTPConnection(*s.address, timeout=2)
        try:
            connection.putrequest("POST", s.base + "/revoke")
            for key, value in headers.items():
                connection.putheader(key, value)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(1024 * 1024))
            connection.endheaders()  # Deliberately send no body.
            response = connection.getresponse()
            assert response.status == expected
            response.read()
        finally:
            connection.close()


def test_partial_request_times_out_and_releases_slot(tmp_path):
    limits = relay.ProjectRelayLimits(socket_timeout=1, concurrent_requests=1, concurrent_connections=2)
    app = SyncServerApp(tmp_path / "timeout.sqlite3", ADMIN, project_limits=limits)
    with running(app) as address:
        scope = Scope(address)
        connection = http.client.HTTPConnection(*address, timeout=3)
        try:
            connection.putrequest("POST", scope.base + "/publish")
            for key, value in scope.headers.items():
                connection.putheader(key, value)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "10")
            connection.endheaders()
            connection.send(b"{")
            response = connection.getresponse()
            assert response.status == 408
            assert json.loads(response.read())["error"]["code"] == "request_timeout"
        finally:
            connection.close()
        assert scope.call("GET", "/state")[0] == 200


def test_connections_are_bounded_before_header_worker_creation(tmp_path, monkeypatch):
    import socket
    limits = relay.ProjectRelayLimits(concurrent_connections=1, socket_timeout=2)
    app = SyncServerApp(tmp_path / "connections.sqlite3", ADMIN, project_limits=limits)
    server = create_http_server(app)
    entered = threading.Event()
    original = server.RequestHandlerClass.setup
    def setup_handler(handler):
        original(handler)
        entered.set()
    monkeypatch.setattr(server.RequestHandlerClass, "setup", setup_handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    first = socket.create_connection(server.server_address, timeout=3)
    try:
        assert entered.wait(2)
        second = socket.create_connection(server.server_address, timeout=3)
        try:
            second.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
            try:
                assert second.recv(1) == b""
            except ConnectionResetError:
                pass
        finally:
            second.close()
        first.close()
        assert server._connections.acquire(timeout=3)
        server._connections.release()
        assert request(server.server_address, "GET", "/healthz")[0] == 200
    finally:
        first.close()
        server.shutdown()
        server.server_close()
        worker.join(5)
