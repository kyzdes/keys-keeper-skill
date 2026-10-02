"""Synthetic relay limits, transactional accounting and bounded history reads."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import http.client
import os
import socket
import sqlite3
import threading
import time
from unittest.mock import Mock
from uuid import uuid4

import pytest

from keys_keeper import sync_server as module
from keys_keeper.project_server import ProjectRelayLimits
from keys_keeper.sync_protocol_v2 import generate_device_identity, generate_vault_key
from keys_keeper.sync_server import SyncServerApp, SyncServerError, create_http_server
from test_sync_server import (
    ADMIN_TOKEN, _auth, _b64, _commit_payload, _create_vault, _identity_payload,
    _request, _running,
)


@pytest.fixture
def app(tmp_path):
    return SyncServerApp(tmp_path / "relay.sqlite3", ADMIN_TOKEN)


def v1(app):
    identity = generate_device_identity()
    token = "synthetic-device-token-for-relay-resources"
    created = app.create_vault(_identity_payload(identity, token), f"Bearer {ADMIN_TOKEN}")
    device = app.authenticate_device(created["device_id"], f"Bearer {token}")
    return created, device, identity, token


def insert_operation(connection, scope, response="synthetic-public-response"):
    operation = str(uuid4())
    connection.execute("INSERT INTO kk3_operations VALUES(?,?,?,?)",
                       (scope, operation, "a" * 64, response))
    return operation, 256 + len(operation) + 64 + len(response.encode())


def test_history_projection_never_reads_snapshot_or_unrequested_manifest(app, monkeypatch):
    created, device, _, _ = v1(app)
    snapshot = b"synthetic-ciphertext" * 100_000
    with app._transaction(immediate=True) as connection:
        for sequence in range(1, 4):
            connection.execute("INSERT INTO commits VALUES(?,?,?,?,?,?,?,?,?)", (
                created["vault_id"], f"synthetic-commit-{sequence}", sequence, None,
                "a" * 64, b"synthetic-signed-manifest", snapshot, device.device_id, 1,
            ))
    forbidden = {"snapshot_ciphertext", "commit_blob"}
    connect = app._connect

    def restricted_connection():
        connection = connect()
        def authorize(action, table, column, *_):
            if action == sqlite3.SQLITE_READ and table == "commits" and column in forbidden:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        connection.set_authorizer(authorize)
        return connection

    monkeypatch.setattr(app, "_connect", restricted_connection)
    page = app.list_commits(created["vault_id"], device, limit=100)
    assert len(page["commits"]) == 3
    assert all("commit_blob" not in row and "snapshot_ciphertext" not in row for row in page["commits"])
    forbidden.remove("commit_blob")
    signed = app.list_commits(created["vault_id"], device, include_commit=True)
    assert all(row["commit_blob"] == _b64(b"synthetic-signed-manifest") for row in signed["commits"])
    manifest = app.get_commit(created["vault_id"], "synthetic-commit-1", device, include_snapshot=False)
    assert "snapshot_ciphertext" not in manifest
    # The guard actually forbids the full read; a response-only omission would fail.
    with pytest.raises(sqlite3.DatabaseError):
        app.get_commit(created["vault_id"], "synthetic-commit-1", device)


def test_history_http_options_keep_defaults_and_reject_ambiguous_query(app):
    with _running(app) as address:
        created, identity, token = _create_vault(address)
        payload, blob, ciphertext = _commit_payload(
            vault_id=created["vault_id"], device_id=created["device_id"],
            identity=identity, vault_key=generate_vault_key(), plaintext=b"synthetic-vault",
        )
        base = f'/v1/vaults/{created["vault_id"]}/commits'
        headers = _auth(created["device_id"], token)
        status, result = _request(address, "POST", base, body=payload, headers=headers)
        assert status == 201
        path = base + "/" + result["commit_id"]
        full = _request(address, "GET", path, headers=headers)[1]
        small = _request(address, "GET", path + "?snapshot=0", headers=headers)[1]
        assert full == {**small, "snapshot_ciphertext": _b64(ciphertext)}
        assert small["commit_blob"] == _b64(blob)
        default = _request(address, "GET", base, headers=headers)[1]["commits"][0]
        signed = _request(address, "GET", base + "?include_commit=1", headers=headers)[1]["commits"][0]
        assert signed == {**default, "commit_blob": _b64(blob)}
        for invalid in ("?snapshot=2", "?snapshot=0&snapshot=1", "?snapshot=0&unknown=1"):
            assert _request(address, "GET", path + invalid, headers=headers)[0] == 400
        for invalid in ("?include_commit=true", "?include_commit=", "?include_commit=1&include_commit=1",
                        "?limit=101", "?after_sequence=-1", "?after_sequence=9223372036854775808"):
            assert _request(address, "GET", base + invalid, headers=headers)[0] == 400


def test_counters_update_move_rollback_delete_and_reopen(app):
    scope, other = str(uuid4()), str(uuid4())
    with app._transaction(immediate=True) as connection:
        operation, size = insert_operation(connection, scope, "public-emoji-\U0001f512")
        assert app.project_relay.storage_usage(connection, scope) == (size, 1)
        connection.execute("UPDATE kk3_operations SET scope_id=?,response=? WHERE operation_id=?",
                           (other, "x", operation))
        changed = size - len("public-emoji-\U0001f512".encode()) + 1
        assert app.project_relay.storage_usage(connection, scope) == (0, 0)
        assert app.project_relay.storage_usage(connection, other) == (changed, 1)
        assert app.project_relay.storage_usage(connection) == (changed, 1)
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with app._transaction(immediate=True) as connection:
            insert_operation(connection, scope)
            raise RuntimeError("synthetic rollback")
    with app._transaction(immediate=True) as connection:
        assert app.project_relay.storage_usage(connection) == (changed, 1)
        connection.execute("DELETE FROM kk3_operations WHERE operation_id=?", (operation,))
        assert app.project_relay.storage_usage(connection) == (0, 0)
    restarted = SyncServerApp(app.database, ADMIN_TOKEN)
    with restarted._connection() as connection:
        assert restarted.project_relay.storage_usage(connection) == (0, 0)


def test_v1_cascade_deletion_keeps_counters_exact(app):
    created, _, _, _ = v1(app)
    with app._transaction(immediate=True) as connection:
        assert app.storage.usage(connection)[1] == 2
        connection.execute("DELETE FROM vaults WHERE vault_id=?", (created["vault_id"],))
        assert connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0
        assert app.storage.usage(connection) == (0, 0)
        assert app.storage.usage(connection, created["vault_id"]) == (0, 0)


def test_concurrent_writers_do_not_lose_accounting_updates(app):
    scope = str(uuid4())
    def write(_):
        with app._transaction(immediate=True) as connection:
            return sum(insert_operation(connection, scope)[1] for _ in range(25))
    with ThreadPoolExecutor(max_workers=4) as pool:
        sizes = list(pool.map(write, range(4)))
    with app._connection() as connection:
        assert app.project_relay.storage_usage(connection, scope) == (sum(sizes), 100)
        assert app.project_relay.storage_usage(connection) == (sum(sizes), 100)


def test_legacy_backfill_rolls_back_on_failure_and_is_not_repeated(app, monkeypatch):
    scope = str(uuid4())
    with app._transaction(immediate=True) as connection:
        # Recreate the exact pre-accounting schema with preserved synthetic data.
        for row in connection.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'relay_usage_%'").fetchall():
            connection.execute(f'DROP TRIGGER "{row[0]}"')
        connection.execute("DROP TABLE relay_usage")
        _, size = insert_operation(connection, scope)
    connect = SyncServerApp._connect

    def fail_migration(self):
        connection = connect(self)
        def authorize(action, name, *_):
            return (sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_CREATE_TRIGGER
                    and name == "relay_usage_kk3_snapshots_insert" else sqlite3.SQLITE_OK)
        connection.set_authorizer(authorize)
        return connection

    monkeypatch.setattr(SyncServerApp, "_connect", fail_migration)
    with pytest.raises(sqlite3.DatabaseError):
        SyncServerApp(app.database, ADMIN_TOKEN)
    with sqlite3.connect(app.database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM relay_usage WHERE namespace='kk3'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'relay_usage_kk3_operations_%'").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM kk3_operations").fetchone()[0] == 1
    monkeypatch.setattr(SyncServerApp, "_connect", connect)
    recovered = SyncServerApp(app.database, ADMIN_TOKEN)
    with recovered._connection() as connection:
        assert recovered.project_relay.storage_usage(connection) == (size, 1)
    queries = []
    def trace_connect(self):
        connection = connect(self)
        connection.set_trace_callback(queries.append)
        return connection
    monkeypatch.setattr(SyncServerApp, "_connect", trace_connect)
    SyncServerApp(app.database, ADMIN_TOKEN)
    assert not any("SUM(" in query.upper() for query in queries)


def test_quota_checks_are_two_small_queries_independent_of_history_size(app):
    scope = str(uuid4())
    with app._transaction(immediate=True) as connection:
        for _ in range(500):
            insert_operation(connection, scope)
        queries = []
        connection.set_trace_callback(queries.append)
        # No stored-record table may be read just to enforce a quota.
        connection.set_authorizer(lambda action, table, *_:
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ and table.startswith("kk3_") else sqlite3.SQLITE_OK)
        app.project_relay._storage_budget(connection, scope)
        assert len(queries) == 2
        assert all("FROM relay_usage" in query for query in queries)
        connection.set_authorizer(None)


def test_v1_ingestion_quota_rolls_back_but_reads_and_revoke_keep_working(app):
    created, device, identity, token = v1(app)
    scope = created["vault_id"]
    with app._transaction(immediate=True) as connection:
        connection.execute("INSERT INTO devices(device_id,vault_id,sign_public_key,wrap_public_key,token_hash,status,approved_by_device_id,created_at) VALUES(?,?,?,?,?,'active',?,1)",
                           ("synthetic-child-device", scope, "public", "public", b"x" * 32, device.device_id))
        used, records = app.storage.usage(connection, scope)
    app.project_relay.limits = replace(app.project_relay.limits, scope_bytes=used,
                                       scope_records=records, relay_records=records)
    payload, _, _ = _commit_payload(vault_id=scope, device_id=device.device_id,
                                   identity=identity, vault_key=generate_vault_key(), plaintext=b"synthetic")
    for write in (
        lambda: app.append_commit(scope, payload, device),
        lambda: app.create_invite(scope, {"secret_hash": "a" * 64}, device),
        lambda: app.create_vault(_identity_payload(identity, token), f"Bearer {ADMIN_TOKEN}"),
    ):
        with pytest.raises(SyncServerError) as caught:
            write()
        assert caught.value.code == "storage_full"
    assert app.get_head(scope, device)["head_commit_id"] is None
    assert app.list_commits(scope, device)["commits"] == []
    assert len(app.list_devices(scope, device)["devices"]) == 2
    with app._connection() as connection:
        assert app.storage.usage(connection, scope) == (used, records)
        assert connection.execute("SELECT COUNT(*) FROM vaults").fetchone()[0] == 1
    assert app.revoke_device(scope, "synthetic-child-device", {
        "expected_head_commit_id": None, "revocation_statement": "synthetic-public-revocation",
        "revocation_signature": "synthetic-signature",
    }, device)["status"] == "revoked"
    reopened = SyncServerApp(app.database, ADMIN_TOKEN,
                            project_limits=ProjectRelayLimits(scope_records=1, relay_records=1))
    assert reopened.health() == {"status": "ok"}
    assert reopened.get_head(scope, device)["head_commit_id"] is None


def test_busy_writer_returns_retryable_503_and_preserves_vault_state(app):
    app._busy_timeout = 100
    with sqlite3.connect(app.database) as blocker, _running(app) as address:
        blocker.execute("BEGIN IMMEDIATE")
        started = time.monotonic()
        status, body = _request(address, "POST", "/v1/vaults",
                                body=_identity_payload(generate_device_identity(), "x" * 32),
                                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
        assert status == 503 and body["error"]["code"] == "storage_busy"
        assert time.monotonic() - started < 2
        assert _request(address, "GET", "/healthz")[0] == 200
        blocker.rollback()
        with app._connection() as connection:
            assert app.storage.usage(connection) == (0, 0)
        _create_vault(address)


@pytest.mark.parametrize("part", ["headers", "body"])
def test_close_cancels_incomplete_requests_before_application_work(app, monkeypatch, part):
    app_work = Mock(side_effect=AssertionError("incomplete request reached application"))
    monkeypatch.setattr(app, "create_vault", app_work)
    server = create_http_server(app)
    done = threading.Event()
    process = server.process_request_thread
    def track(*args):
        try:
            process(*args)
        finally:
            done.set()
    monkeypatch.setattr(server, "process_request_thread", track)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as peer:
            prefix = b"POST /v1/vaults HTTP/1.1\r\nHost: synthetic\r\n"
            if part == "body":
                prefix += (f"Authorization: Bearer {ADMIN_TOKEN}\r\n".encode()
                           + b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
            peer.sendall(prefix)
            started = time.monotonic()
            while not server._connections and time.monotonic() - started < 2:
                time.sleep(.005)
            assert server._connections
            server.shutdown()
            server.server_close()
            assert done.wait(1)
            assert not server._connections
            app_work.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_v1_admission_rejects_before_body_and_returns_capacity(app):
    with _running(app) as address, ExitStack() as stack:
        for _ in range(app.project_relay.limits.concurrent_requests):
            stack.enter_context(app.project_relay.request_slot())
        connection = http.client.HTTPConnection(*address, timeout=1)
        try:
            connection.putrequest("POST", "/v1/vaults")
            connection.putheader("Authorization", f"Bearer {ADMIN_TOKEN}")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "100")
            connection.endheaders()
            response = connection.getresponse()
            assert response.status == 429
            assert b"relay_busy" in response.read()
        finally:
            connection.close()
        stack.close()
        assert _request(address, "GET", "/healthz")[0] == 200


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits; native ACL tests cover Windows")
@pytest.mark.parametrize("part", ["database", "directory", "sidecar"])
def test_startup_rejects_nonprivate_objects_without_chmod_or_payload_change(app, part):
    from pathlib import Path
    database = Path(app.database)
    if part == "database":
        target, mode = database, 0o644
    elif part == "directory":
        target, mode = database.parent, 0o755
    else:
        target, mode = database.with_name(database.name + "-journal"), 0o644
        target.write_bytes(b"synthetic-untrusted-sidecar")
    before = hashlib.sha256(database.read_bytes()).digest()
    target.chmod(mode)
    with pytest.raises(ValueError, match="private"):
        SyncServerApp(database, ADMIN_TOKEN)
    assert target.stat().st_mode & 0o777 == mode
    assert hashlib.sha256(database.read_bytes()).digest() == before


@pytest.mark.parametrize("part", ["database", "directory", "sidecar"])
def test_startup_rejects_symlink_database_paths_without_following(app, part, tmp_path):
    from pathlib import Path
    database = Path(app.database)
    before = hashlib.sha256(database.read_bytes()).digest()
    if part == "database":
        candidate = tmp_path / "alias.sqlite3"
        candidate.symlink_to(database)
    elif part == "directory":
        parent = tmp_path / "alias-directory"
        parent.symlink_to(database.parent, target_is_directory=True)
        candidate = parent / database.name
    else:
        candidate = database
        database.with_name(database.name + "-journal").symlink_to(database)
    with pytest.raises(ValueError, match="regular files"):
        SyncServerApp(candidate, ADMIN_TOKEN)
    assert hashlib.sha256(database.read_bytes()).digest() == before


def test_oversized_binary_fields_stop_before_base64_decoding(monkeypatch):
    decode = Mock(side_effect=AssertionError("oversized base64 allocated decoded bytes"))
    monkeypatch.setattr(module.base64, "b64decode", decode)
    with pytest.raises(SyncServerError) as caught:
        module._decode_base64("A" * 101, "synthetic", max_bytes=32)
    assert caught.value.code == "invalid_request"
    decode.assert_not_called()


def test_invalid_unicode_returns_fixed_request_error_before_vault_write(app):
    identity = generate_device_identity()
    with pytest.raises(SyncServerError) as caught:
        app.create_vault(_identity_payload(identity, "synthetic-canary-\ud800"), f"Bearer {ADMIN_TOKEN}")
    assert caught.value.status == 400
    assert "synthetic-canary" not in str(caught.value)
    with app._connection() as connection:
        assert app.storage.usage(connection) == (0, 0)


def test_pairing_preflight_does_not_read_packets_and_get_keeps_wal_readers_concurrent(tmp_path, monkeypatch):
    from test_project_server import ADMIN, Scope
    app = SyncServerApp(tmp_path / "pairing.sqlite3", ADMIN)
    with _running(app) as address:
        scope = Scope(address)
        pair = str(uuid4())
        token = "synthetic-pairing-token"
        path = f"{scope.base}/pairings/{pair}"
        with app._transaction(immediate=True) as connection:
            connection.execute("INSERT INTO kk3_pairings VALUES(?,?,?,?,?,?,?)", (
                pair, scope.scope_id, hashlib.sha256(token.encode()).hexdigest(),
                app._clock() + 300, "a" * 100_000, "b" * 100_000, "c" * 1_000_000,
            ))
        connect = app._connect
        def restricted():
            connection = connect()
            connection.set_authorizer(lambda action, table, column, *_:
                sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_READ
                and table == "kk3_pairings" and column in {"invitation", "request", "response"}
                else sqlite3.SQLITE_OK)
            return connection
        monkeypatch.setattr(app, "_connect", restricted)
        app.project_relay.preflight("GET", path, {"Authorization": f"Bearer {token}"})
        app.project_relay.preflight("POST", path + "/response", scope.headers)
        monkeypatch.setattr(app, "_connect", connect)
        with sqlite3.connect(app.database) as writer:
            writer.execute("BEGIN IMMEDIATE")
            status, data = _request(address, "GET", path, headers={"Authorization": f"Bearer {token}"})
            assert status == 200
            assert len(data["response"]) == 1_000_000
            writer.rollback()


def test_pairing_counters_preserve_idempotency_conflicts_and_expired_cleanup(tmp_path):
    from test_project_server import ADMIN, Scope
    from test_sync_server import Clock
    clock = Clock()
    app = SyncServerApp(tmp_path / "pairing.sqlite3", ADMIN, clock=clock)
    with _running(app) as address:
        scope = Scope(address)
        base, pair, token = scope.base + "/pairings", str(uuid4()), "synthetic-pairing-token"
        invitation = {"pair_id": pair, "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                      "expires_at": clock() + 10, "invitation": "a" * 38}
        assert _request(address, "POST", base, body=invitation, headers=scope.headers)[0] == 201
        assert _request(address, "POST", base, body=invitation, headers=scope.headers)[0] == 200
        for slot, headers in (("request", {"Authorization": f"Bearer {token}"}), ("response", scope.headers)):
            path = base + "/" + pair + "/" + slot
            assert _request(address, "POST", path, body={"packet": "b" * 38}, headers=headers)[0] == 201
            assert _request(address, "POST", path, body={"packet": "b" * 38}, headers=headers)[0] == 200
            assert _request(address, "POST", path, body={"packet": "c" * 38}, headers=headers)[0] == 409
        with app._connection() as connection:
            assert app.project_relay.pairings.storage.usage(connection) == (256 + 3 * 38, 1)
        clock.value += 20
        assert _request(address, "GET", base + "/" + pair, headers=scope.headers)[0] == 410
        next_pair = {**invitation, "pair_id": str(uuid4()), "expires_at": clock() + 10}
        assert _request(address, "POST", base, body=next_pair, headers=scope.headers)[0] == 201
        with app._connection() as connection:
            assert app.project_relay.pairings.storage.usage(connection) == (256 + 38, 1)
