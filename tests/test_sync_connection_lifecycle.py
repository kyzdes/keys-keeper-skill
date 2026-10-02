"""Actual SQLite connections must close on read, setup, and rollback failure."""
import base64
import sqlite3
from types import SimpleNamespace

import pytest

from keys_keeper import sync_server as module
from keys_keeper.sync_server import SyncServerApp, SyncServerError


@pytest.fixture
def tracked(monkeypatch):
    state = SimpleNamespace(connections=[], fail_sql=None, fail_script=None)
    connect = sqlite3.connect

    class Connection(sqlite3.Connection):
        closes = 0

        def close(self):
            self.closes += 1
            return super().close()

        def execute(self, sql, *args, **kwargs):
            if state.fail_sql and sql.strip().startswith(state.fail_sql):
                raise sqlite3.OperationalError("synthetic SQL failure")
            return super().execute(sql, *args, **kwargs)

        def executescript(self, sql, *args, **kwargs):
            if state.fail_script and state.fail_script in sql:
                raise sqlite3.OperationalError("synthetic schema failure")
            return super().executescript(sql, *args, **kwargs)

    def open_tracked(*args, **kwargs):
        kwargs["factory"] = Connection
        connection = connect(*args, **kwargs)
        state.connections.append(connection)
        return connection

    monkeypatch.setattr(module.sqlite3, "connect", open_tracked)
    return state


def assert_all_closed(tracked):
    assert tracked.connections
    for connection in tracked.connections:
        assert connection.closes == 1
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            sqlite3.Connection.execute(connection, "SELECT 1")


@pytest.fixture
def app(tmp_path, tracked):
    result = SyncServerApp(tmp_path / "synthetic.sqlite3", "synthetic-admin")
    encoded = base64.urlsafe_b64encode(b"s" * 32).decode().rstrip("=")
    token = "synthetic-device-authentication-token"
    created = result.create_vault({"device_token": token, "sign_public_key": encoded,
                                   "wrap_public_key": encoded}, "Bearer synthetic-admin")
    device = result.authenticate_device(created["device_id"], "Bearer " + token,
                                        vault_id=created["vault_id"])
    assert_all_closed(tracked)
    return result, created, device, token


def test_database_project_and_pairing_initialization_close_every_owned_connection(tmp_path, tracked):
    result = SyncServerApp(tmp_path / "synthetic.sqlite3", "synthetic-admin")
    assert len(tracked.connections) == 3
    assert_all_closed(tracked)
    with result._connection() as connection:
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"vaults", "kk3_scopes", "kk3_pairings"} <= tables
    assert_all_closed(tracked)


@pytest.mark.parametrize("action", ["health", "authenticate", "head", "commit", "commits", "devices", "append_lookup"])
def test_every_read_lookup_closes_connection_including_missing_or_invalid_records(app, tracked, action):
    instance, created, device, token = app
    before = len(tracked.connections)
    vault = created["vault_id"]
    if action == "health":
        assert instance.health() == {"status": "ok"}
    elif action == "authenticate":
        assert instance.authenticate_device(device.device_id, "Bearer " + token) == device
    elif action == "head":
        assert instance.get_head(vault, device)["head_commit_id"] is None
    elif action == "commit":
        with pytest.raises(SyncServerError) as failure:
            instance.get_commit(vault, "cmt_syntheticmissingrecord", device)
        assert failure.value.status == 404
    elif action == "commits":
        assert instance.list_commits(vault, device)["commits"] == []
    elif action == "devices":
        assert instance.list_devices(vault, device)["devices"][0]["device_id"] == device.device_id
    else:
        with pytest.raises(SyncServerError) as failure:
            instance.append_commit(vault, {"expected_parent_commit_id": None,
                                           "commit_blob": "eA", "snapshot_ciphertext": "eA"}, device)
        assert failure.value.status == 422
    assert len(tracked.connections) == before + 1
    assert_all_closed(tracked)


def test_failed_read_sql_closes_connection_without_hiding_failure(app, tracked):
    instance, _, _, _ = app
    tracked.fail_sql = "SELECT 1"
    with pytest.raises(sqlite3.OperationalError, match="synthetic SQL failure"):
        instance.health()
    assert_all_closed(tracked)


def test_owned_context_preserves_sqlite_commit_and_rollback_before_close(app, tracked):
    instance, _, _, _ = app
    with instance._connection() as connection:
        connection.execute("BEGIN")
        connection.execute("CREATE TABLE synthetic_changes (marker INTEGER)")
        connection.execute("INSERT INTO synthetic_changes VALUES (1)")
    assert_all_closed(tracked)
    with pytest.raises(RuntimeError, match="synthetic rollback"):
        with instance._connection() as connection:
            connection.execute("BEGIN")
            connection.execute("INSERT INTO synthetic_changes VALUES (2)")
            raise RuntimeError("synthetic rollback")
    assert_all_closed(tracked)
    with instance._connection() as connection:
        assert [row[0] for row in connection.execute("SELECT marker FROM synthetic_changes")] == [1]
    assert_all_closed(tracked)


def test_failed_begin_in_explicit_transaction_closes_connection(app, tracked):
    instance, _, _, _ = app
    tracked.fail_sql = "BEGIN"
    with pytest.raises(sqlite3.OperationalError, match="synthetic SQL failure"):
        with instance._transaction():
            pytest.fail("failed BEGIN entered transaction body")
    assert_all_closed(tracked)


@pytest.mark.parametrize("pragma", ["PRAGMA foreign_keys", "PRAGMA busy_timeout"])
def test_connect_configuration_failure_closes_created_descriptor(tmp_path, tracked, pragma):
    instance = object.__new__(SyncServerApp)
    instance.database = str(tmp_path / "synthetic.sqlite3")
    tracked.fail_sql = pragma
    with pytest.raises(sqlite3.OperationalError, match="synthetic SQL failure"):
        instance._connect()
    assert len(tracked.connections) == 1
    assert_all_closed(tracked)


@pytest.mark.parametrize("phase", ["wal", "v1_schema", "project_schema", "pairing_schema"])
def test_initialization_failure_closes_all_previously_created_connections(tmp_path, tracked, phase):
    if phase == "wal":
        tracked.fail_sql = "PRAGMA journal_mode"
    elif phase == "v1_schema":
        tracked.fail_script = "CREATE TABLE IF NOT EXISTS vaults"
    elif phase == "project_schema":
        tracked.fail_script = "CREATE TABLE IF NOT EXISTS kk3_scopes"
    else:
        tracked.fail_sql = "CREATE TABLE IF NOT EXISTS kk3_pairings"
    with pytest.raises(sqlite3.OperationalError, match="synthetic (SQL|schema) failure"):
        SyncServerApp(tmp_path / "synthetic.sqlite3", "synthetic-admin")
    assert_all_closed(tracked)


def test_raw_connect_return_type_and_caller_ownership_remain_compatible(app, tracked):
    instance, _, _, _ = app
    connection = instance._connect()
    try:
        assert isinstance(connection, sqlite3.Connection)
        assert connection.closes == 0
        assert connection.execute("SELECT 1").fetchone()[0] == 1
    finally:
        connection.close()
    assert_all_closed(tracked)
