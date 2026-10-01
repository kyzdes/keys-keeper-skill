"""Adversarial WebVault isolation and memory bounds; all roots are synthetic."""
import http.client
import json
import threading
from contextlib import closing

import pytest

from keys_keeper.webvault import server, store


def _register(registry, uid="tenant"):
    return registry.register(uid=uid, prefix=f"tenants/{uid}", auth_salt="ab" * 16,
                             auth_iters=600_000, auth_hash="cd" * 32)


@pytest.fixture
def harmless_scrypt(monkeypatch):
    calls = []
    monkeypatch.setattr(store, "_scrypt", lambda *args: calls.append(args) or b"s" * 32)
    return calls


@pytest.fixture
def vault(tmp_path, monkeypatch, harmless_scrypt):
    app = server.WebVaultServer(data_dir=tmp_path / "web", port=0, multi_tenant=True)
    _register(app.accounts)
    token = app.sessions.create("tenant")
    remote_calls = []
    monkeypatch.setattr(server, "remote_for", lambda *args: remote_calls.append(args))
    monkeypatch.setattr(app, "s3_base", lambda: pytest.fail("unexpected S3 credential access"))
    httpd = app.create_http_server()
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield app, token, httpd.server_port, remote_calls
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)


def _get(port, token, path):
    with closing(http.client.HTTPConnection("127.0.0.1", port, timeout=2)) as conn:
        conn.request("GET", path, headers={"Cookie": f"kkv_session={token}"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())


@pytest.mark.parametrize("path", ["/vault/head", "/vault/object?key=HEAD", "/auth/whoami"])
def test_removed_session_account_never_falls_back_to_operator(vault, path):
    app, token, port, calls = vault
    app.accounts._write({"accounts": {}})
    status, body = _get(port, token, path)
    assert status == (200 if path == "/auth/whoami" else 401)
    assert body == ({"uid": None} if path == "/auth/whoami" else {"error": "not authenticated"})
    assert not calls
    assert app.sessions.resolve(token) is None
    with pytest.raises(store.AccountStoreError):
        app.prefix_for("tenant")


@pytest.mark.parametrize("damage", ["corrupt", "missing", "duplicate", "wrong_schema"])
def test_damaged_registry_never_authorizes_or_overwrites(vault, harmless_scrypt, damage):
    app, token, port, calls = vault
    path = app.accounts.path
    if damage == "missing":
        path.unlink()
        original = None
    else:
        original = {"corrupt": b"{secret-placeholder", "duplicate": b'{"accounts":{},"accounts":{}}',
                    "wrong_schema": b'{"accounts":[]}' }[damage]
        path.write_bytes(original)
    status, body = _get(port, token, "/vault/head")
    assert status == 503
    assert body == {"error": "account registry unavailable"}
    with pytest.raises(store.AccountStoreError):
        _register(app.accounts, "replacement")
    assert not calls
    assert len(harmless_scrypt) == 1  # initial valid account only
    assert path.read_bytes() == original if original is not None else not path.exists()


def test_account_symlink_and_oversized_registry_are_rejected_before_read(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    path = tmp_path / "accounts.json"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(store.AccountStoreError):
        store.AccountStore(path)._read()
    assert target.read_bytes() == b"{}"
    path.unlink()
    path.write_bytes(b"x" * 129)
    path.chmod(0o600)
    monkeypatch.setattr(store, "_MAX_ACCOUNTS_BYTES", 128)
    monkeypatch.setattr(store.os, "read", lambda *args: pytest.fail("oversized file was read"))
    with pytest.raises(store.AccountStoreError):
        store.AccountStore(path)._read()


def test_account_capacity_and_malformed_auth_stop_before_scrypt(tmp_path, monkeypatch, harmless_scrypt):
    registry = store.AccountStore(tmp_path / "accounts.json")
    monkeypatch.setattr(store, "_MAX_ACCOUNTS", 1)
    _register(registry)
    original = registry.path.read_bytes()
    with pytest.raises(store.AccountError, match="capacity"):
        _register(registry, "second")
    for field, value in (("uid", "x" * 129), ("auth_salt", "bad"), ("auth_hash", "bad"),
                         ("auth_iters", True), ("auth_iters", 599_999), ("prefix", "tenants/../operator")):
        params = dict(uid="second", prefix="tenants/second", auth_salt="ab" * 16,
                      auth_iters=600_000, auth_hash="cd" * 32)
        params[field] = value
        with pytest.raises(store.AccountError):
            registry.register(**params)
    assert len(harmless_scrypt) == 1
    assert registry.path.read_bytes() == original


def test_live_rate_key_cap_does_not_reset_existing_throttle(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(server.time, "monotonic", lambda: clock[0])
    limiter = server._RateLimiter(2, 60, max_keys=4)
    assert limiter.allow("blocked") and limiter.allow("blocked")
    for key in ("b", "c", "d"):
        assert limiter.allow(key)
    for i in range(1000):
        assert not limiter.allow(f"new-{i}")
    assert len(limiter._hits) == 4
    assert not limiter.allow("blocked")
    clock[0] = 61.0
    assert limiter.allow("new")
    assert list(limiter._hits) == ["new"]


def test_session_cap_reclaims_abandoned_expiry_and_preserves_refresh(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(store.time, "monotonic", lambda: clock[0])
    sessions = store.SessionStore(idle_sec=10, max_sessions=2)
    refreshed = sessions.create("a")
    abandoned = sessions.create("b")
    clock[0] = 5.0
    assert sessions.resolve(refreshed) == "a"
    with pytest.raises(store.SessionCapacityError):
        sessions.create("c")
    clock[0] = 11.0
    new = sessions.create("c")
    assert sessions.resolve(abandoned) is None
    assert sessions.resolve(refreshed) == "a"
    assert sessions.resolve(new) == "c"
    assert len(sessions._sessions) == 2


def test_authenticated_newline_key_is_rejected_before_remote(vault):
    app, token, port, calls = vault
    status, _ = _get(port, token, "/vault/object?key=HEAD%0A")
    assert status == 400
    assert not calls
