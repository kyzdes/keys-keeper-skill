"""Web-vault proxy: auth, session-derived namespacing, read-only vault, hardened
headers, and the never-decrypts invariant. Uses a fake S3 remote (no network)."""
import hashlib
import http.cookiejar
import http.server
import json
import secrets
import subprocess
import sys
import threading
import urllib.error
import urllib.request

import pytest

import keys_keeper.webvault.server as server_mod
from keys_keeper.crypto import encrypt_blob
from keys_keeper.sync_remote import NotFound
from keys_keeper.webvault.server import WebVaultServer

AUTH_ITERS = 600_000  # must match _AUTH_ITERS_DEFAULT and the SPA's AUTH_ITERS
PW = "vault-pass-123"
SNAP = "snapshots/000001-dev.kk"


class FakeRemote:
    def __init__(self, prefix, objs):
        self.prefix = prefix
        self.objs = objs

    def get_object(self, key):
        if key not in self.objs:
            raise NotFound(key)
        return self.objs[key]

    def list_objects(self, prefix):
        return [k for k in self.objs if k.startswith(prefix)]


def _ah(pw, salt_hex, iters):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt_hex), iters, 32).hex()


@pytest.fixture
def vaultsrv(tmp_path, monkeypatch):
    payload = {"schema_version": 2, "entries": [{
        "id": "kk:1", "name": "demo-key", "type": "api_key", "fields": {"env": "prod"},
        "tags": ["x"], "note": "", "refs": [], "created_at": "t", "updated_at": "t",
        "_secret": "sk-SENSITIVE", "_secret_passphrase": None}], "tombstones": []}
    blob = encrypt_blob(json.dumps(payload).encode(), password=PW)
    objs = {
        "HEAD": json.dumps({"version": 1, "snapshot": SNAP}).encode(),
        "versions/000001.json": json.dumps({"version": 1, "snapshot": SNAP}).encode(),
        SNAP: blob,
    }
    captured = {}

    def fake_remote_for(base, prefix):
        captured["prefix"] = prefix
        return FakeRemote(prefix, objs)

    monkeypatch.setattr(server_mod, "remote_for", fake_remote_for)
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wv", port=0, register_token="REGTOK")
    srv._s3_base = object()  # bypass load_s3_base (no real S3)
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server_mod._make_handler(srv))
    srv.bound_port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield srv, blob, captured
    httpd.shutdown()


def _opener():
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def _call(op, port, method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data,
                                 method=method, headers=headers or {})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        r = op.open(req, timeout=10)
        return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def _register_and_login(op, port):
    salt = secrets.token_bytes(16).hex()
    st, _, _ = _call(op, port, "POST", "/auth/register",
                     {"uid": "me", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                      "auth_hash": _ah(PW, salt, AUTH_ITERS)},
                     {"X-Register-Token": "REGTOK"})
    assert st == 201
    st, b, _ = _call(op, port, "POST", "/auth/params", {"uid": "me"})
    p = json.loads(b)
    st, _, _ = _call(op, port, "POST", "/auth/login",
                     {"uid": "me", "auth_hash": _ah(PW, p["auth_salt"], p["auth_iters"])})
    assert st == 200


def test_register_login_read_vault_namespace_from_session(vaultsrv):
    srv, blob, captured = vaultsrv
    port = srv.bound_port
    op = _opener()
    _register_and_login(op, port)
    st, b, _ = _call(op, port, "GET", "/vault/head")
    assert st == 200 and json.loads(b)["snapshot"] == SNAP
    st, b, h = _call(op, port, "GET", "/vault/object?key=" + SNAP)
    assert st == 200 and b == blob                 # proxy forwards ciphertext unchanged
    assert h["Content-Type"] == "application/octet-stream"
    assert captured["prefix"] == "keys-keeper"     # prefix from the account, not the request


def test_vault_requires_auth(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    assert _call(op, srv.bound_port, "GET", "/vault/head")[0] == 401
    assert _call(op, srv.bound_port, "GET", "/vault/object?key=HEAD")[0] == 401


def test_bad_keys_rejected(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    _register_and_login(op, port)
    for bad in ["../../etc/passwd", "snapshots/../x", "config.toml", "versions/x"]:
        st, _, _ = _call(op, port, "GET", "/vault/object?key=" + urllib.parse.quote(bad, safe=""))
        assert st == 400, bad


def test_wrong_passphrase_login_fails(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    salt = secrets.token_bytes(16).hex()
    _call(op, port, "POST", "/auth/register",
          {"uid": "me", "auth_salt": salt, "auth_iters": AUTH_ITERS,
           "auth_hash": _ah(PW, salt, AUTH_ITERS)}, {"X-Register-Token": "REGTOK"})
    st, _, _ = _call(op, port, "POST", "/auth/login",
                     {"uid": "me", "auth_hash": _ah("WRONG", salt, AUTH_ITERS)})
    assert st == 401


def test_register_requires_token(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    salt = secrets.token_bytes(16).hex()
    st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                     {"uid": "x", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                      "auth_hash": _ah(PW, salt, AUTH_ITERS)})  # no token header
    assert st == 403


def test_hardened_headers_and_csp(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    st, body, h = _call(op, srv.bound_port, "GET", "/")
    assert st == 200
    csp = h["Content-Security-Policy"]
    assert "script-src 'self'" in csp and "'unsafe-inline'" not in csp
    assert "require-trusted-types-for 'script'" in csp
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Cache-Control"] == "no-store"
    assert "sha384-" in body.decode()              # SRI injected into the shell


def test_auth_params_does_not_leak_account_existence(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    # unknown uid still returns plausible params (no 404 / no error)
    st, b, _ = _call(op, srv.bound_port, "POST", "/auth/params", {"uid": "ghost"})
    assert st == 200 and len(json.loads(b)["auth_salt"]) == 32


def _spawn(srv):
    """Bind srv on an ephemeral loopback port and start serving; returns httpd."""
    srv._s3_base = object()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), server_mod._make_handler(srv))
    srv.bound_port = httpd.socket.getsockname()[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_single_tenant_public_host_closes_registration(tmp_path, monkeypatch):
    # Security fix: single-tenant + no token + no opt-in => registration closed
    # regardless of bind host (fail-closed behind a reverse proxy too). Else an
    # anon user could pull the operator's encrypted vault.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wv2", host="0.0.0.0", port=0,
                         register_token=None)  # public, no token, single-tenant
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "x", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 403       # fail closed — no anonymous account creation
    finally:
        httpd.shutdown()


def test_single_tenant_loopback_still_closed_without_flag(tmp_path, monkeypatch):
    # The old is_loopback auto-exception is REMOVED: even a loopback bind must
    # fail closed when single-tenant with no token and no --allow-open-registration
    # (a reverse proxy connects from 127.0.0.1, so loopback != local client).
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvlb", host="127.0.0.1", port=0,
                         register_token=None)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "x", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 403
    finally:
        httpd.shutdown()


def test_allow_open_registration_flag_permits_signup(tmp_path, monkeypatch):
    # With the explicit opt-in flag, token-less single-tenant sign-up is allowed.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvopen", host="0.0.0.0", port=0,
                         register_token=None, allow_open_registration=True)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "opener", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 201       # fail-open only with the explicit flag
    finally:
        httpd.shutdown()


def test_register_rejects_weak_auth_iters(vaultsrv):
    # auth_iters floor: anything below the blob's 600k KDF strength is rejected.
    srv, *_ = vaultsrv
    op = _opener()
    salt = secrets.token_bytes(16).hex()
    st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                     {"uid": "weak", "auth_salt": salt, "auth_iters": 1000,
                      "auth_hash": _ah(PW, salt, 1000)},
                     {"X-Register-Token": "REGTOK"})
    assert st == 400


def test_oversized_body_rejected_413(vaultsrv):
    # Hard body cap: a request body over 64 KiB is rejected with 413 before
    # the handler runs (we never buffer it).
    srv, *_ = vaultsrv
    op = _opener()
    big = {"uid": "x", "blob": "A" * (70 * 1024)}
    st, _, _ = _call(op, srv.bound_port, "POST", "/auth/params", big)
    assert st == 413


def test_rate_limit_login_429(tmp_path, monkeypatch):
    # Per-IP login lockout: after the modest limit, further attempts get 429.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvrl", host="127.0.0.1", port=0,
                         allow_open_registration=True)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "rl", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 201
        body = {"uid": "rl", "auth_hash": _ah("nope", salt, AUTH_ITERS)}
        seen_429 = False
        for _ in range(server_mod._RL_LOGIN_MAX + 3):
            st, _, _ = _call(op, srv.bound_port, "POST", "/auth/login", body)
            if st == 429:
                seen_429 = True
                break
        assert seen_429, "login rate-limit never tripped"
    finally:
        httpd.shutdown()


def test_rate_limit_register_429(tmp_path, monkeypatch):
    # Per-IP register lockout blunts unbounded account creation.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvrr", host="127.0.0.1", port=0,
                         allow_open_registration=True)
    httpd = _spawn(srv)
    try:
        op = _opener()
        seen_429 = False
        for i in range(server_mod._RL_REGISTER_MAX + 3):
            salt = secrets.token_bytes(16).hex()
            st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                             {"uid": f"u{i}", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                              "auth_hash": _ah(PW, salt, AUTH_ITERS)})
            if st == 429:
                seen_429 = True
                break
        assert seen_429, "register rate-limit never tripped"
    finally:
        httpd.shutdown()


def test_secure_cookie_when_trusted_forwarded_proto_https(tmp_path, monkeypatch):
    # Behind a trusted proxy, X-Forwarded-Proto=https makes the session cookie
    # Secure (and applies the __Host- prefix) even though we run plain http.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvsec", host="127.0.0.1", port=0,
                         allow_open_registration=True, trust_forwarded=True)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        _call(op, srv.bound_port, "POST", "/auth/register",
              {"uid": "sec", "auth_salt": salt, "auth_iters": AUTH_ITERS,
               "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        st, _, h = _call(op, srv.bound_port, "POST", "/auth/login",
                         {"uid": "sec", "auth_hash": _ah(PW, salt, AUTH_ITERS)},
                         {"X-Forwarded-Proto": "https"})
        assert st == 200
        sc = h["Set-Cookie"]
        assert "Secure" in sc
        assert sc.startswith("__Host-")


    finally:
        httpd.shutdown()


def test_forwarded_proto_ignored_without_trust_flag(tmp_path, monkeypatch):
    # Without --behind-proxy a client can't spoof X-Forwarded-Proto to fake Secure.
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvnospoof", host="127.0.0.1", port=0,
                         allow_open_registration=True, trust_forwarded=False)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        _call(op, srv.bound_port, "POST", "/auth/register",
              {"uid": "ns", "auth_salt": salt, "auth_iters": AUTH_ITERS,
               "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        st, _, h = _call(op, srv.bound_port, "POST", "/auth/login",
                         {"uid": "ns", "auth_hash": _ah(PW, salt, AUTH_ITERS)},
                         {"X-Forwarded-Proto": "https"})
        assert st == 200
        assert "Secure" not in h["Set-Cookie"]   # spoofed header ignored
    finally:
        httpd.shutdown()


def test_server_module_never_imports_crypto():
    # The proxy must never be able to decrypt. Importing it must not pull in crypto.
    code = ("import keys_keeper.webvault.server, sys; "
            "print('keys_keeper.crypto' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert out.stdout.strip() == "False", out.stdout + out.stderr


import urllib.parse  # noqa: E402  (used in test_bad_keys_rejected)
