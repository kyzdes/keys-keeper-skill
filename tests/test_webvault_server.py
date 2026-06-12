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


# ===========================================================================
# Negative / edge + hardening sweep (appended; existing tests above unchanged).
# ===========================================================================
import socket  # noqa: E402

from keys_keeper.sync_remote import AuthError, TransportError  # noqa: E402
from keys_keeper.webvault.store import SessionStore  # noqa: E402


def _vault_objs():
    """A minimal, valid single-tenant object set (HEAD + version + snapshot)."""
    payload = {"schema_version": 2, "entries": [], "tombstones": []}
    blob = encrypt_blob(json.dumps(payload).encode(), password=PW)
    return {
        "HEAD": json.dumps({"version": 1, "snapshot": SNAP}).encode(),
        "versions/000001.json": json.dumps({"version": 1, "snapshot": SNAP}).encode(),
        SNAP: blob,
    }, blob


def _spawn_srv(tmp_path, monkeypatch, *, name, remote_for=None, prefix="keys-keeper",
               capture=None, **kwargs):
    """Build + serve a WebVaultServer with a fake remote; returns (srv, httpd).

    Mirrors the `vaultsrv` fixture wiring (monkeypatch remote_for /
    default_base_prefix, bypass S3, serve on an ephemeral loopback port)."""
    if remote_for is None:
        objs, _blob = _vault_objs()
        cap = capture if capture is not None else {}

        def remote_for(base, prefix):  # noqa: A001 (shadow ok inside factory)
            cap["prefix"] = prefix
            return FakeRemote(prefix, objs)

    monkeypatch.setattr(server_mod, "remote_for", remote_for)
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: prefix)
    kwargs.setdefault("register_token", "REGTOK")  # so _register_and_login works
    srv = WebVaultServer(data_dir=tmp_path / name, port=0, **kwargs)
    httpd = _spawn(srv)
    return srv, httpd


# --- 1. H1: per-source bucketing when the forwarded header is trusted --------
def test_h1_rate_limit_buckets_per_xff_when_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvh1", host="127.0.0.1", port=0,
                         allow_open_registration=True, trust_forwarded=True)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "h1", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 201
        bad = {"uid": "h1", "auth_hash": _ah("nope", salt, AUTH_ITERS)}
        seen_429 = False
        for _ in range(server_mod._RL_LOGIN_MAX + 3):
            st, _, _ = _call(op, srv.bound_port, "POST", "/auth/login", bad,
                             {"X-Forwarded-For": "9.9.9.9"})
            if st == 429:
                seen_429 = True
                break
        assert seen_429, "9.9.9.9 bucket never tripped"
        # A DIFFERENT forwarded source is an independent bucket → not yet limited.
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/login", bad,
                         {"X-Forwarded-For": "8.8.8.8"})
        assert st != 429, "8.8.8.8 must have its own bucket (per-XFF keying)"
    finally:
        httpd.shutdown()


# --- 2. H1: spoofed XFF cannot evade the limiter without the trust flag -------
def test_h1_xff_ignored_without_trust_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvh1b", host="127.0.0.1", port=0,
                         allow_open_registration=True, trust_forwarded=False)
    httpd = _spawn(srv)
    try:
        op = _opener()
        salt = secrets.token_bytes(16).hex()
        st, _, _ = _call(op, srv.bound_port, "POST", "/auth/register",
                         {"uid": "h1b", "auth_salt": salt, "auth_iters": AUTH_ITERS,
                          "auth_hash": _ah(PW, salt, AUTH_ITERS)})
        assert st == 201
        bad = {"uid": "h1b", "auth_hash": _ah("nope", salt, AUTH_ITERS)}
        seen_429 = False
        # Rotate a fresh spoofed XFF each attempt; all share the socket-peer bucket.
        for i in range(server_mod._RL_LOGIN_MAX + 3):
            st, _, _ = _call(op, srv.bound_port, "POST", "/auth/login", bad,
                             {"X-Forwarded-For": f"10.0.0.{i}"})
            if st == 429:
                seen_429 = True
                break
        assert seen_429, "spoofed XFF must not evade the limiter (one peer bucket)"
    finally:
        httpd.shutdown()


# --- 3. H2: Server header is "kkvault" with no "Python/" token ----------------
def test_h2_server_header_no_python(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    st, _, h = _call(op, srv.bound_port, "GET", "/")
    assert st == 200
    assert h["Server"] == "kkvault"
    assert "Python" not in h["Server"]


# --- 4. Logout destroys the session ------------------------------------------
def test_logout_destroys_session(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    _register_and_login(op, port)
    assert _call(op, port, "GET", "/vault/head")[0] == 200
    st, _, _ = _call(op, port, "POST", "/auth/logout", {})
    assert st == 200
    assert _call(op, port, "GET", "/vault/head")[0] == 401


# --- 5. SessionStore idle expiry (unit, no HTTP) -----------------------------
def test_sessionstore_idle_expiry_unit():
    s = SessionStore(idle_sec=-1)
    tok = s.create("u")
    assert s.resolve(tok) is None        # already expired (idle_sec < 0)
    assert s.resolve(None) is None
    assert s.resolve("garbage") is None


# --- 6. Tampered/garbage session cookie → 401 --------------------------------
def test_garbage_session_cookie_unauthenticated(vaultsrv):
    srv, *_ = vaultsrv
    op = _opener()
    st, _, _ = _call(op, srv.bound_port, "GET", "/vault/head", None,
                     {"Cookie": "kkv_session=deadbeefdeadbeef"})
    assert st == 401


# --- 7. /auth/whoami null vs uid ---------------------------------------------
def test_whoami_null_then_uid(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    st, b, _ = _call(op, port, "GET", "/auth/whoami")
    assert st == 200 and json.loads(b)["uid"] is None
    _register_and_login(op, port)
    st, b, _ = _call(op, port, "GET", "/auth/whoami")
    assert st == 200 and json.loads(b)["uid"] == "me"


# --- 8. Multi-tenant: prefix comes from the session, isolated per tenant ------
def test_multi_tenant_prefix_from_session_isolation(tmp_path, monkeypatch):
    seen_prefixes = []

    class _PrefixAwareRemote:
        def __init__(self, prefix):
            self.prefix = prefix
            # A fixed, allow-list-valid snapshot key; the BLOB content is what's
            # distinct per prefix (proving the bytes came from this tenant's remote).
            self.snap = SNAP
            self.objs = {
                "HEAD": json.dumps({"version": 1, "snapshot": self.snap}).encode(),
                self.snap: b"BLOB-FOR-" + prefix.encode(),
            }

        def get_object(self, key):
            if key not in self.objs:
                raise NotFound(key)
            return self.objs[key]

        def list_objects(self, prefix):
            return [k for k in self.objs if k.startswith(prefix)]

    def fake_remote_for(base, prefix):
        seen_prefixes.append(prefix)
        return _PrefixAwareRemote(prefix)

    monkeypatch.setattr(server_mod, "remote_for", fake_remote_for)
    monkeypatch.setattr(server_mod, "default_base_prefix", lambda: "keys-keeper")
    srv = WebVaultServer(data_dir=tmp_path / "wvmt", port=0, multi_tenant=True)
    httpd = _spawn(srv)
    try:
        port = srv.bound_port

        def register_login(op, uid):
            salt = secrets.token_bytes(16).hex()
            st, _, _ = _call(op, port, "POST", "/auth/register",
                             {"uid": uid, "auth_salt": salt, "auth_iters": AUTH_ITERS,
                              "auth_hash": _ah(PW, salt, AUTH_ITERS)})
            assert st == 201, uid          # multi-tenant register needs no token
            st, b, _ = _call(op, port, "POST", "/auth/params", {"uid": uid})
            p = json.loads(b)
            st, _, _ = _call(op, port, "POST", "/auth/login",
                             {"uid": uid, "auth_hash": _ah(PW, p["auth_salt"],
                                                           p["auth_iters"])})
            assert st == 200, uid

        op_a = _opener()
        op_b = _opener()
        register_login(op_a, "alice")
        register_login(op_b, "bob")

        seen_prefixes.clear()
        st, b, _ = _call(op_a, port, "GET", "/vault/head")
        assert st == 200
        snap_a = json.loads(b)["snapshot"]
        st, ba, _ = _call(op_a, port, "GET", "/vault/object?key=" + snap_a)
        assert st == 200 and ba == b"BLOB-FOR-tenants/alice"
        assert set(seen_prefixes) == {"tenants/alice"}, seen_prefixes

        seen_prefixes.clear()
        st, b, _ = _call(op_b, port, "GET", "/vault/head")
        assert st == 200
        snap_b = json.loads(b)["snapshot"]
        st, bb, _ = _call(op_b, port, "GET", "/vault/object?key=" + snap_b)
        assert st == 200 and bb == b"BLOB-FOR-tenants/bob"
        assert set(seen_prefixes) == {"tenants/bob"}, seen_prefixes
    finally:
        httpd.shutdown()


# --- 9. HEAD-rebuild branch (and empty-vault 404) ----------------------------
def test_vault_head_rebuilt_from_versions(tmp_path, monkeypatch):
    rebuilt_snap = "snapshots/000003-dev.kk"
    objs = {
        "versions/000003.json": json.dumps(
            {"version": 3, "snapshot": rebuilt_snap}).encode(),
        rebuilt_snap: b"ciphertext",
    }
    srv, httpd = _spawn_srv(tmp_path, monkeypatch, name="wvhr",
                            remote_for=lambda base, prefix: FakeRemote(prefix, objs))
    try:
        port = srv.bound_port
        op = _opener()
        _register_and_login(op, port)
        st, b, _ = _call(op, port, "GET", "/vault/head")
        assert st == 200 and json.loads(b)["snapshot"] == rebuilt_snap
    finally:
        httpd.shutdown()


def test_vault_head_empty_vault_404(tmp_path, monkeypatch):
    srv, httpd = _spawn_srv(tmp_path, monkeypatch, name="wvempty",
                            remote_for=lambda base, prefix: FakeRemote(prefix, {}))
    try:
        port = srv.bound_port
        op = _opener()
        _register_and_login(op, port)
        assert _call(op, port, "GET", "/vault/head")[0] == 404
    finally:
        httpd.shutdown()


# --- 10. Upstream S3 errors map to 502 ---------------------------------------
class _RaisingRemote:
    def __init__(self, prefix, exc):
        self.prefix = prefix
        self._exc = exc

    def get_object(self, key):
        raise self._exc

    def list_objects(self, prefix):
        return []


@pytest.mark.parametrize("exc", [AuthError("nope"), TransportError("boom")])
def test_vault_head_upstream_error_502(tmp_path, monkeypatch, exc):
    srv, httpd = _spawn_srv(
        tmp_path, monkeypatch, name="wv502-" + type(exc).__name__,
        remote_for=lambda base, prefix: _RaisingRemote(prefix, exc))
    try:
        port = srv.bound_port
        op = _opener()
        _register_and_login(op, port)
        assert _call(op, port, "GET", "/vault/head")[0] == 502
    finally:
        httpd.shutdown()


# --- 11. NotFound on a syntactically-valid key → 404 -------------------------
def test_vault_object_notfound_404(tmp_path, monkeypatch):
    key = "snapshots/000009-dev.kk"
    srv, httpd = _spawn_srv(
        tmp_path, monkeypatch, name="wv404",
        remote_for=lambda base, prefix: _RaisingRemote(prefix, NotFound(key)))
    try:
        port = srv.bound_port
        op = _opener()
        _register_and_login(op, port)
        st, _, _ = _call(op, port, "GET", "/vault/object?key=" + key)
        assert st == 404
    finally:
        httpd.shutdown()


# --- 12. Key allow-list: accepted shapes vs rejected bad keys ----------------
def test_vault_object_key_allowlist(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    _register_and_login(op, port)
    # Accepted shapes (200 if present, 404 if not) — must NOT be 400.
    for ok in ["versions/000001.json", "snapshots/000001-dev.kk"]:
        st, _, _ = _call(op, port, "GET",
                         "/vault/object?key=" + urllib.parse.quote(ok, safe=""))
        assert st != 400, ok
    # Missing key param entirely → 400.
    assert _call(op, port, "GET", "/vault/object")[0] == 400
    # Malformed keys → 400.
    bad = ["versions/12.json", "snapshots/000001-dev.txt", "HEAD/x", "/HEAD",
           "snapshots/000001-dev\x00.kk"]
    for k in bad:
        st, _, _ = _call(op, port, "GET",
                         "/vault/object?key=" + urllib.parse.quote(k, safe=""))
        assert st == 400, k


# --- 13. Register edge cases -------------------------------------------------
def test_register_edge_cases(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    hdr = {"X-Register-Token": "REGTOK"}

    def reg(uid, iters=AUTH_ITERS):
        salt = secrets.token_bytes(16).hex()
        return _call(op, port, "POST", "/auth/register",
                     {"uid": uid, "auth_salt": salt, "auth_iters": iters,
                      "auth_hash": _ah(PW, salt, AUTH_ITERS)}, hdr)[0]

    assert reg("dupe") == 201
    assert reg("dupe") == 400                 # duplicate uid → "already exists"
    assert reg("a/b") == 400                  # invalid uid
    assert reg("a b") == 400                  # invalid uid (space)
    # non-integer auth_iters → 400
    salt = secrets.token_bytes(16).hex()
    st, _, _ = _call(op, port, "POST", "/auth/register",
                     {"uid": "baditers", "auth_salt": salt, "auth_iters": "lots",
                      "auth_hash": _ah(PW, salt, AUTH_ITERS)}, hdr)
    assert st == 400


# --- 14. /static/ traversal hardening ----------------------------------------
def test_static_traversal_hardening(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    for bad in ["/static/../server.py", "/static/.hidden", "/static/sub/dir"]:
        assert _call(op, port, "GET", bad)[0] == 404, bad
    st, _, h = _call(op, port, "GET", "/static/vault.mjs")
    assert st == 200 and "javascript" in h["Content-Type"]


# --- 15. No write surface (PUT/DELETE/PATCH never succeed) -------------------
def test_no_write_surface(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    for path in ["/vault/object?key=HEAD", "/auth/login"]:
        for method in ["PUT", "DELETE", "PATCH"]:
            st, _, _ = _call(op, port, method, path, {})
            assert st >= 400, f"{method} {path} returned {st}"


# --- 16. Malformed Content-Length → 400 (raw socket) -------------------------
def _raw_status(port, content_length):
    """Send a hand-crafted POST with a chosen Content-Length; return the numeric
    status from the response status line."""
    body = b"{}"
    req = (
        f"POST /auth/params HTTP/1.1\r\n"
        f"Host: x\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode() + body
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(req)
        sock.settimeout(10)
        chunks = []
        while True:
            try:
                d = sock.recv(4096)
            except socket.timeout:
                break
            if not d:
                break
            chunks.append(d)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    resp = b"".join(chunks)
    first = resp.split(b"\r\n", 1)[0].decode("latin-1")
    # "HTTP/1.1 400 Bad Request" → 400
    return int(first.split(" ", 2)[1])


def test_malformed_content_length_400(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    assert _raw_status(port, "-1") == 400
    assert _raw_status(port, "abc") == 400


# --- 17. Anti-enumeration: deterministic fake salt for unknown uids ----------
def test_auth_params_unknown_uid_deterministic(vaultsrv):
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    st1, b1, _ = _call(op, port, "POST", "/auth/params", {"uid": "ghost"})
    st2, b2, _ = _call(op, port, "POST", "/auth/params", {"uid": "ghost"})
    assert st1 == 200 and st2 == 200
    assert json.loads(b1)["auth_salt"] == json.loads(b2)["auth_salt"]


# --- 10b. /vault/object upstream S3 errors map to 502 (independent branch) ----
@pytest.mark.parametrize("exc", [AuthError("nope"), TransportError("boom")])
def test_vault_object_upstream_error_502(tmp_path, monkeypatch, exc):
    # _vault_object has its OWN `except (AuthError, TransportError) -> 502` block,
    # separate from _vault_head's. Drive a syntactically-valid key against a remote
    # that raises so the object handler's 502 branch is actually exercised — a
    # regression that let the object handler 500/200 on upstream failure would
    # otherwise slip through (every other object test only hits NotFound/bad-key).
    srv, httpd = _spawn_srv(
        tmp_path, monkeypatch, name="wvobj502-" + type(exc).__name__,
        remote_for=lambda base, prefix: _RaisingRemote(prefix, exc))
    try:
        port = srv.bound_port
        op = _opener()
        _register_and_login(op, port)
        st, _, _ = _call(op, port, "GET", "/vault/object?key=" + SNAP)
        assert st == 502, type(exc).__name__
    finally:
        httpd.shutdown()


# --- 15b. No write surface: writes are unroutable (501), not merely "not 2xx" -
def test_no_write_surface_status_pinned(vaultsrv):
    # Tighten the "no write surface" guarantee: the proxy defines no
    # do_PUT/do_DELETE/do_PATCH, so BaseHTTPRequestHandler answers 501 (Unsupported
    # method) for every write verb on every routed path — auth AND vault, read AND
    # head. Pin the EXACT status (501; 405 also acceptable if a method-not-allowed
    # gate is ever added) rather than `>= 400`, so an accidental 500 from a
    # half-implemented write path would FAIL instead of silently passing.
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    # Snapshot the pre-state of the vault so we can assert nothing mutated.
    _register_and_login(op, port)
    before_st, before_body, _ = _call(op, port, "GET", "/vault/object?key=" + SNAP)
    assert before_st == 200
    paths = ["/vault/object?key=" + SNAP, "/vault/head",
             "/auth/login", "/auth/register"]
    for path in paths:
        for method in ["PUT", "DELETE", "PATCH"]:
            st, _, _ = _call(op, port, method, path, {})
            # Unrouted write verb → 501 (no handler) or 405 (method-not-allowed).
            assert st in (501, 405), f"{method} {path} returned {st}"
    # The write attempts must have been non-mutating: the vault is byte-identical.
    after_st, after_body, _ = _call(op, port, "GET", "/vault/object?key=" + SNAP)
    assert after_st == 200 and after_body == before_body


# --- 17b. Anti-enumeration security shape: per-uid distinct + known-indistinct -
def test_auth_params_anti_enumeration_shape(vaultsrv):
    # The fake salt for an unknown uid must be indistinguishable from a real one,
    # AND must not collapse to a single constant (which would re-enable a probe:
    # "any uid whose salt == K is unknown"). Assert the full security shape:
    #   (a) the fake salt DIFFERS per uid (not a global constant),
    #   (b) it is a 32-hex string with auth_iters == _AUTH_ITERS_DEFAULT
    #       (the indistinguishability shape), and
    #   (c) an UNKNOWN uid is shape-indistinguishable from a KNOWN one
    #       (same 32-hex salt + default-iters envelope), so /auth/params can't be
    #       used to enumerate which accounts exist.
    srv, *_ = vaultsrv
    port = srv.bound_port
    op = _opener()
    # `me` is the account registered by _register_and_login → a KNOWN uid.
    _register_and_login(op, port)
    st_known, b_known, _ = _call(op, port, "POST", "/auth/params", {"uid": "me"})
    st_g1, bg1, _ = _call(op, port, "POST", "/auth/params", {"uid": "ghost"})
    st_g2, bg2, _ = _call(op, port, "POST", "/auth/params", {"uid": "phantom"})
    assert st_known == 200 and st_g1 == 200 and st_g2 == 200
    known = json.loads(b_known)
    g1 = json.loads(bg1)
    g2 = json.loads(bg2)
    # (a) distinct fake salts per unknown uid — not a single constant.
    assert g1["auth_salt"] != g2["auth_salt"], "fake salt must vary per uid"
    # (b) indistinguishability shape for unknown uids: 32-hex + default iters.
    for fake in (g1, g2):
        assert len(fake["auth_salt"]) == 32
        int(fake["auth_salt"], 16)                      # valid hex
        assert fake["auth_iters"] == server_mod._AUTH_ITERS_DEFAULT
    # (c) a KNOWN uid presents the SAME envelope (32-hex salt + default iters), so
    # the response shape can't distinguish existing from non-existing accounts.
    assert len(known["auth_salt"]) == 32
    int(known["auth_salt"], 16)
    assert known["auth_iters"] == server_mod._AUTH_ITERS_DEFAULT
    # And the known salt is not equal to either fake (different keying material),
    # confirming the fakes aren't accidentally echoing a real account's salt.
    assert known["auth_salt"] not in (g1["auth_salt"], g2["auth_salt"])
