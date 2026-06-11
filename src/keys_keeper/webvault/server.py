"""The web-vault proxy: a hardened, internet-facing HTTP server that
authenticates an account and shuttles ENCRYPTED bytes between the browser and
S3. It decrypts NOTHING — there is deliberately no import of keys_keeper.crypto
anywhere in this module (a test asserts it). All secret material stays in the
browser; the proxy only ever sees ciphertext blobs + non-secret commit JSON.

Read-only (v1): GET /vault/head, GET /vault/object. Account auth via the
passphrase-derived auth-hash (different salt than the vault key). The per-account
S3 prefix is taken from the server-side account record (session uid), NEVER from
the request — the browser cannot point the proxy at another tenant's data.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from keys_keeper.sync_remote import AuthError, NotFound, TransportError
from keys_keeper.webvault.remote import (
    default_base_prefix, load_s3_base, remote_for,
)
from keys_keeper.webvault.store import AccountStore, AccountError, SessionStore

_STATIC = Path(__file__).parent / "static"
_AUTH_ITERS_DEFAULT = 600_000     # AH must be >= the blob's 600k so it's not the weak link
_AUTH_ITERS_MIN = 600_000         # reject registrations weaker than the blob's KDF
_SESSION_COOKIE = "kkv_session"
# When the cookie is Secure we additionally apply the __Host- prefix (which the
# browser enforces: Secure + Path=/ + no Domain). Accept either name on read so
# sessions keep working whether or not the request was over TLS.
_SESSION_COOKIE_HOST = "__Host-" + _SESSION_COOKIE
_SESSION_COOKIE_NAMES = (_SESSION_COOKIE_HOST, _SESSION_COOKIE)

# DoS guards (unauthenticated). A hard body cap rejects oversized requests before
# we read them; a per-IP sliding-window rate limiter sheds auth floods.
_MAX_BODY_BYTES = 64 * 1024        # 64 KiB hard cap for ALL request bodies
_RL_LOGIN_MAX = 10                 # max /auth/login attempts ...
_RL_REGISTER_MAX = 5               # ... and /auth/register attempts ...
_RL_WINDOW_SEC = 60                # ... per client IP per this sliding window


class _RateLimiter:
    """Per-IP sliding-window counter. In-memory, thread-safe, stdlib only.

    Keeps the last `window` seconds of hit timestamps per (bucket, ip) and
    returns False once a key exceeds `limit`. Bounded memory: stale keys are
    dropped lazily and the table is swept when it grows large."""

    def __init__(self, limit: int, window: int):
        self.limit = limit
        self.window = window
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        cutoff = now - self.window
        with self._lock:
            if len(self._hits) > 4096:
                # lazy sweep so a churn of distinct IPs can't grow the table forever
                self._hits = {k: [t for t in v if t >= cutoff]
                              for k, v in self._hits.items()}
                self._hits = {k: v for k, v in self._hits.items() if v}
            times = [t for t in self._hits.get(key, ()) if t >= cutoff]
            if len(times) >= self.limit:
                self._hits[key] = times
                return False
            times.append(now)
            self._hits[key] = times
            return True

# Only these (account-relative) keys may be fetched; the prefix is added
# server-side. No traversal, no arbitrary keys.
_KEY_RE = re.compile(
    r"^(HEAD|versions/\d{6,}\.json|snapshots/\d{6,}-[A-Za-z0-9._-]+\.kk)$")
_VERSION_RE = re.compile(r"versions/(\d{6,})\.json$")

_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'none'; require-trusted-types-for 'script'"
)
_SECURITY_HEADERS = {
    "Content-Security-Policy": _CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), "
                          "gyroscope=(), microphone=(), usb=(), payment=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
}
_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8", ".js": "text/javascript; charset=utf-8",
    ".json": "application/json", ".svg": "image/svg+xml",
    ".woff2": "font/woff2", ".ico": "image/x-icon",
}


def _sri(path: Path) -> str:
    return "sha384-" + base64.b64encode(hashlib.sha384(path.read_bytes()).digest()).decode()


class WebVaultServer:
    """Owns the account/session stores, the S3 base, and the SRI map; runs the
    threaded HTTP(S) server."""

    def __init__(self, *, data_dir: Path, host: str = "127.0.0.1", port: int = 8333,
                 multi_tenant: bool = False, register_token: str | None = None,
                 allow_open_registration: bool = False, trust_forwarded: bool = False,
                 idle_sec: int = 15 * 60, certfile: str | None = None,
                 keyfile: str | None = None):
        self.host = host
        self.port = port
        self.multi_tenant = multi_tenant
        self.register_token = register_token
        # Open registration is an explicit opt-in. We do NOT derive it from the
        # bind host: behind a TLS reverse proxy the proxy connects to 127.0.0.1,
        # so a loopback bind is NOT proof the *client* is local. Fail closed.
        self.allow_open_registration = allow_open_registration
        # Only honor X-Forwarded-Proto (for the Secure cookie flag) when the
        # operator promises a trusted proxy sets it; otherwise a direct client
        # could spoof it.
        self.trust_forwarded = trust_forwarded
        self.is_loopback = host in ("127.0.0.1", "localhost", "::1", "[::1]")
        self.accounts = AccountStore(data_dir / "accounts.json")
        self.sessions = SessionStore(idle_sec=idle_sec)
        self.params_secret = secrets.token_bytes(32)   # for anti-enumeration fake salts
        self.login_limiter = _RateLimiter(_RL_LOGIN_MAX, _RL_WINDOW_SEC)
        self.register_limiter = _RateLimiter(_RL_REGISTER_MAX, _RL_WINDOW_SEC)
        self.certfile = certfile
        self.keyfile = keyfile
        self._s3_base = None
        self.bound_port = 0
        # SRI for the bundle (computed once; injected into the shell).
        self.sri = {
            "__SRI_KKCRYPTO__": _sri(_STATIC / "kkcrypto.mjs"),
            "__SRI_VAULT__": _sri(_STATIC / "vault.mjs"),
            "__SRI_VAULT_CSS__": _sri(_STATIC / "vault.css"),
            "__SRI_APP_CSS__": _sri(_STATIC / "app.css"),
        }
        self._index = (_STATIC / "index.html").read_text(encoding="utf-8")
        for k, v in self.sri.items():
            self._index = self._index.replace(k, v)

    def s3_base(self):
        if self._s3_base is None:
            self._s3_base = load_s3_base()
        return self._s3_base

    def prefix_for(self, uid: str) -> str:
        acct = self.accounts.get(uid)
        return acct.prefix if acct else default_base_prefix()

    def serve_forever(self) -> None:
        httpd = ThreadingHTTPServer((self.host, self.port), _make_handler(self))
        if self.certfile and self.keyfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self.bound_port = httpd.socket.getsockname()[1]
        scheme = "https" if self.certfile else "http"
        print(f"keys-keeper web vault on {scheme}://{self.host}:{self.bound_port}/")
        if (not self.multi_tenant and self.register_token is None
                and not self.allow_open_registration):
            print("  ! registration is DISABLED (single-tenant, no --register-token). "
                  "Set --register-token, or pass --allow-open-registration to allow "
                  "token-less sign-up (only safe on a trusted/local network).")
        if not self.certfile and not self.is_loopback:
            print("  ! no TLS configured — put an HTTPS reverse proxy in front "
                  "(or pass --certfile/--keyfile).")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def _make_handler(srv: "WebVaultServer"):
    class Handler(BaseHTTPRequestHandler):
        server_version = "kkvault"
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # no request logging (avoid leaking uids/paths)
            pass

        # ---- low-level send ----
        def _headers(self, status: int, ctype: str, length: int,
                     extra: dict | None = None):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            for k, v in _SECURITY_HEADERS.items():
                self.send_header(k, v)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()

        def _send(self, status, body: bytes, ctype="application/octet-stream", extra=None):
            self._headers(status, ctype, len(body), extra)
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status, obj, extra=None):
            self._send(status, json.dumps(obj).encode(), "application/json", extra)

        class _BodyTooLarge(Exception):
            """Content-Length exceeds the hard cap (-> 413)."""

        class _BadLength(Exception):
            """Content-Length missing-but-needed or malformed/negative (-> 400)."""

        def _client_ip(self) -> str:
            return (self.client_address[0] if self.client_address else "?")

        def _body(self) -> bytes:
            # Validate Content-Length BEFORE reading anything off the wire so an
            # oversized (or malformed) request is rejected without buffering it.
            raw = self.headers.get("Content-Length", None)
            if raw is None:
                return b""
            try:
                n = int(raw)
            except (TypeError, ValueError):
                raise self._BadLength()
            if n < 0:
                raise self._BadLength()
            if n > _MAX_BODY_BYTES:
                raise self._BodyTooLarge()
            return self.rfile.read(n) if n else b""

        # ---- auth ----
        def _uid(self) -> str | None:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k in _SESSION_COOKIE_NAMES:
                    uid = srv.sessions.resolve(v)
                    if uid:
                        return uid
            return None

        # ---- routing ----
        def _reject_oversized(self) -> bool:
            """Enforce the hard body cap for ALL endpoints up front (before any
            handler runs). Returns True if a 4xx was already sent."""
            raw = self.headers.get("Content-Length", None)
            if raw is None:
                return False
            try:
                n = int(raw)
            except (TypeError, ValueError):
                self._json(400, {"error": "bad content-length"})
                return True
            if n < 0:
                self._json(400, {"error": "bad content-length"})
                return True
            if n > _MAX_BODY_BYTES:
                self._json(413, {"error": "request body too large"})
                return True
            return False

        def do_GET(self):
            if self._reject_oversized():
                return
            u = urlparse(self.path)
            p = u.path
            if p == "/healthz":
                return self._send(200, b"ok", "text/plain")
            if p in ("/", "/index.html"):
                return self._send(200, srv._index.encode(), _CONTENT_TYPES[".html"])
            if p.startswith("/static/"):
                return self._static(p[len("/static/"):])
            if p == "/vault/head":
                return self._vault_head()
            if p == "/vault/object":
                return self._vault_object(parse_qs(u.query))
            if p == "/auth/whoami":
                uid = self._uid()
                return self._json(200, {"uid": uid} if uid else {"uid": None})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if self._reject_oversized():
                return
            p = urlparse(self.path).path
            if p == "/auth/params":
                return self._auth_params()
            if p == "/auth/register":
                return self._auth_register()
            if p == "/auth/login":
                return self._auth_login()
            if p == "/auth/logout":
                return self._auth_logout()
            self._json(404, {"error": "not found"})

        # ---- static ----
        def _static(self, name: str):
            if "/" in name or ".." in name or name.startswith("."):
                return self._json(404, {"error": "not found"})
            f = (_STATIC / name).resolve()
            if not str(f).startswith(str(_STATIC.resolve())) or not f.is_file():
                return self._json(404, {"error": "not found"})
            ctype = _CONTENT_TYPES.get(f.suffix, "application/octet-stream")
            self._send(200, f.read_bytes(), ctype)

        # ---- auth handlers ----
        def _auth_params(self):
            data = self._parse_json()
            if data is None:
                return
            uid = (data.get("uid") or "").strip()
            acct = srv.accounts.get(uid) if uid else None
            if acct:
                return self._json(200, {"auth_salt": acct.auth_salt,
                                        "auth_iters": acct.auth_iters})
            # anti-enumeration: deterministic plausible salt for unknown uids
            fake = hmac.new(srv.params_secret, uid.encode(), hashlib.sha256).hexdigest()[:32]
            self._json(200, {"auth_salt": fake, "auth_iters": _AUTH_ITERS_DEFAULT})

        def _auth_register(self):
            # Rate-limit per IP first (cheap) so a flood can't even reach scrypt.
            if not srv.register_limiter.allow(self._client_ip()):
                return self._json(429, {"error": "too many registration attempts"},
                                  extra={"Retry-After": str(_RL_WINDOW_SEC)})
            # Fail CLOSED for single-tenant registration regardless of bind host.
            # In single-tenant mode every account maps to the SAME (operator's)
            # vault prefix, so token-less open registration would let anyone pull
            # the operator's encrypted blob. We must NOT key this off the bind
            # host: behind a TLS reverse proxy the proxy connects from 127.0.0.1,
            # so a loopback bind is not proof the client is local. Allow token-less
            # single-tenant sign-up ONLY when explicitly opted in via
            # --allow-open-registration. Multi-tenant (isolated tenants/<uid>/) and
            # token-gated registration stay open as before.
            if (srv.register_token is None and not srv.multi_tenant
                    and not srv.allow_open_registration):
                return self._json(403, {"error": "registration is closed (single-tenant); "
                                                 "set --register-token or "
                                                 "--allow-open-registration"})
            if srv.register_token is not None:
                if not hmac.compare_digest(
                        self.headers.get("X-Register-Token", ""), srv.register_token):
                    return self._json(403, {"error": "registration disabled or bad token"})
            data = self._parse_json()
            if data is None:
                return
            uid = (data.get("uid") or "").strip()
            try:
                auth_iters = int(data["auth_iters"])
                if auth_iters < _AUTH_ITERS_MIN:
                    return self._json(400, {"error": f"auth_iters must be >= "
                                                     f"{_AUTH_ITERS_MIN}"})
                prefix = (f"tenants/{uid}" if srv.multi_tenant else default_base_prefix())
                srv.accounts.register(
                    uid=uid, prefix=prefix,
                    auth_salt=str(data["auth_salt"]), auth_iters=auth_iters,
                    auth_hash=str(data["auth_hash"]))
            except (AccountError, KeyError, ValueError) as e:
                return self._json(400, {"error": str(e)})
            self._json(201, {"ok": True, "uid": uid})

        def _client_is_https(self) -> bool:
            """True when the request reached the user over TLS. Direct TLS
            (we terminate it) OR a trusted upstream proxy that set
            X-Forwarded-Proto=https (only honored when --trust-forwarded)."""
            if srv.certfile:
                return True
            if srv.trust_forwarded:
                proto = self.headers.get("X-Forwarded-Proto", "")
                # take the first hop if a comma-chained list is present
                return proto.split(",")[0].strip().lower() == "https"
            return False

        def _auth_login(self):
            # Per-IP login lockout to blunt online password guessing / floods.
            if not srv.login_limiter.allow(self._client_ip()):
                return self._json(429, {"error": "too many login attempts"},
                                  extra={"Retry-After": str(_RL_WINDOW_SEC)})
            data = self._parse_json()
            if data is None:
                return
            uid = (data.get("uid") or "").strip()
            auth_hash = str(data.get("auth_hash") or "")
            if not srv.accounts.verify(uid, auth_hash):
                return self._json(401, {"error": "invalid credentials"})
            token = srv.sessions.create(uid)
            secure = "; Secure" if self._client_is_https() else ""
            # __Host- prefix requires Secure + Path=/ + no Domain; only safe to use
            # when the cookie is actually Secure, so gate it on that.
            name = _SESSION_COOKIE_HOST if secure else _SESSION_COOKIE
            cookie = f"{name}={token}; HttpOnly; SameSite=Strict; Path=/{secure}"
            self._json(200, {"ok": True, "uid": uid}, extra={"Set-Cookie": cookie})

        def _auth_logout(self):
            cookie = self.headers.get("Cookie", "")
            present = _SESSION_COOKIE
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k in _SESSION_COOKIE_NAMES:
                    srv.sessions.destroy(v)   # server-side kill is the real logout
                    present = k
            # Best-effort clear of the cookie the client actually sent. (The
            # server-side session is already destroyed above, so even a lingering
            # cookie value is inert.) __Host- cookies must carry Secure to clear.
            secure = "; Secure" if present == _SESSION_COOKIE_HOST else ""
            expired = (f"{present}=; HttpOnly; SameSite=Strict; Path=/; "
                       f"Max-Age=0{secure}")
            self._json(200, {"ok": True}, extra={"Set-Cookie": expired})

        # ---- vault (read-only) ----
        def _vault_head(self):
            uid = self._uid()
            if not uid:
                return self._json(401, {"error": "not authenticated"})
            remote = remote_for(srv.s3_base(), srv.prefix_for(uid))
            try:
                head = json.loads(remote.get_object("HEAD"))
                return self._json(200, head)
            except NotFound:
                pass
            except (AuthError, TransportError) as e:
                return self._json(502, {"error": type(e).__name__})
            # HEAD missing → rebuild tip from the version listing
            try:
                ns = [int(m.group(1)) for k in remote.list_objects("versions/")
                      if (m := _VERSION_RE.search(k))]
                if not ns:
                    return self._json(404, {"error": "empty vault"})
                commit = json.loads(remote.get_object(f"versions/{max(ns):06d}.json"))
                self._json(200, {"version": max(ns), "snapshot": commit["snapshot"]})
            except (AuthError, TransportError) as e:
                self._json(502, {"error": type(e).__name__})

        def _vault_object(self, query):
            uid = self._uid()
            if not uid:
                return self._json(401, {"error": "not authenticated"})
            key = (query.get("key", [""])[0])
            if not _KEY_RE.match(key):
                return self._json(400, {"error": "bad key"})
            remote = remote_for(srv.s3_base(), srv.prefix_for(uid))
            try:
                body = remote.get_object(key)
            except NotFound:
                return self._json(404, {"error": "not found"})
            except (AuthError, TransportError) as e:
                return self._json(502, {"error": type(e).__name__})
            ctype = ("application/json" if key.endswith(".json") or key == "HEAD"
                     else "application/octet-stream")
            self._send(200, body, ctype)

        # ---- helpers ----
        def _parse_json(self):
            """Return a dict, or None after having already sent a 4xx error
            (oversized / malformed body). Callers must stop on None."""
            try:
                body = self._body()
            except self._BodyTooLarge:
                self._json(413, {"error": "request body too large"})
                return None
            except self._BadLength:
                self._json(400, {"error": "bad content-length"})
                return None
            try:
                d = json.loads(body or b"{}")
            except ValueError:
                return {}
            return d if isinstance(d, dict) else {}

    return Handler
