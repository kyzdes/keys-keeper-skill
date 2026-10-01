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
import ipaddress
import json
import re
import secrets
import ssl
import threading
import time
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from keys_keeper.sync_remote import AuthError, NotFound, TransportError
from keys_keeper.http_resources import BoundedThreadingHTTPServer, RequestDeadlineMixin
from keys_keeper.webvault.remote import (
    default_base_prefix, load_s3_base, remote_for,
)
from keys_keeper.webvault.store import (
    AccountStore, AccountError, AccountStoreError, SessionCapacityError, SessionStore,
)

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

    def __init__(self, limit: int, window: int, *, max_keys: int = 4096):
        if any(type(v) is not int or v < 1 for v in (limit, window, max_keys)):
            raise ValueError("rate limits must be positive integers")
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            # Last accepted hit orders expiry. Each key is removed at most
            # once; distinct live clients cannot trigger repeated whole sweeps.
            while self._hits:
                first, hits = next(iter(self._hits.items()))
                if hits[-1] > cutoff:
                    break
                self._hits.pop(first)
            times = self._hits.get(key)
            if times is None:
                if len(self._hits) >= self.max_keys:
                    return False
                times = deque()
            while times and times[0] <= cutoff:
                times.popleft()
            if len(times) >= self.limit:
                return False
            times.append(now)
            self._hits[key] = times
            self._hits.move_to_end(key)
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
            "__SRI_THEME__": _sri(_STATIC / "theme.js"),
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
        if acct is None:
            raise AccountStoreError("session account unavailable")
        return acct.prefix

    def create_http_server(self):
        httpd = BoundedThreadingHTTPServer((self.host, self.port), _make_handler(self),
                                          max_workers=16, request_timeout=15)
        if self.certfile and self.keyfile:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            # Accepted TLS handshakes run in admitted handlers, where the
            # cumulative input deadline applies, instead of blocking accept().
            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True,
                                          do_handshake_on_connect=False)
        return httpd

    def serve_forever(self) -> None:
        httpd = self.create_http_server()
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
        finally:
            httpd.server_close()


def _make_handler(srv: "WebVaultServer"):
    class Handler(RequestDeadlineMixin, BaseHTTPRequestHandler):
        server_version = "kkvault"
        protocol_version = "HTTP/1.1"

        def version_string(self):
            # Don't leak the Python interpreter version in the Server header.
            return "kkvault"

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
            # Behind a trusted reverse proxy the socket peer is the proxy itself, so
            # every real client would collapse into ONE rate-limit bucket — letting a
            # single attacker DoS-lock login/registration for everyone, and removing
            # per-source throttling of online guessing. When the operator promises a
            # trusted proxy (--behind-proxy / trust_forwarded) we instead take the
            # RIGHTMOST X-Forwarded-For entry: the hop our proxy observed and appended
            # (nginx $proxy_add_x_forwarded_for). Leftmost entries are attacker-
            # controlled and must never be trusted. Same trust model as
            # _client_is_https; assumes a single trusted proxy directly in front.
            if srv.trust_forwarded:
                parts = [p.strip() for p in self.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
                if parts:
                    try:
                        return str(ipaddress.ip_address(parts[-1]))
                    except ValueError:
                        pass
            return (self.client_address[0] if self.client_address else "?")

        def _body(self) -> bytes:
            # Validate Content-Length BEFORE reading anything off the wire so an
            # oversized (or malformed) request is rejected without buffering it.
            if self.headers.get("Transfer-Encoding") is not None:
                raise self._BadLength()
            lengths = self.headers.get_all("Content-Length", [])
            if not lengths:
                return b""
            if len(lengths) != 1:
                raise self._BadLength()
            try:
                n = int(lengths[0])
            except (TypeError, ValueError):
                raise self._BadLength()
            if n < 0:
                raise self._BadLength()
            if n > _MAX_BODY_BYTES:
                raise self._BodyTooLarge()
            data = self.rfile.read(n) if n else b""
            if len(data) != n:
                raise self._BadLength()
            return data

        # ---- auth ----
        def _uid(self) -> str | None:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                k, _, v = part.strip().partition("=")
                if k in _SESSION_COOKIE_NAMES:
                    uid = srv.sessions.resolve(v)
                    if uid:
                        if srv.accounts.get(uid) is None:
                            srv.sessions.destroy(v)
                            return None
                        return uid
            return None

        # ---- routing ----
        def _reject_oversized(self) -> bool:
            """Enforce the hard body cap for ALL endpoints up front (before any
            handler runs). Returns True if a 4xx was already sent."""
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") is not None or len(lengths) > 1:
                self.close_connection = True
                self._json(400, {"error": "bad content-length"})
                return True
            if not lengths:
                return False
            try:
                n = int(lengths[0])
            except (TypeError, ValueError):
                self.close_connection = True
                self._json(400, {"error": "bad content-length"})
                return True
            if n < 0:
                self.close_connection = True
                self._json(400, {"error": "bad content-length"})
                return True
            if n > _MAX_BODY_BYTES:
                self.close_connection = True
                self._json(413, {"error": "request body too large"})
                return True
            return False

        def do_GET(self):
            self._dispatch(self._get)

        def do_POST(self):
            self._dispatch(self._post)

        def _dispatch(self, action):
            try:
                action()
            except AccountStoreError:
                self._json(503, {"error": "account registry unavailable"})
            except SessionCapacityError:
                self._json(429, {"error": "session capacity exceeded"},
                           extra={"Retry-After": "60"})

        def _get(self):
            if self._reject_oversized():
                return
            if int(self.headers.get("Content-Length", "0")):
                self.close_connection = True
                return self._json(400, {"error": "GET request body unsupported"})
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

        def _post(self):
            # Early token/rate-limit failures do not consume the body. Close
            # POST connections so those bytes cannot become another request.
            self.close_connection = True
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
            uid = self._input_uid(data)
            if uid is None:
                return
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
            uid = self._input_uid(data)
            if uid is None:
                return
            try:
                auth_iters = data["auth_iters"]
                if type(auth_iters) is not int:
                    return self._json(400, {"error": "invalid authentication parameters"})
                if auth_iters < _AUTH_ITERS_MIN:
                    return self._json(400, {"error": f"auth_iters must be >= "
                                                     f"{_AUTH_ITERS_MIN}"})
                prefix = (f"tenants/{uid}" if srv.multi_tenant else default_base_prefix())
                srv.accounts.register(
                    uid=uid, prefix=prefix,
                    auth_salt=data["auth_salt"], auth_iters=auth_iters,
                    auth_hash=data["auth_hash"])
            except AccountStoreError:
                raise
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
            uid = self._input_uid(data)
            if uid is None:
                return
            auth_hash = data.get("auth_hash")
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
            prefix = srv.prefix_for(uid)
            remote = remote_for(srv.s3_base(), prefix)
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
            if not _KEY_RE.fullmatch(key):
                return self._json(400, {"error": "bad key"})
            prefix = srv.prefix_for(uid)
            remote = remote_for(srv.s3_base(), prefix)
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
        def _input_uid(self, data):
            uid = data.get("uid", "")
            if not isinstance(uid, str) or len(uid) > 128:
                self._json(400, {"error": "invalid uid"})
                return None
            return uid.strip()

        def _parse_json(self):
            """Return a dict, or None after having already sent a 4xx error
            (oversized / malformed body). Callers must stop on None."""
            try:
                body = self._body()
            except self._BodyTooLarge:
                self.close_connection = True
                self._json(413, {"error": "request body too large"})
                return None
            except self._BadLength:
                self.close_connection = True
                self._json(400, {"error": "bad content-length"})
                return None
            try:
                def pairs(items):
                    result = {}
                    for key, value in items:
                        if key in result:
                            raise ValueError("duplicate member")
                        result[key] = value
                    return result
                d = json.loads(body or b"{}", object_pairs_hook=pairs,
                               parse_constant=lambda value: (_ for _ in ()).throw(ValueError("invalid number")))
                if not isinstance(d, dict):
                    raise ValueError("invalid object")
            except (ValueError, UnicodeError, RecursionError):
                self._json(400, {"error": "invalid JSON object"})
                return None
            return d

    return Handler
