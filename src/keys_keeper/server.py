"""Localhost admin HTTP server with token auth."""
from __future__ import annotations
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from keys_keeper.paths import Paths


_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'"
    ),
}


class AdminServer:
    """Wraps ThreadingHTTPServer with idle-timeout auto-shutdown and a generated session token."""

    def __init__(self, *, paths: Paths, port: int = 7777, idle_timeout_sec: int = 900):
        self.paths = paths
        self.requested_port = port
        self.bound_port = 0
        self.idle_timeout_sec = idle_timeout_sec
        self.token = secrets.token_hex(32)
        self.last_seen = time.monotonic()
        self._server: ThreadingHTTPServer | None = None
        self._stop_event = threading.Event()

    # ---- public ----

    def serve_forever(self) -> None:
        handler_cls = make_handler(self)
        self._server = ThreadingHTTPServer(("127.0.0.1", self.requested_port), handler_cls)
        self._server._kk_started = time.monotonic()
        self.bound_port = self._server.server_port
        threading.Thread(target=self._idle_watchdog, daemon=True).start()
        self._server.serve_forever()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server is not None:
            self._server.shutdown()

    def heartbeat(self) -> None:
        self.last_seen = time.monotonic()

    # ---- internal ----

    def _idle_watchdog(self) -> None:
        while not self._stop_event.is_set():
            time.sleep(5)
            if time.monotonic() - self.last_seen > self.idle_timeout_sec:
                self.stop()
                return


def make_handler(admin: "AdminServer"):
    paths = admin.paths

    class Handler(BaseHTTPRequestHandler):
        # silence default noisy logging during tests
        def log_message(self, fmt: str, *args) -> None:
            return

        # ---- helpers ----

        def _verify_token(self) -> bool:
            # Accept token via header (fetch/XHR) or session cookie (browser
            # nav). The ?t=TOKEN query form is accepted ONLY on the initial
            # HTML bootstrap (GET / or /index.html) so that a leaked URL
            # (screenshot, browser history sync, address-bar autocomplete,
            # malicious extension reading window.location) cannot directly
            # call /api/* endpoints.
            header_token = self.headers.get("Sec-Keys-Token")
            if header_token == admin.token:
                self._auth_ok = True
                return True
            cookie_header = self.headers.get("Cookie", "")
            for part in cookie_header.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "kk_session" and v == admin.token:
                    self._auth_ok = True
                    return True
            parsed = urlparse(self.path)
            if self.command == "GET" and parsed.path in ("/", "/index.html"):
                qs = parse_qs(parsed.query)
                if qs.get("t", [""])[0] == admin.token:
                    self._auth_ok = True
                    return True
            return False

        def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for k, v in _NO_CACHE_HEADERS.items():
                self.send_header(k, v)
            # On every authenticated response, refresh the session cookie so subsequent
            # browser navigation (regular <a href> clicks) carries auth without needing
            # JS to inject the Sec-Keys-Token header.
            if getattr(self, "_auth_ok", False):
                self.send_header(
                    "Set-Cookie",
                    f"kk_session={admin.token}; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, status: int, payload: dict | list) -> None:
            data = json.dumps(payload).encode("utf-8")
            self._send(status, data, "application/json")

        # ---- routing ----

        def do_GET(self) -> None:
            admin.heartbeat()
            parsed = urlparse(self.path)
            path = parsed.path
            # Static assets (CSS / JS) are public — they hold no secrets and the
            # browser cannot attach our session header to <link>/<script> requests.
            if path.startswith("/static/"):
                self._serve_static(path)
                return
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            if path == "/" or path == "/index.html":
                from keys_keeper.pages import render_dashboard
                html = render_dashboard(paths=paths, token=admin.token)
                self._send(200, html.encode("utf-8"))
                return
            if path.startswith("/api/"):
                from keys_keeper.api import handle_api
                # pass full self.path (with query) so /api/audit?limit=… etc work
                handle_api(self, paths=paths, method="GET", path=self.path, body=None)
                return
            if path == "/new":
                from keys_keeper.pages import render_new_edit
                self._send(200, render_new_edit(paths=paths, token=admin.token).encode("utf-8"))
                return
            if path == "/paste":
                from keys_keeper.pages import render_bulk_paste
                self._send(200, render_bulk_paste(paths=paths, token=admin.token).encode("utf-8"))
                return
            if path.startswith("/entry/") and path.endswith("/edit"):
                from keys_keeper.pages import render_new_edit
                from keys_keeper.store import MetadataStore
                from urllib.parse import unquote
                eid = unquote(path[len("/entry/"):-len("/edit")])
                e = MetadataStore(paths).get_by_id(eid) or MetadataStore(paths).get_by_name(eid)
                if e is None:
                    self._send(404, b"entry not found")
                    return
                self._send(200, render_new_edit(paths=paths, token=admin.token, entry=e).encode("utf-8"))
                return
            if path.startswith("/entry/"):
                from urllib.parse import unquote
                entry_id = unquote(path[len("/entry/"):])
                from keys_keeper.pages import render_entry_detail
                from keys_keeper.store import MetadataStore
                store = MetadataStore(paths)
                e = store.get_by_id(entry_id) or store.get_by_name(entry_id)
                if e is None:
                    self._send(404, b"entry not found")
                    return
                html = render_entry_detail(paths=paths, token=admin.token, entry=e)
                self._send(200, html.encode("utf-8"))
                return
            if path == "/audit":
                from keys_keeper.pages import render_audit
                self._send(200, render_audit(paths=paths, token=admin.token).encode("utf-8"))
                return
            if path == "/settings":
                from keys_keeper.pages import render_settings
                self._send(200, render_settings(paths=paths, token=admin.token).encode("utf-8"))
                return
            if path.startswith("/static/"):
                self._serve_static(path)
                return
            self._send(404, b"not found")

        def do_POST(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="POST", path=self.path, body=body)

        def do_DELETE(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="DELETE", path=self.path, body=None)

        def do_PATCH(self) -> None:
            admin.heartbeat()
            if not self._verify_token():
                self._send(403, b"forbidden")
                return
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            from keys_keeper.api import handle_api
            handle_api(self, paths=paths, method="PATCH", path=self.path, body=body)

        def _serve_static(self, path: str) -> None:
            base = (Path(__file__).parent / "static").resolve()
            # Anchor the join from `base` so any traversal segments (../)
            # resolve relative to the static dir, then verify containment via
            # `is_relative_to` (NOT string prefix — `startswith` would match
            # sibling dirs whose name begins with "static").
            relative = path[len("/static/"):] if path.startswith("/static/") else ""
            asset = (base / relative).resolve()
            if not asset.is_relative_to(base) or not asset.is_file():
                self._send(404, b"not found")
                return
            content_type = (
                "text/css" if asset.suffix == ".css"
                else "application/javascript" if asset.suffix == ".js"
                else "application/octet-stream"
            )
            self._send(200, asset.read_bytes(), content_type)

    return Handler
