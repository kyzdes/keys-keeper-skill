"""Localhost admin HTTP server with token auth."""

from __future__ import annotations

import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from keys_keeper.paths import Paths

_MAX_BODY_BYTES = 8 * 1024 * 1024
_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}


class AdminServer:
    """Wraps ThreadingHTTPServer with idle-timeout auto-shutdown and a generated session token."""

    def __init__(self, *, paths: Paths, port: int = 7777, idle_timeout_sec: int = 900,
                 profile_selector: str | None = None, project_runtime=None):
        self.paths = paths
        self.profile_selector = profile_selector
        self.project_runtime = project_runtime
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
        self._server = ThreadingHTTPServer(
            ("127.0.0.1", self.requested_port), handler_cls
        )
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


_GET_PAGE_HANDLERS = {
    "/": "_serve_dashboard",
    "/index.html": "_serve_dashboard",
    "/new": "_serve_new",
    "/paste": "_serve_bulk_paste",
    "/audit": "_serve_audit",
    "/settings": "_serve_settings",
    "/projects": "_serve_projects",
}


class _AdminRequestHandler(BaseHTTPRequestHandler):
    admin: AdminServer
    paths: Paths

    # Silence default noisy logging during tests.
    def log_message(self, fmt: str, *args) -> None:
        return

    # ---- helpers ----

    def _session_cookie_name(self) -> str:
        # Cookies are scoped to hosts, not ports. A port suffix prevents
        # two simultaneous local admin instances from overwriting each
        # other's session capability.
        return f"kk_session_{self.admin.bound_port}"

    def _verify_token(self) -> bool:
        # Accept token via header (fetch/XHR) or session cookie (browser
        # nav). The ?t=TOKEN query form is accepted ONLY on the initial
        # HTML bootstrap (GET / or /index.html) so that a leaked URL
        # (screenshot, browser history sync, address-bar autocomplete,
        # malicious extension reading window.location) cannot directly
        # call /api/* endpoints.
        header_token = self.headers.get("Sec-Keys-Token")
        if header_token == self.admin.token:
            self._auth_ok = True
            return True
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            key, _, value = part.strip().partition("=")
            if key == self._session_cookie_name() and value == self.admin.token:
                self._auth_ok = True
                return True
        parsed = urlparse(self.path)
        if self.command == "GET" and parsed.path in ("/", "/index.html"):
            qs = parse_qs(parsed.query)
            if qs.get("t", [""])[0] == self.admin.token:
                self._auth_ok = True
                return True
        return False

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str = "text/html; charset=utf-8",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in _NO_CACHE_HEADERS.items():
            self.send_header(key, value)
        # On every authenticated response, refresh the session cookie so subsequent
        # browser navigation (regular <a href> clicks) carries auth without needing
        # JS to inject the Sec-Keys-Token header.
        if getattr(self, "_auth_ok", False):
            self.send_header(
                "Set-Cookie",
                f"{self._session_cookie_name()}={self.admin.token}; "
                "HttpOnly; SameSite=Strict; Path=/",
            )
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status: int, payload: dict | list) -> None:
        data = json.dumps(payload).encode("utf-8")
        self._send(status, data, "application/json")

    def _read_request_body(self) -> bytes | None:
        if self.headers.get("Transfer-Encoding"):
            self._send_json(400, {"error": "transfer-encoding is unsupported"})
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            return b""
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            self._send_json(400, {"error": "bad content-length"})
            return None
        if length < 0:
            self._send_json(400, {"error": "bad content-length"})
            return None
        if length > _MAX_BODY_BYTES:
            self._send_json(413, {"error": "request body too large"})
            return None
        return self.rfile.read(length) if length else b""

    # ---- routing ----

    def do_GET(self) -> None:
        self.admin.heartbeat()
        path = urlparse(self.path).path
        # Static assets (CSS / JS) are public — they hold no secrets and the
        # browser cannot attach our session header to <link>/<script> requests.
        if path.startswith("/static/"):
            self._serve_static(path)
            return
        if not self._verify_token():
            self._send(403, b"forbidden")
            return
        self._dispatch_authenticated_get(path)

    def _dispatch_authenticated_get(self, path: str) -> None:
        page_handler = _GET_PAGE_HANDLERS.get(path)
        if page_handler is not None:
            try:
                getattr(self, page_handler)()
            except (ValueError, RuntimeError) as ex:
                # Profile resolution is metadata-only, but an unknown selector
                # must still be a normal client error rather than a handler
                # crash (and never reach a backend).
                self._send(400, f"bad profile selection: {ex}".encode("utf-8"))
            return
        if path.startswith("/api/"):
            self._handle_api("GET", body=None)
            return
        if path.startswith("/entry/"):
            self._serve_entry_path(path)
            return
        self._send(404, b"not found")

    def do_POST(self) -> None:
        self._handle_api_write("POST", read_body=True)

    def do_DELETE(self) -> None:
        self._handle_api_write("DELETE", read_body=False)

    def do_PATCH(self) -> None:
        self._handle_api_write("PATCH", read_body=True)

    def _handle_api_write(self, method: str, *, read_body: bool) -> None:
        self.admin.heartbeat()
        if not self._verify_token():
            self._send(403, b"forbidden")
            return
        body = self._read_request_body() if read_body else None
        if read_body and body is None:
            return
        self._handle_api(method, body=body)

    def _handle_api(self, method: str, *, body: bytes | None) -> None:
        from keys_keeper.api import handle_api

        # Pass full self.path (with query) so /api/audit?limit=… etc work.
        handle_api(self, paths=self.paths, method=method, path=self.path, body=body,
                   runtime=self.admin.project_runtime,
                   server_selector=self.admin.profile_selector)

    # ---- pages ----

    def _serve_dashboard(self) -> None:
        from keys_keeper.pages import render_dashboard

        html = render_dashboard(paths=self.paths, token=self.admin.token,
                                context=self._context_for_page())
        self._send(200, html.encode("utf-8"))

    def _serve_new(self) -> None:
        from keys_keeper.pages import render_new_edit

        context = self._context_for_page()
        if context.kind == "master_scope":
            self._send(403, b"project profile is read-only")
            return
        html = render_new_edit(paths=self.paths, token=self.admin.token, context=context)
        self._send(200, html.encode("utf-8"))

    def _serve_bulk_paste(self) -> None:
        from keys_keeper.pages import render_bulk_paste

        context = self._context_for_page()
        if context.kind != "master":
            self._send(403, b"bulk import requires the master profile")
            return
        html = render_bulk_paste(paths=self.paths, token=self.admin.token, context=context)
        self._send(200, html.encode("utf-8"))

    def _serve_audit(self) -> None:
        from keys_keeper.pages import render_audit

        html = render_audit(paths=self.paths, token=self.admin.token,
                            context=self._context_for_page())
        self._send(200, html.encode("utf-8"))

    def _serve_settings(self) -> None:
        from keys_keeper.pages import render_settings

        html = render_settings(paths=self.paths, token=self.admin.token,
                               context=self._context_for_page())
        self._send(200, html.encode("utf-8"))

    def _serve_projects(self) -> None:
        from keys_keeper.pages import render_projects

        html = render_projects(paths=self.paths, token=self.admin.token,
                               context=self._context_for_page())
        self._send(200, html.encode("utf-8"))

    def _serve_entry_path(self, path: str) -> None:
        edit = path.endswith("/edit")
        suffix = (
            path[len("/entry/") : -len("/edit")] if edit else path[len("/entry/") :]
        )
        context = self._context_for_page()
        entry = self._find_entry(unquote(suffix), context)
        if entry is None:
            self._send(404, b"entry not found")
            return
        if edit:
            self._serve_entry_edit(entry, context)
            return
        self._serve_entry_detail(entry)

    def _context_for_page(self):
        from keys_keeper.composition import AccessContext
        from keys_keeper.project_runtime import ProjectRuntime
        from keys_keeper.api import _selector

        runtime = self.admin.project_runtime
        if runtime is None:
            runtime = ProjectRuntime(self.paths, access=AccessContext.UI_FORBIDDEN)
        return runtime.context(_selector(urlparse(self.path), self.admin.profile_selector))

    @staticmethod
    def _find_entry(identifier: str, context):
        return context.store.get_by_id(identifier) or context.store.get_by_name(identifier)

    def _serve_entry_edit(self, entry, context) -> None:
        from keys_keeper.pages import render_new_edit

        if context.kind != "master":
            self._serve_entry_detail(entry, context)
            return
        html = render_new_edit(paths=self.paths, token=self.admin.token, entry=entry, context=context)
        self._send(200, html.encode("utf-8"))

    def _serve_entry_detail(self, entry, context=None) -> None:
        from keys_keeper.pages import render_entry_detail

        html = render_entry_detail(
            paths=self.paths, token=self.admin.token, entry=entry,
            context=context or self._context_for_page(),
        )
        self._send(200, html.encode("utf-8"))

    def _serve_static(self, path: str) -> None:
        base = (Path(__file__).parent / "static").resolve()
        # Anchor the join from `base` so any traversal segments (../)
        # resolve relative to the static dir, then verify containment via
        # `is_relative_to` (NOT string prefix — `startswith` would match
        # sibling dirs whose name begins with "static").
        relative = path[len("/static/") :] if path.startswith("/static/") else ""
        asset = (base / relative).resolve()
        if not asset.is_relative_to(base) or not asset.is_file():
            self._send(404, b"not found")
            return
        content_types = {
            ".css": "text/css",
            ".js": "application/javascript",
            ".svg": "image/svg+xml",
        }
        content_type = content_types.get(asset.suffix, "application/octet-stream")
        self._send(200, asset.read_bytes(), content_type)


def make_handler(admin: AdminServer):
    class Handler(_AdminRequestHandler):
        pass

    Handler.admin = admin
    Handler.paths = admin.paths
    return Handler
