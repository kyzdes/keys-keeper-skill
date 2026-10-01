"""Real remote handlers reject allocating work before auth and expire drips."""
import http.client
import socket
import threading
import time
from contextlib import contextmanager

import pytest

from keys_keeper.sync_server import SyncServerApp, create_http_server
from keys_keeper.webvault.server import WebVaultServer


@contextmanager
def listener(server):
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize("path,headers,status", [
    ("/v1/vaults", {}, 401), ("/v1/vaults/unknown/commits", {}, 401),
    ("/v1/not-real", {}, 404),
    ("/v1/vaults", {"Authorization": "Bearer synthetic-admin"}, 413),
])
def test_v1_preflight_rejects_no_body_requests_immediately(tmp_path, path, headers, status):
    app = SyncServerApp(tmp_path / "relay.sqlite3", "synthetic-admin")
    with listener(create_http_server(app)) as server:
        connection = http.client.HTTPConnection(*server.server_address, timeout=1)
        try:
            connection.putrequest("POST", path)
            for name, value in headers.items():
                connection.putheader(name, value)
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", str(1024 * 1024))
            connection.endheaders()  # No body: an allocating read would hang.
            response = connection.getresponse()
            assert response.status == status
            response.read()
        finally:
            connection.close()


@pytest.mark.parametrize("kind", ["sync", "webvault"])
@pytest.mark.parametrize("part", ["headers", "body"])
def test_real_handlers_cumulative_input_deadline_defeats_drip(tmp_path, kind, part):
    if kind == "sync":
        server = create_http_server(SyncServerApp(tmp_path / "relay.sqlite3", "synthetic-admin"))
        path, auth = "/v1/vaults", b"Authorization: Bearer synthetic-admin\r\n"
    else:
        server = WebVaultServer(data_dir=tmp_path / "web", port=0).create_http_server()
        path, auth = "/auth/params", b""
    server.request_timeout = .2
    with listener(server), socket.create_connection(server.server_address, timeout=1) as peer:
        prefix = (f"POST {path} HTTP/1.1\r\nHost: synthetic\r\n".encode() + auth)
        if part == "body":
            prefix += b"Content-Type: application/json\r\nContent-Length: 100\r\n\r\n"
        else:
            prefix += b"X-Drip: "
        peer.sendall(prefix)
        started = time.monotonic()
        for _ in range(15):
            try:
                peer.sendall(b"a")
            except OSError:
                break
            time.sleep(.03)
        received = b""
        while True:
            try:
                chunk = peer.recv(1024)
            except ConnectionResetError:
                # An unread request can close with TCP RST; both RST and EOF
                # prove the admitted handler stopped, unlike a read timeout.
                break
            if not chunk:
                break
            received += chunk
        assert time.monotonic() - started < 1
        assert b"201 Created" not in received and b"200 OK" not in received
        connection = http.client.HTTPConnection(*server.server_address, timeout=1)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            assert response.status == 200
            response.read()
        finally:
            connection.close()


@pytest.mark.parametrize("extra", [b"Content-Length: 2\r\nContent-Length: 2\r\n",
                                   b"Transfer-Encoding: chunked\r\n",
                                   b"Content-Length: -1\r\n"])
def test_webvault_ambiguous_framing_closes_without_body(tmp_path, extra):
    app = WebVaultServer(data_dir=tmp_path / "web", port=0)
    with listener(app.create_http_server()) as server, socket.create_connection(server.server_address, timeout=1) as peer:
        peer.sendall(b"POST /auth/params HTTP/1.1\r\nHost: synthetic\r\n" + extra + b"\r\n")
        received = b""
        while chunk := peer.recv(1024):
            received += chunk
        assert b"400 Bad Request" in received
