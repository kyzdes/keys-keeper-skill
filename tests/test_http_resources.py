"""Real sockets verify bounded admission, slow input, and local-server cleanup."""
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest

from keys_keeper.http_resources import BoundedThreadingHTTPServer, RequestDeadlineMixin
from keys_keeper.paths import Paths
from keys_keeper import server as admin_module
from keys_keeper.server import AdminServer


class EchoHandler(RequestDeadlineMixin, BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Length', '2')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_POST(self):
        self.rfile.read(int(self.headers['Content-Length']))
        self.do_GET()


@contextmanager
def listener(*, workers=2, timeout=.25):
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler,
                                       max_workers=workers, request_timeout=timeout)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()


def connect(server):
    return socket.create_connection(('127.0.0.1', server.server_port), timeout=1)


def wait_for(predicate):
    end = time.monotonic() + 2
    while not predicate():
        assert time.monotonic() < end, 'bounded handler did not finish'
        time.sleep(.005)


def test_excess_connections_never_create_another_handler_and_capacity_returns():
    with listener(timeout=.3) as server:
        peers = [connect(server) for _ in range(2)]
        try:
            wait_for(lambda: len(server._connections) == 2)
            with connect(server) as excess:
                assert excess.recv(1) == b''
            assert len(server._connections) == 2
            for peer in peers:
                peer.close()
            wait_for(lambda: not server._connections)
            with connect(server) as normal:
                normal.sendall(b'GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
                assert b'200' in normal.recv(1024)
        finally:
            for peer in peers:
                peer.close()


def test_handler_thread_start_failure_rolls_back_socket_and_slot_before_next_request(monkeypatch):
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler,
                                       max_workers=1, request_timeout=1)
    serving = None
    attempted = []
    try:
        # Accept manually so the injected resource failure is asserted directly,
        # before a serve_forever loop could report/consume its exception.
        with connect(server) as rejected:
            accepted, address = server.socket.accept()
            def cannot_start(thread):
                attempted.append(thread)
                assert accepted in server._connections
                assert not server._capacity.acquire(blocking=False)
                raise RuntimeError("synthetic thread resource exhaustion")
            with monkeypatch.context() as failure:
                failure.setattr(threading.Thread, 'start', cannot_start)
                with pytest.raises(RuntimeError, match="synthetic thread resource exhaustion"):
                    server.process_request(accepted, address)
            assert len(attempted) == 1 and not attempted[0].is_alive()
            assert accepted.fileno() == -1
            assert rejected.recv(1) == b''
            assert not server._connections
            assert server._capacity.acquire(blocking=False)
            server._capacity.release()

        candidate = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
        candidate.start()
        serving = candidate
        with connect(server) as normal:
            normal.sendall(b'GET / HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n')
            response = b''
            while chunk := normal.recv(1024):
                response += chunk
            assert response.startswith(b'HTTP/1.1 200 ')
            assert response.endswith(b'\r\n\r\nok')
        wait_for(lambda: not server._connections)
    finally:
        if serving is not None:
            server.shutdown()
        server.server_close()
        if serving is not None:
            serving.join(2)
            assert not serving.is_alive()


@pytest.mark.parametrize('prefix', [b'GET / HTTP/1.1\r\nX-Slow: ',
                                   b'POST / HTTP/1.1\r\nContent-Length: 10000\r\n\r\n'])
def test_slow_drip_cannot_extend_header_or_body_deadline(prefix):
    with listener(timeout=.18) as server, connect(server) as peer:
        peer.sendall(prefix)
        wait_for(lambda: len(server._connections) == 1)
        start = time.monotonic()
        while time.monotonic() - start < .4:
            try:
                peer.sendall(b'a')
            except OSError:
                break
            time.sleep(.03)
        wait_for(lambda: not server._connections)
        assert time.monotonic() - start < .7


def test_keepalive_requests_each_have_a_new_input_budget():
    with listener(timeout=.3) as server, connect(server) as peer:
        for _ in range(3):
            peer.sendall(b'GET / HTTP/1.1\r\nHost: local\r\n\r\n')
            data = b''
            while b'\r\n\r\nok' not in data:
                data += peer.recv(1024)
            assert b'200' in data
            time.sleep(.12)


def test_server_close_interrupts_owned_incomplete_connections():
    with listener(timeout=10) as server, connect(server) as peer:
        peer.sendall(b'GET / HTTP/1.1\r\n')
        wait_for(lambda: len(server._connections) == 1)
        server.server_close()
        wait_for(lambda: not server._connections)


@pytest.fixture
def admin(tmp_path):
    server = AdminServer(paths=Paths(tmp_path / 'empty-synthetic'), port=0)
    server.start()
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
    finally:
        server.stop()
        thread.join(2)
        assert not thread.is_alive()


def raw_request(admin, headers, body=b''):
    with socket.create_connection(('127.0.0.1', admin.bound_port), timeout=1) as peer:
        peer.sendall((f'POST /api/heartbeat HTTP/1.0\r\nSec-Keys-Token: {admin.token}\r\n'
                      + headers + '\r\n\r\n').encode() + body)
        peer.shutdown(socket.SHUT_WR)
        return peer.recv(4096)


def test_admin_rejects_duplicate_length_and_short_body_before_dispatch(admin):
    assert b'400' in raw_request(admin, 'Content-Length: 2\r\nContent-Length: 1', b'{}')
    assert b'400' in raw_request(admin, 'Content-Length: 10', b'{}')
    assert b'200' in raw_request(admin, 'Content-Length: 2', b'{}')


def test_unauthenticated_and_public_static_requests_do_not_extend_idle_lifetime(admin, monkeypatch):
    before = admin.last_seen
    # Assert which requests refresh activity independently of OS timer resolution.
    # Replace this module's clock, leaving real socket/deadline clocks untouched.
    monkeypatch.setattr(admin_module, 'time', SimpleNamespace(monotonic=lambda: before + 1))
    for path in ('/api/entries', '/static/bootstrap.js'):
        with socket.create_connection(('127.0.0.1', admin.bound_port), timeout=1) as peer:
            peer.sendall(f'GET {path} HTTP/1.0\r\n\r\n'.encode())
            peer.recv(4096)
    assert admin.last_seen == before
    assert b'200' in raw_request(admin, 'Content-Length: 2', b'{}')
    assert admin.last_seen == before + 1


def test_admin_stop_before_serve_is_prompt_and_closes_listener(tmp_path):
    server = AdminServer(paths=Paths(tmp_path / 'empty'), port=0)
    server.start()
    thread = threading.Thread(target=server.stop, daemon=True)
    thread.start()
    thread.join(.5)
    assert not thread.is_alive()
    assert server._server.socket.fileno() == -1
    server.serve_forever()


@pytest.mark.parametrize('workers,timeout', [(0, 1), (129, 1), (True, 1), (1, 0), (1, float('inf'))])
def test_invalid_resource_limits_never_bind(workers, timeout):
    with pytest.raises(ValueError):
        BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler,
                                  max_workers=workers, request_timeout=timeout)
