"""Real sockets verify bounded admission, slow input, and local-server cleanup."""
import socket
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from keys_keeper.http_resources import BoundedThreadingHTTPServer, RequestDeadlineMixin
from keys_keeper import http_resources
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
        server.shutdown()
        server.server_close()
        wait_for(lambda: not server._connections)


def test_close_preserves_receiving_fd_until_owner_exits_and_cancels_partial_dispatch(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = http_resources._DeadlineSocketReader.readinto
    app_work = Mock()
    monkeypatch.setattr(EchoHandler, 'do_GET', lambda self: app_work())
    def paused_read(reader, buffer):
        entered.set()
        assert release.wait(2), 'receiving owner was not released'
        return original(reader, buffer)
    monkeypatch.setattr(http_resources._DeadlineSocketReader, 'readinto', paused_read)
    with listener(timeout=10) as server, connect(server) as peer:
        try:
            peer.sendall(b'GET / HTTP/1.1\r\nX-Incomplete: ')
            assert entered.wait(1)
            accepted, = server._connections
            descriptor = accepted.fileno()
            assert descriptor >= 0
            server.shutdown()
            server.server_close()
            # Only the owner may invalidate its receive descriptor. Immediate
            # cross-thread close would deterministically violate this contract.
            assert accepted.fileno() == descriptor
        finally:
            release.set()
        wait_for(lambda: not server._connections)
        assert accepted.fileno() == -1
        app_work.assert_not_called()
        assert server._capacity.acquire(blocking=False)
        server._capacity.release()


def test_close_before_queued_handler_starts_skips_handler_construction_and_releases_slot(monkeypatch):
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler,
                                       max_workers=1, request_timeout=10)
    queued = []
    finish = Mock(side_effect=AssertionError('closed queued request constructed handler'))
    monkeypatch.setattr(server, 'finish_request', finish)
    try:
        with connect(server) as peer:
            accepted, address = server.socket.accept()
            with monkeypatch.context() as held:
                held.setattr(threading.Thread, 'start', lambda thread: queued.append(thread))
                server.process_request(accepted, address)
            assert len(queued) == 1 and accepted in server._connections
            server.server_close()
            queued[0].start()
            queued[0].join(1)
            assert not queued[0].is_alive()
            assert accepted.fileno() == -1 and not server._connections
            finish.assert_not_called()
            assert server._capacity.acquire(blocking=False)
            server._capacity.release()
    finally:
        server.server_close()


def test_close_does_not_dispatch_next_keepalive_request_already_in_read_buffer(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    app_work = Mock()
    def first_request(handler):
        app_work()
        entered.set()
        assert release.wait(2), 'in-flight application work was not released'
    monkeypatch.setattr(EchoHandler, 'do_GET', first_request)
    with listener(timeout=10) as server, connect(server) as peer:
        try:
            request = b'GET / HTTP/1.1\r\nHost: synthetic\r\n\r\n'
            peer.sendall(request + request)
            assert entered.wait(1)
            server.shutdown()
            server.server_close()
        finally:
            release.set()
        wait_for(lambda: not server._connections)
        app_work.assert_called_once()


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


def test_cancellation_wakes_all_select_waiters_and_retains_reader_until_last_owner(monkeypatch):
    app_work = Mock()
    monkeypatch.setattr(EchoHandler, 'do_GET', lambda self: app_work())
    waiting, release_last, last_finished = threading.Condition(), threading.Event(), threading.Event()
    blocked, last_owner = set(), []
    original_select = http_resources.select.select
    with listener(workers=4, timeout=10) as server:
        cancel_reader, cancel_writer = server._cancel_reader, server._cancel_writer

        def observed_select(reading, writing, errors, timeout=None):
            if cancel_reader in reading and not any(original_select(reading, writing, errors, 0)):
                with waiting:
                    blocked.add(threading.get_ident())
                    waiting.notify_all()
            return original_select(reading, writing, errors, timeout)

        monkeypatch.setattr(http_resources.select, 'select', observed_select)
        finish_request = server.finish_request

        def retain_last_owner(request, address):
            try:
                finish_request(request, address)
            finally:
                if last_owner and request is last_owner[0]:
                    last_finished.set()
                    assert release_last.wait(2), 'last admitted owner was not released'

        monkeypatch.setattr(server, 'finish_request', retain_last_owner)
        peers = [connect(server) for _ in range(4)]
        try:
            for peer in peers:
                peer.sendall(b'GET / HTTP/1.1\r\nX-Incomplete: ')
            with waiting:
                assert waiting.wait_for(lambda: len(blocked) == 4, timeout=1)
            assert len(server._connections) == 4
            last_owner.append(next(iter(server._connections)))
            server.shutdown()
            server.server_close()
            assert last_finished.wait(1)
            wait_for(lambda: server._connections == {last_owner[0]})
            assert cancel_writer.fileno() == -1
            assert cancel_reader.fileno() >= 0
            app_work.assert_not_called()
            release_last.set()
            wait_for(lambda: not server._connections)
            assert cancel_reader.fileno() == -1
            assert server._capacity.acquire(blocking=False)
            server._capacity.release()
        finally:
            release_last.set()
            for peer in peers:
                peer.close()


def test_cancellation_queued_owner_keeps_reader_until_thread_exits(monkeypatch):
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler,
                                       max_workers=1, request_timeout=10)
    cancel_reader, cancel_writer = server._cancel_reader, server._cancel_writer
    queued, finish = [], Mock()
    monkeypatch.setattr(server, 'finish_request', finish)
    try:
        with connect(server):
            accepted, address = server.socket.accept()
            with monkeypatch.context() as held:
                held.setattr(threading.Thread, 'start', lambda thread: queued.append(thread))
                server.process_request(accepted, address)
            assert len(queued) == 1 and server._connections == {accepted}
            server.server_close()
            assert cancel_writer.fileno() == -1 and cancel_reader.fileno() >= 0
            assert accepted.fileno() >= 0
            queued[0].start()
            queued[0].join(1)
            assert not queued[0].is_alive()
            assert accepted.fileno() == -1 and cancel_reader.fileno() == -1
            assert not server._connections
            finish.assert_not_called()
    finally:
        server.server_close()


def test_cancellation_no_handlers_and_idempotent_close_release_both_sockets():
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler)
    cancel_reader, cancel_writer = server._cancel_reader, server._cancel_writer
    assert cancel_reader.fileno() >= 0 and cancel_writer.fileno() >= 0
    server.server_close()
    server.server_close()
    assert server.socket.fileno() == cancel_reader.fileno() == cancel_writer.fileno() == -1


def test_cancellation_pair_construction_failure_closes_bound_listener(monkeypatch):
    bound = []
    failure = OSError('synthetic cancellation socket exhaustion')

    class CaptureBoundServer(BoundedThreadingHTTPServer):
        def server_bind(self):
            super().server_bind()
            bound.append(self.socket)

    monkeypatch.setattr(http_resources.socket, 'socketpair', Mock(side_effect=failure))
    with pytest.raises(OSError) as caught:
        CaptureBoundServer(('127.0.0.1', 0), EchoHandler)
    assert caught.value is failure
    assert len(bound) == 1 and bound[0].fileno() == -1


@pytest.mark.parametrize('stage', ['server_bind', 'server_activate'])
def test_cancellation_bind_activate_failure_preserves_original_exception(monkeypatch, stage):
    owned = []
    failure = OSError('synthetic listener setup failure')

    def fail_setup(server):
        owned.append(server.socket)
        raise failure

    class FailureServer(BoundedThreadingHTTPServer):
        pass

    monkeypatch.setattr(FailureServer, stage, fail_setup)
    make_pair = Mock(side_effect=AssertionError('pair created before listener setup completed'))
    monkeypatch.setattr(http_resources.socket, 'socketpair', make_pair)
    with pytest.raises(OSError) as caught:
        FailureServer(('127.0.0.1', 0), EchoHandler)
    assert caught.value is failure
    assert len(owned) == 1 and owned[0].fileno() == -1
    make_pair.assert_not_called()


def _synthetic_tls_context(tmp_path):
    import ssl
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    certificate_file, key_file = tmp_path / 'synthetic-cert.pem', tmp_path / 'synthetic-key.pem'
    certificate_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_file, key_file)
    return context


@pytest.mark.parametrize('fragment', ['handshake', 'record'])
def test_cancellation_tls_partial_handshake_or_record_wakes_without_dispatch(tmp_path, monkeypatch, fragment):
    import ssl

    app_work, armed, blocked = Mock(), threading.Event(), threading.Event()
    monkeypatch.setattr(EchoHandler, 'do_GET', lambda self: app_work())
    context = _synthetic_tls_context(tmp_path)
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler, request_timeout=10)
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    cancel_reader, cancel_writer = server._cancel_reader, server._cancel_writer
    original_select = http_resources.select.select

    def observed_select(reading, writing, errors, timeout=None):
        if (armed.is_set() and cancel_reader in reading
                and not any(original_select(reading, writing, errors, 0))):
            blocked.set()
        return original_select(reading, writing, errors, timeout)

    monkeypatch.setattr(http_resources.select, 'select', observed_select)
    serving = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01})
    serving.start()
    try:
        with connect(server) as peer:
            if fragment == 'handshake':
                armed.set()
                # TLS header declares 16 handshake bytes; only one is supplied.
                peer.sendall(b'\x16\x03\x01\x00\x10\x01')
            else:
                client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                client.check_hostname = False
                client.verify_mode = ssl.CERT_NONE
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                tls = client.wrap_bio(incoming, outgoing, server_hostname='localhost')
                for _ in range(10):
                    try:
                        tls.do_handshake()
                    except ssl.SSLWantReadError:
                        peer.sendall(outgoing.read())
                        incoming.write(peer.recv(64 * 1024))
                    else:
                        peer.sendall(outgoing.read())
                        break
                else:
                    pytest.fail('synthetic TLS handshake exceeded bounded steps')
                tls.write(b'GET / HTTP/1.1\r\nHost: synthetic\r\n\r\n')
                encrypted = outgoing.read()
                assert len(encrypted) > 6
                armed.set()
                peer.sendall(encrypted[:6])
            assert blocked.wait(1), 'partial TLS input did not reach a cancellable wait'
            server.shutdown()
            server.server_close()
            wait_for(lambda: not server._connections)
            assert cancel_reader.fileno() == cancel_writer.fileno() == -1
            app_work.assert_not_called()
    finally:
        server.shutdown()
        server.server_close()
        serving.join(2)
        assert not serving.is_alive()


def test_cancellation_thread_start_failure_during_close_releases_last_reader_and_slot(monkeypatch):
    server = BoundedThreadingHTTPServer(('127.0.0.1', 0), EchoHandler, max_workers=1)
    cancel_reader, cancel_writer = server._cancel_reader, server._cancel_writer
    failure = RuntimeError('synthetic thread start failure during cancellation')
    try:
        with connect(server):
            accepted, address = server.socket.accept()

            def fail_start(thread):
                assert server._connections == {accepted}
                server.server_close()
                assert cancel_writer.fileno() == -1 and cancel_reader.fileno() >= 0
                raise failure

            with monkeypatch.context() as exhausted:
                exhausted.setattr(threading.Thread, 'start', fail_start)
                with pytest.raises(RuntimeError) as caught:
                    server.process_request(accepted, address)
            assert caught.value is failure
            assert accepted.fileno() == cancel_reader.fileno() == -1
            assert not server._connections
            assert server._capacity.acquire(blocking=False)
            server._capacity.release()
    finally:
        server.server_close()
