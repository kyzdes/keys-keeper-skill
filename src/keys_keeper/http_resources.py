"""Small, shared resource limits for the local admin and remote HTTP services.

Admission happens before creating a thread. Request input uses an absolute
deadline, so sending one byte just before each socket timeout cannot keep a
handler alive indefinitely. No tokens, request bodies or client errors are
retained by these limits.
"""
from __future__ import annotations

import io
import math
import socket
import threading
import time
from http.server import ThreadingHTTPServer


class _DeadlineSocketReader(io.RawIOBase):
    def __init__(self, connection, seconds, closing=None):
        super().__init__()
        self.connection = connection
        self.seconds = seconds
        self.closing = closing
        self.begin_request()

    def begin_request(self):
        self.deadline = time.monotonic() + self.seconds

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.closing is not None and self.closing.is_set():
            raise ConnectionAbortedError("server is closing")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request input deadline exceeded")
        self.connection.settimeout(remaining)
        received = self.connection.recv_into(buffer)
        # Shutdown can return EOF after only part of the HTTP headers arrived.
        # Do not let the parser dispatch that unfinished request during close.
        if self.closing is not None and self.closing.is_set():
            raise ConnectionAbortedError("server is closing")
        return received


class RequestDeadlineMixin:
    """Place before BaseHTTPRequestHandler in the handler's inheritance list."""

    def setup(self):
        super().setup()
        seconds = float(getattr(self.server, "request_timeout", 15))
        if not math.isfinite(seconds) or not 0 < seconds <= 300:
            raise ValueError("invalid request deadline")
        self.rfile.close()
        self._deadline_reader = _DeadlineSocketReader(
            self.connection, seconds, getattr(self.server, "_closing", None)
        )
        self.rfile = io.BufferedReader(self._deadline_reader)

    def handle_one_request(self):
        closing = getattr(self.server, "_closing", None)
        if closing is not None and closing.is_set():
            self.close_connection = True
            return
        # HTTP/1.1 keep-alive gets a fresh bounded budget per request. Waiting
        # for the next request is included, and admission remains bounded.
        self._deadline_reader.begin_request()
        self.connection.settimeout(self._deadline_reader.seconds)
        try:
            super().handle_one_request()
        except ConnectionError:
            self.close_connection = True


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound accepted handlers; reject excess sockets without another thread."""

    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, max_workers=16, request_timeout=15, **kwargs):
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 128:
            raise ValueError("invalid handler limit")
        if not math.isfinite(request_timeout) or not 0 < request_timeout <= 300:
            raise ValueError("invalid request deadline")
        self.request_timeout = request_timeout
        self._capacity = threading.BoundedSemaphore(max_workers)
        self._connections = set()
        self._connection_lock = threading.Lock()
        self._closing = threading.Event()
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if self._closing.is_set() or not self._capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        with self._connection_lock:
            if self._closing.is_set():
                self._capacity.release()
                self.shutdown_request(request)
                return
            self._connections.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._connection_lock:
                self._connections.discard(request)
            self._capacity.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            if self._closing.is_set():
                self.shutdown_request(request)
                return
            super().process_request_thread(request, client_address)
        finally:
            with self._connection_lock:
                self._connections.discard(request)
            self._capacity.release()

    def handle_error(self, request, client_address):
        # Closing owned sockets is expected cancellation, not a traceback for
        # every idle client. In-flight application failures still use the
        # server's ordinary error reporting.
        if not self._closing.is_set():
            super().handle_error(request, client_address)

    def server_close(self):
        self._closing.set()
        with self._connection_lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            # The handler owns close in process_request_thread's finally.
            # Invalidating its fd while another thread is in timeout/select
            # can lose the shutdown wakeup on macOS or race descriptor reuse.
        super().server_close()
