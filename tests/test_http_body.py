"""Body limits are independent of payload contents and the vault."""
from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

from keys_keeper import http_body


def test_undeclared_large_body_is_stopped_at_limit():
    with pytest.raises(http_body.BodyTooLargeError, match="^response_size_exceeded$"):
        http_body.read_bounded_body(io.BytesIO(b"x" * 1024), max_bytes=16, timeout=1)


def test_trickled_body_cannot_refresh_timeout_each_chunk(monkeypatch):
    current, timeouts = [0.0], []
    class TrickledResponse:
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=timeouts.append)))
        def read1(self, maximum):
            current[0] += 0.4
            return b"x"
    monkeypatch.setattr(http_body.time, "monotonic", lambda: current[0])
    with pytest.raises(TimeoutError, match="^response_deadline_exceeded$"):
        http_body.read_bounded_body(TrickledResponse(), max_bytes=1024, timeout=1)
    assert timeouts == pytest.approx([1.0, 0.6, 0.2])


def test_small_body_is_read_exactly_once():
    assert http_body.read_bounded_body(io.BytesIO(b"synthetic"), max_bytes=16, timeout=1) == b"synthetic"


def test_response_may_close_socket_after_final_chunk():
    class ClosingSocket:
        closed = False
        def fileno(self):
            return -1 if self.closed else 1
        def settimeout(self, seconds):
            assert not self.closed
    socket = ClosingSocket()
    class Response:
        fp = SimpleNamespace(raw=SimpleNamespace(_sock=socket))
        def read1(self, maximum):
            if socket.closed:
                return b""
            socket.closed = True
            return b"complete"
    assert http_body.read_bounded_body(Response(), max_bytes=16, timeout=1) == b"complete"
