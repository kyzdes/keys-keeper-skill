"""Size and elapsed-time bounds for HTTP bodies, including trickled responses."""
from __future__ import annotations

import time


class BodyTooLargeError(ValueError):
    pass


def read_bounded_body(response, *, max_bytes, timeout):
    deadline = time.monotonic() + timeout
    chunks, size = [], 0
    reader = getattr(response, "read1", None) or response.read
    # urllib HTTPResponse exposes its socket here. Updating the remaining read
    # timeout prevents each trickled chunk from receiving a fresh full budget.
    socket = getattr(getattr(getattr(response, "fp", None), "raw", None), "_sock", None)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("response_deadline_exceeded")
        fileno = getattr(socket, "fileno", None)
        if socket is not None and (fileno is None or fileno() >= 0):
            socket.settimeout(remaining)
        data = reader(min(64 * 1024, max_bytes - size + 1))
        if time.monotonic() >= deadline:
            raise TimeoutError("response_deadline_exceeded")
        if not data:
            return b"".join(chunks)
        size += len(data)
        if size > max_bytes:
            raise BodyTooLargeError("response_size_exceeded")
        chunks.append(data)
