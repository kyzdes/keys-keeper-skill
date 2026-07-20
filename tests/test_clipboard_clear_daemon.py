from __future__ import annotations

import hashlib
import io
import subprocess

from keys_keeper import _clipboard_clear_daemon as daemon
from keys_keeper import clipboard


def test_spawn_clear_passes_digest_through_pipe_not_argv(monkeypatch):
    expected_hash = hashlib.sha256(b"short-secret").hexdigest()
    captured: dict = {}

    class RecordingPipe:
        def __init__(self):
            self.data = bytearray()
            self.closed = False

        def write(self, value):
            self.data.extend(value)

        def flush(self):
            pass

        def close(self):
            self.closed = True

    class FakeProcess:
        def __init__(self):
            self.stdin = RecordingPipe()

    process = FakeProcess()

    def fake_popen(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return process

    monkeypatch.setattr(clipboard.subprocess, "Popen", fake_popen)
    clipboard.spawn_clear_after(expected_hash, 30)

    assert expected_hash not in captured["args"]
    assert captured["args"][-1] == "30"
    assert captured["kwargs"]["stdin"] is subprocess.PIPE
    assert bytes(process.stdin.data) == expected_hash.encode("ascii") + b"\n"
    assert process.stdin.closed


def test_daemon_reads_digest_before_sleep_and_clears_matching_value(monkeypatch):
    value = "clipboard-value"
    expected_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    events = []

    monkeypatch.setattr(daemon.sys, "stdin", io.StringIO(expected_hash + "\n"))
    monkeypatch.setattr(daemon.time, "sleep", lambda delay: events.append(("sleep", delay)))
    monkeypatch.setattr(clipboard, "read", lambda: value)
    monkeypatch.setattr(clipboard, "clear", lambda: events.append(("clear", None)))

    assert daemon.main(["clipboard-clear", "5"]) == 0
    assert events == [("sleep", 5), ("clear", None)]


def test_daemon_rejects_missing_or_malformed_pipe_digest(monkeypatch):
    monkeypatch.setattr(daemon.sys, "stdin", io.StringIO("not-a-digest\n"))
    assert daemon.main(["clipboard-clear", "5"]) == 2

    monkeypatch.setattr(daemon.sys, "stdin", io.StringIO(""))
    assert daemon.main(["clipboard-clear", "5"]) == 2
