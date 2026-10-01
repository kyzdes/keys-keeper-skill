"""Provider hangs and repeated UI copies use no real clipboard or keychain."""
import hashlib
import subprocess
from types import SimpleNamespace

import pytest

from keys_keeper import api, backend_linux, clipboard
from keys_keeper.backend import KeychainError


@pytest.mark.parametrize("operation", ["get", "set", "delete", "list_ids"])
def test_secret_service_helpers_have_deadlines_and_redact_provider_failure(monkeypatch, operation):
    monkeypatch.setattr(backend_linux, "_secret_tool_path", lambda: "/synthetic/secret-tool")
    calls = []

    def hung(command, **kwargs):
        calls.append(kwargs)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="synthetic-secret")

    monkeypatch.setattr(backend_linux.subprocess, "run", hung)
    backend = backend_linux.SecretToolBackend()
    with pytest.raises(KeychainError) as exc:
        getattr(backend, operation)(*({"get": ["id"], "set": ["id", "synthetic-secret"],
                                    "delete": ["id"], "list_ids": []}[operation]))
    assert calls[0]["timeout"] == 10
    assert "synthetic-secret" not in str(exc.value)
    assert exc.value.__suppress_context__


@pytest.mark.parametrize("operation", ["set", "list_ids"])
def test_secret_service_does_not_echo_failed_provider_stderr(monkeypatch, operation):
    monkeypatch.setattr(backend_linux, "_secret_tool_path", lambda: "/synthetic/secret-tool")
    monkeypatch.setattr(backend_linux.subprocess, "run",
                        lambda *args, **kwargs: SimpleNamespace(returncode=2, stderr="synthetic-secret"))
    with pytest.raises(KeychainError) as exc:
        backend = backend_linux.SecretToolBackend()
        getattr(backend, operation)(*(["id", "value"] if operation == "set" else []))
    assert "synthetic-secret" not in str(exc.value)


def test_clipboard_helper_deadline_and_fixed_failure(monkeypatch):
    def hung(command, **kwargs):
        assert kwargs["timeout"] == 10
        raise subprocess.TimeoutExpired(command, 10, output="synthetic-secret")
    monkeypatch.setattr(clipboard.subprocess, "run", hung)
    with pytest.raises(clipboard.ClipboardUnavailable, match="failed or timed out") as exc:
        clipboard._run_clipboard(["synthetic-copy"], input="synthetic-secret", text=True)
    assert "synthetic-secret" not in str(exc.value)


def test_ui_copy_scheduler_retains_one_thread_and_latest_deadline(monkeypatch):
    started = []
    clock = [10.]
    class Thread:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
        def start(self):
            started.append(self)
    monkeypatch.setattr(clipboard.threading, "Thread", Thread)
    monkeypatch.setattr(clipboard.time, "monotonic", lambda: clock[0])
    scheduler = clipboard._ClearScheduler()
    for i in range(1000):
        scheduler.schedule(str(i), 30)
    assert len(started) == 1
    assert scheduler.pending == ("999", 40.)
    clock[0] = 39.
    assert scheduler._take_due() is None
    scheduler.schedule("latest", 30)
    clock[0] = 40.
    assert scheduler._take_due() is None
    clock[0] = 69.
    assert scheduler._take_due() == "latest"
    assert scheduler.pending is None
    scheduler.schedule("cancelled", 30)
    scheduler.schedule("no-timer", 0)
    clock[0] = 999.
    assert scheduler._take_due() is None
    assert len(started) == 1


def test_clear_scheduler_preserves_replaced_clipboard_and_ignores_provider_failure(monkeypatch):
    events = []
    digest = hashlib.sha256(b"original").hexdigest()
    monkeypatch.setattr(clipboard, "clear", lambda: events.append("cleared"))
    monkeypatch.setattr(clipboard, "read", lambda: "replacement")
    clipboard._clear_if_matching(digest)
    assert events == []
    monkeypatch.setattr(clipboard, "read", lambda: "original")
    clipboard._clear_if_matching(digest)
    assert events == ["cleared"]
    def unavailable():
        raise clipboard.ClipboardUnavailable("helper timeout")
    monkeypatch.setattr(clipboard, "read", unavailable)
    clipboard._clear_if_matching(digest)
    assert events == ["cleared"]


@pytest.mark.parametrize("delay", [-1, True, 0.5, 86401, 10 ** 300])
def test_invalid_clipboard_delay_cannot_spawn_or_schedule(monkeypatch, delay):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid delay spawned a helper")
    monkeypatch.setattr(clipboard.subprocess, "Popen", unexpected)
    with pytest.raises(ValueError):
        clipboard.spawn_clear_after("a" * 64, delay)
    scheduler = clipboard._ClearScheduler()
    with pytest.raises(ValueError):
        scheduler.schedule("a" * 64, delay)
    assert scheduler.thread is None and scheduler.pending is None


@pytest.mark.parametrize("query", ["limit=-1", "limit=0", "limit=2001", "limit=bad",
                                  "limit=1&limit=2"])
def test_audit_bad_limits_fail_before_resolving_profile(monkeypatch, query):
    responses = []
    handler = SimpleNamespace(_send_json=lambda code, body: responses.append((code, body)))
    def unexpected(*args):
        raise AssertionError("invalid query reached profile")
    monkeypatch.setattr(api, "_context", unexpected)
    api._audit(handler, None, query)
    assert responses[0][0] == 400


def test_audit_budget_exhaustion_is_explicit(monkeypatch):
    from keys_keeper.audit import AuditReadLimit
    responses = []
    def oversized(**kwargs):
        raise AuditReadLimit()
    monkeypatch.setattr(api, "_context", lambda *args: SimpleNamespace(audit=SimpleNamespace(search=oversized)))
    handler = SimpleNamespace(_send_json=lambda code, body: responses.append((code, body)))
    api._audit(handler, None, "limit=1")
    assert responses[0][0] == 413
