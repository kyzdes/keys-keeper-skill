"""The default pytest fixture cannot operate on the OS clipboard."""
import pytest

from keys_keeper import clipboard


def test_default_provider_and_timer_are_in_memory(isolated_clipboard, monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("OS clipboard helper must not run")
    monkeypatch.setattr(clipboard, "_run_clipboard", forbidden)
    assert clipboard.write("synthetic-value") is True
    assert clipboard.read() == "synthetic-value"
    clipboard.schedule_clear_after("a" * 64, 30)
    clipboard.spawn_clear_after("a" * 64, 30)
    assert isolated_clipboard["timers"] == [("a" * 64, 30)]
    clipboard.clear()
    assert clipboard.read() == ""


@pytest.fixture
def subprocess_cleanup_observer():
    """Model a resource cleanup which must run after test fault restoration."""
    original_run = clipboard.subprocess.run
    yield
    assert clipboard.subprocess.run is original_run


def test_test_faults_restore_before_resource_cleanup(subprocess_cleanup_observer, monkeypatch):
    calls = []
    monkeypatch.setattr(clipboard.subprocess, "run", lambda command: calls.append(command))
    clipboard.subprocess.run(["synthetic-test-process"])
    assert calls == [["synthetic-test-process"]]
