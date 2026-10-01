"""Isolated scheduler checks; never invoke the installed secrets manager."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="macOS launchd scheduler uses POSIX locks")


@pytest.fixture
def scheduler():
    path = Path(__file__).parents[1] / "scripts/daily-project-sync.py"
    spec = importlib.util.spec_from_file_location("daily_project_scheduler", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


COMMAND = ["/synthetic/keys", "project-sync", "sync", "--scope",
           "00000000-0000-4000-8000-000000000001"]
JOB = "a" * 64


def test_restart_daily_cap_failure_and_clock_rollback(scheduler, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(scheduler.subprocess, "run",
                        lambda *args, **kwargs: calls.append(args) or SimpleNamespace(returncode=1))
    assert scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000) == ("failed", 1)
    assert scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000 + 86399) == ("deferred", 0)
    assert scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 999) == ("deferred", 0)
    assert len(calls) == 1
    assert scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000 + 86400) == ("failed", 1)
    assert len(calls) == 2


def test_attempt_is_durable_before_child_starts(scheduler, tmp_path, monkeypatch):
    def child(*args, **kwargs):
        assert json.loads((tmp_path / (JOB + ".json")).read_text()) == {"last_attempt": 1000}
        assert kwargs["stdin"] == scheduler.subprocess.DEVNULL
        assert kwargs["stdout"] == scheduler.subprocess.DEVNULL
        assert kwargs["stderr"] == scheduler.subprocess.DEVNULL
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(scheduler.subprocess, "run", child)
    assert scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000) == ("synced", 0)


@pytest.mark.parametrize("content", ["broken", '{"last_attempt":true}', '{"last_attempt":NaN}', '{}',
                                     '{"last_attempt":1000,"last_attempt":0}'])
def test_corrupt_timestamp_fails_closed(scheduler, tmp_path, monkeypatch, content):
    stamp = tmp_path / (JOB + ".json")
    stamp.write_text(content)
    stamp.chmod(0o600)
    monkeypatch.setattr(scheduler.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not sync"))
    with pytest.raises((ValueError, json.JSONDecodeError)):
        scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000)


def test_timestamp_symlink_is_rejected(scheduler, tmp_path, monkeypatch):
    target = tmp_path / "other"
    target.write_text('{"last_attempt":0}')
    (tmp_path / (JOB + ".json")).symlink_to(target)
    monkeypatch.setattr(scheduler.subprocess, "run", lambda *args, **kwargs: pytest.fail("must not sync"))
    with pytest.raises(OSError):
        scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 100000)


def test_concurrent_launches_run_child_once(scheduler, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import time
    count = 0
    gate = threading.Barrier(2)
    def child(*args, **kwargs):
        nonlocal count
        count += 1
        time.sleep(0.03)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(scheduler.subprocess, "run", child)
    def launch():
        gate.wait()
        return scheduler.run_daily(tmp_path, JOB, COMMAND, clock=lambda: 1000)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: launch(), range(2)))
    assert sorted(results) == [("deferred", 0), ("synced", 0)]
    assert count == 1


def test_separate_scopes_run_serially(scheduler, tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    import time
    running = 0
    peak = 0
    gate = threading.Barrier(2)
    def child(*args, **kwargs):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        time.sleep(0.03)
        running -= 1
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(scheduler.subprocess, "run", child)
    def launch(job):
        gate.wait()
        return scheduler.run_daily(tmp_path, job, COMMAND, clock=lambda: 1000)
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(pool.map(launch, [JOB, "b" * 64])) == [("synced", 0)] * 2
    assert peak == 1


def test_unscoped_or_other_commands_rejected(scheduler, tmp_path):
    with pytest.raises(ValueError, match="explicit"):
        scheduler.run_daily(tmp_path, JOB, COMMAND[:3], clock=lambda: 1000)
    with pytest.raises(ValueError, match="explicit"):
        scheduler.run_daily(tmp_path, JOB, [COMMAND[0], "devices", "sync", "--scope", COMMAND[4]])
