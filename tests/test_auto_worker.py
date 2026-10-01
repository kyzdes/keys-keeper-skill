"""Hard deadline checks use harmless synthetic subprocesses, never sync/vaults."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from keys_keeper import auto_worker as worker
from keys_keeper.paths import Paths
from keys_keeper.project_runtime import ProjectRuntime


def test_timeout_reaps_worker_before_return_and_prevents_late_writes(tmp_path, monkeypatch):
    late = tmp_path / "late"
    script = "import time; from pathlib import Path; time.sleep(0.5); Path(" + repr(str(late)) + ").touch()"
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw: [sys.executable, "-c", script])
    processes = []
    original = worker.subprocess.Popen
    def spawn(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process
    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    with pytest.raises(worker.AutoWorkerError, match="^operation_timed_out$"):
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=0.15)
    assert processes[0].poll() is not None
    time.sleep(0.6)
    assert not late.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group regression")
def test_timeout_terminates_descendant_processes(tmp_path, monkeypatch):
    late = tmp_path / "descendant-late"
    ready = tmp_path / "ready"
    descendant = "import time; from pathlib import Path; time.sleep(0.7); Path(" + repr(str(late)) + ").touch()"
    script = ("import subprocess,sys,time; from pathlib import Path; "
              "subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); "
              "Path(" + repr(str(ready)) + ").touch(); time.sleep(10)")
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw: [sys.executable, "-c", script])
    with pytest.raises(worker.AutoWorkerError, match="operation_timed_out"):
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=0.3)
    assert ready.exists()
    time.sleep(0.8)
    assert not late.exists()


def test_failed_worker_never_exposes_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw:
                        [sys.executable, "-c", "import sys; print('SYNTHETIC-PRIVATE'); sys.exit(7)"])
    with pytest.raises(worker.AutoWorkerError, match="^operation_failed$"):
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=2)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


def test_detached_entry_runs_supervisor_and_preserves_explicit_root(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **kw: calls.append((a, kw)))
    worker.start_auto_worker("s3", Paths(tmp_path))
    argv = calls[0][0][0]
    assert argv[1:4] == ["-m", "keys_keeper.auto_worker", "s3"]
    assert argv[-3:] == ["--home", str(tmp_path), "--supervise"]


def test_s3_worker_rechecks_replica_role_before_master_backend(tmp_path, monkeypatch):
    from keys_keeper import cli_sync
    runtime = ProjectRuntime(Paths(tmp_path))
    item = {"id": "00000000-0000-4000-8000-000000000001", "kind": "replica",
            "scope_id": "00000000-0000-4000-8000-000000000002",
            "vault_id": "00000000-0000-4000-8000-000000000003",
            "device_id": "00000000-0000-4000-8000-000000000004",
            "project": "synthetic", "environment": "test", "endpoint": "https://relay.example", "status": "active"}
    runtime.registry.put(item)
    runtime.registry.set_default(item["id"])
    monkeypatch.setattr(cli_sync, "_run_auto_worker", lambda _paths: pytest.fail("replica opened master sync"))
    assert worker.main(["s3", "--home", str(tmp_path)]) == 1


def test_disabled_auto_is_rechecked_before_expensive_worker_setup(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from keys_keeper import cli_sync, personal_sync
    monkeypatch.setattr(cli_sync, "load_sync_config", lambda _paths: SimpleNamespace(mode="off"))
    monkeypatch.setattr(cli_sync, "_build_engine", lambda *_a, **_kw: pytest.fail("disabled S3 opened backend"))
    assert worker.main(["s3", "--home", str(tmp_path)]) == 0
    monkeypatch.setattr(personal_sync, "read_settings", lambda _paths: {"auto": False})
    monkeypatch.setattr(personal_sync.PersonalSync, "sync", lambda *_a: pytest.fail("disabled personal read state"))
    assert worker.main(["personal", "--home", str(tmp_path)]) == 0


@pytest.mark.skipif(os.name != "posix", reason="POSIX terminal-close regression")
def test_terminal_hangup_cancels_worker(tmp_path):
    late, ready = tmp_path / "late", tmp_path / "ready"
    harmless = "import time; from pathlib import Path; time.sleep(0.7); Path(" + repr(str(late)) + ").touch()"
    script = ("import sys; from pathlib import Path; from keys_keeper import auto_worker as w; "
              "from keys_keeper.paths import Paths; "
              "w._arguments=lambda *a,**kw: [sys.executable,'-c'," + repr(harmless) + "]; "
              "original=w.subprocess.Popen; "
              "\ndef spawn(*a,**kw):\n p=original(*a,**kw); Path(" + repr(str(ready)) + ").touch(); return p\n"
              "w.subprocess.Popen=spawn\nw.run_auto_worker('personal',Paths(" + repr(str(tmp_path)) + "),timeout=2)")
    parent = subprocess.Popen([sys.executable, "-c", script], start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < until:
            time.sleep(0.01)
        assert ready.exists()
        os.kill(parent.pid, signal.SIGHUP)
        assert parent.wait(timeout=3) != 0
        time.sleep(0.8)
        assert not late.exists()
    finally:
        if parent.poll() is None:
            os.killpg(parent.pid, signal.SIGKILL)
            parent.wait()


@pytest.mark.skipif(os.name != "posix", reason="POSIX uncatchable-caller-kill regression")
def test_independent_supervisor_keeps_deadline_after_caller_sigkill(tmp_path):
    late, ready = tmp_path / "late", tmp_path / "ready"
    harmless = "import time; from pathlib import Path; time.sleep(0.7); Path(" + repr(str(late)) + ").touch()"
    guardian = ("import sys; from keys_keeper import auto_worker as w; from keys_keeper.paths import Paths; "
                "w._arguments=lambda *a,**kw: [sys.executable,'-c'," + repr(harmless) + "]; "
                "w.run_auto_worker('personal',Paths(" + repr(str(tmp_path)) + "),timeout=0.2,_direct=True)")
    caller = ("import sys; from pathlib import Path; from keys_keeper import auto_worker as w; "
              "from keys_keeper.paths import Paths; "
              "w._arguments=lambda *a,**kw: [sys.executable,'-c'," + repr(guardian) + "]; "
              "original=w.subprocess.Popen; "
              "\ndef spawn(*a,**kw):\n p=original(*a,**kw); Path(" + repr(str(ready)) + ").write_text(str(p.pid)); return p\n"
              "w.subprocess.Popen=spawn\nw.run_auto_worker('personal',Paths(" + repr(str(tmp_path)) + "),timeout=2)")
    parent = subprocess.Popen([sys.executable, "-c", caller], start_new_session=True,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    guardian_pid = None
    try:
        until = time.monotonic() + 3
        while not ready.exists() and time.monotonic() < until:
            time.sleep(0.01)
        assert ready.exists()
        guardian_pid = int(ready.read_text())
        os.kill(parent.pid, signal.SIGKILL)
        parent.wait(timeout=3)
        time.sleep(0.9)
        assert not late.exists()
    finally:
        if parent.poll() is None:
            os.killpg(parent.pid, signal.SIGKILL)
            parent.wait()
        if guardian_pid is not None:
            try:
                os.killpg(guardian_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
