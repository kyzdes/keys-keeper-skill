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
@pytest.mark.parametrize("direct", [False, True], ids=["foreground", "direct"])
def test_timeout_terminates_descendant_processes(tmp_path, monkeypatch, direct):
    late = tmp_path / "descendant-late"
    ready = tmp_path / "ready"
    release = tmp_path / "release"
    descendant = tmp_path / "synthetic_descendant.py"
    parent = tmp_path / "synthetic_parent.py"
    descendant.write_text(
        "import json,os,sys,time\n"
        "from pathlib import Path\n"
        "ready,release,late=map(Path,sys.argv[1:])\n"
        "temporary=ready.with_suffix('.tmp')\n"
        "temporary.write_text(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),'pgid':os.getpgrp()}))\n"
        "temporary.replace(ready)\n"
        "until=time.monotonic()+10\n"
        "while not release.exists():\n"
        "    if time.monotonic()>=until: raise TimeoutError('synthetic release was not received')\n"
        "    time.sleep(0.01)\n"
        "late.touch()\n"
    )
    parent.write_text(
        "import subprocess,sys\n"
        "child=subprocess.Popen([sys.executable,'-I',*sys.argv[1:]])\n"
        "sys.exit(child.wait())\n"
    )
    for script in (descendant, parent):
        compile(script.read_text(), script.name, "exec")
    # Separate argv/files avoid nested -c quoting, and isolated interpreters
    # keep unrelated CI Python environment settings out of this fixture.
    command = [sys.executable, "-I", str(parent), str(descendant), str(ready), str(release), str(late)]
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw: command)
    original_spawn = worker.subprocess.Popen
    processes = []
    diagnostic_path = tmp_path / "synthetic-stderr"
    with diagnostic_path.open("wb", buffering=0) as diagnostics:
        def diagnostic_text():
            return diagnostic_path.read_text(errors="replace")[-8192:]

        def spawn(argv, **kwargs):
            if argv != command:
                return original_spawn(argv, **kwargs)
            assert kwargs["start_new_session"] is True
            # Capture only this allowlisted, stdlib-only synthetic process.
            # Production workers retain DEVNULL and the secrecy test below.
            kwargs["stderr"] = diagnostics
            process = original_spawn(argv, **kwargs)
            processes.append(process)
            try:
                until = time.monotonic() + 5
                while not ready.exists():
                    if process.poll() is not None:
                        pytest.fail(f"synthetic startup exited={process.returncode}: {diagnostic_text()}")
                    if time.monotonic() >= until:
                        pytest.fail(f"synthetic descendant did not become ready: {diagnostic_text()}")
                    time.sleep(0.01)
                identity = json.loads(ready.read_text())
                assert identity["ppid"] == identity["pgid"] == process.pid
                return process  # Start the worker deadline only after actual readiness.
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
                raise

        monkeypatch.setattr(worker.subprocess, "Popen", spawn)
        try:
            with pytest.raises(worker.AutoWorkerError) as failure:
                worker.run_auto_worker("personal", Paths(tmp_path), timeout=0.3, _direct=direct)
            assert str(failure.value) == "operation_timed_out", diagnostic_text()
            assert processes[0].poll() is not None
            identity = json.loads(ready.read_text())
            until = time.monotonic() + 2
            while True:
                state = subprocess.run(
                    ["ps", "-o", "stat=", "-p", str(identity["pid"])],
                    capture_output=True, text=True, check=False,
                ).stdout.strip()
                # An orphan zombie cannot execute or write; macOS may reap it
                # asynchronously after its parent process group is killed.
                if not state or state.startswith("Z"):
                    break
                assert time.monotonic() < until, f"synthetic descendant remains active: {state}; {diagnostic_text()}"
                time.sleep(0.01)
            release.touch()
            assert not late.exists()
        finally:
            for process in processes:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)


def test_failed_worker_never_exposes_output(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw:
                        [sys.executable, "-c", "import sys; print('SYNTHETIC-PRIVATE'); sys.exit(7)"])
    with pytest.raises(worker.AutoWorkerError, match="^operation_failed$"):
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=2)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group regression")
@pytest.mark.parametrize("exit_code", [0, 7])
def test_worker_exit_reaps_remaining_descendants(tmp_path, monkeypatch, exit_code):
    late = tmp_path / "late-descendant"
    ready = tmp_path / "ready-descendant"
    descendant = ("import time; from pathlib import Path; Path(" + repr(str(ready)) +
                  ").touch(); time.sleep(.4); Path(" + repr(str(late)) + ").touch()")
    script = ("import subprocess,sys,time; from pathlib import Path; "
              "subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); "
              "ready=Path(" + repr(str(ready)) + ")\n"
              "while not ready.exists(): time.sleep(.01)\n"
              "sys.exit(" + str(exit_code) + ")")
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw: [sys.executable, "-c", script])
    if exit_code:
        with pytest.raises(worker.AutoWorkerError, match="^operation_failed$"):
            worker.run_auto_worker("personal", Paths(tmp_path), timeout=2, _direct=True)
    else:
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=2, _direct=True)
    assert ready.exists()
    time.sleep(.5)
    assert not late.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX spawn-cancellation regression")
@pytest.mark.parametrize("kind", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_signal_during_spawn_defers_until_child_handle_is_acquired(tmp_path, monkeypatch, kind):
    late = tmp_path / "late-spawn"
    script = "import time; from pathlib import Path; time.sleep(.3); Path(" + repr(str(late)) + ").touch()"
    monkeypatch.setattr(worker, "_arguments", lambda *_a, **_kw: [sys.executable, "-c", script])
    original, children = worker.subprocess.Popen, []
    def spawn(*args, **kwargs):
        process = original(*args, **kwargs)
        children.append(process)
        os.kill(os.getpid(), getattr(signal, kind))
        return process
    monkeypatch.setattr(worker.subprocess, "Popen", spawn)
    with pytest.raises(SystemExit):
        worker.run_auto_worker("personal", Paths(tmp_path), timeout=2, _direct=True)
    assert children[0].poll() is not None
    time.sleep(.4)
    assert not late.exists()


def test_supervisor_job_failure_aborts_before_child_spawn(tmp_path, monkeypatch):
    def failed():
        raise worker.AutoWorkerError("operation_failed")
    monkeypatch.setattr(worker, "_bind_supervisor_job", failed)
    monkeypatch.setattr(worker, "run_auto_worker", lambda *_a, **_kw: pytest.fail("unsafe supervisor spawned worker"))
    assert worker.main(["personal", "--home", str(tmp_path), "--supervise"]) == 1


@pytest.mark.skipif(os.name != "nt", reason="real Win32 supervisor Job Object")
@pytest.mark.parametrize("ending", ["success", "failure", "hardkill"])
def test_windows_job_reaps_descendants_on_every_supervisor_exit(tmp_path, ending):
    ready, late = tmp_path / "ready", tmp_path / "late"
    descendant = ("import time; from pathlib import Path; Path(" + repr(str(ready)) +
                  ").touch(); time.sleep(.7); Path(" + repr(str(late)) + ").touch()")
    script = ("import subprocess,sys,time; from pathlib import Path; "
              "from keys_keeper.auto_worker import _bind_supervisor_job; _bind_supervisor_job(); "
              "subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]); "
              "ready=Path(" + repr(str(ready)) + ")\n"
              "until=time.monotonic()+5\n"
              "while not ready.exists():\n"
              " if time.monotonic()>until: sys.exit(9)\n"
              " time.sleep(.01)\n"
              + ("time.sleep(5)" if ending == "hardkill" else "sys.exit(" + ("0" if ending == "success" else "7") + ")"))
    parent = subprocess.Popen([sys.executable, "-c", script],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        until = time.monotonic() + 5
        while not ready.exists() and parent.poll() is None and time.monotonic() < until:
            time.sleep(.01)
        assert ready.exists(), "Windows job setup must succeed before spawning a descendant"
        if ending == "hardkill":
            parent.kill()
        expected = 0 if ending == "success" else (7 if ending == "failure" else None)
        result = parent.wait(timeout=5)
        if expected is not None:
            assert result == expected
        time.sleep(.8)
        assert not late.exists()
    finally:
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)


def test_detached_entry_runs_supervisor_and_preserves_explicit_root(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **kw: calls.append((a, kw)))
    worker.start_auto_worker("s3", Paths(tmp_path))
    argv = calls[0][0][0]
    assert argv[1:4] == ["-m", "keys_keeper.auto_worker", "s3"]
    assert argv[-3:] == ["--home", str(tmp_path), "--supervise"]


def test_s3_worker_rechecks_replica_role_before_master_backend(tmp_path, monkeypatch):
    from keys_keeper import sync_application
    runtime = ProjectRuntime(Paths(tmp_path))
    item = {"id": "00000000-0000-4000-8000-000000000001", "kind": "replica",
            "scope_id": "00000000-0000-4000-8000-000000000002",
            "vault_id": "00000000-0000-4000-8000-000000000003",
            "device_id": "00000000-0000-4000-8000-000000000004",
            "project": "synthetic", "environment": "test", "endpoint": "https://relay.example", "status": "active"}
    runtime.registry.put(item)
    runtime.registry.set_default(item["id"])
    monkeypatch.setattr(sync_application, "_run_auto_worker", lambda _paths: pytest.fail("replica opened master sync"))
    assert worker.main(["s3", "--home", str(tmp_path)]) == 1


def test_disabled_auto_is_rechecked_before_expensive_worker_setup(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from keys_keeper import sync_application, personal_sync
    monkeypatch.setattr(sync_application, "load_sync_config", lambda _paths: SimpleNamespace(mode="off"))
    monkeypatch.setattr(sync_application, "_build_engine", lambda *_a, **_kw: pytest.fail("disabled S3 opened backend"))
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
              "\ndef spawn(*a,**kw):\n p=original(*a,**kw); ready=Path(" + repr(str(ready)) + "); "
              "temporary=ready.with_suffix('.tmp'); temporary.write_text(str(p.pid)); temporary.replace(ready); return p\n"
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
