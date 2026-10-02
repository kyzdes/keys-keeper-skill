"""Bounded subprocess boundary for automatic sync; manual commands stay immediate."""
from __future__ import annotations

import argparse
import contextlib
import errno
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from keys_keeper.paths import Paths

AUTO_TIMEOUT = 300
_MODES = {"project", "personal"}
_supervisor_job = None


class AutoWorkerError(RuntimeError):
    """A fixed public code, never worker output or exception content."""


def _bind_supervisor_job():
    """Windows closes this private job on supervisor exit, killing descendants.

    Bind the supervisor before creating children so inheritance has no spawn
    race. Never close its job handle while alive: the supervisor belongs to it.
    Nested-job assignment failures abort before any mutation worker is started.
    """
    global _supervisor_job
    if os.name != "nt" or _supervisor_job is not None:
        return
    import ctypes
    from ctypes import wintypes

    class BasicLimits(ctypes.Structure):
        _fields_ = [("ProcessTime", ctypes.c_longlong), ("JobTime", ctypes.c_longlong),
                    ("Flags", wintypes.DWORD), ("MinWorkingSet", ctypes.c_size_t),
                    ("MaxWorkingSet", ctypes.c_size_t), ("ActiveProcesses", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t), ("Priority", wintypes.DWORD),
                    ("Scheduling", wintypes.DWORD)]
    class Counters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_ulonglong) for name in
                    ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]
    class ExtendedLimits(ctypes.Structure):
        _fields_ = [("Basic", BasicLimits), ("IO", Counters),
                    ("ProcessMemory", ctypes.c_size_t), ("JobMemory", ctypes.c_size_t),
                    ("PeakProcessMemory", ctypes.c_size_t), ("PeakJobMemory", ctypes.c_size_t)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise AutoWorkerError("operation_failed")
    limits = ExtendedLimits()
    limits.Basic.Flags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
    if (not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits))
            or not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess())):
        kernel.CloseHandle(job)  # No worker has been created or assigned.
        raise AutoWorkerError("operation_failed")
    _supervisor_job = job  # Raw HANDLE, non-inheritable; OS closes it on exit.


def _arguments(mode, paths, selector=None, *, supervise=False):
    if mode not in _MODES or (mode == "project") != bool(selector):
        raise ValueError("invalid automatic worker")
    result = [sys.executable, "-m", "keys_keeper.auto_worker", mode,
              "--home", str(paths.root.absolute())]
    if selector:
        result += ["--scope", selector]
    if supervise:
        result += ["--supervise"]
    return result


def _signal_group(pgid, kind):
    try:
        os.killpg(pgid, kind)
    except ProcessLookupError:
        return
    except PermissionError as original:
        if original.errno != errno.EPERM:
            raise
        # macOS can report transient EPERM during process-group teardown.
        # EPERM itself never proves the group has stopped. Only
        # an independent ESRCH permits us to finish; a live or unverifiable
        # group retains the original failure after this short bounded wait.
        deadline = time.monotonic() + 0.2
        while True:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return
            except PermissionError as probe:
                if probe.errno != errno.EPERM:
                    raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise original
            time.sleep(min(0.01, remaining))


def _stop_tree(process, *, graceful=False):
    # Wait for termination before returning: no timed-out thread keeps writing.
    if os.name == "posix":
        if graceful:
            _signal_group(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        _signal_group(process.pid, signal.SIGKILL)
    else:
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if process.poll() is None:
            process.kill()
    process.wait()


@contextlib.contextmanager
def _cancel_on_termination():
    # The outer macOS launcher sends TERM first, so nested workers are reaped
    # before its final hard kill. Signals can only be installed in a main thread.
    previous = {}
    cancellation = {"protected": True, "pending": False}
    def cancelled(*_args):
        # Popen may have created a child before returning its handle. Finish
        # acquiring that handle, then cancel through the ordinary tree cleanup.
        # Also defer a second signal while the first cancellation is reaping.
        if cancellation["protected"]:
            cancellation["pending"] = True
        else:
            raise SystemExit(1)
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for kind in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous[kind] = signal.getsignal(kind)
            signal.signal(kind, cancelled)
    try:
        yield cancellation
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)


def run_auto_worker(mode, paths, selector=None, *, timeout=AUTO_TIMEOUT, _direct=False):
    """Run one already-claimed attempt, with a hard process-tree deadline."""
    # Foreground callers also get an independent supervisor. Its timer survives
    # an uncatchable caller SIGKILL; only the supervisor starts mutation work.
    arguments = _arguments(mode, paths, selector, supervise=not _direct)
    environment = os.environ.copy()
    environment["KEYS_KEEPER_HOME"] = str(paths.root.absolute())
    options = {"start_new_session": True} if os.name == "posix" else {}
    try:
        with _cancel_on_termination() as cancellation:
            process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
            try:
                cancellation["protected"] = False
                if cancellation["pending"]:
                    raise SystemExit(1)
                result = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                cancellation["protected"] = True
                _stop_tree(process, graceful=not _direct)
                raise AutoWorkerError("operation_timed_out") from None
            except BaseException:
                cancellation["protected"] = True
                _stop_tree(process, graceful=not _direct)
                raise
            else:
                cancellation["protected"] = True
                # Reaping the worker PID does not reap its subprocesses. Clean
                # its group on success and failure, before releasing the caller.
                _stop_tree(process)
    except OSError:
        raise AutoWorkerError("operation_failed") from None
    if result != 0:
        raise AutoWorkerError("operation_failed")


def start_auto_worker(mode, paths, selector=None):
    """Detach a supervisor, never an unbounded mutation worker."""
    options = {"start_new_session": True} if os.name == "posix" else {"creationflags": 0x00000008}
    return subprocess.Popen(_arguments(mode, paths, selector, supervise=True),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, **options)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=sorted(_MODES))
    parser.add_argument("--home", type=Path, required=True)
    parser.add_argument("--scope")
    parser.add_argument("--supervise", action="store_true")
    args = parser.parse_args(argv)
    paths = Paths(args.home)
    try:
        _arguments(args.mode, paths, args.scope)
        if args.supervise:
            _bind_supervisor_job()
            run_auto_worker(args.mode, paths, args.scope, _direct=True)
        elif args.mode == "project":
            from keys_keeper.project_runtime import ProjectRuntime
            ProjectRuntime(paths).sync(args.scope)
        elif args.mode == "personal":
            from keys_keeper.personal_sync import PersonalSync, read_settings
            settings = read_settings(paths)
            if settings is None or not settings["auto"]:
                return 0
            PersonalSync(paths).sync()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
