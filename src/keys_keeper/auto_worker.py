"""Bounded subprocess boundary for automatic sync; manual commands stay immediate."""
from __future__ import annotations

import argparse
import contextlib
import os
import signal
import subprocess
import sys
import threading
from pathlib import Path

from keys_keeper.paths import Paths

AUTO_TIMEOUT = 300
_MODES = {"project", "personal", "s3"}


class AutoWorkerError(RuntimeError):
    """A fixed public code, never worker output or exception content."""


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


def _stop_tree(process, *, graceful=False):
    # Wait for termination before returning: no timed-out thread keeps writing.
    if os.name == "posix":
        if graceful:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
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
    if os.name == "posix" and threading.current_thread() is threading.main_thread():
        for kind in (signal.SIGTERM, signal.SIGHUP):
            previous[kind] = signal.getsignal(kind)
            signal.signal(kind, lambda *_args: (_ for _ in ()).throw(SystemExit(1)))
    try:
        yield
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
        with _cancel_on_termination():
            process = subprocess.Popen(arguments, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **options)
            try:
                result = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                _stop_tree(process, graceful=not _direct)
                raise AutoWorkerError("operation_timed_out") from None
            except BaseException:
                _stop_tree(process, graceful=not _direct)
                raise
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
        else:
            from keys_keeper.project_runtime import ProjectRuntime
            # Re-check role at execution time, after the public scheduling claim.
            # A root reconfigured as a replica must never open master credentials.
            if ProjectRuntime(paths).context().kind != "master":
                return 1
            from keys_keeper.cli_sync import _run_auto_worker
            if _run_auto_worker(paths) is False:
                return 1
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
