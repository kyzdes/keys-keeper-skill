#!/usr/bin/env python3
"""Bounded, serialized updates of this plugin only (Python standard library)."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

MARKETPLACE = "claude-skills"


def number(env, key, default, maximum):
    try:
        return min(maximum, max(0, int(env.get(key, default))))
    except (TypeError, ValueError):
        return default


def recent(path, interval):
    try:
        return 0 <= time.time() - path.stat().st_mtime < interval
    except OSError:
        return False


def stamp(path):
    tmp = path.with_name(path.name + "." + str(os.getpid()))
    tmp.write_text(str(time.time()), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


@contextlib.contextmanager
def locked(path, wait_seconds):
    """OS releases this lock after a crash; never delete the shared lock file."""
    with path.open("a+b") as handle:
        os.chmod(path, 0o600)
        if os.name == "nt":
            import msvcrt
            if path.stat().st_size == 0:
                handle.write(b"0")
                handle.flush()
            def acquire():
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            def acquire():
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + wait_seconds
        while True:
            try:
                acquire()
                break
            except (OSError, BlockingIOError):
                if time.monotonic() >= deadline:
                    yield None
                    return
                time.sleep(0.1)
        # Release by closing this descriptor, not LOCK_UN: a POSIX supervisor
        # may still hold the inherited lock after this updater is interrupted.
        yield handle


def stop_process(proc):
    if os.name == "nt":
        try:
            result = subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if result.returncode and proc.poll() is None:
                proc.kill()
        except (OSError, subprocess.SubprocessError):
            proc.kill()
    else:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    proc.wait(timeout=10)


def run_foreground_command(args, timeout, handle_signals=False):
    try:
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=os.name != "nt")
    except OSError:
        return 127
    previous_handlers = {}
    if handle_signals:
        def interrupted(signum, frame):
            stop_process(proc)
            raise SystemExit(128 + signum)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous_handlers[sig] = signal.signal(sig, interrupted)
    try:
        return proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_process(proc)
        return 124
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def run_command(args, timeout, lock_fd=None):
    if os.name == "nt" or lock_fd is None:
        return run_foreground_command(args, timeout)
    # The supervisor retains the flock and enforces the CLI timeout even if
    # this updater is killed. Closing the updater's fd cannot unlock it early.
    try:
        proc = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                 "--command", str(timeout), *args],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                pass_fds=(lock_fd,))
    except OSError:
        return 127
    return proc.wait()


def cache_directory(config, env):
    base = Path(env.get("KKZ_PLUGIN_CACHE_ROOT", str(Path.home() / ".cache/kyzdes-claude-skills/v2")))
    # One Claude config may not suppress or hold up updates for another.
    namespace = hashlib.sha256(os.fsencode(config.resolve())).hexdigest()[:16]
    return base / namespace


def update(root=None, env=None):
    env = os.environ if env is None else env
    # A Codex hook must never mutate a separate Claude installation.
    if "PLUGIN_DATA" in env or env.get("KKZ_NO_AUTOUPDATE"):
        return
    root = Path(__file__).resolve().parent.parent if root is None else Path(root)
    name = json.loads((root / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))["name"]
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
        return
    if name == "keys-keeper" and (env.get("KEYS_KEEPER_NO_AUTOUPDATE") or
                                  env.get("KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE") != "1"):
        return
    config = Path(env.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))
    ref = name + "@" + MARKETPLACE
    installed = json.loads((config / "plugins/installed_plugins.json").read_text(encoding="utf-8"))
    if ref not in installed.get("plugins", {}):
        return
    known = config / "plugins/known_marketplaces.json"
    if known.exists() and json.loads(known.read_text(encoding="utf-8")).get(MARKETPLACE, {}).get("autoUpdate") is True:
        # Native host policy is independent of hook environment flags.
        return
    binary = shutil.which("claude")
    if not binary:
        return
    cache = cache_directory(config, env)
    interval = number(env, "KKZ_AUTO_UPDATE_INTERVAL_SEC", 14400, 2592000)
    success = cache / (name + ".success")
    failed = cache / (name + ".failed")
    if recent(success, interval) or recent(failed, 60):
        return
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    timeout = max(1, number(env, "KKZ_UPDATE_TIMEOUT_SEC", 120, 120))
    with locked(cache / "claude.lock", number(env, "KKZ_UPDATE_LOCK_WAIT_SEC", 180, 180)) as handle:
        if handle is None or recent(success, interval) or recent(failed, 60):
            return
        log = cache / (name + ".log")
        def record(operation, code):
            # Never persist CLI output: it may contain local paths or credentials.
            previous = log.read_bytes()[-32000:] if log.exists() else b""
            line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {operation} exit={code}\n"
            log.write_bytes(previous + line.encode())
            os.chmod(log, 0o600)
        catalog = cache / "catalog.success"
        catalog_failed = cache / "catalog.failed"
        if not recent(catalog, interval):
            if recent(catalog_failed, 60):
                return
            code = run_command([binary, "plugin", "marketplace", "update", MARKETPLACE], timeout, handle.fileno())
            record("catalog", code)
            if code:
                stamp(failed)
                stamp(catalog_failed)
                return
            stamp(catalog)
            catalog_failed.unlink(missing_ok=True)
        code = run_command([binary, "plugin", "update", ref], timeout, handle.fileno())
        record(ref, code)
        if code:
            stamp(failed)
            return
        stamp(success)
        failed.unlink(missing_ok=True)


if __name__ == "__main__":
    if len(sys.argv) > 3 and sys.argv[1] == "--command":
        try:
            result = run_foreground_command(sys.argv[3:], float(sys.argv[2]), handle_signals=os.name != "nt")
        except (OSError, ValueError, subprocess.SubprocessError):
            result = 1
        sys.exit(result)
    else:
        try:
            update()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            # Offline/missing client/config must never prevent starting a session.
            pass
