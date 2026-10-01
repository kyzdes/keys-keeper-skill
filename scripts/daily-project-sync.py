#!/usr/bin/env python3
"""macOS one-shot scheduler for an explicitly selected project scope.

Uses only the standard library, without unlocking or reading the vault. All
jobs share one lock to serialize CPU-heavy sync. A durable attempt timestamp
prevents restart, failure or timer drift from repeating work inside 24 hours.
Manual Sync uses the ordinary CLI/API and bypasses this launcher entirely.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
from uuid import UUID

DAY = 86_400


def _private_directory(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("invalid scheduler directory")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("scheduler directory must be private")


def _unique_fields(items):
    data = {}
    for key, value in items:
        if key in data:
            raise ValueError("duplicate scheduler timestamp field")
        data[key] = value
    return data


def _last_attempt(path: Path) -> float | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077 or info.st_size > 256):
            raise ValueError("invalid scheduler timestamp")
        data = json.loads(stream.read(257), object_pairs_hook=_unique_fields)
    if not isinstance(data, dict) or set(data) != {"last_attempt"}:
        raise ValueError("invalid scheduler timestamp")
    value = data["last_attempt"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid scheduler timestamp")
    if not math.isfinite(value) or value < 0:
        raise ValueError("invalid scheduler timestamp")
    return value


def _write_attempt(path: Path, now: float) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".attempt-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump({"last_attempt": now}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run_daily(root: Path, job_id: str, command: list[str], *, clock=time.time) -> tuple[str, int]:
    if not re.fullmatch(r"[a-f0-9]{64}", job_id):
        raise ValueError("invalid scheduler job")
    if (len(command) != 5 or not Path(command[0]).is_absolute()
            or Path(command[0]).name != "keys"
            or command[1:4] != ["project-sync", "sync", "--scope"]):
        raise ValueError("explicit project sync command required")
    UUID(command[4])
    _private_directory(root)
    fd = os.open(root / "scheduler.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "rb") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("invalid scheduler lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        stamp = root / (job_id + ".json")
        now = clock()
        previous = _last_attempt(stamp)
        # A backwards clock adjustment delays work instead of bypassing the cap.
        if previous is not None and now - previous < DAY:
            return "deferred", 0
        # Count failures as attempts too; commit before any costly child work.
        _write_attempt(stamp, now)
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return "failed", 1
        return ("synced", 0) if result.returncode == 0 else ("failed", 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--command", nargs=argparse.REMAINDER, required=True)
    args = parser.parse_args()
    try:
        status, code = run_daily(args.state_dir, args.job_id, args.command)
    except Exception:
        # Never echo a child error, command, scope identifier or metadata value.
        status, code = "scheduler_unavailable", 1
    print(json.dumps({"status": status}), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
