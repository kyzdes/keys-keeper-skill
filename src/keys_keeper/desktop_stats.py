"""Read-only, value-free daily activity projection for the desktop companion."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import stat
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta, timezone
from uuid import UUID
from zoneinfo import ZoneInfo

from keys_keeper.audit import caller_identity
from keys_keeper.paths import Paths

ACCESS_OPS = frozenset({"copy", "inject", "resolve", "ssh", "reveal", "export"})
AGENTS = {"codex": "Codex", "claude": "Claude Code", "opencode": "OpenCode"}


def _local_now() -> datetime:
    try:
        if os.environ.get("TZ"):
            zone = ZoneInfo(os.environ["TZ"])
        else:
            with open("/etc/localtime", "rb") as f:
                zone = ZoneInfo.from_file(f, key="Local")
        return datetime.now(zone)
    except (OSError, ValueError, KeyError):
        return datetime.now().astimezone()


def _log_files(paths: Paths, start: datetime, now: datetime):
    roots = [paths]
    if paths.profiles_dir.is_dir():
        for profile in paths.profiles_dir.iterdir():
            try:
                if str(UUID(profile.name)) == profile.name and not profile.is_symlink():
                    roots.append(Paths(profile))
            except ValueError:
                continue
    # At local month boundaries, today's first events can be in a UTC-month
    # archive. Include both relevant months; don't load unrelated history.
    months = {start.astimezone(timezone.utc).strftime("%Y-%m"),
              now.astimezone(timezone.utc).strftime("%Y-%m")}
    for root in roots:
        yield root.audit_jsonl
        for month in sorted(months):
            yield root.audit_archive(month)


@dataclass
class _Counts:
    total: int = 0
    failed: int = 0
    unknown: int = 0
    desktop: int = 0
    skipped: int = 0
    unreadable: int = 0
    agents: Counter = field(default_factory=Counter)
    operations: Counter = field(default_factory=Counter)
    last_access: datetime | None = None
    future_at: datetime | None = None

    def copy(self):
        return _Counts(self.total, self.failed, self.unknown, self.desktop,
                       self.skipped, self.unreadable, self.agents.copy(),
                       self.operations.copy(), self.last_access, self.future_at)

    def include(self, other):
        for name in ("total", "failed", "unknown", "desktop", "skipped", "unreadable"):
            setattr(self, name, getattr(self, name) + getattr(other, name))
        self.agents.update(other.agents)
        self.operations.update(other.operations)
        if other.last_access is not None and (self.last_access is None or other.last_access > self.last_access):
            self.last_access = other.last_access
        if other.future_at is not None and (self.future_at is None or other.future_at < self.future_at):
            self.future_at = other.future_at


def _count_line(line: bytes, counts: _Counts, start: datetime, now: datetime) -> None:
    text = line.decode("utf-8", errors="replace")
    if not text.strip():
        return
    try:
        event = json.loads(text)
        if not isinstance(event, dict):
            raise ValueError("not an event")
        ts = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
        if ts.tzinfo is None:
            raise ValueError("missing timezone")
        op = event.get("op")
        if not isinstance(op, str):
            raise ValueError("missing operation")
        if not start <= ts <= now or op not in ACCESS_OPS:
            # Keep only a timestamp, never a deferred raw event. Recompute once
            # if a future event enters today's window, or the clock moves back.
            if op in ACCESS_OPS and now < ts:
                end = datetime.combine(now.date() + timedelta(days=1), time.min, tzinfo=now.tzinfo)
                if ts < end and (counts.future_at is None or ts < counts.future_at):
                    counts.future_at = ts
            return
        if not isinstance(event.get("success"), bool):
            raise ValueError("missing outcome")
    except (ValueError, TypeError, KeyError, AttributeError):
        counts.skipped += 1
        return
    counts.total += 1
    counts.failed += int(not event["success"])
    counts.operations[op] += 1
    kind, agent = event.get("caller_kind"), event.get("caller_agent")
    if kind is None:
        caller = event.get("caller_path")
        kind, agent = caller_identity(caller if isinstance(caller, str) else "?", {})
    if kind == "agent" and isinstance(agent, str) and agent in AGENTS:
        counts.agents[agent] += 1
    elif kind == "desktop":
        counts.desktop += 1
    else:
        counts.unknown += 1
    if counts.last_access is None or ts > counts.last_access:
        counts.last_access = ts


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode)


@dataclass
class _CachedFile:
    signature: tuple
    digest: bytes
    offset: int
    stable: _Counts
    tail: _Counts

    def counts(self):
        counts = self.stable.copy()
        counts.include(self.tail)
        return counts


class DailySummaryCache:
    """Bounded projection cache owned only by one live desktop bridge.

    Entries contain counters, timestamps and file fingerprints, never audit
    rows, names, paths from records, secret values or unlocking material. Every
    request stats all currently discovered logs. Changed files are read again;
    appends verify the old prefix before parsing only the new suffix so an
    in-place rewrite plus growth cannot masquerade as an append. No cache is
    serialized, shared between roots, or used after an I/O error.
    """

    def __init__(self, paths: Paths, *, max_files: int = 128):
        if max_files < 1:
            raise ValueError("max_files must be positive")
        self.paths = paths
        self._max_files = max_files
        self._files: OrderedDict = OrderedDict()
        self._window = None
        self._last_now = None
        self._full_scans = self._incremental_scans = self._parsed_lines = 0

    def summary(self, *, now: datetime | None = None) -> dict:
        now = now or _local_now()
        if now.tzinfo is None:
            raise ValueError("now must include a timezone")
        start = datetime.combine(now.date(), time.min, tzinfo=now.tzinfo)
        window = (start.isoformat(), str(now.tzinfo))
        instant = now.astimezone(timezone.utc)
        if self._window != window or (self._last_now is not None and instant < self._last_now):
            self._files.clear()
        self._window, self._last_now = window, instant
        counts = _Counts()
        try:
            files = list(_log_files(self.paths, start, now))
        except OSError:
            files = [self.paths.audit_jsonl]
            counts.unreadable += 1
        available = set(files)
        for path in tuple(self._files):
            if path not in available:
                del self._files[path]
        for path in files:
            counts.include(self._file_counts(path, start, now))
        return _summary(counts, start, now)

    def _file_counts(self, path, start, now):
        cached = self._files.pop(path, None)
        try:
            signature = _signature(path.stat())
            if not stat.S_ISREG(signature[-1]):
                raise OSError("audit log is not a regular file")
            previous = cached.counts() if cached else None
            current_time = previous is None or previous.future_at is None or now < previous.future_at
            if cached and cached.signature == signature and current_time:
                self._remember(path, cached)
                return previous
            if not current_time:
                cached = None
            counts, entry = self._read_file(path, signature, cached, start, now)
            if entry is not None:
                self._remember(path, entry)
            return counts
        except FileNotFoundError:
            return _Counts()
        except (OSError, EOFError):
            return _Counts(unreadable=1)

    def _remember(self, path, entry):
        self._files[path] = entry
        while len(self._files) > self._max_files:
            self._files.popitem(last=False)

    def _read_file(self, path, signature, cached, start, now):
        compressed = path.suffix == ".gz"
        opener = gzip.open if compressed else open
        stable, tail = _Counts(), _Counts()
        offset = 0
        digest = hashlib.sha256()
        try:
            with opener(path, "rb") as stream:
                old_size = 0
                incremental = False
                if (not compressed and cached and signature[:2] == cached.signature[:2]
                        and signature[2] > cached.signature[2]):
                    remaining = cached.signature[2]
                    while remaining:
                        chunk = stream.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            break
                        digest.update(chunk)
                        remaining -= len(chunk)
                    if remaining == 0 and digest.digest() == cached.digest:
                        stable = cached.stable.copy()
                        offset, old_size = cached.offset, cached.signature[2]
                        stream.seek(offset)
                        incremental = True
                        self._incremental_scans += 1
                    else:
                        digest = hashlib.sha256()
                        stream.seek(0)
                if not incremental:
                    self._full_scans += 1
                position = offset
                for raw in stream:
                    digest.update(raw[max(0, old_size - position):])
                    # Binary iteration splits on LF; splitlines also preserves
                    # the existing text reader's CR/CRLF newline semantics.
                    for line in raw.splitlines(keepends=True):
                        position += len(line)
                        self._parsed_lines += 1
                        if line.endswith((b"\n", b"\r")):
                            _count_line(line, stable, start, now)
                            offset = position
                        else:
                            _count_line(line, tail, start, now)
                after = _signature(path.stat())
                result = stable.copy()
                result.include(tail)
                # A concurrent writer/replacement is never retained as an
                # unchanged snapshot. The next request reads the file again.
                entry = _CachedFile(signature, digest.digest(), offset, stable, tail) if after == signature else None
                return result, entry
        except (OSError, EOFError):
            result = stable.copy()
            result.include(tail)
            result.unreadable += 1
            return result, None


def _summary(counts: _Counts, start: datetime, now: datetime) -> dict:
    return {
        "date": now.date().isoformat(), "since": start.isoformat(),
        "updated_at": now.isoformat(), "total": counts.total, "agent_total": sum(counts.agents.values()),
        "failed": counts.failed, "unknown": counts.unknown, "desktop": counts.desktop,
        "agents": [{"id": key, "name": AGENTS[key], "count": value}
                   for key, value in sorted(counts.agents.items(), key=lambda row: (-row[1], row[0]))],
        "operations": dict(sorted(counts.operations.items())),
        "last_access": counts.last_access.astimezone(now.tzinfo).isoformat() if counts.last_access else None,
        "complete": counts.skipped == 0 and counts.unreadable == 0,
        "skipped_records": counts.skipped, "unreadable_logs": counts.unreadable,
    }


def today_summary(paths: Paths, *, now: datetime | None = None) -> dict:
    """Stateless daily projection; the bridge owns its separate live cache.

    Count logged operations including failures, never vault values. A resolve,
    export or SSH invocation counts once. Unreadable/malformed logs explicitly
    report incomplete coverage; attribution remains only a hint.
    """
    return DailySummaryCache(paths).summary(now=now)
