"""Read-only, value-free daily activity projection for the desktop companion."""
from __future__ import annotations

import gzip
import json
import os
from collections import Counter
from datetime import datetime, time, timezone
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


def today_summary(paths: Paths, *, now: datetime | None = None) -> dict:
    """Count logged operations, including failures; never read the vault.

    One resolve/export/SSH invocation counts as one operation, not the number
    of credentials it may use. Absent logs mean no recorded activity; unreadable
    or malformed logs are explicitly incomplete. Attribution is only a hint.
    """
    now = now or _local_now()
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    start = datetime.combine(now.date(), time.min, tzinfo=now.tzinfo)
    total = failed = unknown = desktop = skipped = unreadable = 0
    agents: Counter = Counter()
    operations: Counter = Counter()
    last_access = None
    try:
        files = list(_log_files(paths, start, now))
    except OSError:
        files = [paths.audit_jsonl]
        unreadable += 1
    for path in files:
        opener = gzip.open if path.suffix == ".gz" else open
        try:
            with opener(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                        if not isinstance(event, dict):
                            raise ValueError("not an event")
                        ts = datetime.fromisoformat(event["ts"].replace("Z", "+00:00"))
                        if ts.tzinfo is None:
                            raise ValueError("missing timezone")
                        op = event.get("op")
                        if not isinstance(op, str):
                            raise ValueError("missing operation")
                        if not start <= ts <= now or op not in ACCESS_OPS:
                            continue
                        if not isinstance(event.get("success"), bool):
                            raise ValueError("missing outcome")
                    except (ValueError, TypeError, KeyError, AttributeError):
                        skipped += 1
                        continue
                    total += 1
                    failed += int(not event["success"])
                    operations[op] += 1
                    kind, agent = event.get("caller_kind"), event.get("caller_agent")
                    if kind is None:
                        caller = event.get("caller_path")
                        kind, agent = caller_identity(caller if isinstance(caller, str) else "?", {})
                    if kind == "agent" and isinstance(agent, str) and agent in AGENTS:
                        agents[agent] += 1
                    elif kind == "desktop":
                        desktop += 1
                    else:
                        unknown += 1
                    if last_access is None or ts > last_access:
                        last_access = ts
        except FileNotFoundError:
            continue
        except (OSError, EOFError):
            unreadable += 1
    return {
        "date": now.date().isoformat(), "since": start.isoformat(),
        "updated_at": now.isoformat(), "total": total, "agent_total": sum(agents.values()),
        "failed": failed, "unknown": unknown, "desktop": desktop,
        "agents": [{"id": key, "name": AGENTS[key], "count": value}
                   for key, value in sorted(agents.items(), key=lambda row: (-row[1], row[0]))],
        "operations": dict(sorted(operations.items())),
        "last_access": last_access.astimezone(now.tzinfo).isoformat() if last_access else None,
        "complete": skipped == 0 and unreadable == 0,
        "skipped_records": skipped, "unreadable_logs": unreadable,
    }
