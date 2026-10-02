"""Durable automatic-sync timing metadata; no vault or credentials are read."""
from __future__ import annotations

import json
import math

from keys_keeper.operation_journal import _atomic_write_bytes, _secure_read, profile_lock
from keys_keeper.paths import Paths

DAILY_INTERVAL = 24 * 60 * 60


class AutoScheduleError(RuntimeError):
    pass


def _unique_fields(items):
    value = {}
    for key, field in items:
        if key in value:
            raise AutoScheduleError("duplicate automatic synchronization schedule field")
        value[key] = field
    return value


def _read_attempt(marker):
    try:
        blob = _secure_read(marker, max_bytes=4096)
    except FileNotFoundError:
        return None
    try:
        saved = json.loads(blob, object_pairs_hook=_unique_fields,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise AutoScheduleError("invalid automatic synchronization schedule") from None
    if (not isinstance(saved, dict) or set(saved) != {"schema_version", "last_attempt"}
            or type(saved["schema_version"]) is not int or saved["schema_version"] != 1
            or type(saved["last_attempt"]) not in {int, float}
            or not math.isfinite(saved["last_attempt"]) or saved["last_attempt"] < 0):
        raise AutoScheduleError("invalid automatic synchronization schedule")
    return saved["last_attempt"]


def claim_auto_sync(schedule: Paths, now, *, interval=DAILY_INTERVAL, force=False, legacy=None):
    """Claim before expensive work, serializing restarts and other workers.

    A failed attempt consumes the daily slot. ``force`` is reserved for an
    explicit manual override.
    The marker contains a timestamp only, and corrupt metadata fails closed.
    """
    if type(now) not in {int, float} or not math.isfinite(now) or now < 0:
        raise AutoScheduleError("invalid automatic synchronization clock")
    if type(interval) is not int or interval < DAILY_INTERVAL or type(force) is not bool:
        raise AutoScheduleError("invalid automatic synchronization interval")
    marker = schedule.root / "last-attempt.json"
    with profile_lock(schedule, timeout=1):
        previous = _read_attempt(marker)
        if legacy is not None and legacy.root != schedule.root:
            old = _read_attempt(legacy.root / "last-attempt.json")
            if old is not None and (previous is None or old > previous):
                previous = old
                # Preserve the latest old profile claim even if its registry
                # identity changes later. Migration never resets a daily slot.
                _atomic_write_bytes(marker, json.dumps({"schema_version": 1, "last_attempt": old},
                                                       sort_keys=True).encode())
        if previous is not None:
            due = previous + interval
            if not force and now < due:
                return False, due
        _atomic_write_bytes(marker, json.dumps({"schema_version": 1, "last_attempt": now},
                                               sort_keys=True).encode())
        return True, now + interval
