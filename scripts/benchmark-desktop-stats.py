#!/usr/bin/env python3
"""Bounded synthetic activity benchmark; never reads a live vault or audit log.

PYTHONPATH=src nice -n 10 ../keys-keeper-skill/.venv/bin/python \
    scripts/benchmark-desktop-stats.py

The baseline is the committed pre-fix desktop_stats.py at --baseline-ref. Data
and logs exist only inside TemporaryDirectory. No backend, sync or UI is started.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types

from keys_keeper.desktop_stats import DailySummaryCache
from keys_keeper.paths import Paths


def measure(action, cycles):
    cpu, wall = time.process_time(), time.perf_counter()
    for index in range(cycles):
        action(index)
    return {"cycles": cycles, "cpu_seconds": round(time.process_time() - cpu, 6),
            "wall_seconds": round(time.perf_counter() - wall, 6)}


def run(rows, cycles, baseline_ref):
    root = Path(__file__).resolve().parents[1]
    source = subprocess.check_output(["git", "show", f"{baseline_ref}:src/keys_keeper/desktop_stats.py"],
                                     cwd=root, text=True)
    baseline = types.ModuleType("_desktop_stats_benchmark_baseline")
    sys.modules[baseline.__name__] = baseline
    exec(compile(source, "<committed desktop stats baseline>", "exec"), baseline.__dict__)
    now = datetime(2026, 10, 1, 12, tzinfo=timezone.utc)
    row = json.dumps({"ts": "2026-10-01T10:00:00Z", "op": "inject", "success": True,
                      "caller_kind": "agent", "caller_agent": "codex", "name": "synthetic", "id": "synthetic"}) + "\n"
    with tempfile.TemporaryDirectory(prefix="keys-statistics-benchmark-") as directory:
        paths = Paths(Path(directory))
        with paths.audit_jsonl.open("w") as log:
            for _ in range(rows):
                log.write(row)
        def cold(_):
            assert baseline.today_summary(paths, now=now)["total"] == rows
        previous = measure(cold, 3)
        cache = DailySummaryCache(paths)
        warmup = measure(lambda _: cache.summary(now=now), 1)
        scans, parsed = cache._full_scans, cache._parsed_lines
        def unchanged(index):
            assert cache.summary(now=now + timedelta(seconds=index + 1))["total"] == rows
        unchanged_result = measure(unchanged, cycles)
        unchanged_result.update(full_scans=cache._full_scans - scans, parsed_records=cache._parsed_lines - parsed)
        assert unchanged_result["full_scans"] == unchanged_result["parsed_records"] == 0
        with paths.audit_jsonl.open("a") as log:
            log.write(row * 10)
        scans, parsed = cache._full_scans, cache._parsed_lines
        def appended(_):
            assert cache.summary(now=now + timedelta(seconds=cycles + 1))["total"] == rows + 10
        append_result = measure(appended, 1)
        append_result.update(full_scans=cache._full_scans - scans, parsed_records=cache._parsed_lines - parsed,
                             prefix_digest_verifications=1)
        assert append_result["full_scans"] == 0 and append_result["parsed_records"] == 10
        return {"synthetic_rows": rows, "baseline_ref": baseline_ref, "baseline": previous,
                "cache_warmup": warmup, "unchanged_after_warmup": unchanged_result,
                "append_10_records": append_result, "cached_files": len(cache._files)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=100_000)
    parser.add_argument("--cycles", type=int, default=100)
    parser.add_argument("--baseline-ref", default="d47fc8787932df912fe196ce81599cfb09dcae1e")
    args = parser.parse_args()
    if not 1 <= args.rows <= 1_000_000 or not 1 <= args.cycles <= 1000:
        parser.error("rows must be 1..1000000 and cycles 1..1000")
    print(json.dumps(run(args.rows, args.cycles, args.baseline_ref), sort_keys=True))
