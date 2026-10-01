import gzip
import json
import os
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from keys_keeper import cli
from keys_keeper.audit import AuditLog, caller_identity
from keys_keeper.desktop_stats import DailySummaryCache, today_summary
from keys_keeper.paths import Paths


def event(ts, **overrides):
    return {"ts": ts, "op": "inject", "success": True, "caller_path": "/bin/zsh", **overrides}


def write_events(path, events):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(e) + "\n" for e in events))


def test_local_midnight_agent_attribution_failures_and_value_free_output(tmp_path):
    paths = Paths(tmp_path)
    write_events(paths.audit_jsonl, [
        event("2026-09-06T20:59:59Z"),  # yesterday in Moscow
        event("2026-09-06T21:00:00Z", caller_kind="agent", caller_agent="codex"),
        event("2026-09-07T08:00:00Z", caller_kind="agent", caller_agent="claude", success=False),
        event("2026-09-07T08:10:00Z", caller_kind="desktop"),
        event("2026-09-07T08:11:00Z", name="secret-name", id="secret-id",
              file_target="/private/path", value="never-output-this", error="secret-error"),
        event("2026-09-07T08:12:00Z", op="add"),
        event("2026-09-07T12:00:00Z"),  # future
    ])
    data = today_summary(paths, now=datetime(2026, 9, 7, 12, tzinfo=ZoneInfo("Europe/Moscow")))
    assert data["total"] == 4
    assert data["agent_total"] == 2
    assert data["failed"] == 1
    assert data["unknown"] == 1
    assert data["desktop"] == 1
    assert data["complete"] is True
    assert data["since"] == "2026-09-07T00:00:00+03:00"
    rendered = json.dumps(data)
    for private in ["secret-name", "secret-id", "/private/path", "never-output-this", "secret-error"]:
        assert private not in rendered


def test_archived_utc_month_and_local_profiles_are_included(tmp_path):
    paths = Paths(tmp_path)
    with gzip.open(paths.audit_archive("2026-08"), "wt") as f:
        f.write(json.dumps(event("2026-08-31T22:00:00Z")) + "\n")
    profile = paths.for_profile("11111111-1111-4111-8111-111111111111")
    write_events(profile.audit_jsonl, [event("2026-09-01T00:10:00Z", caller_path="/bin/codex")])
    data = today_summary(paths, now=datetime(2026, 9, 1, 4, tzinfo=ZoneInfo("Europe/Moscow")))
    assert data["total"] == 2
    assert data["agent_total"] == 1


def test_daylight_saving_day_uses_midnight_offset(tmp_path):
    paths = Paths(tmp_path)
    write_events(paths.audit_jsonl, [event("2026-03-08T05:00:00Z"), event("2026-03-08T04:59:59Z")])
    data = today_summary(paths, now=datetime(2026, 3, 8, 12, tzinfo=ZoneInfo("America/New_York")))
    assert data["total"] == 1
    assert data["since"].endswith("-05:00")


def test_no_old_tail_limit_and_malformed_records_are_explicit(tmp_path):
    paths = Paths(tmp_path)
    write_events(paths.audit_jsonl, [event("2026-09-07T10:00:00Z") for _ in range(1201)])
    with paths.audit_jsonl.open("a") as f:
        f.write('not-json\n{"ts":\n[]\n')
        f.write(json.dumps(event("2026-09-07T10:00:00Z", caller_kind="agent", caller_agent=[])) + "\n")
    data = today_summary(paths, now=datetime(2026, 9, 7, 12, tzinfo=timezone.utc))
    assert data["total"] == 1202
    assert data["unknown"] == 1202
    assert data["complete"] is False
    assert data["skipped_records"] == 3


def test_missing_logs_do_not_create_a_vault(tmp_path):
    paths = Paths(tmp_path / "absent")
    data = today_summary(paths)
    assert data["total"] == 0
    assert data["complete"] is True
    assert not paths.root.exists()


def test_unreadable_log_is_not_a_successful_empty_result(tmp_path):
    paths = Paths(tmp_path)
    paths.audit_jsonl.mkdir()
    data = today_summary(paths)
    assert data["total"] == 0
    assert data["complete"] is False
    assert data["unreadable_logs"] == 1


@pytest.mark.parametrize("path,environment,expected", [
    ("/bin/zsh", {}, ("unknown", None)),
    ("/bin/zsh", {"CODEX_THREAD_ID": "never-save-this-id"}, ("agent", "codex")),
    ("/bin/zsh", {"CLAUDECODE": "1"}, ("agent", "claude")),
    ("/usr/bin/opencode", {}, ("agent", "opencode")),
    ("C:\\bin\\codex.exe", {}, ("agent", "codex")),
    ("/bin/zsh", {"KEYS_KEEPER_CALLER": "desktop", "CODEX_THREAD_ID": "id"}, ("desktop", None)),
])
def test_identity_uses_only_fixed_names(path, environment, expected):
    assert caller_identity(path, environment) == expected


def test_record_captures_hint_without_persisting_environment_values(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYS_KEEPER_CALLER", raising=False)
    monkeypatch.setenv("CODEX_THREAD_ID", "private-session-marker")
    paths = Paths(tmp_path)
    AuditLog(paths).record(op="inject", name="test", id_="test")
    payload = json.loads(paths.audit_jsonl.read_text())
    assert payload["caller_kind"] == "agent"
    assert payload["caller_agent"] == "codex"
    assert "private-session-marker" not in paths.audit_jsonl.read_text()


def test_cli_summary_never_builds_a_backend(kk_home, monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("metadata summary must not compose a backend")
    monkeypatch.setattr(cli, "_context_or_error", forbidden)
    assert cli.main(["audit", "--summary"]) == 0
    assert json.loads(capsys.readouterr().out)["total"] == 0
    assert not kk_home.exists()


def test_live_cache_unchanged_logs_require_no_reads_or_parses(tmp_path, monkeypatch):
    import builtins
    from keys_keeper import desktop_stats
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    write_events(paths.audit_jsonl, [event("2026-09-07T10:00:00Z", caller_kind="agent", caller_agent="codex")])
    cache = DailySummaryCache(paths)
    initial = cache.summary(now=now)
    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged audit was read or parsed again")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(desktop_stats, "_count_line", forbidden)
    for minute in range(1, 5):
        current = cache.summary(now=now + timedelta(minutes=minute))
        assert current["total"] == current["agent_total"] == 1
        assert current["last_access"] == initial["last_access"]
    assert cache._full_scans == cache._parsed_lines == 1


def test_live_cache_append_parses_only_the_suffix(tmp_path):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    write_events(paths.audit_jsonl, [event("2026-09-07T10:00:00Z") for _ in range(100)])
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["total"] == 100
    with paths.audit_jsonl.open("a") as log:
        log.write(json.dumps(event("2026-09-07T11:00:00Z", success=False)) + "\n")
    result = cache.summary(now=now)
    assert result["total"] == 101
    assert result["failed"] == 1
    assert cache._full_scans == 1
    assert cache._incremental_scans == 1
    assert cache._parsed_lines == 101


def test_live_cache_preserves_universal_newlines_and_unicode_blank_lines(tmp_path):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    row = json.dumps(event("2026-09-07T10:00:00Z"))
    paths.audit_jsonl.write_bytes((row + "\r" + row + "\r\n\u00a0\n").encode())
    cache = DailySummaryCache(paths)
    result = cache.summary(now=now)
    assert result["total"] == 2
    assert result["complete"] is True
    with paths.audit_jsonl.open("ab") as log:
        log.write((row + "\n").encode())
    assert cache.summary(now=now)["total"] == 3


@pytest.mark.parametrize("change", ["rewrite", "truncate", "replace", "rewrite_and_append"])
def test_live_cache_file_mutations_never_reuse_stale_counts(tmp_path, change):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    original = [event("2026-09-07T10:00:00Z") for _ in range(3)]
    write_events(paths.audit_jsonl, original)
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["total"] == 3
    updated = [{**row, "success": False} for row in original]
    if change == "truncate":
        updated = updated[:1]
    elif change == "rewrite_and_append":
        # The head and former tail are unchanged; only an interior record was
        # rewritten before appending. A boundary-only check would miss this.
        updated = [original[0], updated[1], original[2], event("2026-09-07T11:00:00Z")]
    if change == "replace":
        replacement = tmp_path / "replacement"
        write_events(replacement, updated)
        replacement.replace(paths.audit_jsonl)
    else:
        write_events(paths.audit_jsonl, updated)
    result = cache.summary(now=now)
    assert result["total"] == len(updated)
    assert result["failed"] == sum(not row["success"] for row in updated)
    assert cache._full_scans == 2


@pytest.mark.parametrize("complete_json", [False, True])
def test_live_cache_partial_last_line_is_replaced_on_append(tmp_path, complete_json):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    row = json.dumps(event("2026-09-07T10:00:00Z"))
    prefix = row if complete_json else row[:15]
    paths.audit_jsonl.write_text(prefix)
    cache = DailySummaryCache(paths)
    first = cache.summary(now=now)
    assert first["total"] == int(complete_json)
    assert first["skipped_records"] == int(not complete_json)
    with paths.audit_jsonl.open("a") as log:
        log.write(row[len(prefix):] + "\n" + row + "\n")
    result = cache.summary(now=now)
    assert result["total"] == 2
    assert result["complete"] is True


def test_live_cache_rotation_archives_and_new_profiles_are_discovered(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 1, 4, tzinfo=ZoneInfo("Europe/Moscow"))
    write_events(paths.audit_jsonl, [event("2026-08-31T22:00:00Z")])
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["total"] == 1
    with gzip.open(paths.audit_archive("2026-08"), "wb") as log:
        log.write(paths.audit_jsonl.read_bytes())
    paths.audit_jsonl.unlink()
    profile = paths.for_profile("11111111-1111-4111-8111-111111111111")
    write_events(profile.audit_jsonl, [event("2026-09-01T00:10:00Z")])
    assert cache.summary(now=now)["total"] == 2
    def forbidden(*args, **kwargs):
        raise AssertionError("unchanged archive decompressed again")
    monkeypatch.setattr(gzip, "open", forbidden)
    monkeypatch.setattr(gzip, "GzipFile", forbidden)
    assert cache.summary(now=now)["total"] == 2
    profile.audit_jsonl.unlink()
    assert cache.summary(now=now)["total"] == 1


def test_live_cache_archive_rewrite_changes_counts(tmp_path):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    archive = paths.audit_archive("2026-09")
    with gzip.open(archive, "wt") as log:
        log.write(json.dumps(event("2026-09-07T10:00:00Z")) + "\n")
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["failed"] == 0
    with gzip.open(archive, "wt") as log:
        log.write(json.dumps(event("2026-09-07T10:00:00Z", success=False)) + "\n")
    result = cache.summary(now=now)
    assert result["total"] == result["failed"] == 1


def test_live_cache_day_timezone_future_and_clock_rollback_are_correct(tmp_path):
    paths = Paths(tmp_path)
    write_events(paths.audit_jsonl, [event("2026-09-07T20:00:00Z"), event("2026-09-07T21:01:00Z")])
    cache = DailySummaryCache(paths)
    assert cache.summary(now=datetime(2026, 9, 7, 20, 30, tzinfo=timezone.utc))["total"] == 1
    assert cache.summary(now=datetime(2026, 9, 7, 22, tzinfo=timezone.utc))["total"] == 2
    assert cache.summary(now=datetime(2026, 9, 7, 20, 30, tzinfo=timezone.utc))["total"] == 1
    moscow = ZoneInfo("Europe/Moscow")
    assert cache.summary(now=datetime(2026, 9, 8, 1, tzinfo=moscow))["total"] == 1
    assert cache.summary(now=datetime(2026, 9, 9, 1, tzinfo=moscow))["total"] == 0


def test_live_cache_read_failure_is_not_cached_and_can_recover(tmp_path, monkeypatch):
    import builtins
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    write_events(paths.audit_jsonl, [event("2026-09-07T10:00:00Z")])
    cache = DailySummaryCache(paths)
    cache.summary(now=now)
    with paths.audit_jsonl.open("a") as log:
        log.write(json.dumps(event("2026-09-07T11:00:00Z")) + "\n")
    original_open = builtins.open
    def fail_audit(path, *args, **kwargs):
        if path == paths.audit_jsonl:
            raise PermissionError("synthetic unreadable audit")
        return original_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", fail_audit)
    failed = cache.summary(now=now)
    assert failed["total"] == 0
    assert failed["complete"] is False
    assert failed["unreadable_logs"] == 1
    monkeypatch.setattr(builtins, "open", original_open)
    recovered = cache.summary(now=now)
    assert recovered["total"] == 2
    assert recovered["complete"] is True


def test_live_cache_is_bounded_and_contains_only_projected_metadata(tmp_path):
    paths = Paths(tmp_path)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    private = "synthetic-sensitive-marker-never-retained"
    for index in range(3):
        profile = paths.for_profile(f"11111111-1111-4111-8111-11111111111{index}")
        write_events(profile.audit_jsonl, [event("2026-09-07T10:00:00Z", value=private, name=private,
                                               file_target=private, caller_path=private, error=private)])
    cache = DailySummaryCache(paths, max_files=2)
    assert cache.summary(now=now)["total"] == 3
    assert len(cache._files) == 2
    assert private not in repr(cache.__dict__)
    assert cache.summary(now=now)["total"] == 3


def _overflow_cache(tmp_path, monkeypatch):
    from keys_keeper import desktop_stats
    logs = [tmp_path / f"synthetic-{index}.jsonl" for index in range(129)]
    for path in logs:
        write_events(path, [event("2026-09-07T10:00:00Z")])
    monkeypatch.setattr(desktop_stats, "_log_files", lambda *_args: iter(logs))
    return DailySummaryCache(Paths(tmp_path)), logs, datetime(2026, 9, 7, 12, tzinfo=timezone.utc)


def test_overflow_129_unchanged_logs_use_one_aggregate_without_reads(tmp_path, monkeypatch):
    import builtins
    from keys_keeper import desktop_stats
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    assert cache.summary(now=now)["total"] == 129
    assert len(cache._files) == 128 and cache._aggregate is not None
    def forbidden(*_args, **_kwargs):
        pytest.fail("unchanged overflow reopened or parsed an audit log")
    monkeypatch.setattr(builtins, "open", forbidden)
    monkeypatch.setattr(desktop_stats, "_count_line", forbidden)
    for minute in range(1, 4):
        updated = now + timedelta(minutes=minute)
        result = cache.summary(now=updated)
        assert result["total"] == 129 and result["complete"] is True
        assert result["updated_at"] == updated.isoformat()
    assert cache._full_scans == cache._parsed_lines == 129
    assert len(cache._aggregate.fingerprint) == 32


def test_overflow_change_and_missing_files_recompute_without_lru_cascade(tmp_path, monkeypatch):
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    cache.summary(now=now)
    write_events(logs[0], [event("2026-09-07T10:00:00Z", success=False),
                           event("2026-09-07T11:00:00Z", success=False)])
    changed = cache.summary(now=now)
    assert changed["total"] == 130 and changed["failed"] == 2
    assert cache._full_scans == 130  # Only the overflow miss is read again.
    logs[1].unlink()
    assert cache.summary(now=now)["total"] == 129
    write_events(logs[1], [event("2026-09-07T10:00:00Z")])
    assert cache.summary(now=now)["total"] == 130
    before = cache._parsed_lines
    assert cache.summary(now=now)["total"] == 130
    assert cache._parsed_lines == before
    assert len(cache._files) == 128


def test_overflow_future_day_and_clock_rollback_invalidate_aggregate(tmp_path, monkeypatch):
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    write_events(logs[0], [event("2026-09-07T13:00:00Z")])
    assert cache.summary(now=now)["total"] == 128
    assert cache.summary(now=now + timedelta(minutes=30))["total"] == 128
    assert cache._full_scans == 129
    assert cache.summary(now=now + timedelta(hours=1))["total"] == 129
    assert cache.summary(now=now)["total"] == 128
    assert cache.summary(now=now + timedelta(days=1))["total"] == 0


@pytest.mark.parametrize("failure", ["read", "stat"])
def test_overflow_io_error_discards_aggregate_and_recovers(tmp_path, monkeypatch, failure):
    import builtins
    from pathlib import Path
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    assert cache.summary(now=now)["total"] == 129
    with monkeypatch.context() as broken:
        if failure == "read":
            write_events(logs[0], [event("2026-09-07T10:00:00Z", success=False)])
            original = builtins.open
            def fail_read(path, *args, **kwargs):
                if path == logs[0]:
                    raise PermissionError("synthetic read error")
                return original(path, *args, **kwargs)
            broken.setattr(builtins, "open", fail_read)
        else:
            original = Path.stat
            def fail_stat(path, *args, **kwargs):
                if path == logs[0]:
                    raise PermissionError("synthetic stat error")
                return original(path, *args, **kwargs)
            broken.setattr(Path, "stat", fail_stat)
        result = cache.summary(now=now)
        assert result["total"] == 128 and result["unreadable_logs"] == 1
        assert result["complete"] is False and cache._aggregate is None
    recovered = cache.summary(now=now)
    assert recovered["total"] == 129 and recovered["complete"] is True
    assert cache._aggregate is not None and len(cache._files) == 128


def test_overflow_concurrent_change_does_not_cache_inconsistent_aggregate(tmp_path, monkeypatch):
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    original = cache._read_file
    changed = []
    def read_then_change(path, *args):
        result = original(path, *args)
        if path == logs[0] and not changed:
            changed.append(True)
            write_events(path, [event("2026-09-07T10:00:00Z"), event("2026-09-07T11:00:00Z")])
        return result
    monkeypatch.setattr(cache, "_read_file", read_then_change)
    assert cache.summary(now=now)["total"] == 129
    assert cache._aggregate is None
    assert cache.summary(now=now)["total"] == 130
    assert cache._aggregate is not None


def _small_scan_limits(monkeypatch, *, line=256, scan=1024, chunk=64):
    from keys_keeper import desktop_stats
    monkeypatch.setattr(desktop_stats, "_MAX_LINE_BYTES", line)
    monkeypatch.setattr(desktop_stats, "_MAX_SCAN_BYTES", scan)
    monkeypatch.setattr(desktop_stats, "_READ_CHUNK_BYTES", chunk)
    return desktop_stats


@pytest.mark.parametrize("compressed", [False, True])
def test_oversized_logical_line_is_bounded_incomplete_and_unchanged_read_free(tmp_path, monkeypatch, compressed):
    import builtins
    stats = _small_scan_limits(monkeypatch)
    paths = Paths(tmp_path)
    normal = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    private = "SYNTHETIC-PRIVATE-NEVER-RETAINED"
    oversized = (json.dumps(event("2026-09-07T10:00:00Z", value=private * 20)) + "\n").encode()
    log = paths.audit_archive("2026-09") if compressed else paths.audit_jsonl
    if compressed:
        with gzip.open(log, "wb") as stream:
            stream.write(normal + oversized + normal)
    else:
        log.write_bytes(normal + oversized + normal)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    result = cache.summary(now=now)
    assert result["total"] == 1 and result["complete"] is False
    assert result["unreadable_logs"] == 1
    assert cache._parsed_lines == 1 and cache._full_scans == 1
    assert private not in repr(cache.__dict__)
    with monkeypatch.context() as unchanged:
        def forbidden(*_args, **_kwargs):
            pytest.fail("unchanged unsupported log was read or parsed again")
        unchanged.setattr(builtins, "open", forbidden)
        unchanged.setattr(gzip, "open", forbidden)
        unchanged.setattr(stats, "_count_line", forbidden)
        assert cache.summary(now=now + timedelta(minutes=1))["total"] == 1
    if compressed:
        with gzip.open(log, "wb") as stream:
            stream.write(normal * 2)
    else:
        log.write_bytes(normal * 2)
    recovered = cache.summary(now=now + timedelta(minutes=2))
    assert recovered["total"] == 2 and recovered["complete"] is True


def test_gzip_decompression_and_all_profiles_share_one_scan_budget(tmp_path, monkeypatch):
    import builtins
    stats = _small_scan_limits(monkeypatch, scan=512)
    paths = Paths(tmp_path)
    row = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    archive = paths.audit_archive("2026-09")
    with gzip.open(archive, "wb") as stream:
        stream.write(row * 30)
    profile = paths.for_profile("11111111-1111-4111-8111-111111111111")
    profile.audit_jsonl.parent.mkdir(parents=True)
    profile.audit_jsonl.write_bytes(row)
    original_open = stats._open_log
    delivered, plain, requests = [], [], []
    class LimitedReader:
        def __init__(self, stream): self.stream = stream
        def __enter__(self): self.reader = self.stream.__enter__(); return self
        def __exit__(self, *args): return self.stream.__exit__(*args)
        def read(self, size):
            assert 0 < size <= 64
            requests.append(size)
            data = self.reader.read(size)
            (delivered if isinstance(self.reader, gzip.GzipFile) else plain).append(len(data))
            return data
    monkeypatch.setattr(stats, "_open_log", lambda *args, **kwargs: LimitedReader(original_open(*args, **kwargs)))
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    result = cache.summary(now=now)
    assert sum(delivered) + sum(plain) + archive.stat().st_size <= 512
    assert result["total"] == sum(delivered) // len(row)
    assert result["complete"] is False and result["unreadable_logs"] == 2
    assert cache._aggregate is not None
    with monkeypatch.context() as unchanged:
        unchanged.setattr(builtins, "open", lambda *_a, **_kw: pytest.fail("budget miss reread unchanged logs"))
        unchanged.setattr(gzip, "open", lambda *_a, **_kw: pytest.fail("budget miss decompressed unchanged archive"))
        again = cache.summary(now=now + timedelta(minutes=1))
        assert again["total"] == result["total"] and again["complete"] is False
    archive.unlink()  # The formerly deferred profile must now be counted.
    recovered = cache.summary(now=now + timedelta(minutes=2))
    assert recovered["total"] == 1 and recovered["complete"] is True


def test_plain_log_exact_scan_boundary_and_crlf_split_across_chunks_are_complete(tmp_path, monkeypatch):
    stats = _small_scan_limits(monkeypatch, chunk=1)
    paths = Paths(tmp_path)
    row = json.dumps(event("2026-09-07T10:00:00Z"))
    raw = (row + "\r\n" + row + "\r").encode()
    monkeypatch.setattr(stats, "_MAX_SCAN_BYTES", len(raw))
    paths.audit_jsonl.write_bytes(raw)
    cache = DailySummaryCache(paths)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    result = cache.summary(now=now)
    assert result["total"] == 2 and result["complete"] is True
    assert cache._parsed_lines == 2


def test_prefix_verification_consumes_the_same_budget_as_append_reads(tmp_path, monkeypatch):
    import builtins
    stats = _small_scan_limits(monkeypatch)
    paths = Paths(tmp_path)
    row = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    paths.audit_jsonl.write_bytes(row * 3)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["total"] == 3
    monkeypatch.setattr(stats, "_MAX_SCAN_BYTES", len(row) * 3 - 1)
    with paths.audit_jsonl.open("ab") as stream:
        stream.write(row)
    result = cache.summary(now=now)
    assert result["total"] == 0 and result["complete"] is False
    assert cache._incremental_scans == 0
    assert cache._aggregate is not None
    monkeypatch.setattr(builtins, "open", lambda *_a, **_kw: pytest.fail("unchanged budget-bound prefix reread"))
    assert cache.summary(now=now + timedelta(minutes=1))["complete"] is False


def test_deeply_nested_small_json_is_skipped_without_aborting_summary(tmp_path):
    paths = Paths(tmp_path)
    nested = b'{"padding":' + b"[" * 2000 + b"0" + b"]" * 2000 + b"}\n"
    row = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    paths.audit_jsonl.write_bytes(nested + row)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    result = DailySummaryCache(paths).summary(now=now)
    assert result["total"] == 1 and result["skipped_records"] == 1
    assert result["complete"] is False


def test_overflow_budget_bound_and_nonregular_log_have_read_free_aggregate(tmp_path, monkeypatch):
    import builtins
    stats = _small_scan_limits(monkeypatch, scan=512)
    cache, logs, now = _overflow_cache(tmp_path, monkeypatch)
    logs[-1].unlink()
    logs[-1].mkdir()
    first = cache.summary(now=now)
    assert first["complete"] is False and first["total"] < 129
    assert cache._aggregate is not None
    monkeypatch.setattr(builtins, "open", lambda *_a, **_kw: pytest.fail("unchanged overflow limit reread"))
    monkeypatch.setattr(stats, "_count_line", lambda *_a, **_kw: pytest.fail("unchanged overflow limit reparsed"))
    second = cache.summary(now=now + timedelta(minutes=1))
    assert second["total"] == first["total"]
    assert second["unreadable_logs"] == first["unreadable_logs"]


def test_corrupt_gzip_is_cached_as_incomplete_but_rewrite_recovers(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    archive = paths.audit_archive("2026-09")
    archive.write_bytes(b"not-a-gzip-stream")
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    first = cache.summary(now=now)
    assert first["total"] == 0 and first["complete"] is False
    with monkeypatch.context() as unchanged:
        unchanged.setattr(gzip, "open", lambda *_a, **_kw: pytest.fail("corrupt unchanged archive reopened"))
        assert cache.summary(now=now + timedelta(minutes=1))["complete"] is False
    with gzip.open(archive, "wt") as stream:
        stream.write(json.dumps(event("2026-09-07T10:00:00Z")) + "\n")
    result = cache.summary(now=now + timedelta(minutes=2))
    assert result["total"] == 1 and result["complete"] is True


def test_incomplete_cache_obeys_future_day_timezone_and_clock_rollback(tmp_path, monkeypatch):
    _small_scan_limits(monkeypatch)
    paths = Paths(tmp_path)
    write_events(paths.audit_jsonl, [event("2026-09-07T13:00:00Z"),
                                    event("2026-09-07T13:00:00Z", padding="x" * 400)])
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    assert cache.summary(now=now)["total"] == 0
    assert cache.summary(now=now + timedelta(minutes=30))["total"] == 0
    assert cache._full_scans == 1
    future = cache.summary(now=now + timedelta(hours=1))
    assert future["total"] == 1 and future["complete"] is False
    assert cache.summary(now=now)["total"] == 0
    next_day = cache.summary(now=now + timedelta(days=1))
    assert next_day["total"] == 0 and next_day["complete"] is False
    moscow = cache.summary(now=datetime(2026, 9, 7, 17, tzinfo=ZoneInfo("Europe/Moscow")))
    assert moscow["total"] == 1 and moscow["complete"] is False


def test_gzip_header_without_output_consumes_scan_budget_and_stays_read_free(tmp_path, monkeypatch):
    import builtins
    stats = _small_scan_limits(monkeypatch, scan=512)
    paths = Paths(tmp_path)
    archive = paths.audit_archive("2026-09")
    row = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    packed = gzip.compress(row)
    archive.write_bytes(packed[:3] + b"\x08" + packed[4:10] + b"x" * 2000 + b"\x00" + packed[10:])
    reads = []
    original = stats._ScanBudget.read
    def track(budget, stream, size):
        assert 0 < size <= 64
        data = original(budget, stream, size)
        reads.append(len(data))
        return data
    monkeypatch.setattr(stats._ScanBudget, "read", track)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    cache = DailySummaryCache(paths)
    result = cache.summary(now=now)
    assert sum(reads) <= 512
    assert result["total"] == 0 and result["complete"] is False
    assert result["unreadable_logs"] == 1 and cache._aggregate is not None
    monkeypatch.setattr(builtins, "open", lambda *_a, **_kw: pytest.fail("unchanged gzip header reread"))
    assert cache.summary(now=now + timedelta(minutes=1))["complete"] is False


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO and no-follow opens")
@pytest.mark.parametrize("replacement", ["fifo", "symlink", "directory"])
@pytest.mark.parametrize("compressed", [False, True])
def test_log_replacement_at_open_is_nonblocking_incomplete_and_recovers(tmp_path, monkeypatch, replacement, compressed):
    from keys_keeper import desktop_stats as stats
    paths = Paths(tmp_path)
    log = paths.audit_archive("2026-09") if compressed else paths.audit_jsonl
    row = (json.dumps(event("2026-09-07T10:00:00Z")) + "\n").encode()
    log.write_bytes(gzip.compress(row) if compressed else row)
    outside = tmp_path / "outside"
    outside.write_bytes(gzip.compress(row) if compressed else row)
    original_open = os.open
    replaced = False
    flags_seen = []
    def replace_at_open(path, flags, *args):
        nonlocal replaced
        flags_seen.append(flags)
        assert flags & os.O_NONBLOCK
        if not replaced:
            replaced = True
            log.unlink()
            if replacement == "fifo":
                os.mkfifo(log)
            elif replacement == "symlink":
                log.symlink_to(outside)
            else:
                log.mkdir()
        return original_open(path, flags, *args)
    monkeypatch.setattr(stats.os, "open", replace_at_open)
    cache = DailySummaryCache(paths)
    now = datetime(2026, 9, 7, 12, tzinfo=timezone.utc)
    first = cache.summary(now=now)
    assert flags_seen and first["total"] == 0
    assert first["complete"] is False and first["unreadable_logs"] == 1
    # The replacement is stable unsupported input; it becomes read-free.
    second = cache.summary(now=now + timedelta(minutes=1))
    opens = len(flags_seen)
    assert second["total"] == 0 and second["complete"] is False
    assert cache.summary(now=now + timedelta(minutes=2))["complete"] is False
    assert len(flags_seen) == opens
    monkeypatch.setattr(stats.os, "open", original_open)
    if replacement == "directory":
        log.rmdir()
    else:
        log.unlink()
    log.write_bytes(gzip.compress(row) if compressed else row)
    recovered = cache.summary(now=now + timedelta(minutes=3))
    assert recovered["total"] == 1 and recovered["complete"] is True
