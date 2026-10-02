import gzip
import json
import os
import stat
import sys
from datetime import datetime, timezone
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from keys_keeper import audit as audit_module
from keys_keeper.audit import AuditLog, AuditReadLimit, normalize_outcome, record_outcome
from keys_keeper.paths import Paths


@pytest.fixture
def audit(kk_home):
    paths = Paths()
    paths.ensure()
    return AuditLog(paths)


def test_record_appends_event(audit):
    audit.record(op="copy", name="openrouter-cline", id_="kk:abc", success=True)
    events = list(audit.tail(10))
    assert len(events) == 1
    assert events[0]["op"] == "copy"
    assert events[0]["name"] == "openrouter-cline"


def test_legacy_and_new_outcomes_remain_readable_without_false_success(audit):
    audit.record(op="copy", name="legacy", id_="kk:old", success=True)
    assert record_outcome(audit, op="update", name="unknown", id_="kk:new", committed=None) == "recorded"
    assert record_outcome(audit, op="update", name="published", id_="kk:new", success=False,
                          committed=True, error="synthetic-private-error") == "recorded"
    legacy, unknown, published = list(audit.tail(3))
    assert "committed" not in legacy and "outcome" not in legacy
    assert unknown["committed"] is None and unknown["outcome"] == "unconfirmed" and unknown["success"] is False
    assert published["committed"] is True and published["outcome"] == "published" and published["success"] is True
    assert published["audit_status"] == "recorded"
    assert "synthetic-private-error" not in audit.paths.audit_jsonl.read_text()
    assert len(list(audit.search(op="update"))) == 2


def test_outcome_normalizer_does_not_trust_truthy_or_secret_bearing_error_fields():
    error = RuntimeError("synthetic-private-error")
    error.committed = 1
    error.audit_status = {"secret": "synthetic-private-error"}
    assert normalize_outcome(error=error) == {"committed": None, "outcome": "unconfirmed", "audit_status": "unknown"}
    error.committed = True
    assert normalize_outcome(error=error, committed=False)["outcome"] == "published"


def test_record_includes_timestamp_and_caller(audit):
    audit.record(op="inject", name="x", id_="kk:1", file_target="~/proj/.env", success=True)
    e = list(audit.tail(1))[0]
    assert "ts" in e
    assert e["caller_pid"] == os.getppid() or e["caller_pid"] == os.getpid()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX caller lookup")
def test_caller_lookup_requests_executable_not_full_argv(monkeypatch):
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="/bin/zsh\n")

    monkeypatch.setattr(audit_module.sys, "platform", "darwin")
    monkeypatch.setattr(audit_module.subprocess, "run", fake_run)
    assert audit_module._resolve_caller_path(123) == "/bin/zsh"
    assert captured["command"] == ["/bin/ps", "-p", "123", "-o", "comm="]
    assert "shell" not in captured["kwargs"]


def test_record_sanitizes_metadata_and_does_not_persist_error_text(audit):
    audit.record(
        op="copy\nforged",
        name="entry\tname",
        id_="kk:test\rvalue",
        error="backend accidentally echoed sk-super-secret",
        success=False,
    )
    event = list(audit.tail(1))[0]
    assert "\n" not in event["op"]
    assert "\t" not in event["name"]
    assert "\r" not in event["id"]
    assert event["error"] == "operation failed"
    assert "sk-super-secret" not in Paths().audit_jsonl.read_text()


def test_jsonl_format_one_event_per_line(audit, kk_home):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    raw = (kk_home / "audit.jsonl").read_text()
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 2
    for line in lines:
        json.loads(line)  # each line is valid JSON


def test_filter_by_op(audit):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="inject", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    copies = list(audit.search(op="copy"))
    assert len(copies) == 2


def test_filter_by_name(audit):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    a_only = list(audit.search(name="a"))
    assert len(a_only) == 1


def test_newest_first_applies_limit_after_ordering(audit):
    audit.record(op="copy", name="old", id_="kk:1")
    audit.record(op="inject", name="new", id_="kk:2")
    assert [e["name"] for e in audit.search(limit=1)] == ["old"]
    assert [e["name"] for e in audit.search(limit=1, newest_first=True)] == ["new"]
    assert [e["name"] for e in audit.search(op="copy", limit=1, newest_first=True)] == ["old"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits only")
def test_audit_jsonl_is_mode_0600(audit, kk_home):
    """The audit log must not be world/group readable: it records which
    secrets were accessed, by whom, and into which files."""
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit_path = kk_home / "audit.jsonl"
    mode = stat.S_IMODE(os.stat(audit_path).st_mode)
    assert oct(mode)[-3:] == "600", f"audit.jsonl is {oct(mode)}, expected 0600"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits only")
def test_audit_jsonl_chmod_tightens_loose_existing_file(audit, kk_home):
    """If the file was somehow created world-readable (older version, umask),
    a record() call must tighten it back to 0600."""
    audit_path = kk_home / "audit.jsonl"
    audit_path.write_text("")  # honors umask, typically 0644
    os.chmod(audit_path, 0o644)
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    mode = stat.S_IMODE(os.stat(audit_path).st_mode)
    assert oct(mode)[-3:] == "600", f"audit.jsonl is {oct(mode)}, expected 0600"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits only")
def test_config_root_is_mode_0700(audit, kk_home):
    """The config/data root dir must be 0700 — it holds the audit log,
    encrypted blobs, and serve-url session token."""
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    mode = stat.S_IMODE(os.stat(kk_home).st_mode)
    assert oct(mode)[-3:] == "700", f"root dir is {oct(mode)}, expected 0700"


def test_rotate_archives_previous_month(audit, kk_home, monkeypatch):
    """When current month differs from latest event's month, rotate."""
    paths = Paths()
    # write a fake old jsonl file
    old_path = paths.audit_jsonl
    old_path.write_text(
        json.dumps({"ts": "2026-04-15T10:00:00Z", "op": "copy", "name": "old", "id": "kk:0", "success": True}) + "\n"
    )
    # set current time to May
    audit.rotate_if_needed(now=datetime(2026, 5, 1, tzinfo=timezone.utc))
    archive = paths.audit_archive("2026-04")
    assert archive.exists()
    with gzip.open(archive, "rt") as f:
        line = f.readline()
        assert "old" in line
    # current jsonl should be empty after rotation
    assert not old_path.exists() or old_path.read_text() == ""


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode bits only")
def test_rotated_archive_is_mode_0600(audit, kk_home):
    """The rotated .gz archive holds the same sensitive metadata as the live
    log, so it must be 0600 too (gzip.open would inherit the umask)."""
    paths = Paths()
    paths.audit_jsonl.write_text(
        json.dumps({"ts": "2026-04-15T10:00:00Z", "op": "copy", "name": "old", "id": "kk:0", "success": True}) + "\n"
    )
    audit.rotate_if_needed(now=datetime(2026, 5, 1, tzinfo=timezone.utc))
    archive = paths.audit_archive("2026-04")
    mode = stat.S_IMODE(os.stat(archive).st_mode)
    assert oct(mode)[-3:] == "600", f"rotated archive is {oct(mode)}, expected 0600"


def _event(name, *, op="copy", ts="2026-10-02T10:00:00Z"):
    return json.dumps({"ts": ts, "op": op, "name": name}, ensure_ascii=False).encode("utf-8")


def _track_reads(monkeypatch):
    original = audit_module._open_audit
    reads = []

    class TrackedStream:
        def __init__(self, stream):
            self.stream = stream

        def fileno(self):
            return self.stream.fileno()

        def seek(self, offset):
            return self.stream.seek(offset)

        def read(self, amount):
            assert 0 < amount <= audit_module._READ_CHUNK_BYTES
            chunk = self.stream.read(amount)
            reads.append(len(chunk))
            return chunk

    @contextmanager
    def tracked(path):
        with original(path) as stream:
            yield TrackedStream(stream) if stream is not None else None

    monkeypatch.setattr(audit_module, "_open_audit", tracked)
    return reads


@pytest.mark.parametrize("bad", [-1, True, False, 1.5, "1", None, 10_001])
def test_invalid_result_limits_fail_before_open(audit, monkeypatch, bad):
    def fail_open(path):
        raise AssertionError("invalid limit opened audit file")

    monkeypatch.setattr(audit_module, "_open_audit", fail_open)
    with pytest.raises(ValueError, match="audit limit must be an integer"):
        list(audit.search(limit=bad))
    with pytest.raises(ValueError, match="audit limit must be an integer"):
        list(audit.tail(bad))


def test_zero_and_missing_log_return_without_records(audit, monkeypatch):
    assert list(audit.search()) == []
    assert list(audit.tail()) == []
    monkeypatch.setattr(audit_module, "_open_audit", lambda path: pytest.fail("zero limit opened file"))
    assert list(audit.search(limit=0)) == []
    assert list(audit.tail(0)) == []


@pytest.mark.parametrize("read_kind", ["tail", "newest", "oldest"])
def test_limited_reads_skip_the_unneeded_large_remainder(audit, monkeypatch, read_kind):
    monkeypatch.setattr(audit_module, "_READ_CHUNK_BYTES", 128)
    monkeypatch.setattr(audit_module, "_MAX_SCAN_BYTES", 128)
    monkeypatch.setattr(audit_module, "_MAX_LINE_BYTES", 100)
    needed = _event("needed") + b"\n"
    remainder = b"x" * 1024 + b"\n"
    audit.paths.audit_jsonl.write_bytes(needed + remainder if read_kind == "oldest" else remainder + needed)
    reads = _track_reads(monkeypatch)
    if read_kind == "tail":
        result = list(audit.tail(1))
    else:
        result = list(audit.search(limit=1, newest_first=read_kind == "newest"))
    assert [event["name"] for event in result] == ["needed"]
    assert reads == [128]


@pytest.mark.parametrize("chunk_size", [1, 2, 7, 64])
def test_unicode_crlf_and_blank_tail_order_cross_chunk_boundaries(audit, monkeypatch, chunk_size):
    monkeypatch.setattr(audit_module, "_READ_CHUNK_BYTES", chunk_size)
    audit.paths.audit_jsonl.write_bytes(_event("старый🔑") + b"\r\n\r\n" + _event("новый") + b"\r")
    assert [event["name"] for event in audit.tail(3)] == ["старый🔑", "новый"]
    assert [event["name"] for event in audit.tail(2)] == ["новый"]
    assert [event["name"] for event in audit.search()] == ["старый🔑", "новый"]
    assert [event["name"] for event in audit.search(newest_first=True)] == ["новый", "старый🔑"]


@pytest.mark.parametrize("raw", [b"", b"\n", b"\r\n", b"\n\n", b"a", b"a\n", b"\na", b"a\r\nb\n", b"a\rb"])
def test_raw_line_order_matches_universal_newline_split(audit, monkeypatch, raw):
    monkeypatch.setattr(audit_module, "_READ_CHUNK_BYTES", 1)
    audit.paths.audit_jsonl.write_bytes(raw)
    expected = raw.decode("utf-8").splitlines()
    with audit_module._open_audit(audit.paths.audit_jsonl) as stream:
        assert [line.decode("utf-8") for line in audit_module._audit_lines(stream)] == expected
    with audit_module._open_audit(audit.paths.audit_jsonl) as stream:
        assert [line.decode("utf-8") for line in audit_module._audit_lines(stream, newest_first=True)] == expected[::-1]


@pytest.mark.parametrize("newest_first", [False, True])
def test_unmatched_search_hits_global_scan_cap_with_fixed_error(audit, monkeypatch, newest_first):
    monkeypatch.setattr(audit_module, "_READ_CHUNK_BYTES", 64)
    monkeypatch.setattr(audit_module, "_MAX_SCAN_BYTES", 128)
    audit.paths.audit_jsonl.write_bytes((_event("other") + b"\n") * 20)
    reads = _track_reads(monkeypatch)
    with pytest.raises(AuditReadLimit, match="^audit log read limit exceeded$"):
        list(audit.search(name="absent", newest_first=newest_first))
    assert sum(reads) == 128


@pytest.mark.parametrize("method", ["tail", "oldest", "newest", "rotate"])
def test_oversized_logical_line_is_rejected_without_large_read(audit, monkeypatch, method):
    monkeypatch.setattr(audit_module, "_READ_CHUNK_BYTES", 32)
    monkeypatch.setattr(audit_module, "_MAX_LINE_BYTES", 64)
    audit.paths.audit_jsonl.write_bytes(b"x" * 1024)
    reads = _track_reads(monkeypatch)
    with pytest.raises(AuditReadLimit, match="^audit log read limit exceeded$"):
        if method == "tail":
            list(audit.tail(1))
        elif method == "rotate":
            audit.rotate_if_needed()
        else:
            list(audit.search(newest_first=method == "newest"))
    assert sum(reads) <= 96
    assert audit.paths.audit_jsonl.read_bytes() == b"x" * 1024


def test_forward_and_backward_filters_apply_before_matching_limit(audit):
    rows = [
        _event("wanted", ts="2026-10-01T10:00:00Z"),
        _event("wanted", op="inject"),
        _event("other"),
        _event("wanted"),
    ]
    audit.paths.audit_jsonl.write_bytes(b"\n".join(rows))
    since = datetime(2026, 10, 2, tzinfo=timezone.utc)
    for newest_first in (False, True):
        result = list(audit.search(op="copy", name="wanted", since=since, limit=1, newest_first=newest_first))
        assert result == [json.loads(rows[-1])]


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO and symlink support")
@pytest.mark.parametrize("kind", ["fifo", "directory", "symlink"])
def test_nonregular_log_is_rejected_without_reading_or_waiting(audit, monkeypatch, tmp_path, kind):
    target = audit.paths.audit_jsonl
    if kind == "fifo":
        os.mkfifo(target)
    elif kind == "directory":
        target.mkdir()
    else:
        outside = tmp_path / "outside.jsonl"
        outside.write_bytes(_event("outside") + b"\n")
        target.symlink_to(outside)
    monkeypatch.setattr(audit_module.os, "open", lambda *a, **k: pytest.fail("nonregular log was opened"))
    with pytest.raises(AuditReadLimit):
        list(audit.search())


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO support")
def test_file_replaced_with_fifo_at_open_is_rejected_nonblocking(audit, monkeypatch):
    audit.paths.audit_jsonl.write_bytes(_event("before") + b"\n")
    original_open = os.open

    def replace_at_open(path, flags, *args):
        assert flags & os.O_NONBLOCK
        audit.paths.audit_jsonl.unlink()
        os.mkfifo(audit.paths.audit_jsonl)
        return original_open(path, flags, *args)

    monkeypatch.setattr(audit_module.os, "open", replace_at_open)
    with pytest.raises(AuditReadLimit):
        list(audit.search())


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX no-follow open support")
def test_file_replaced_with_symlink_at_open_does_not_read_target(audit, monkeypatch, tmp_path):
    audit.paths.audit_jsonl.write_bytes(_event("before") + b"\n")
    outside = tmp_path / "outside.jsonl"
    outside.write_bytes(_event("outside") + b"\n")
    original_open = os.open

    def replace_at_open(path, flags, *args):
        assert flags & os.O_NOFOLLOW
        audit.paths.audit_jsonl.unlink()
        audit.paths.audit_jsonl.symlink_to(outside)
        return original_open(path, flags, *args)

    monkeypatch.setattr(audit_module.os, "open", replace_at_open)
    with pytest.raises(AuditReadLimit, match="^audit log read limit exceeded$"):
        list(audit.search())
