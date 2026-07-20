import gzip
import json
import os
import stat
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from keys_keeper import audit as audit_module
from keys_keeper.audit import AuditLog
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
