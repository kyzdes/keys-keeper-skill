import gzip
import json
import os
import time
from datetime import datetime, timezone
import pytest
from keys_keeper.audit import AuditLog, AuditEvent
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


def test_jsonl_format_one_event_per_line(audit, kk_home):
    audit.record(op="copy", name="a", id_="kk:1", success=True)
    audit.record(op="copy", name="b", id_="kk:2", success=True)
    raw = (kk_home / "audit.jsonl").read_text()
    lines = [l for l in raw.splitlines() if l.strip()]
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
