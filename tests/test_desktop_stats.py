import gzip
import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from keys_keeper import cli
from keys_keeper.audit import AuditLog, caller_identity
from keys_keeper.desktop_stats import today_summary
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
