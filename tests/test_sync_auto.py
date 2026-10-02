"""Auto-mode (SessionStart hook) — fail-open, non-interactive, debounced."""
import io
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.cli_sync import SYNC_PASS
from keys_keeper import cli_sync, sync_application
from keys_keeper.composition import AccessContext
from _sync_fakes import FakeRemote, FakeBackend


@pytest.fixture(autouse=True)
def isolated_automatic_worker_boundary(monkeypatch):
    monkeypatch.setattr(cli_sync, "run_auto_worker", lambda mode, paths: sync_application._run_auto_worker(paths))

AKID, S3SECRET, PW = "AKID", "s3secret", "passphrase-X"


@pytest.fixture
def sync_cli(kk_home, monkeypatch):
    backend = FakeBackend()
    remote = FakeRemote()
    access_calls = []
    def make_backend(*, access=AccessContext.INTERACTIVE, paths=None):
        access_calls.append(access)
        return backend
    monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.sync_application.build_backend", make_backend)
    monkeypatch.setattr("keys_keeper.sync_application._build_remote", lambda cfg, b: remote)
    return SimpleNamespace(backend=backend, remote=remote, access_calls=access_calls)


def _setup_auto():
    args = ["sync", "setup", "--endpoint", "https://s3.example.com", "--bucket", "b",
            "--access-key-id", AKID, "--auto"]
    with patch("getpass.getpass", side_effect=[S3SECRET, PW, PW]):
        return cli.main(args)


def _add(name, secret):
    with patch("sys.stdin", io.StringIO(secret + "\n")):
        cli.main(["add", name, "--type", "api_key", "--stdin"])


def test_N12_mode_off_is_noop(sync_cli):
    # default mode is off -> auto does nothing, touches no remote object
    assert cli.main(["sync", "auto"]) == 0
    assert sync_cli.remote.objs == {}


def test_auto_foreground_pulls_and_pushes(sync_cli):
    _setup_auto()
    _add("api-1", "sk-AAA")
    assert cli.main(["sync", "auto", "--foreground", "--force"]) == 0
    assert any(k.startswith("versions/000001") for k in sync_cli.remote.objs)
    assert sync_cli.access_calls[-1] is AccessContext.UI_FORBIDDEN


def test_F46_fails_open_on_missing_passphrase(sync_cli, capsys):
    _setup_auto()
    sync_cli.backend.delete(SYNC_PASS)            # break the non-interactive path
    capsys.readouterr()                           # drop setup's output
    rc = cli.main(["sync", "auto", "--foreground", "--force"])
    assert rc == 0                                # never blocks
    out = capsys.readouterr()
    assert out.out == "" and "Traceback" not in out.err
    log = (Paths().root / "sync.log")
    if log.exists():
        assert PW not in log.read_text() and S3SECRET not in log.read_text()


def test_S6_auto_never_calls_getpass(sync_cli):
    _setup_auto()
    sync_cli.backend.delete(SYNC_PASS)
    with patch("getpass.getpass", side_effect=AssertionError("auto must not prompt")):
        assert cli.main(["sync", "auto", "--foreground", "--force"]) == 0


def test_default_path_spawns_detached_worker(sync_cli, monkeypatch):
    # The real SessionStart hook calls `keys sync auto` WITHOUT --foreground,
    # which must spawn a detached worker and return 0 immediately (KI #12).
    _setup_auto()
    calls = {}

    def fake_popen(argv, **kwargs):
        calls["argv"] = argv
        calls["kwargs"] = kwargs
        return object()

    monkeypatch.setattr("keys_keeper.auto_worker.subprocess.Popen", fake_popen)
    rc = cli.main(["sync", "auto", "--force"])   # no --foreground
    assert rc == 0
    assert calls["argv"][1:4] == ["-m", "keys_keeper.auto_worker", "s3"]
    assert calls["argv"][-1] == "--supervise"
    # detached: new session (POSIX) or DETACHED_PROCESS (Windows)
    assert ("start_new_session" in calls["kwargs"]) or ("creationflags" in calls["kwargs"])


def test_auto_debounced_skips_work(sync_cli):
    _setup_auto()
    _add("api-1", "sk-AAA")
    # first run (force) does work + stamps last_auto_at
    cli.main(["sync", "auto", "--foreground", "--force"])
    sync_cli.remote.objs.clear()
    # second run without --force is debounced -> no remote work
    assert cli.main(["sync", "auto", "--foreground"]) == 0
    assert sync_cli.remote.objs == {}


@pytest.mark.parametrize("configured", ["60", "0", "-1", "invalid", "86400", "172800"])
def test_automatic_debounce_environment_never_lowers_daily_floor(monkeypatch, configured):
    monkeypatch.setenv("KEYS_KEEPER_SYNC_DEBOUNCE_SEC", configured)
    assert cli_sync._auto_debounce_seconds() == (172800 if configured == "172800" else 86400)


def test_normal_automatic_work_is_claimed_once_across_concurrent_hooks(sync_cli, monkeypatch):
    _setup_auto()
    calls = []
    monkeypatch.setattr(sync_application, "_auto_debounced", lambda _paths: False)
    monkeypatch.setattr(sync_application, "_run_auto_worker", lambda _paths: calls.append("work"))
    args = SimpleNamespace(force=False, foreground=True)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: cli_sync.cmd_sync_auto(args), range(2)))
    assert results == [0, 0]
    assert calls == ["work"]


def test_daily_failure_claim_survives_new_hook_and_explicit_force_is_manual(sync_cli, monkeypatch):
    _setup_auto()
    calls = []

    def fail(_paths):
        calls.append("attempt")
        raise ConnectionError("SYNTHETIC-ERROR-MUST-NOT-APPEAR")

    monkeypatch.setattr(sync_application, "_run_auto_worker", fail)
    monkeypatch.setattr(sync_application, "_auto_debounced", lambda _paths: False)
    # A failed attempt still blocks a later hook, even if public sync status is
    # overwritten by some other operation after the first hook.
    for _ in range(2):
        assert cli_sync.cmd_sync_auto(SimpleNamespace(force=False, foreground=True)) == 0
    assert calls == ["attempt"]
    assert cli_sync.cmd_sync_auto(SimpleNamespace(force=True, foreground=True)) == 0
    assert calls == ["attempt", "attempt"]


def test_s3_daily_marker_corruption_and_stamp_failure_do_not_run_work(sync_cli, monkeypatch):
    _setup_auto()
    monkeypatch.setattr(sync_application, "_run_auto_worker", lambda _paths: pytest.fail("invalid timing metadata ran work"))
    monkeypatch.setattr(sync_application, "_auto_debounced", lambda _paths: False)
    from keys_keeper.auto_schedule import claim_auto_sync
    schedule = Paths(Paths().root / "sync-auto-schedule")
    claim_auto_sync(schedule, 1000)
    marker = schedule.root / "last-attempt.json"
    marker.write_bytes(b"null")
    assert cli_sync.cmd_sync_auto(SimpleNamespace(force=False, foreground=True)) == 0
    assert marker.read_bytes() == b"null"
    marker.unlink()
    monkeypatch.setattr(sync_application, "_touch_auto_stamp", lambda _paths: (_ for _ in ()).throw(OSError("synthetic failure")))
    assert cli_sync.cmd_sync_auto(SimpleNamespace(force=False, foreground=True)) == 0
    assert marker.exists()  # Claim was durable before stamping or launching failed.


def test_legacy_s3_timestamp_remains_debounced_for_a_full_day(sync_cli, monkeypatch):
    _setup_auto()
    paths = Paths()
    paths.sync_state_json.write_text(json.dumps({"last_auto_at":
        (datetime.now(timezone.utc) - timedelta(hours=23)).strftime("%Y-%m-%dT%H:%M:%SZ")}))
    paths.sync_state_json.chmod(0o600)
    monkeypatch.setattr(sync_application, "_DEBOUNCE_SEC", 60)
    assert sync_application._auto_debounced(paths) is True
    paths.sync_state_json.write_text(json.dumps({"last_auto_at":
        (datetime.now(timezone.utc) - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")}))
    assert sync_application._auto_debounced(paths) is False


def test_manual_s3_push_remains_immediate_after_daily_automatic_pass(sync_cli):
    _setup_auto()
    _add("first", "synthetic-first")
    assert cli.main(["sync", "auto", "--foreground"]) == 0
    _add("second", "synthetic-second")
    assert cli.main(["sync", "push"]) == 0
    assert any(key.startswith("versions/000002") for key in sync_cli.remote.objs)
