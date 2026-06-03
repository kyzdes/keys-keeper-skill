"""Auto-mode (SessionStart hook) — fail-open, non-interactive, debounced."""
import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.cli_sync import SYNC_PASS
from _sync_fakes import FakeRemote, FakeBackend

AKID, S3SECRET, PW = "AKID", "s3secret", "passphrase-X"


@pytest.fixture
def sync_cli(kk_home, monkeypatch):
    backend = FakeBackend()
    remote = FakeRemote()
    monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync._build_remote", lambda cfg, b: remote)
    return SimpleNamespace(backend=backend, remote=remote)


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

    monkeypatch.setattr("keys_keeper.cli_sync.subprocess.Popen", fake_popen)
    rc = cli.main(["sync", "auto", "--force"])   # no --foreground
    assert rc == 0
    assert calls["argv"][1:] == ["-m", "keys_keeper", "sync", "auto", "--foreground", "--force"]
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
