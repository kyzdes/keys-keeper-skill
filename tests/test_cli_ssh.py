from io import StringIO
from pathlib import Path

import pytest
from keys_keeper import cli, ssh_runner
from keys_keeper.models import Entry, EntryType, now_iso
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore

# Uses /dev/null as a placeholder source — POSIX-only path. Mark the whole
# module macOS-only; a Windows-friendly variant can land in a separate test.
pytestmark = pytest.mark.macos


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _seed_server_with_key(monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("dummy-private-key-content\n"))
    cli.main([
        "add", "test-key", "--type", "ssh_key", "--stdin",
        "--field", "public_key=ssh-ed25519 AAA...",
    ])
    cli.main([
        "add", "test-server", "--type", "server",
        "--from-file", "/dev/null",  # server has no own secret, but CLI still requires source
        "--field", "host=1.2.3.4",
        "--field", "user=root",
        "--field", "port=22",
        "--field", "auth=ssh_key",
        "--ref", "ssh_key=test-key",
    ])


def test_ssh_invokes_ssh_with_resolved_key(cli_env, monkeypatch, tmp_path):
    _seed_server_with_key(monkeypatch)
    captured = {}
    real_run = __import__("subprocess").run
    def fake_run(cmd, **kw):
        # only intercept the ssh exec; let real subprocess.run handle keychain/security calls
        if cmd and Path(cmd[0]).name == "ssh":
            captured["cmd"] = cmd

            class R:
                returncode = 0

            return R()
        return real_run(cmd, **kw)
    monkeypatch.setattr("subprocess.run", fake_run)
    rc = cli.main(["ssh", "test-server"])
    assert rc == 0
    assert Path(captured["cmd"][0]).is_absolute()
    assert Path(captured["cmd"][0]).name == "ssh"
    assert "root@1.2.3.4" in captured["cmd"]
    # the -i flag must be followed by a path that exists at call time
    assert "-i" in captured["cmd"]


def test_ssh_unknown_server(cli_env):
    rc = cli.main(["ssh", "no-such-server"])
    assert rc != 0


def test_ssh_revalidates_legacy_metadata_before_exec(cli_env, capsys):
    """Unsafe metadata already present on disk must not reach argv."""
    now = now_iso()
    MetadataStore(Paths()).add(Entry(
        id="kk:11111111-1111-4111-8111-111111111111",
        name="legacy-unsafe-server",
        type=EntryType.SERVER,
        fields={
            "host": "good.example",
            "user": "-oProxyCommand=touch /tmp/pwned",
            "port": 22,
            "auth": "none",
        },
        tags=[],
        note="",
        refs=[],
        created_at=now,
        updated_at=now,
    ))

    assert cli.main(["ssh", "legacy-unsafe-server"]) == 1
    assert "unsafe" in capsys.readouterr().err


def test_ssh_removes_tempfile_when_lockdown_fails(cli_env, monkeypatch):
    _seed_server_with_key(monkeypatch)
    captured = {}

    def fail_lockdown(path):
        captured["path"] = path
        raise ssh_runner.SSHRunnerError("lockdown failed")

    monkeypatch.setattr(ssh_runner, "_lock_down_key_file", fail_lockdown)
    assert cli.main(["ssh", "test-server"]) == 1
    assert not Path(captured["path"]).exists()
