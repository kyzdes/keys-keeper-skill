"""`keys sync` CLI integration — fakes for backend + remote, cross-platform."""
import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.config import load_sync_config
from keys_keeper.cli_sync import SYNC_ACCESS, SYNC_SECRET, SYNC_PASS
from _sync_fakes import FakeRemote, FakeBackend

AKID = "AKID-LEAKTEST"
S3SECRET = "s3secret-LEAKTEST"
PASSPHRASE = "passphrase-LEAKTEST"


@pytest.fixture
def sync_cli(kk_home, monkeypatch):
    backend = FakeBackend()
    remote = FakeRemote()
    monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync._build_remote", lambda cfg, b: remote)
    return SimpleNamespace(backend=backend, remote=remote)


def _setup(extra=None):
    args = ["sync", "setup", "--endpoint", "https://s3.example.com",
            "--bucket", "mybucket", "--access-key-id", AKID, "--prefix", "kk"]
    if extra:
        args += extra
    with patch("getpass.getpass", side_effect=[S3SECRET, PASSPHRASE, PASSPHRASE]):
        return cli.main(args)


def _add(name, secret):
    with patch("sys.stdin", io.StringIO(secret + "\n")):
        return cli.main(["add", name, "--type", "api_key", "--stdin"])


def test_setup_stores_secrets_in_keychain_not_config(sync_cli):
    assert _setup() == 0
    # secrets live in the keychain
    assert sync_cli.backend.get(SYNC_ACCESS).unseal() == AKID
    assert sync_cli.backend.get(SYNC_SECRET).unseal() == S3SECRET
    assert sync_cli.backend.get(SYNC_PASS).unseal() == PASSPHRASE
    # config is non-secret only
    cfg = load_sync_config(Paths())
    assert cfg.mode == "manual"
    assert cfg.bucket == "mybucket"
    blob = Paths().config_toml.read_text()
    for secret in (AKID, S3SECRET, PASSPHRASE):
        assert secret not in blob


def test_push_then_status(sync_cli, capsys):
    _setup()
    _add("api-1", "sk-AAA")
    capsys.readouterr()
    assert cli.main(["sync", "push"]) == 0
    assert any(k.startswith("versions/000001") for k in sync_cli.remote.objs)
    capsys.readouterr()
    assert cli.main(["sync", "status"]) == 0
    out = capsys.readouterr().out
    assert "remote version:  1" in out
    assert "local changes:   none" in out


def test_pull_restores_on_fresh_home(sync_cli):
    _setup()
    _add("api-1", "sk-AAA")
    cli.main(["sync", "push"])
    # simulate a fresh machine: wipe local metadata (no tombstone), keep creds
    Paths().data_json.unlink()
    assert cli.main(["sync", "pull"]) == 0
    from keys_keeper.store import MetadataStore
    assert [e.name for e in MetadataStore(Paths()).list()] == ["api-1"]


def test_mode_toggle(sync_cli):
    _setup()
    assert cli.main(["sync", "mode", "auto"]) == 0
    assert load_sync_config(Paths()).mode == "auto"
    assert cli.main(["sync", "mode", "off"]) == 0
    assert load_sync_config(Paths()).mode == "off"


def test_S2_no_secret_leaks_into_outputs_or_files(sync_cli, capsys):
    _setup()
    _add("api-1", "sk-AAA")
    cli.main(["sync", "push"])
    cli.main(["sync", "status"])
    captured = capsys.readouterr()
    haystacks = [captured.out, captured.err]
    p = Paths()
    for f in (p.config_toml, p.audit_jsonl, p.sync_state_json):
        if f.exists():
            haystacks.append(f.read_text())
    blob = "\n".join(haystacks)
    for secret in (AKID, S3SECRET, PASSPHRASE, "sk-AAA"):
        assert secret not in blob, f"secret {secret!r} leaked into output/files"
