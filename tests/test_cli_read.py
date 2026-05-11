import os
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def _seed(monkeypatch, name, type_="api_key", tags=None, note=""):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    args = ["add", name, "--type", type_, "--stdin"]
    if note:
        args += ["--note", note]
    for t in tags or []:
        args += ["--tag", t]
    cli.main(args)


def test_list_empty(cli_env, capsys):
    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no entries" in out.lower() or out.strip() == ""


def test_list_shows_added_entries(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "alpha")
    _seed(monkeypatch, "beta", tags=["dev"])
    capsys.readouterr()  # clear seed output
    cli.main(["list"])
    out = capsys.readouterr().out
    assert "alpha" in out
    assert "beta" in out


def test_list_filter_by_tag(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "x-with-tag", tags=["llm"])
    _seed(monkeypatch, "x-without-tag")
    capsys.readouterr()
    cli.main(["list", "--tag", "llm"])
    out = capsys.readouterr().out
    assert "x-with-tag" in out
    assert "x-without-tag" not in out


def test_list_search_by_name_substring(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "openrouter-cline")
    _seed(monkeypatch, "stripe-test")
    capsys.readouterr()
    cli.main(["list", "--search", "router"])
    out = capsys.readouterr().out
    assert "openrouter-cline" in out
    assert "stripe-test" not in out


def test_info_shows_metadata_no_value(cli_env, capsys, monkeypatch):
    _seed(monkeypatch, "info-target", note="my note")
    capsys.readouterr()
    cli.main(["info", "info-target"])
    out = capsys.readouterr().out
    assert "info-target" in out
    assert "my note" in out
    assert "v\n" not in out  # secret value never printed


def test_info_unknown_name_errors(cli_env, capsys):
    rc = cli.main(["info", "does-not-exist"])
    assert rc != 0
    err = capsys.readouterr().err
    assert "not found" in err.lower() or "no entry" in err.lower()


def test_info_shows_reverse_refs(cli_env, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("k\n"))
    cli.main([
        "add", "ref-target", "--type", "ssh_key", "--stdin",
        "--field", "public_key=ssh-...",
    ])
    cli.main([
        "add", "ref-server", "--type", "server",
        "--from-file", "/dev/null",
        "--field", "host=h", "--field", "user=u", "--field", "auth=ssh_key",
        "--ref", "ssh_key=ref-target",
    ])
    capsys.readouterr()
    cli.main(["info", "ref-target"])
    out = capsys.readouterr().out
    assert "used by" in out.lower()
    assert "ref-server" in out
