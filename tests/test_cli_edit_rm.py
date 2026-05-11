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


def _add(name, monkeypatch, **kw):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    args = ["add", name, "--type", "api_key", "--stdin"]
    for t in kw.get("tags", []):
        args += ["--tag", t]
    if "note" in kw:
        args += ["--note", kw["note"]]
    cli.main(args)


def test_edit_add_tag(cli_env, monkeypatch):
    _add("ed1", monkeypatch, tags=["a"])
    cli.main(["edit", "ed1", "--add-tag", "b"])
    e = MetadataStore(Paths()).get_by_name("ed1")
    assert set(e.tags) == {"a", "b"}


def test_edit_remove_tag(cli_env, monkeypatch):
    _add("ed2", monkeypatch, tags=["a", "b"])
    cli.main(["edit", "ed2", "--rm-tag", "a"])
    e = MetadataStore(Paths()).get_by_name("ed2")
    assert e.tags == ["b"]


def test_edit_change_note(cli_env, monkeypatch):
    _add("ed3", monkeypatch, note="old")
    cli.main(["edit", "ed3", "--note", "new note"])
    e = MetadataStore(Paths()).get_by_name("ed3")
    assert e.note == "new note"


def test_edit_rename(cli_env, monkeypatch):
    _add("ed4", monkeypatch)
    cli.main(["edit", "ed4", "--name", "ed4-renamed"])
    assert MetadataStore(Paths()).get_by_name("ed4") is None
    assert MetadataStore(Paths()).get_by_name("ed4-renamed") is not None


def test_rm_deletes_entry(cli_env, monkeypatch, capsys):
    _add("to-delete", monkeypatch)
    rc = cli.main(["rm", "to-delete"])
    assert rc == 0
    assert MetadataStore(Paths()).get_by_name("to-delete") is None


def test_rm_missing_returns_error(cli_env):
    rc = cli.main(["rm", "ghost"])
    assert rc != 0
