import os
import sys
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.backend import MacOSKeychainBackend
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def run(*argv):
    return cli.main(list(argv))


def test_add_from_stdin(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("sk-test-secret\n"))
    rc = run("add", "test-key", "--type", "api_key", "--stdin", "--service", "openrouter")
    assert rc == 0
    paths = Paths()
    store = MetadataStore(paths)
    e = store.get_by_name("test-key")
    assert e is not None
    assert e.fields["service"] == "openrouter"
    backend = MacOSKeychainBackend(
        service=os.environ["KEYS_KEEPER_TEST_SERVICE"],
        keychain_path=os.environ["KEYS_KEEPER_TEST_KEYCHAIN"],
    )
    assert backend.get(e.id).unseal() == "sk-test-secret"


def test_add_from_file(cli_env, tmp_path):
    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("file-stored-secret")
    rc = run("add", "from-file-key", "--type", "api_key", "--from-file", str(secret_file))
    assert rc == 0
    backend = MacOSKeychainBackend(
        service=os.environ["KEYS_KEEPER_TEST_SERVICE"],
        keychain_path=os.environ["KEYS_KEEPER_TEST_KEYCHAIN"],
    )
    e = MetadataStore(Paths()).get_by_name("from-file-key")
    assert backend.get(e.id).unseal() == "file-stored-secret"


def test_add_requires_input_source(cli_env, capsys):
    rc = run("add", "no-source-key", "--type", "api_key")
    assert rc != 0
    out = capsys.readouterr()
    assert "specify" in (out.out + out.err).lower() or "source" in (out.out + out.err).lower()


def test_add_with_tags_and_note(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    run("add", "tagged", "--type", "api_key", "--stdin", "--tag", "llm", "--tag", "personal", "--note", "test note")
    e = MetadataStore(Paths()).get_by_name("tagged")
    assert set(e.tags) == {"llm", "personal"}
    assert e.note == "test note"


def test_add_rejects_duplicate_name(cli_env, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    run("add", "dupe", "--type", "api_key", "--stdin")
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    rc = run("add", "dupe", "--type", "api_key", "--stdin")
    assert rc != 0
