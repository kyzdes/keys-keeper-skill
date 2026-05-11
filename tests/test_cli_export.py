import pytest
from io import StringIO
from unittest.mock import patch
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def cli_env(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    return kk_home


def test_export_then_import_round_trip(cli_env, tmp_path, monkeypatch):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    cli.main(["add", "exp1", "--type", "api_key", "--stdin"])
    monkeypatch.setattr("sys.stdin", StringIO("v2\n"))
    cli.main(["add", "exp2", "--type", "api_key", "--stdin"])

    out_file = tmp_path / "backup.kk"

    with patch("getpass.getpass", side_effect=["password123", "password123"]):
        cli.main(["export", str(out_file)])
    assert out_file.exists()
    assert out_file.stat().st_size > 32

    cli.main(["rm", "exp1"])
    cli.main(["rm", "exp2"])
    assert MetadataStore(Paths()).get_by_name("exp1") is None

    with patch("getpass.getpass", return_value="password123"):
        cli.main(["import", str(out_file)])

    assert MetadataStore(Paths()).get_by_name("exp1") is not None
    assert MetadataStore(Paths()).get_by_name("exp2") is not None
