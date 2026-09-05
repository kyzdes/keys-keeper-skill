import json
import pytest
from io import StringIO
from unittest.mock import patch
from keys_keeper import cli
from keys_keeper.crypto import encrypt_blob
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


def test_import_rolls_back_and_resumes_on_keychain_failure(
    cli_env, tmp_path, monkeypatch
):
    """A keychain write failure mid-import (e.g. Windows' per-app credential
    cap) must not leave orphan metadata, and a re-run must resume cleanly."""
    from keys_keeper.backend import KeychainError
    from keys_keeper import composition

    for name, val in [("imp1", "a"), ("imp2", "b"), ("imp3", "c")]:
        monkeypatch.setattr("sys.stdin", StringIO(val + "\n"))
        cli.main(["add", name, "--type", "api_key", "--stdin"])

    out_file = tmp_path / "backup.kk"
    with patch("getpass.getpass", side_effect=["pw", "pw"]):
        cli.main(["export", str(out_file)])
    for name in ["imp1", "imp2", "imp3"]:
        cli.main(["rm", name])

    real = composition.build_backend()
    state = {"armed": True}

    class FlakyBackend:
        """Wraps the real test backend; fails the 2nd set() while armed."""
        def __init__(self):
            self.calls = 0

        def get(self, account):
            return real.get(account)

        def set(self, account, value):
            self.calls += 1
            if state["armed"] and self.calls == 2:
                raise KeychainError("simulated WinError 8 (per-app cap)")
            return real.set(account, value)

        def delete(self, account):
            return real.delete(account)

        def list_ids(self):
            return real.list_ids()

    monkeypatch.setattr(cli, "build_backend", lambda: FlakyBackend())

    # First run: imp1 lands, imp2 fails → rolled back, loop stops before imp3.
    with patch("getpass.getpass", return_value="pw"):
        rc = cli.main(["import", str(out_file)])
    assert rc == 1
    store = MetadataStore(Paths())
    assert store.get_by_name("imp1") is not None
    assert store.get_by_name("imp2") is None  # rolled back, not orphaned
    assert store.get_by_name("imp3") is None  # never reached

    # Re-run after the cause is fixed: imp1 skipped, imp2 + imp3 resume.
    state["armed"] = False
    with patch("getpass.getpass", return_value="pw"):
        rc = cli.main(["import", str(out_file)])
    assert rc == 0
    store = MetadataStore(Paths())
    assert store.get_by_name("imp1") is not None
    assert store.get_by_name("imp2") is not None
    assert store.get_by_name("imp3") is not None


def test_import_rejects_reserved_account_before_mutating_vault(cli_env, tmp_path):
    payload = {
        "schema_version": 1,
        "entries": [{
            "id": "kk:sync-passphrase",
            "name": "attacker-entry",
            "type": "api_key",
            "fields": {},
            "tags": [],
            "note": "",
            "refs": [],
            "created_at": "2026-07-20T00:00:00Z",
            "updated_at": "2026-07-20T00:00:00Z",
            "_secret": "overwrite-attempt",
            "_secret_passphrase": None,
        }],
    }
    backup = tmp_path / "malicious.kk"
    backup.write_bytes(encrypt_blob(json.dumps(payload).encode(), password="pw"))

    with patch("getpass.getpass", return_value="pw"):
        assert cli.main(["import", str(backup)]) == 1
    assert MetadataStore(Paths()).list() == []


def test_import_rejects_duplicate_id_without_overwriting_existing_secret(
    cli_env, tmp_path, monkeypatch
):
    from keys_keeper.composition import build_backend

    monkeypatch.setattr("sys.stdin", StringIO("sentinel-original\n"))
    assert cli.main(["add", "original-entry", "--type", "api_key", "--stdin"]) == 0
    store = MetadataStore(Paths())
    original = store.get_by_name("original-entry")
    payload = {
        "schema_version": 1,
        "entries": [{
            "id": original.id,
            "name": "collision-entry",
            "type": "api_key",
            "fields": {},
            "tags": [],
            "note": "",
            "refs": [],
            "created_at": "2026-07-20T00:00:00Z",
            "updated_at": "2026-07-20T00:00:00Z",
            "_secret": "sentinel-collision",
            "_secret_passphrase": None,
        }],
    }
    backup = tmp_path / "duplicate-id.kk"
    backup.write_bytes(encrypt_blob(json.dumps(payload).encode(), password="pw"))

    with patch("getpass.getpass", return_value="pw"):
        assert cli.main(["import", str(backup)]) == 1

    assert store.get_by_name("collision-entry") is None
    assert build_backend().get(original.id).unseal() == "sentinel-original"


def test_legacy_import_export_refuse_catalog_schema_before_prompt_or_backend(
    kk_home, tmp_path, monkeypatch, capsys
):
    """A v3 vault cannot be silently flattened by the legacy backup commands."""
    MetadataStore(Paths()).migrate_catalog_v3()

    def forbidden(*_args, **_kwargs):
        raise AssertionError("legacy handler touched a prompt or backend")

    monkeypatch.setattr(cli, "build_backend", forbidden)
    monkeypatch.setattr("getpass.getpass", forbidden)
    backup = tmp_path / "legacy.kk"
    assert cli.main(["export", str(backup)]) == 1
    assert not backup.exists()
    assert cli.main(["import", str(backup)]) == 1
    assert "schema v3" in capsys.readouterr().err.lower()
