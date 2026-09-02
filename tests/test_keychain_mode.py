"""Persistent macOS Keychain prompt/bypass policy."""
from __future__ import annotations

import os
import stat

import pytest

from keys_keeper import cli, composition
from keys_keeper.backend import KeychainError
from keys_keeper.keychain_config import (
    BYPASS,
    PROMPT,
    KeychainConfig,
    interaction_allowed,
    load_keychain_config,
    save_keychain_config,
)
from keys_keeper.paths import Paths


def _capture_backend(monkeypatch):
    captured = {}

    class FakeBackend:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(composition, "MacOSKeychainBackend", FakeBackend)
    monkeypatch.setattr(composition.sys, "platform", "darwin")
    return captured


def test_default_mode_allows_prompt(kk_home, monkeypatch):
    captured = _capture_backend(monkeypatch)
    composition.build_backend()
    assert captured["allow_interaction"] is True
    assert load_keychain_config().mode == PROMPT


def test_persisted_bypass_disables_interaction_without_changing_backend(kk_home, monkeypatch):
    save_keychain_config(KeychainConfig(mode=BYPASS))
    captured = _capture_backend(monkeypatch)
    composition.build_backend()
    assert captured["allow_interaction"] is False
    assert captured["service"] == "keys-keeper"


def test_test_keychain_always_disables_interaction(kk_home, monkeypatch, tmp_path):
    captured = _capture_backend(monkeypatch)
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(tmp_path / "test.keychain-db"))
    composition.build_backend()
    assert captured["allow_interaction"] is False


def test_corrupt_policy_fails_closed_before_backend_construction(kk_home, monkeypatch):
    paths = Paths()
    paths.ensure()
    paths.keychain_toml.write_text('mode = "broken"\n')
    captured = _capture_backend(monkeypatch)
    with pytest.raises(KeychainError, match="invalid keychain mode"):
        composition.build_backend()
    assert captured == {}


def test_environment_override_wins(kk_home, monkeypatch):
    save_keychain_config(KeychainConfig(mode=PROMPT))
    monkeypatch.setenv("KEYS_KEEPER_KEYCHAIN_MODE", BYPASS)
    assert interaction_allowed() is False


def test_cli_bypass_is_persistent_and_owner_only(kk_home, monkeypatch, capsys):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    assert cli.main(["keychain", "bypass"]) == 0
    out = capsys.readouterr().out
    assert "original macOS Keychain items remain in place" in out
    assert load_keychain_config().mode == BYPASS
    if os.name == "posix":
        assert stat.S_IMODE(Paths().keychain_toml.stat().st_mode) == 0o600


def test_cli_status_does_not_build_or_open_keychain(kk_home, monkeypatch, capsys):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    monkeypatch.setattr(
        "keys_keeper.composition.build_backend",
        lambda: (_ for _ in ()).throw(AssertionError("opened keychain")),
    )
    assert cli.main(["keychain", "status"]) == 0
    assert "native Security.framework" in capsys.readouterr().out


def test_cli_prompt_restores_interaction(kk_home, monkeypatch):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    save_keychain_config(KeychainConfig(mode=BYPASS))
    assert cli.main(["keychain", "prompt"]) == 0
    assert load_keychain_config().mode == PROMPT
