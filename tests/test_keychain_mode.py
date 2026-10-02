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
    KeychainConfigCommitError,
    MAX_KEYCHAIN_CONFIG_BYTES,
    interaction_allowed,
    load_keychain_config,
    save_keychain_config,
)
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.private_files import atomic_write_bytes
from keys_keeper.store import MetadataStore


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
    assert captured["allow_legacy_bridge"] is False
    assert load_keychain_config().mode == PROMPT


def test_persisted_bypass_disables_interaction_without_changing_backend(kk_home, monkeypatch):
    save_keychain_config(KeychainConfig(mode=BYPASS))
    captured = _capture_backend(monkeypatch)
    composition.build_backend()
    assert captured["allow_interaction"] is False
    assert captured["allow_legacy_bridge"] is True
    assert captured["service"] == "keys-keeper"


def test_test_keychain_always_disables_interaction(kk_home, monkeypatch, tmp_path):
    captured = _capture_backend(monkeypatch)
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(tmp_path / "test.keychain-db"))
    composition.build_backend()
    assert captured["allow_interaction"] is False
    assert captured["allow_legacy_bridge"] is True


def test_ui_forbidden_context_overrides_prompt_and_disables_bridge(kk_home, monkeypatch):
    save_keychain_config(KeychainConfig(mode=PROMPT))
    captured = _capture_backend(monkeypatch)
    composition.build_backend(access=composition.AccessContext.UI_FORBIDDEN)
    assert captured["allow_interaction"] is False
    assert captured["allow_legacy_bridge"] is False


def test_ui_forbidden_context_does_not_depend_on_persistent_policy(kk_home, monkeypatch):
    paths = Paths()
    paths.ensure()
    paths.keychain_toml.write_text('mode = "broken"\n')
    captured = _capture_backend(monkeypatch)
    composition.build_backend(access=composition.AccessContext.UI_FORBIDDEN)
    assert captured["allow_interaction"] is False


def test_acl_preparation_context_explicitly_allows_one_setup_prompt(
    kk_home, monkeypatch
):
    save_keychain_config(KeychainConfig(mode=BYPASS))
    captured = _capture_backend(monkeypatch)
    composition.build_backend(access=composition.AccessContext.ACL_PREPARATION)
    assert captured["allow_interaction"] is True
    assert captured["allow_legacy_bridge"] is False


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


def test_cli_status_check_uses_metadata_only_ui_forbidden_probe(
    kk_home, monkeypatch, capsys
):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    captured = {}

    class FakeBackend:
        def readiness(self):
            from keys_keeper.backend import MacOSKeychainReadiness

            return MacOSKeychainReadiness(
                state="ready",
                interaction_allowed=False,
                legacy_bridge_allowed=False,
            )

    def fake_build_backend(*, access):
        captured["access"] = access
        return FakeBackend()

    monkeypatch.setattr("keys_keeper.composition.build_backend", fake_build_backend)
    assert cli.main(["keychain", "status", "--check"]) == 0
    out = capsys.readouterr().out
    assert "no-UI metadata probe: ready" in out
    assert "secret values: not read" in out
    assert captured["access"] is composition.AccessContext.UI_FORBIDDEN


def test_cli_prompt_restores_interaction(kk_home, monkeypatch):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    save_keychain_config(KeychainConfig(mode=BYPASS))
    assert cli.main(["keychain", "prompt"]) == 0
    assert load_keychain_config().mode == PROMPT


def test_cli_prepare_targets_one_original_item_with_bounded_acl_commit(
    kk_home, monkeypatch, capsys
):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    entry = Entry.new(name="provider-api", type=EntryType.API_KEY)
    MetadataStore(Paths()).add(entry)
    calls = []

    class StrictBackend:
        def native_access_state(self, account):
            calls.append(("preflight", account))
            return "needs-preparation"

    class SetupBackend:
        def prepare_native_access(self, account):
            calls.append(("commit", account))
            return True

    def fake_build_backend(*, access):
        calls.append(("context", access))
        if access is composition.AccessContext.UI_FORBIDDEN:
            return StrictBackend()
        assert access is composition.AccessContext.ACL_PREPARATION
        return SetupBackend()

    monkeypatch.setattr("keys_keeper.composition.build_backend", fake_build_backend)
    assert cli.main(["keychain", "prepare", "provider-api"]) == 0
    out = capsys.readouterr().out
    assert "secret value was not read or copied" in out
    assert calls == [
        ("context", composition.AccessContext.UI_FORBIDDEN),
        ("preflight", entry.id),
        ("context", composition.AccessContext.ACL_PREPARATION),
        ("commit", entry.id),
    ]


def test_cli_prepare_check_never_builds_interactive_backend(
    kk_home, monkeypatch, capsys
):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    entry = Entry.new(name="provider-api", type=EntryType.API_KEY)
    MetadataStore(Paths()).add(entry)

    class StrictBackend:
        def native_access_state(self, account):
            assert account == entry.id
            return "needs-preparation"

    def fake_build_backend(*, access):
        assert access is composition.AccessContext.UI_FORBIDDEN
        return StrictBackend()

    monkeypatch.setattr("keys_keeper.composition.build_backend", fake_build_backend)
    assert cli.main(["keychain", "prepare", "provider-api", "--check"]) == 1
    assert "needs preparation" in capsys.readouterr().out


def test_cli_prepare_refuses_to_weaken_partition_policy(
    kk_home, monkeypatch, capsys
):
    monkeypatch.setattr("keys_keeper.cli_keychain.sys.platform", "darwin")
    entry = Entry.new(name="signed-item", type=EntryType.API_KEY)
    MetadataStore(Paths()).add(entry)

    class StrictBackend:
        def native_access_state(self, account):
            assert account == entry.id
            return "partitioned"

    def fake_build_backend(*, access):
        assert access is composition.AccessContext.UI_FORBIDDEN
        return StrictBackend()

    monkeypatch.setattr("keys_keeper.composition.build_backend", fake_build_backend)
    assert cli.main(["keychain", "prepare", "signed-item"]) == 1
    err = capsys.readouterr().err
    assert "will not weaken" in err
    assert "signed Keys Keeper broker" in err


def _policy_paths(tmp_path, monkeypatch):
    monkeypatch.delenv("KEYS_KEEPER_KEYCHAIN_MODE", raising=False)
    return Paths(tmp_path / "policy")


def _symlink_or_skip(link, target):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")


def test_policy_final_symlink_is_rejected_on_read_and_write(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)
    paths.ensure()
    target = tmp_path / "unrelated-policy"
    original = b'mode = "bypass"\n'
    atomic_write_bytes(target, original)
    _symlink_or_skip(paths.keychain_toml, target)

    with pytest.raises(KeychainError, match="safely"):
        load_keychain_config(paths)
    with pytest.raises(KeychainError, match="safely"):
        save_keychain_config(KeychainConfig(mode=PROMPT), paths)

    assert paths.keychain_toml.is_symlink()
    assert target.read_bytes() == original


def test_dangling_policy_link_does_not_silently_restore_prompt(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)
    paths.ensure()
    _symlink_or_skip(paths.keychain_toml, tmp_path / "absent-policy")
    with pytest.raises(KeychainError):
        load_keychain_config(paths)


def test_policy_size_cap_is_checked_before_open(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)
    atomic_write_bytes(paths.keychain_toml, b"x" * (MAX_KEYCHAIN_CONFIG_BYTES + 1))

    def forbidden_open(*_args, **_kwargs):
        pytest.fail("oversized policy reached an opened descriptor")

    monkeypatch.setattr("keys_keeper.private_files._open_read", forbidden_open)
    with pytest.raises(KeychainError, match="safely"):
        load_keychain_config(paths)


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_policy_fifo_fails_without_blocking(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)
    paths.ensure()
    os.mkfifo(paths.keychain_toml, 0o600)
    with pytest.raises(KeychainError, match="safely"):
        load_keychain_config(paths)


def test_invalid_policy_encoding_has_fixed_error(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)
    atomic_write_bytes(paths.keychain_toml, b'mode = "\xff"\n')
    with pytest.raises(KeychainError) as caught:
        load_keychain_config(paths)
    assert str(caught.value) == "cannot read keychain policy safely; verify keychain.toml"
    assert "\\xff" not in str(caught.value)


def test_policy_postpublication_fsync_failure_keeps_committed_error(tmp_path, monkeypatch):
    paths = _policy_paths(tmp_path, monkeypatch)

    def failed_fsync(_path):
        raise OSError("synthetic parent fsync failure")

    monkeypatch.setattr("keys_keeper.private_files.fsync_parent", failed_fsync)
    with pytest.raises(KeychainConfigCommitError) as caught:
        save_keychain_config(KeychainConfig(mode=BYPASS), paths)

    assert caught.value.committed is True
    assert paths.keychain_toml.read_bytes() == b'mode = "bypass"\n'
