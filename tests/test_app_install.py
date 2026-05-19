"""Tests for `keys app install` / `keys app uninstall`.

macOS path covers bundle layout, executable bits, Info.plist correctness,
icon embedding, and idempotent re-install via --force. Windows path covers
the FileNotFoundError fast-path and is skipped on macOS.
"""
from __future__ import annotations

import plistlib
import sys
from pathlib import Path

import pytest

from keys_keeper import cli, macos_app, windows_app


# ---------- macOS bundle builder ----------


@pytest.mark.macos
def test_install_creates_bundle_structure(tmp_path):
    result = macos_app.install_app(tmp_path)
    bundle = result.bundle_path

    assert result.created is True
    assert bundle == tmp_path / "Keys Keeper.app"
    assert (bundle / "Contents" / "Info.plist").is_file()
    launcher = bundle / "Contents" / "MacOS" / "keys-keeper-launcher"
    assert launcher.is_file()
    # executable bit set for owner
    assert launcher.stat().st_mode & 0o100


@pytest.mark.macos
def test_install_writes_valid_plist_with_bundle_id(tmp_path):
    macos_app.install_app(tmp_path)
    plist_bytes = (tmp_path / "Keys Keeper.app" / "Contents" / "Info.plist").read_bytes()
    info = plistlib.loads(plist_bytes)
    assert info["CFBundleIdentifier"] == macos_app.BUNDLE_ID
    assert info["CFBundleExecutable"] == "keys-keeper-launcher"
    assert info["LSUIElement"] is True  # no Dock icon


@pytest.mark.macos
def test_install_embeds_shipped_icon(tmp_path):
    macos_app.install_app(tmp_path)
    icon = tmp_path / "Keys Keeper.app" / "Contents" / "Resources" / "AppIcon.icns"
    assert icon.is_file()
    # icns magic: "icns" at offset 0
    assert icon.read_bytes()[:4] == b"icns"


@pytest.mark.macos
def test_launcher_skips_zshrc_and_uses_abs_path(tmp_path):
    macos_app.install_app(tmp_path)
    launcher = (tmp_path / "Keys Keeper.app" / "Contents" / "MacOS" / "keys-keeper-launcher").read_text()
    assert launcher.startswith("#!/bin/sh"), "launcher must be /bin/sh, not zsh (zshrc adds seconds)"
    assert "source" not in launcher.split("\n")[0:5][0]  # no sourcing in shebang/early lines
    assert ".local/pipx/venvs/keys-keeper/bin/keys" in launcher
    assert "lsof -nP -iTCP:7777" in launcher  # port-busy detection
    assert "Already running" in launcher  # notification on second launch


@pytest.mark.macos
def test_install_refuses_to_overwrite_without_force(tmp_path):
    macos_app.install_app(tmp_path)
    with pytest.raises(FileExistsError):
        macos_app.install_app(tmp_path)


@pytest.mark.macos
def test_install_force_overwrites_existing(tmp_path):
    macos_app.install_app(tmp_path)
    # mutate the launcher so we can detect overwrite
    launcher = tmp_path / "Keys Keeper.app" / "Contents" / "MacOS" / "keys-keeper-launcher"
    launcher.write_text("# tampered")
    result = macos_app.install_app(tmp_path, force=True)
    assert result.created is False
    assert "tampered" not in launcher.read_text()
    assert "keys-keeper-launcher" not in launcher.read_text()  # sanity: it's the new content


@pytest.mark.macos
def test_uninstall_removes_bundle(tmp_path):
    macos_app.install_app(tmp_path)
    assert macos_app.uninstall_app(tmp_path) is True
    assert not (tmp_path / "Keys Keeper.app").exists()


@pytest.mark.macos
def test_uninstall_returns_false_when_absent(tmp_path):
    assert macos_app.uninstall_app(tmp_path) is False


@pytest.mark.macos
def test_is_installed_detects_user_bundle(tmp_path):
    assert macos_app.is_installed(tmp_path) is False
    macos_app.install_app(tmp_path)
    assert macos_app.is_installed(tmp_path) is True


# ---------- CLI dispatch ----------


@pytest.mark.macos
def test_cli_app_install_writes_to_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    rc = cli.main(["app", "install"])
    out = capsys.readouterr().out
    assert rc == 0
    assert (tmp_path / "Keys Keeper.app").is_dir()
    assert "installed" in out
    assert "Cmd+Space" in out


@pytest.mark.macos
def test_cli_app_install_fails_without_force_when_present(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    cli.main(["app", "install"])
    capsys.readouterr()
    rc = cli.main(["app", "install"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "already installed" in err
    assert "--force" in err


@pytest.mark.macos
def test_cli_app_install_force_overwrites(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    cli.main(["app", "install"])
    capsys.readouterr()
    rc = cli.main(["app", "install", "--force"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "reinstalled" in out


@pytest.mark.macos
def test_cli_app_uninstall_removes(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    cli.main(["app", "install"])
    capsys.readouterr()
    rc = cli.main(["app", "uninstall"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "removed" in out
    assert not (tmp_path / "Keys Keeper.app").exists()


@pytest.mark.macos
def test_cli_app_uninstall_returns_1_when_nothing_there(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    rc = cli.main(["app", "uninstall"])
    err = capsys.readouterr().err
    assert rc == 1
    assert "nothing to remove" in err


# ---------- Windows shortcut builder (logic that doesn't need win32) ----------


def test_windows_install_raises_if_keys_not_on_path(tmp_path, monkeypatch):
    """The PATH-resolution helper raises FileNotFoundError when `keys` is missing."""
    monkeypatch.setattr("shutil.which", lambda _name: None)
    with pytest.raises(FileNotFoundError) as exc:
        windows_app._resolve_keys_binary()
    assert "pipx install" in str(exc.value)


def test_windows_default_user_dir_uses_appdata_when_set(monkeypatch):
    monkeypatch.setenv("APPDATA", "/fake/AppData/Roaming")
    target = windows_app.default_user_dir()
    assert str(target).endswith("Programs")
    assert "Microsoft" in str(target)
    assert "Start Menu" in str(target)


def test_windows_default_user_dir_falls_back_when_appdata_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("APPDATA", raising=False)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    target = windows_app.default_user_dir()
    assert "AppData" in str(target)
    assert str(target).endswith("Programs")


def test_windows_is_installed_checks_filesystem(tmp_path):
    assert windows_app.is_installed(tmp_path) is False
    (tmp_path / "Keys Keeper.lnk").write_bytes(b"")
    assert windows_app.is_installed(tmp_path) is True


# ---------- Cross-platform: serve tip ----------


@pytest.mark.macos
def test_serve_prints_install_tip_when_app_not_installed(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    monkeypatch.setattr(macos_app, "system_dir", lambda: tmp_path / "system_unused")
    cli._maybe_suggest_app_install()
    out = capsys.readouterr().out
    assert "keys app install" in out


@pytest.mark.macos
def test_serve_omits_install_tip_when_app_present(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(macos_app, "default_user_dir", lambda: tmp_path)
    monkeypatch.setattr(macos_app, "system_dir", lambda: tmp_path / "system_unused")
    macos_app.install_app(tmp_path)
    capsys.readouterr()
    cli._maybe_suggest_app_install()
    out = capsys.readouterr().out
    assert "keys app install" not in out


def test_serve_tip_silent_on_non_macos(monkeypatch, capsys):
    monkeypatch.setattr(sys, "platform", "linux")
    cli._maybe_suggest_app_install()
    assert capsys.readouterr().out == ""
