"""Shared pytest fixtures for keys-keeper."""
import os
import subprocess
import sys
from pathlib import Path
import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "macos: requires macOS (keychain, pbcopy, etc.)")
    config.addinivalue_line("markers", "windows: requires Windows (Credential Manager, etc.)")


def pytest_collection_modifyitems(config, items):
    plat = sys.platform
    skip_macos = pytest.mark.skip(reason="macOS-only test")
    skip_windows = pytest.mark.skip(reason="Windows-only test")
    for item in items:
        if "macos" in item.keywords and plat != "darwin":
            item.add_marker(skip_macos)
        if "windows" in item.keywords and plat != "win32":
            item.add_marker(skip_windows)


@pytest.fixture
def kk_home(tmp_path, monkeypatch):
    """Isolated KEYS_KEEPER_HOME for each test."""
    home = tmp_path / "kk-home"
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(home))
    return home


@pytest.fixture
def test_keychain(tmp_path):
    """Create an isolated macOS keychain for testing.

    Returns the keychain path. Caller is responsible for setting
    `KEYS_KEEPER_TEST_KEYCHAIN` env var if the backend reads it,
    or for passing it explicitly to the backend constructor.
    """
    if sys.platform != "darwin":
        pytest.skip("macOS keychain tests require Darwin")
    kc_path = tmp_path / "test.keychain-db"
    pwd = "test-pwd"
    subprocess.run(
        ["security", "create-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "unlock-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "set-keychain-settings", "-u", str(kc_path)],
        check=True, capture_output=True,
    )
    yield kc_path
    subprocess.run(["security", "delete-keychain", str(kc_path)], capture_output=True)
