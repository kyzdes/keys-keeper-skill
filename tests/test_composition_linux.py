"""Tests for the Linux backend selection in composition.build_backend().

All run on every platform: we monkeypatch sys.platform to "linux" and stub the
Secret Service probe, so no real keyring or D-Bus is needed.
"""
from __future__ import annotations

import pytest

from keys_keeper import composition
from keys_keeper.backend import KeychainError
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.backend_linux import SecretToolBackend


@pytest.fixture(autouse=True)
def linux(monkeypatch):
    monkeypatch.setattr(composition.sys, "platform", "linux")
    monkeypatch.delenv("KEYS_KEEPER_BACKEND", raising=False)
    monkeypatch.setattr(
        "keys_keeper.backend_linux.shutil.which",
        lambda _name: "/usr/bin/secret-tool",
    )


def _stub_available(monkeypatch, value: bool):
    monkeypatch.setattr(
        "keys_keeper.backend_linux.secret_service_available", lambda *_a, **_k: value
    )


def test_explicit_file_override(monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "file")
    assert isinstance(composition.build_backend(), EncryptedFileBackend)


def test_explicit_secret_tool_override(monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "secret-tool")
    assert isinstance(composition.build_backend(), SecretToolBackend)


def test_unknown_override_raises(monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "nonsense")
    with pytest.raises(KeychainError):
        composition.build_backend()


def test_autodetect_picks_keyring_when_available(monkeypatch):
    _stub_available(monkeypatch, True)
    assert isinstance(composition.build_backend(), SecretToolBackend)


def test_autodetect_falls_back_to_file_when_no_keyring(monkeypatch):
    _stub_available(monkeypatch, False)
    assert isinstance(composition.build_backend(), EncryptedFileBackend)


def test_linux_platform_variants(monkeypatch):
    # sys.platform can be "linux" (py3) — also accept future "linux2"-style.
    monkeypatch.setattr(composition.sys, "platform", "linux2")
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "file")
    assert isinstance(composition.build_backend(), EncryptedFileBackend)
