"""Tests for SecretToolBackend (Linux Secret Service via `secret-tool`).

Two layers:
  - Pure-function tests for the output parser + availability gate (run on every
    platform, no daemon needed).
  - Live roundtrip tests that exercise the real `secret-tool` binary; these
    runtime-skip unless a Secret Service daemon actually answers (so they no-op
    on macOS, Windows, and headless CI without an unlocked keyring).
"""
from __future__ import annotations

import pytest

from keys_keeper.backend import KeychainError, Sealed
from keys_keeper.backend_linux import (
    SecretToolBackend,
    _parse_accounts,
    secret_service_available,
)


# ---------- pure parser (all platforms) ----------


def test_parse_accounts_extracts_ids():
    out = (
        "[/org/freedesktop/secrets/collection/login/1]\n"
        "label = keys-keeper: kk:abc\n"
        "secret = sk-or-v1-xxxx\n"
        "created = 2026-06-01 12:00:00\n"
        "attribute.account = kk:abc\n"
        "attribute.service = keys-keeper\n"
        "\n"
        "[/org/freedesktop/secrets/collection/login/2]\n"
        "attribute.account = kk:def:passphrase\n"
        "attribute.service = keys-keeper\n"
    )
    assert _parse_accounts(out) == ["kk:abc", "kk:def:passphrase"]


def test_parse_accounts_empty():
    assert _parse_accounts("") == []


def test_parse_accounts_ignores_secret_lines():
    # a malicious/odd value must never be mistaken for an account id
    out = "secret = attribute.account = not-an-id\nattribute.account = real-id\n"
    assert _parse_accounts(out) == ["real-id"]


def test_parse_accounts_dedupes_preserving_order():
    # the same account can appear in both stderr and stdout once we concat them
    out = "attribute.account = kk:a\nattribute.account = kk:b\nattribute.account = kk:a\n"
    assert _parse_accounts(out) == ["kk:a", "kk:b"]


def test_list_ids_reads_stderr(monkeypatch):
    """Regression (CI Ubuntu): `secret-tool search` prints the item dump with
    `attribute.account =` to STDERR, while stdout carries only secret values.
    list_ids() must parse stderr — parsing stdout alone returned []."""
    class _R:
        returncode = 0
        stdout = "sk-secret-value\n"   # secret on stdout — must be ignored
        stderr = (
            "[/org/freedesktop/secrets/collection/login/1]\n"
            "attribute.account = kk:a\n"
            "attribute.service = keys-keeper\n"
            "attribute.account = kk:b\n"
        )
    monkeypatch.setattr("keys_keeper.backend_linux.subprocess.run", lambda *a, **k: _R())
    ids = SecretToolBackend(service="keys-keeper").list_ids()
    assert sorted(ids) == ["kk:a", "kk:b"]
    assert "sk-secret-value" not in ids


def test_availability_false_when_secret_tool_absent(monkeypatch):
    monkeypatch.setattr("keys_keeper.backend_linux.shutil.which", lambda _n: None)
    assert secret_service_available() is False


def test_availability_true_when_daemon_answers(monkeypatch):
    monkeypatch.setattr("keys_keeper.backend_linux.shutil.which", lambda _n: "/usr/bin/secret-tool")

    class _R:
        returncode = 1  # "no results" still means the daemon answered

    monkeypatch.setattr("keys_keeper.backend_linux.subprocess.run", lambda *a, **k: _R())
    assert secret_service_available() is True


def test_availability_false_on_dbus_error(monkeypatch):
    monkeypatch.setattr("keys_keeper.backend_linux.shutil.which", lambda _n: "/usr/bin/secret-tool")

    class _R:
        returncode = 127  # e.g. "Cannot autolaunch D-Bus" on headless

    monkeypatch.setattr("keys_keeper.backend_linux.subprocess.run", lambda *a, **k: _R())
    assert secret_service_available() is False


# ---------- live roundtrip (skips unless a real keyring answers) ----------

_SERVICE = "keys-keeper-test"

live = pytest.mark.skipif(
    not secret_service_available(_SERVICE),
    reason="no Secret Service daemon available",
)


@pytest.fixture
def backend():
    b = SecretToolBackend(service=_SERVICE)
    yield b
    for acct in b.list_ids():
        b.delete(acct)


@live
def test_live_set_get_roundtrip(backend):
    backend.set("kk:abc", "sk-or-v1-secret")
    assert backend.get("kk:abc") == Sealed("sk-or-v1-secret")


@live
def test_live_list_and_delete(backend):
    backend.set("kk:a", "1")
    backend.set("kk:b", "2")
    assert sorted(backend.list_ids()) == ["kk:a", "kk:b"]
    backend.delete("kk:a")
    assert backend.list_ids() == ["kk:b"]


@live
def test_live_get_missing_raises(backend):
    with pytest.raises(KeychainError):
        backend.get("kk:nope")


@live
def test_live_overwrite_does_not_duplicate(backend):
    """`secret-tool store` upserts on matching attributes (service+account), so
    setting the same key twice must update in place, not create a 2nd item that
    would make list_ids() report a duplicate."""
    backend.set("kk:dup", "first")
    backend.set("kk:dup", "second")
    assert backend.list_ids().count("kk:dup") == 1
    assert backend.get("kk:dup").unseal() == "second"
