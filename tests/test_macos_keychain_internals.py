"""Regression coverage for the private macOS Keychain decomposition."""

from __future__ import annotations

import ctypes
from types import SimpleNamespace

import pytest

import keys_keeper.macos_keychain as macos_keychain
import keys_keeper.macos_keychain_abi as keychain_abi
from keys_keeper.macos_keychain import MacOSNativeKeychain, SecurityFrameworkError
from keys_keeper.macos_keychain_cf import release_cf_refs


class _RecordingCoreFoundation:
    def __init__(self) -> None:
        self.released: list[int | None] = []

    def CFRelease(self, reference: ctypes.c_void_p) -> None:
        self.released.append(reference.value)


def test_public_types_keep_their_original_module_and_error_contract():
    assert MacOSNativeKeychain.__module__ == "keys_keeper.macos_keychain"
    assert SecurityFrameworkError.__module__ == "keys_keeper.macos_keychain"

    error = SecurityFrameworkError("read keychain item", -25308)
    assert error.operation == "read keychain item"
    assert error.status == -25308
    assert str(error) == "read keychain item failed (OSStatus -25308)"


def test_framework_loading_failure_stays_a_public_security_error(monkeypatch):
    macos_keychain._bindings.cache_clear()
    monkeypatch.setattr(keychain_abi.sys, "platform", "unsupported")

    with pytest.raises(
        SecurityFrameworkError,
        match="load macOS Security framework failed",
    ):
        macos_keychain._bindings()

    macos_keychain._bindings.cache_clear()


def test_release_cf_refs_skips_nulls_and_preserves_release_order():
    core_foundation = _RecordingCoreFoundation()

    release_cf_refs(
        core_foundation,
        ctypes.c_void_p(11),
        ctypes.c_void_p(),
        ctypes.c_void_p(22),
    )

    assert core_foundation.released == [11, 22]


def test_keychain_ref_releases_owned_reference_when_body_raises():
    core_foundation = _RecordingCoreFoundation()

    class Security:
        @staticmethod
        def SecKeychainOpen(_path, output) -> int:
            output._obj.value = 73
            return 0

    native = object.__new__(MacOSNativeKeychain)
    native.keychain_path = "/tmp/non-secret-test.keychain-db"
    native.api = SimpleNamespace(
        security=Security(),
        core_foundation=core_foundation,
    )

    with pytest.raises(RuntimeError, match="sentinel failure"):
        with native._keychain_ref() as reference:
            assert reference.value == 73
            raise RuntimeError("sentinel failure")

    assert core_foundation.released == [73]


def test_release_cf_refs_does_not_hide_native_cleanup_failure():
    calls: list[int | None] = []

    class FailingCoreFoundation:
        @staticmethod
        def CFRelease(reference: ctypes.c_void_p) -> None:
            calls.append(reference.value)
            raise RuntimeError("release failed")

    with pytest.raises(RuntimeError, match="release failed"):
        release_cf_refs(
            FailingCoreFoundation(),
            ctypes.c_void_p(31),
            ctypes.c_void_p(32),
        )

    assert calls == [31]
