"""Regression coverage for the private macOS Keychain decomposition."""

from __future__ import annotations

import ctypes
from contextlib import nullcontext
from pathlib import Path
import traceback
from types import SimpleNamespace

import pytest

import keys_keeper.macos_keychain as macos_keychain
import keys_keeper.macos_keychain_abi as keychain_abi
from keys_keeper.macos_keychain import MacOSNativeKeychain, SecurityFrameworkError
from keys_keeper.macos_keychain_cf import release_cf_refs
from keys_keeper.backend import KeychainError, MacOSKeychainBackend


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


@pytest.mark.parametrize("public_backend", [False, True])
def test_invalid_utf8_native_buffer_is_zeroed_freed_and_absent_from_error_chain(monkeypatch, public_backend):
    marker = b"SYNTHETIC-NATIVE-SENSITIVE-PAYLOAD"
    contents = b"\xff" + marker
    buffer = ctypes.create_string_buffer(contents, len(contents))
    frees = []

    class Security:
        @staticmethod
        def SecKeychainFindGenericPassword(_keychain, _service_len, _service, _account_len, _account,
                                          length, data, _item):
            length._obj.value = len(contents)
            data._obj.value = ctypes.addressof(buffer)
            return 0

        @staticmethod
        def SecKeychainItemFreeContent(_attributes, data):
            frees.append(ctypes.string_at(data, len(contents)))
            return 0

    native = object.__new__(MacOSNativeKeychain)
    native.service = b"synthetic-native-test"
    native.allow_interaction = False
    native.api = SimpleNamespace(security=Security())
    monkeypatch.setattr(native, "_interaction_policy", lambda: nullcontext())
    monkeypatch.setattr(native, "_keychain_ref", lambda: nullcontext())
    backend = object.__new__(MacOSKeychainBackend)
    backend._native = native
    expected_error = KeychainError if public_backend else SecurityFrameworkError
    with pytest.raises(expected_error) as caught:
        (backend if public_backend else native).get("kk:synthetic-invalid-utf8")

    assert frees == [b"\x00" * len(contents)]
    assert buffer.raw == b"\x00" * len(contents)
    error = caught.value
    while error is not None:
        assert isinstance(error, (KeychainError, SecurityFrameworkError))
        assert marker.decode() not in str(error)
        frames = error.__traceback__
        while frames is not None:
            if Path(frames.tb_frame.f_code.co_filename).name in {"backend.py", "macos_keychain.py"}:
                assert not any(marker in value for value in frames.tb_frame.f_locals.values()
                               if isinstance(value, (bytes, bytearray)))
            frames = frames.tb_next
        if isinstance(error, SecurityFrameworkError):
            assert error.operation == "decode keychain item"
            assert error.status is None
            assert error.__cause__ is None
            assert error.__context__ is None
        error = error.__cause__ or error.__context__
    assert marker.decode() not in "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
