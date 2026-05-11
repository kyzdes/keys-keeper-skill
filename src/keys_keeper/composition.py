"""Composition root — builds adapters from environment.

Single dispatch point for swappable adapters. Selects the OS-native
credential backend by `sys.platform`; tests can override the namespace
via `KEYS_KEEPER_TEST_SERVICE`.
"""
from __future__ import annotations
import os
import sys

from keys_keeper.backend import KeychainBackend, MacOSKeychainBackend


def build_backend() -> KeychainBackend:
    service = os.environ.get("KEYS_KEEPER_TEST_SERVICE", "keys-keeper")
    if sys.platform == "win32":
        from keys_keeper.backend_windows import WindowsCredentialBackend
        return WindowsCredentialBackend(service=service)
    return MacOSKeychainBackend(
        service=service,
        keychain_path=os.environ.get("KEYS_KEEPER_TEST_KEYCHAIN"),
    )
