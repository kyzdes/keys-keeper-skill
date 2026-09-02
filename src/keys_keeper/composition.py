"""Composition root — builds adapters from environment.

Single dispatch point for swappable adapters. Selects the OS-native
credential backend by `sys.platform`; tests can override the namespace
via `KEYS_KEEPER_TEST_SERVICE`.

This is the ONLY module that branches on `sys.platform` (D-017). Any new
platform support adds a branch here and a backend module, nothing else.
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
    if sys.platform.startswith("linux"):
        return _build_linux_backend(service)
    keychain_path = os.environ.get("KEYS_KEEPER_TEST_KEYCHAIN")
    if keychain_path is None:
        from keys_keeper.keychain_config import interaction_allowed
        allow_interaction = interaction_allowed()
    else:
        # Tests must never open a login/UI prompt even if a developer's normal
        # home is configured for prompt mode.
        allow_interaction = False
    return MacOSKeychainBackend(
        service=service,
        keychain_path=keychain_path,
        allow_interaction=allow_interaction,
    )


def _build_linux_backend(service: str) -> KeychainBackend:
    """Pick the Linux backend.

    Explicit `KEYS_KEEPER_BACKEND=secret-tool|file` wins. Otherwise auto-detect:
    a desktop with a live Secret Service uses the OS keyring; a headless server
    (no D-Bus / no keyring daemon) falls back to the encrypted file.
    """
    choice = (os.environ.get("KEYS_KEEPER_BACKEND") or "").strip().lower()
    if choice == "file":
        from keys_keeper.backend_file import EncryptedFileBackend
        return EncryptedFileBackend(service=service)
    if choice in ("secret-tool", "secret_service", "keyring"):
        from keys_keeper.backend_linux import SecretToolBackend
        return SecretToolBackend(service=service)
    if choice:
        from keys_keeper.backend import KeychainError
        raise KeychainError(
            f"unknown KEYS_KEEPER_BACKEND={choice!r} — use 'secret-tool' or 'file'"
        )
    # auto-detect
    from keys_keeper.backend_linux import SecretToolBackend, secret_service_available
    if secret_service_available(service):
        return SecretToolBackend(service=service)
    from keys_keeper.backend_file import EncryptedFileBackend
    return EncryptedFileBackend(service=service)
