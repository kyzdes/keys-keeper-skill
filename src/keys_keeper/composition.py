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
from enum import Enum

from keys_keeper.backend import KeychainBackend, MacOSKeychainBackend


class AccessContext(str, Enum):
    """Whether a caller is allowed to involve interactive credential UI."""

    INTERACTIVE = "interactive"
    UI_FORBIDDEN = "ui-forbidden"
    ACL_PREPARATION = "acl-preparation"


def build_backend(
    *, access: AccessContext = AccessContext.INTERACTIVE,
) -> KeychainBackend:
    try:
        access = AccessContext(access)
    except ValueError as ex:
        raise ValueError(f"unsupported backend access context: {access!r}") from ex
    service = os.environ.get("KEYS_KEEPER_TEST_SERVICE", "keys-keeper")
    if sys.platform == "win32":
        from keys_keeper.backend_windows import WindowsCredentialBackend
        return WindowsCredentialBackend(service=service)
    if sys.platform.startswith("linux"):
        return _build_linux_backend(service)
    keychain_path = os.environ.get("KEYS_KEEPER_TEST_KEYCHAIN")
    if keychain_path is not None:
        # Tests must never open a login/UI prompt, including preparation tests.
        allow_interaction = False
    elif access is AccessContext.ACL_PREPARATION:
        # This context is reachable only from the explicit, single-item
        # preparation command. It intentionally overrides persistent bypass so
        # macOS can authorize the one ACL mutation requested by the human.
        allow_interaction = True
    elif access is AccessContext.INTERACTIVE:
        from keys_keeper.keychain_config import interaction_allowed
        allow_interaction = interaction_allowed()
    else:
        # Explicit background access must never open a login/UI prompt, even
        # when the persistent policy allows interactive commands to do so.
        allow_interaction = False
    return MacOSKeychainBackend(
        service=service,
        keychain_path=keychain_path,
        allow_interaction=allow_interaction,
        # The compatibility bridge is intentionally narrower than "no UI".
        # It remains available to an explicit interactive command running in
        # persistent bypass mode, but background/server callers never spawn it:
        # an ACL check followed by a child process has an unavoidable race.
        allow_legacy_bridge=(
            access is AccessContext.INTERACTIVE and not allow_interaction
        ),
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
