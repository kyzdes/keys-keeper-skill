"""Persistent macOS Keychain interaction policy.

Bypass keeps the native Keychain backend and original items. It disables
Keychain UI for interactive CLI operations; an ACL-proven legacy item may still
use the existing compatibility bridge. Background/server operations override
either persistent mode with a stricter UI-forbidden access context.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from keys_keeper.backend import KeychainError
from keys_keeper.paths import Paths
from keys_keeper.private_files import PrivateFileCommitError, PrivateFileError, atomic_write_bytes, secure_read

PROMPT = "prompt"
BYPASS = "bypass"
_VALID_MODES = {PROMPT, BYPASS}
_ENV = "KEYS_KEEPER_KEYCHAIN_MODE"
MAX_KEYCHAIN_CONFIG_BYTES = 64 * 1024


class KeychainConfigCommitError(KeychainError):
    """The policy was published; its directory durability is uncertain."""
    committed = True


@dataclass(frozen=True)
class KeychainConfig:
    mode: str = PROMPT


def load_keychain_config(paths: Paths | None = None) -> KeychainConfig:
    paths = paths or Paths()
    override = (os.environ.get(_ENV) or "").strip().lower()
    if override:
        if override not in _VALID_MODES:
            raise KeychainError(
                f"invalid {_ENV}={override!r}; expected '{PROMPT}' or '{BYPASS}'"
            )
        return KeychainConfig(mode=override)
    try:
        # This is legacy policy metadata, so public owner-readable mode is
        # accepted; type, ownership, size and final-component links are checked.
        text = secure_read(paths.keychain_toml, max_bytes=MAX_KEYCHAIN_CONFIG_BYTES,
                           require_private=False).decode("utf-8")
        mode = _parse_mode(text)
    except FileNotFoundError:
        return KeychainConfig()
    except (PrivateFileError, OSError, UnicodeError, ValueError):
        # Fail closed: a damaged policy must never silently re-enable dialogs.
        raise KeychainError("cannot read keychain policy safely; verify keychain.toml") from None
    if mode not in _VALID_MODES:
        raise KeychainError(
            f"invalid keychain mode; expected '{PROMPT}' or '{BYPASS}'"
        )
    return KeychainConfig(mode=mode)


def save_keychain_config(config: KeychainConfig, paths: Paths | None = None) -> None:
    if not isinstance(config.mode, str) or config.mode not in _VALID_MODES:
        raise ValueError("unsupported keychain mode")
    paths = paths or Paths()
    try:
        atomic_write_bytes(paths.keychain_toml, f'mode = "{config.mode}"\n'.encode("utf-8"))
    except PrivateFileCommitError:
        raise KeychainConfigCommitError(
            "keychain policy was published but durability is uncertain; inspect before retrying"
        ) from None
    except (PrivateFileError, OSError):
        raise KeychainError("cannot safely publish keychain policy") from None


def interaction_allowed(paths: Paths | None = None) -> bool:
    return load_keychain_config(paths).mode != BYPASS


def _parse_mode(text: str) -> str | None:
    mode = None
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        key, sep, raw = line.partition("=")
        if not sep or key.strip() != "mode" or mode is not None:
            raise ValueError("expected exactly one mode assignment")
        raw = raw.strip()
        if len(raw) < 2 or raw[0] != raw[-1] or raw[0] not in ("'", '"'):
            raise ValueError("mode must be a quoted string")
        mode = raw[1:-1]
    return mode
