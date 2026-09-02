"""Persistent macOS Keychain interaction policy.

Bypass keeps the native Keychain backend and original items. It only disables
Keychain UI, turning an untrusted-item authorization request into a clean error.
"""
from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass

from keys_keeper.backend import KeychainError
from keys_keeper.paths import Paths

PROMPT = "prompt"
BYPASS = "bypass"
_VALID_MODES = {PROMPT, BYPASS}
_ENV = "KEYS_KEEPER_KEYCHAIN_MODE"


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
    if not paths.keychain_toml.exists():
        return KeychainConfig()
    try:
        text = paths.keychain_toml.read_text(encoding="utf-8")
        mode = _parse_mode(text)
    except (OSError, UnicodeDecodeError, ValueError) as ex:
        # Fail closed: a damaged policy must never silently re-enable dialogs.
        raise KeychainError(f"cannot read {paths.keychain_toml.name}: {ex}") from ex
    if mode not in _VALID_MODES:
        raise KeychainError(
            f"invalid keychain mode {mode!r}; expected '{PROMPT}' or '{BYPASS}'"
        )
    return KeychainConfig(mode=mode)


def save_keychain_config(config: KeychainConfig, paths: Paths | None = None) -> None:
    if config.mode not in _VALID_MODES:
        raise ValueError(f"unsupported keychain mode: {config.mode!r}")
    paths = paths or Paths()
    paths.ensure()
    fd, tmp_name = tempfile.mkstemp(
        dir=paths.root,
        prefix=".keychain.",
        suffix=".tmp",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(f'mode = "{config.mode}"\n')
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "posix":
            os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, paths.keychain_toml)
        if os.name == "posix":
            os.chmod(paths.keychain_toml, 0o600)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


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
