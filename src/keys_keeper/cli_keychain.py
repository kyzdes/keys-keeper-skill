"""CLI for macOS Keychain prompt/bypass interaction policy."""
from __future__ import annotations

import argparse
import os
import stat
import sys

from keys_keeper.audit import AuditLog
from keys_keeper.backend import KeychainError
from keys_keeper.keychain_config import (
    BYPASS,
    PROMPT,
    KeychainConfig,
    load_keychain_config,
    save_keychain_config,
)
from keys_keeper.paths import Paths


def _require_macos() -> bool:
    if sys.platform == "darwin":
        return True
    sys.stderr.write("error: `keys keychain` is available only on macOS\n")
    return False


def cmd_keychain_status(args: argparse.Namespace) -> int:
    if not _require_macos():
        return 1
    paths = Paths()
    try:
        config = load_keychain_config(paths)
    except KeychainError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    print("storage: macOS Keychain (original items, no migration)")
    print(f"interaction mode: {config.mode}")
    print(f"authorization dialogs: {'disabled' if config.mode == BYPASS else 'allowed when macOS requires them'}")
    print("implementation: native Security.framework")
    print("legacy reads: ACL-gated /usr/bin/security bridge only when already trusted")
    if paths.keychain_toml.exists() and os.name == "posix":
        print(f"policy file: {paths.keychain_toml} ({stat.S_IMODE(paths.keychain_toml.stat().st_mode):04o})")
    return 0


def _set_mode(mode: str) -> int:
    if not _require_macos():
        return 1
    paths = Paths()
    if os.environ.get("KEYS_KEEPER_KEYCHAIN_MODE"):
        sys.stderr.write(
            "error: KEYS_KEEPER_KEYCHAIN_MODE overrides the persistent policy; unset it first\n"
        )
        return 1
    try:
        save_keychain_config(KeychainConfig(mode=mode), paths)
    except (OSError, ValueError) as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 1
    AuditLog(paths).record(op=f"keychain.{mode}", name="<all>", id_="-", success=True)
    if mode == BYPASS:
        print("Keychain bypass enabled — authorization dialogs are disabled")
        print("original macOS Keychain items remain in place; no secrets were moved or copied")
        print("legacy security-only items remain in place and use their pre-authorized path")
        print("unknown or locked ACLs fail instead of opening a system window")
    else:
        print("Keychain prompt mode enabled — macOS may request authorization when required")
    return 0


def cmd_keychain_bypass(args: argparse.Namespace) -> int:
    return _set_mode(BYPASS)


def cmd_keychain_prompt(args: argparse.Namespace) -> int:
    return _set_mode(PROMPT)


def register_keychain(sub) -> None:
    parser = sub.add_parser("keychain", help="control macOS Keychain authorization dialogs")
    actions = parser.add_subparsers(dest="keychain_command", required=True)
    status = actions.add_parser("status", help="show policy without opening Keychain")
    status.set_defaults(func=cmd_keychain_status)
    bypass = actions.add_parser("bypass", help="disable authorization dialogs persistently")
    bypass.set_defaults(func=cmd_keychain_bypass)
    prompt = actions.add_parser("prompt", help="allow macOS authorization dialogs")
    prompt.set_defaults(func=cmd_keychain_prompt)
