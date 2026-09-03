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
from keys_keeper.store import MetadataStore


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
    print("background/server access: UI forbidden, native-only")
    print("interactive bypass compatibility: ACL-gated /usr/bin/security bridge")
    if paths.keychain_toml.exists() and os.name == "posix":
        print(f"policy file: {paths.keychain_toml} ({stat.S_IMODE(paths.keychain_toml.stat().st_mode):04o})")
    if args.check:
        # Resolve the Keychain only for an explicit check, and force the strict
        # server/background access context so the diagnostic itself cannot ask.
        from keys_keeper.composition import AccessContext, build_backend

        try:
            backend = build_backend(access=AccessContext.UI_FORBIDDEN)
            readiness = backend.readiness()
        except KeychainError as ex:
            sys.stderr.write(f"error: no-UI metadata probe failed: {ex}\n")
            return 1
        print(f"no-UI metadata probe: {readiness.state}")
        print("secret values: not read")
        if readiness.state != "ready":
            return 1
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


def cmd_keychain_prepare(args: argparse.Namespace) -> int:
    """Prepare exactly one original item for native no-UI access."""
    if not _require_macos():
        return 1
    paths = Paths()
    entry = MetadataStore(paths).get_by_name(args.name)
    if entry is None:
        sys.stderr.write(f"no entry named {args.name!r}\n")
        return 1

    from keys_keeper.composition import AccessContext, build_backend

    audit = AuditLog(paths)
    try:
        # The preflight is strict and metadata-only: an already prepared item
        # never causes an authorization dialog.
        strict = build_backend(access=AccessContext.UI_FORBIDDEN)
        access_state = strict.native_access_state(entry.id)
        if access_state == "prepared":
            print(f"native no-UI access already prepared for {entry.name}")
            print("original Keychain item unchanged; secret value was not read")
            return 0
        if access_state == "partitioned":
            sys.stderr.write(
                "error: this item has a code-signature partition policy; "
                "compatibility preparation will not weaken it. A signed "
                "Keys Keeper broker is required.\n"
            )
            return 1
        if args.check:
            print(f"native no-UI access needs preparation for {entry.name}")
            print("secret value was not read")
            return 1

        # One command targets one item and performs one protected ACL commit.
        # macOS may show an authorization dialog for this explicit setup step.
        setup_backend = build_backend(access=AccessContext.ACL_PREPARATION)
        changed = setup_backend.prepare_native_access(entry.id)
    except KeychainError as ex:
        audit.record(
            op="keychain.prepare",
            name=entry.name,
            id_=entry.id,
            success=False,
            error=str(ex),
        )
        sys.stderr.write(f"error: {ex}\n")
        return 1

    audit.record(
        op="keychain.prepare",
        name=entry.name,
        id_=entry.id,
        success=True,
    )
    state = "prepared" if changed else "already prepared"
    print(f"native no-UI access {state} for {entry.name}")
    print("updated the original item's decrypt ACL; secret value was not read or copied")
    print("trusted identity: current executable verified by Security.framework")
    return 0


def register_keychain(sub) -> None:
    parser = sub.add_parser("keychain", help="control macOS Keychain authorization dialogs")
    actions = parser.add_subparsers(dest="keychain_command", required=True)
    status = actions.add_parser("status", help="show policy without opening Keychain")
    status.add_argument(
        "--check",
        action="store_true",
        help="probe lock/readiness metadata with Keychain UI disabled",
    )
    status.set_defaults(func=cmd_keychain_status)
    bypass = actions.add_parser("bypass", help="disable authorization dialogs persistently")
    bypass.set_defaults(func=cmd_keychain_bypass)
    prompt = actions.add_parser("prompt", help="allow macOS authorization dialogs")
    prompt.set_defaults(func=cmd_keychain_prompt)
    prepare = actions.add_parser(
        "prepare",
        help="prepare one original item for native no-UI access",
    )
    prepare.add_argument("name", help="exact Keys Keeper entry name")
    prepare.add_argument(
        "--check",
        action="store_true",
        help="metadata-only preflight; do not change the item's ACL",
    )
    prepare.set_defaults(func=cmd_keychain_prepare)
