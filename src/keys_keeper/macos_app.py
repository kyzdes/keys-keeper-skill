"""macOS .app bundle installer for the Spotlight-launchable Keys Keeper shortcut.

The bundle wraps `keys serve` in a minimal `/bin/sh` launcher that:
  - skips `~/.zshrc` (conda init can cost seconds on dev machines),
  - prefers the pipx venv binary, falls back to `command -v keys`,
  - detects port 7777 already bound and emits a Notification Center toast
    instead of failing on second-launch.

Install paths:
  - default (user):  ~/Applications/Keys Keeper.app
  - --system:         /Applications/Keys Keeper.app   (needs sudo)

No external dependencies — uses only the stdlib + macOS preinstalled tools
(`mdimport` to nudge Spotlight; not required for correctness).
"""
from __future__ import annotations

import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from keys_keeper import __version__

_ICON_FILE = Path(__file__).parent / "static" / "icons" / "keys-keeper.icns"

BUNDLE_NAME = "Keys Keeper.app"
BUNDLE_ID = "com.kyzdes.keys-keeper.launcher"


@dataclass(frozen=True)
class InstallResult:
    bundle_path: Path
    created: bool   # True if newly created, False if overwritten


def default_user_dir() -> Path:
    return Path.home() / "Applications"


def system_dir() -> Path:
    return Path("/Applications")


def is_macos() -> bool:
    return sys.platform == "darwin"


def _info_plist(version: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        '    <key>CFBundleName</key>\n'
        '    <string>Keys Keeper</string>\n'
        '    <key>CFBundleDisplayName</key>\n'
        '    <string>Keys Keeper</string>\n'
        f'    <key>CFBundleIdentifier</key>\n    <string>{BUNDLE_ID}</string>\n'
        '    <key>CFBundleVersion</key>\n    <string>1</string>\n'
        f'    <key>CFBundleShortVersionString</key>\n    <string>{version}</string>\n'
        '    <key>CFBundleExecutable</key>\n    <string>keys-keeper-launcher</string>\n'
        '    <key>CFBundlePackageType</key>\n    <string>APPL</string>\n'
        '    <key>CFBundleSignature</key>\n    <string>????</string>\n'
        '    <key>CFBundleIconFile</key>\n    <string>AppIcon</string>\n'
        '    <key>LSMinimumSystemVersion</key>\n    <string>10.13</string>\n'
        '    <key>LSUIElement</key>\n    <true/>\n'
        '    <key>NSHighResolutionCapable</key>\n    <true/>\n'
        '</dict>\n'
        '</plist>\n'
    )


_LAUNCHER_SH = r"""#!/bin/sh
# Spotlight-launched wrapper for `keys serve`.
# Skips zsh init (conda/oh-my-zsh add seconds) by calling the pipx venv directly.

LOG="${HOME}/Library/Logs/keys-keeper.log"
mkdir -p "${HOME}/Library/Logs"

KEYS_BIN="${HOME}/.local/pipx/venvs/keys-keeper/bin/keys"
if [ ! -x "${KEYS_BIN}" ]; then
    KEYS_BIN="$(PATH="${HOME}/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" command -v keys)"
fi
if [ -z "${KEYS_BIN}" ] || [ ! -x "${KEYS_BIN}" ]; then
    printf '[%s] keys binary not found\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "${LOG}"
    /usr/bin/osascript -e 'display notification "keys CLI not found. Run: pipx install keys-keeper" with title "Keys Keeper"' >/dev/null 2>&1
    exit 1
fi

# Already running? Show a notification instead of failing on bind.
if /usr/sbin/lsof -nP -iTCP:7777 -sTCP:LISTEN >/dev/null 2>&1; then
    printf '[%s] server already running on :7777, skipping\n' "$(date '+%Y-%m-%d %H:%M:%S')" >> "${LOG}"
    /usr/bin/osascript -e 'display notification "Already running on 127.0.0.1:7777 — check your existing browser tab." with title "Keys Keeper"' >/dev/null 2>&1
    exit 0
fi

printf '[%s] launching: %s serve\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${KEYS_BIN}" >> "${LOG}"
exec "${KEYS_BIN}" serve >> "${LOG}" 2>&1
"""


def _read_icon_bytes() -> bytes | None:
    """Return the shipped .icns bytes, or None if missing (graceful skip)."""
    try:
        return _ICON_FILE.read_bytes()
    except (FileNotFoundError, OSError):
        return None


def _write_bundle(bundle: Path, version: str) -> None:
    contents = bundle / "Contents"
    macos = contents / "MacOS"
    resources_dir = contents / "Resources"
    macos.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)

    (contents / "Info.plist").write_text(_info_plist(version), encoding="utf-8")

    launcher = macos / "keys-keeper-launcher"
    launcher.write_text(_LAUNCHER_SH, encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    icon = _read_icon_bytes()
    if icon is not None:
        (resources_dir / "AppIcon.icns").write_bytes(icon)


def install_app(
    target_dir: Path | None = None,
    *,
    force: bool = False,
    version: str | None = None,
) -> InstallResult:
    """Install Keys Keeper.app into `target_dir` (defaults to ~/Applications).

    Raises FileExistsError if the bundle exists and `force=False`.
    Raises NotADirectoryError if `target_dir` exists but isn't a directory.
    """
    target_dir = target_dir or default_user_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    if not target_dir.is_dir():
        raise NotADirectoryError(target_dir)
    bundle = target_dir / BUNDLE_NAME
    existed = bundle.exists()
    if existed and not force:
        raise FileExistsError(bundle)
    if existed:
        shutil.rmtree(bundle)
    _write_bundle(bundle, version or __version__)
    _spotlight_reindex(bundle)
    return InstallResult(bundle_path=bundle, created=not existed)


def uninstall_app(target_dir: Path | None = None) -> bool:
    """Remove the bundle if present. Returns True if anything was removed."""
    target_dir = target_dir or default_user_dir()
    bundle = target_dir / BUNDLE_NAME
    if not bundle.exists():
        return False
    shutil.rmtree(bundle)
    return True


def is_installed(target_dir: Path | None = None) -> bool:
    """True if the bundle exists in either the user or system location."""
    if target_dir is not None:
        return (target_dir / BUNDLE_NAME).is_dir()
    return (default_user_dir() / BUNDLE_NAME).is_dir() or (system_dir() / BUNDLE_NAME).is_dir()


def _spotlight_reindex(bundle: Path) -> None:
    """Nudge Spotlight to index the newly written bundle. Best-effort."""
    mdimport = Path("/usr/bin/mdimport")
    if not mdimport.exists():
        return
    try:
        subprocess.run([str(mdimport), str(bundle)], check=False, capture_output=True, timeout=5)
    except (subprocess.SubprocessError, OSError):
        pass
