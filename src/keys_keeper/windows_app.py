"""Windows Start Menu shortcut installer for the Keys Keeper quick-launcher.

Creates a `.lnk` in the user's Start Menu Programs directory pointing at
`keys serve`. Shortcut creation uses PowerShell + WScript.Shell COM — no
pywin32/winshell dependency.

Install path: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Keys Keeper.lnk
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

SHORTCUT_NAME = "Keys Keeper.lnk"


@dataclass(frozen=True)
class InstallResult:
    bundle_path: Path
    created: bool


def is_windows() -> bool:
    return sys.platform == "win32"


def default_user_dir() -> Path:
    appdata = os.environ.get("APPDATA")
    base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
    return base / "Microsoft" / "Windows" / "Start Menu" / "Programs"


def _resolve_keys_binary() -> Path:
    """Find the `keys` CLI on PATH. Raises FileNotFoundError if missing."""
    found = shutil.which("keys") or shutil.which("keys.exe")
    if not found:
        raise FileNotFoundError(
            "`keys` CLI not found on PATH. Run `pipx install keys-keeper` first."
        )
    return Path(found)


def _ps_dq_escape(value: str) -> str:
    """Escape a string for safe interpolation into a PowerShell DOUBLE-quoted
    string literal (`"..."`).

    Inside a PS double-quoted string the metacharacters are the backtick (the
    escape char), the closing double-quote, and `$` (variable/subexpression
    interpolation). Escaping the backtick FIRST is essential — otherwise the
    backticks we add for `"` and `$` would themselves get doubled.

    Without this, a path or description containing `"` would terminate the
    string early and let the remainder be parsed as PowerShell — i.e. command
    injection via a crafted target/workdir/description.
    """
    return (
        value.replace("`", "``")  # must be first
        .replace('"', '`"')
        .replace("$", "`$")
    )


def _create_shortcut_via_powershell(
    lnk_path: Path, target: Path, args: str, workdir: Path, description: str
) -> None:
    # Every interpolated value is escaped for the PS double-quoted context so a
    # stray quote/backtick in a path can't break out into executable PowerShell.
    lnk_e = _ps_dq_escape(str(lnk_path))
    target_e = _ps_dq_escape(str(target))
    args_e = _ps_dq_escape(args)
    workdir_e = _ps_dq_escape(str(workdir))
    description_e = _ps_dq_escape(description)
    script = (
        '$ws = New-Object -ComObject WScript.Shell\n'
        f'$lnk = $ws.CreateShortcut("{lnk_e}")\n'
        f'$lnk.TargetPath = "{target_e}"\n'
        f'$lnk.Arguments = "{args_e}"\n'
        f'$lnk.WorkingDirectory = "{workdir_e}"\n'
        f'$lnk.Description = "{description_e}"\n'
        '$lnk.Save()\n'
    )
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        check=True,
        capture_output=True,
    )


def install_app(
    target_dir: Path | None = None,
    *,
    force: bool = False,
) -> InstallResult:
    """Create the Start Menu shortcut. Returns InstallResult.

    Raises FileExistsError if shortcut exists and force=False.
    Raises FileNotFoundError if `keys` is not on PATH.
    """
    target_dir = target_dir or default_user_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    lnk = target_dir / SHORTCUT_NAME
    existed = lnk.exists()
    if existed and not force:
        raise FileExistsError(lnk)
    if existed:
        lnk.unlink()
    keys_bin = _resolve_keys_binary()
    _create_shortcut_via_powershell(
        lnk_path=lnk,
        target=keys_bin,
        args="serve",
        workdir=Path.home(),
        description="Open the Keys Keeper admin in a browser",
    )
    return InstallResult(bundle_path=lnk, created=not existed)


def uninstall_app(target_dir: Path | None = None) -> bool:
    target_dir = target_dir or default_user_dir()
    lnk = target_dir / SHORTCUT_NAME
    if not lnk.exists():
        return False
    lnk.unlink()
    return True


def is_installed(target_dir: Path | None = None) -> bool:
    target_dir = target_dir or default_user_dir()
    return (target_dir / SHORTCUT_NAME).is_file()
