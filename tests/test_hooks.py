"""SessionStart hooks: auto-sync is bounded and mutable updates are opt-in."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_F45_session_start_has_both_commands_with_timeouts():
    data = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    groups = data["hooks"]["SessionStart"]
    cmds = [h for g in groups for h in g["hooks"]]
    joined = " ".join(c["command"] for c in cmds)
    assert "auto-update.sh" in joined
    assert "sync-hook.sh" in joined
    for c in cmds:
        assert c["type"] == "command"
        assert isinstance(c["timeout"], int) and c["timeout"] > 0


def test_sync_hook_script_is_failsafe():
    sh = (ROOT / "scripts" / "sync-hook.sh").read_text()
    assert "exit 0" in sh                 # always exits 0
    assert "command -v keys" in sh        # locates the CLI defensively


# --- auto-update chain-of-trust (H2 partial) --------------------------------

AUTO_UPDATE = ROOT / "scripts" / "auto-update.sh"


def test_auto_update_documents_trust_assumption():
    """The script must spell out that updates are only as trustworthy as the
    kyzdes account/marketplace, and point high-assurance users at pinning."""
    sh = AUTO_UPDATE.read_text()
    assert "kyzdes" in sh
    # Trust assumption + the pin-to-a-reviewed-tag safe default are documented.
    assert "trustworthy" in sh.lower()
    assert "pin" in sh.lower()
    assert "KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE" in sh
    assert "KEYS_KEEPER_NO_AUTOUPDATE" in sh


@pytest.mark.skipif(sys.platform == "win32", reason="bash hook is POSIX-only")
def test_auto_update_is_disabled_by_default(tmp_path):
    """A normal SessionStart must not touch disk or attempt an update."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env.pop("KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE", None)
    env.pop("KEYS_KEEPER_NO_AUTOUPDATE", None)
    env.pop("KKZ_NO_AUTOUPDATE", None)
    proc = subprocess.run(
        ["bash", str(AUTO_UPDATE)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    assert not (tmp_path / ".cache" / "kyzdes-claude-skills").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="bash hook is POSIX-only")
@pytest.mark.parametrize("optout_var", ["KEYS_KEEPER_NO_AUTOUPDATE", "KKZ_NO_AUTOUPDATE"])
def test_auto_update_optout_exits_zero_with_no_side_effects(tmp_path, optout_var):
    """Security property: the opt-out disables the HEAD-pull. It must return
    early (exit 0, fail-soft) and touch nothing — no stamp dir, no network."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE"] = "1"
    env[optout_var] = "1"
    proc = subprocess.run(
        ["bash", str(AUTO_UPDATE)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    # Opt-out must short-circuit BEFORE the debounce stamp dir is created.
    assert not (tmp_path / ".cache" / "kyzdes-claude-skills").exists()


# --- Windows shortcut PowerShell quoting (L) --------------------------------
# Lives here (not test_app_install.py, owned by another cluster) but exercises
# the pure escaping helper directly so it runs on every platform.


def test_ps_dq_escape_neutralizes_quote_breakout():
    """Security property: a `"` in an interpolated value must NOT be able to
    close the PS string and inject code — it gets backtick-escaped instead."""
    from keys_keeper import windows_app

    payload = 'C:\\evil"; Remove-Item C:\\ -Recurse; "'
    escaped = windows_app._ps_dq_escape(payload)
    # No bare (un-backticked) double-quote survives, so the literal can't end early.
    for i, ch in enumerate(escaped):
        if ch == '"':
            assert i > 0 and escaped[i - 1] == "`", f"bare quote at {i}: {escaped!r}"
    # Backtick and $ are also escaped so they can't introduce escapes/interpolation.
    assert windows_app._ps_dq_escape("a`b") == "a``b"
    assert windows_app._ps_dq_escape("$env:X") == "`$env:X"
    # Backtick is doubled FIRST: a quote stays a single backtick-quote.
    assert windows_app._ps_dq_escape('"') == '`"'


def test_ps_dq_escape_leaves_normal_paths_unchanged():
    """Normal Windows paths have none of the metacharacters, so behavior for
    the common case is identical (no over-escaping)."""
    from keys_keeper import windows_app

    normal = r"C:\Users\alice\AppData\Roaming\Keys Keeper.lnk"
    assert windows_app._ps_dq_escape(normal) == normal


@pytest.mark.skipif(sys.platform == "win32", reason="bash hook is POSIX-only")
def test_auto_update_is_failsafe_exit_zero(tmp_path):
    """Even after explicit opt-in, a missing Claude install cannot block start."""
    env = dict(os.environ)
    env["HOME"] = str(tmp_path)
    env["KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE"] = "1"
    env.pop("KEYS_KEEPER_NO_AUTOUPDATE", None)
    env.pop("KKZ_NO_AUTOUPDATE", None)
    # Force the debounce to elapse instantly so we exercise past the stamp gate.
    env["KKZ_AUTO_UPDATE_INTERVAL_SEC"] = "0"
    proc = subprocess.run(
        ["bash", str(AUTO_UPDATE)],
        env=env,
        capture_output=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr.decode()
