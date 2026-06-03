"""SessionStart hooks: both auto-update and auto-sync are wired, each bounded."""
import json
from pathlib import Path

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
