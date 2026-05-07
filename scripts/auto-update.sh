#!/usr/bin/env bash
# kyzdes/claude-skills · marketplace auto-update hook
#
# Fires at every Claude Code SessionStart from each installed plugin in this
# marketplace. Refreshes the marketplace manifest, then asks Claude Code to
# update each installed plugin from this marketplace to its latest commit.
# New versions apply on the NEXT session start (Claude Code design).
#
# Debounce: a shared timestamp at ~/.cache/kyzdes-claude-skills/last-update
# means even if N skills from this marketplace are installed (and hence N
# copies of this hook fire), only the first to win the race does the
# network work — others exit silently within milliseconds.

set -e

MARKETPLACE="claude-skills"
STAMP_DIR="${HOME}/.cache/kyzdes-claude-skills"
STAMP="${STAMP_DIR}/last-update"
LOG="${STAMP_DIR}/update.log"
DEBOUNCE_SEC="${KKZ_AUTO_UPDATE_INTERVAL_SEC:-14400}"  # default 4h

if [ -f "$STAMP" ]; then
  if [ "$(uname)" = "Darwin" ]; then
    last_mtime=$(stat -f %m "$STAMP" 2>/dev/null || echo 0)
  else
    last_mtime=$(stat -c %Y "$STAMP" 2>/dev/null || echo 0)
  fi
  age=$(( $(date +%s) - last_mtime ))
  if [ "$age" -lt "$DEBOUNCE_SEC" ]; then
    exit 0
  fi
fi

mkdir -p "$STAMP_DIR"
date > "$STAMP"

CLAUDE_BIN="$(command -v claude || true)"
[ -n "$CLAUDE_BIN" ] && [ -x "$CLAUDE_BIN" ] || exit 0

INSTALLED_JSON="${HOME}/.claude/plugins/installed_plugins.json"
[ -f "$INSTALLED_JSON" ] || exit 0

{
  echo "--- $(date) ---"

  "$CLAUDE_BIN" plugin marketplace update "$MARKETPLACE" 2>&1 | sed 's/^/  /' || true

  python3 -c "
import json
with open('${INSTALLED_JSON}') as f:
    data = json.load(f)
suffix = '@${MARKETPLACE}'
for key in data.get('plugins', {}):
    if key.endswith(suffix):
        print(key[:-len(suffix)])
" 2>/dev/null | while IFS= read -r plugin; do
    [ -n "$plugin" ] || continue
    echo "  updating $plugin@${MARKETPLACE}"
    "$CLAUDE_BIN" plugin update "$plugin@${MARKETPLACE}" 2>&1 | sed 's/^/    /' || true
  done
} >> "$LOG" 2>&1 || true

exit 0
