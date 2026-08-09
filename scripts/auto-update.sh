#!/usr/bin/env bash
# kyzdes/claude-skills · marketplace auto-update hook
#
# Invoked at Claude Code SessionStart, but intentionally does NOTHING unless
# the user explicitly opts into mutable-HEAD updates. Silent auto-update is an
# unacceptable default for a process that can access a local secrets store.
#
# ---------------------------------------------------------------------------
# CHAIN-OF-TRUST / THREAT MODEL — read before relying on this.
#
# This hook pulls and installs the LATEST commit of each installed plugin from
# the `kyzdes/claude-skills` marketplace. That means an auto-update is only as
# trustworthy as:
#   - the `kyzdes` GitHub account (and its 2FA), and
#   - the marketplace + per-plugin repositories it points at.
# If any of those is compromised, this hook will happily fetch and stage the
# attacker's code on the next session start. There is no signature or pinned-
# digest verification here — `claude plugin update` resolves the marketplace
# ref (effectively HEAD) at update time.
#
# The safe default is a reviewed, pinned release. To retain the legacy update
# behaviour despite the risk, set KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE=1.
# KEYS_KEEPER_NO_AUTOUPDATE and KKZ_NO_AUTOUPDATE remain supported and take
# precedence over that opt-in. The hook always exits 0 (fail-soft).
# ---------------------------------------------------------------------------

set -e

# Explicit opt-out always wins, including when an inherited environment also
# contains the legacy opt-in.
if [ -n "${KEYS_KEEPER_NO_AUTOUPDATE:-}" ] || [ -n "${KKZ_NO_AUTOUPDATE:-}" ]; then
  exit 0
fi

# Safe default: no network, no filesystem writes, no update. This check must
# stay before creation of the debounce stamp directory.
if [ "${KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE:-}" != "1" ]; then
  exit 0
fi

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
