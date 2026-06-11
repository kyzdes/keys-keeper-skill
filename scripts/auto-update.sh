#!/usr/bin/env bash
# kyzdes/claude-skills · marketplace auto-update hook
#
# Fires at every Claude Code SessionStart from each installed plugin in this
# marketplace. Refreshes the marketplace manifest, then asks Claude Code to
# update each installed plugin from this marketplace to its latest commit.
# New versions apply on the NEXT session start (Claude Code design).
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
# For HIGH-ASSURANCE installs, do NOT auto-update from HEAD:
#   - set KEYS_KEEPER_NO_AUTOUPDATE=1 (see below) to disable this hook, and
#   - pin the plugin to a reviewed tag/commit you have audited, updating it
#     manually after review.
#
# OPT-OUT: export KEYS_KEEPER_NO_AUTOUPDATE=1 (any non-empty value) to skip all
# update work. The hook still exits 0 (fail-soft) so a SessionStart is never
# blocked. KKZ_NO_AUTOUPDATE is honored as a back-compat alias.
# ---------------------------------------------------------------------------

set -e

# Opt-out (high-assurance / pinned installs): bail out before any network or
# filesystem work, but still exit 0 so SessionStart is never blocked.
if [ -n "${KEYS_KEEPER_NO_AUTOUPDATE:-}" ] || [ -n "${KKZ_NO_AUTOUPDATE:-}" ]; then
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
