#!/usr/bin/env bash
# kyzdes/claude-skills · marketplace auto-update hook
#
# Runs at every Claude Code SessionStart. Pulls the latest version of the
# marketplace and each plugin's cached source repo, so installed skills
# stay current without the friend ever running /plugin marketplace update.
#
# Debounce: a shared timestamp at ~/.cache/kyzdes-claude-skills/last-update
# means that even if 5 skills from this marketplace are installed (and hence
# 5 copies of this script are queued at SessionStart), only the first one
# does the network work — the other 4 exit silently.

set -e

STAMP_DIR="${HOME}/.cache/kyzdes-claude-skills"
STAMP="${STAMP_DIR}/last-update"
LOG="${STAMP_DIR}/update.log"
DEBOUNCE_SEC=$((4 * 60 * 60))  # 4 hours; tweak with KKZ_AUTO_UPDATE_INTERVAL_SEC

if [ -n "${KKZ_AUTO_UPDATE_INTERVAL_SEC:-}" ]; then
  DEBOUNCE_SEC="$KKZ_AUTO_UPDATE_INTERVAL_SEC"
fi

# Debounce — silent skip if recent
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

# Best-effort: walk the cache dir for our marketplace and ff-pull every git
# repo under it. Failures are swallowed — friend can still run
# /plugin marketplace update manually if something goes wrong.
{
  echo "--- $(date) ---"
  CACHE_ROOT="${HOME}/.claude/plugins/cache"
  for marketplace_name in claude-skills kyzdes-claude-skills kyzdes claude-skills-kyzdes; do
    d="${CACHE_ROOT}/${marketplace_name}"
    [ -d "$d" ] || continue
    echo "  scanning $d"
    while IFS= read -r gitdir; do
      repo="$(dirname "$gitdir")"
      out=$(git -C "$repo" pull --ff-only --quiet 2>&1 || echo "  pull failed: $repo")
      [ -n "$out" ] && echo "  $out"
    done < <(find "$d" -maxdepth 5 -type d -name ".git" 2>/dev/null)
  done
} >> "$LOG" 2>&1 || true

exit 0
