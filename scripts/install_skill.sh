#!/usr/bin/env bash
# Install the keys-keeper skill into ~/.claude/skills/
set -euo pipefail
SOURCE="$(cd "$(dirname "$0")/.." && pwd)/skills/keys-keeper"
DEST="$HOME/.claude/skills/keys-keeper"
if [[ -e "$DEST" ]]; then
  echo "warning: $DEST already exists; pass --force to overwrite" >&2
  if [[ "${1:-}" != "--force" ]]; then
    exit 1
  fi
  rm -rf "$DEST"
fi
mkdir -p "$(dirname "$DEST")"
cp -R "$SOURCE" "$DEST"
echo "installed skill at $DEST"
