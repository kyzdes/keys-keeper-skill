#!/usr/bin/env bash
# Wipe the demo state. Real ~/.config/keys-keeper and login keychain untouched.
set -euo pipefail

DEMO_HOME="$HOME/.config/keys-keeper-demo"
DEMO_KC="/tmp/kk-demo.keychain-db"

# stop any keys serve still running on the demo port
PIDS=$(lsof -t -i :7777 2>/dev/null || true)
if [[ -n "$PIDS" ]]; then
  echo "→ stopping keys serve (pid $PIDS)"
  kill $PIDS 2>/dev/null || true
fi

echo "→ removing $DEMO_HOME"
rm -rf "$DEMO_HOME"

echo "→ removing $DEMO_KC"
security delete-keychain "$DEMO_KC" 2>/dev/null || true
rm -f "$DEMO_KC"

echo "✓ demo state torn down. Real data untouched."
