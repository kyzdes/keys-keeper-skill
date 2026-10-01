#!/usr/bin/env bash
# Keys Keeper's optional fallback updater has one attempt per rolling day.
# The reviewed shared updater remains unchanged; manual plugin update is immediate.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)" || exit 0
command -v python3 >/dev/null 2>&1 || exit 0
python3 "$SCRIPT_DIR/keys_keeper_update.py" >/dev/null 2>&1 || true
exit 0
