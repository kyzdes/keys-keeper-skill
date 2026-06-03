#!/usr/bin/env bash
# keys-keeper · auto-sync SessionStart hook.
#
# Always exits 0. Does nothing unless the user ran `keys sync mode auto` —
# `keys sync auto` itself checks the mode, debounces, and backgrounds the real
# work, so this wrapper just locates the CLI and fires it. A missing `keys` on
# PATH (e.g. before first install) is a silent no-op, not an error.
set +e
KEYS_BIN="$(command -v keys || true)"
if [ -n "$KEYS_BIN" ] && [ -x "$KEYS_BIN" ]; then
  "$KEYS_BIN" sync auto >/dev/null 2>&1
fi
exit 0
