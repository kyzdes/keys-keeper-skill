#!/usr/bin/env bash
# kyzdes plugin updates are only as trustworthy as the source account/repo.
# Pin a reviewed release when mutable updates are unsuitable.
# Keys Keeper additionally requires KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE=1;
# KEYS_KEEPER_NO_AUTOUPDATE and KKZ_NO_AUTOUPDATE take precedence in its helper.
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)" || exit 0
command -v python3 >/dev/null 2>&1 || exit 0
python3 "$SCRIPT_DIR/auto_update.py" >/dev/null 2>&1 || true
exit 0
