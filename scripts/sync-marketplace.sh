#!/bin/sh
# Keep the keys-keeper entry in the kyzdes/claude-skills marketplace consistent
# with THIS repo's plugin.json. Versions are already auto-synced (the marketplace
# sources the plugin by git URL, so `/plugin install` clones repo HEAD), so the
# only field that hand-duplicates plugin metadata — and therefore drifts — is the
# `description`. This mirrors it verbatim, then commits + pushes the marketplace.
#
# Maintainer/personal tool: it no-ops cleanly when the marketplace clone isn't
# present, so a contributor who only has this repo is never affected. The
# matching PostToolUse hook lives in .claude/settings.local.json (gitignored).
#
# Marketplace location: $KEYS_KEEPER_MARKETPLACE_DIR, else the maintainer default.

set -u

SKILL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_JSON="${SKILL_DIR}/.claude-plugin/plugin.json"
MP_DIR="${KEYS_KEEPER_MARKETPLACE_DIR:-${HOME}/.superset/projects/claude-skills}"
MP_JSON="${MP_DIR}/.claude-plugin/marketplace.json"

[ -f "$PLUGIN_JSON" ] || { echo "[sync-marketplace] no plugin.json — skipping"; exit 0; }
# No marketplace clone on this machine → nothing to sync (e.g. a contributor).
[ -f "$MP_JSON" ] || { echo "[sync-marketplace] no marketplace at $MP_DIR — skipping"; exit 0; }

# Mirror plugin.json description (+ surface version in the commit msg) into the
# keys-keeper entry. Exit 0 = the file changed; exit 1 = already in sync; any
# other failure also exits non-zero and is treated as "no change" (fail-closed —
# never commit/push on a parse error).
VERSION="$(python3 - "$PLUGIN_JSON" "$MP_JSON" <<'PY'
import json, sys
plugin_path, mp_path = sys.argv[1], sys.argv[2]
plugin = json.load(open(plugin_path))
desc = plugin["description"]
ver = plugin.get("version", "?")
mp = json.load(open(mp_path))
changed = False
for p in mp.get("plugins", []):
    if p.get("name") == "keys-keeper" and p.get("description") != desc:
        p["description"] = desc
        changed = True
if changed:
    with open(mp_path, "w") as f:
        json.dump(mp, f, indent=2, ensure_ascii=False)
        f.write("\n")
# stdout carries the version (for the commit message); exit code carries drift.
sys.stdout.write(ver)
sys.exit(0 if changed else 1)
PY
)" || { echo "[sync-marketplace] description already in sync"; exit 0; }

echo "[sync-marketplace] description drifted → updating marketplace (keys-keeper v${VERSION})"
cd "$MP_DIR" || { echo "[sync-marketplace] cannot cd to $MP_DIR"; exit 0; }
# Commit ONLY the manifest path so unrelated staged/working changes in the
# marketplace repo are never swept in.
git commit .claude-plugin/marketplace.json \
    -m "chore(keys-keeper): sync description from plugin.json (v${VERSION})" \
    >/dev/null 2>&1 || { echo "[sync-marketplace] nothing to commit"; exit 0; }
# The marketplace repo gets commits from other plugins, so the local clone is
# often behind origin. Rebase our single manifest-only commit on top before
# pushing — it only touches keys-keeper's description, so it never conflicts
# with other plugins' entries. Fail-soft: if fetch/rebase/push can't complete,
# leave the local commit and tell the user to finish by hand.
git fetch origin >/dev/null 2>&1
if ! git rebase origin/main >/dev/null 2>&1; then
    git rebase --abort >/dev/null 2>&1
    echo "[sync-marketplace] ⚠ committed locally; rebase needs attention — finish in $MP_DIR"
    exit 0
fi
if git push >/dev/null 2>&1; then
    echo "[sync-marketplace] ✓ committed + pushed marketplace"
else
    echo "[sync-marketplace] ⚠ committed locally; push failed — run 'git push' in $MP_DIR"
fi
