#!/bin/sh
# Check the Keys Keeper entry against a reviewed source ref. Default is read-only.
# --write updates ONLY the local manifest; commit/push remain explicit actions.
set -eu
SKILL_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
MP_DIR="${KEYS_KEEPER_MARKETPLACE_DIR:-${HOME}/.superset/projects/claude-skills}"
exec python3 - "$SKILL_DIR" "$MP_DIR/.claude-plugin/marketplace.json" "$@" <<'PYTHON'
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser(description="Check or update one pinned marketplace entry")
parser.add_argument("--ref", default="HEAD", help="reviewed source ref, normally a release tag")
parser.add_argument("--write", action="store_true", help="update the local manifest without committing or pushing")
root, manifest = Path(sys.argv[1]), Path(sys.argv[2])
args = parser.parse_args(sys.argv[3:])

def git(*argv):
    return subprocess.check_output(["git", "-C", str(root), *argv], text=True, stderr=subprocess.DEVNULL).strip()

try:
    # Resolve first so untrusted ref text never becomes a git option or pathspec.
    sha = git("rev-parse", "--verify", "--end-of-options", args.ref + "^{commit}")
    plugin = json.loads(git("show", sha + ":.claude-plugin/plugin.json"))
    original = manifest.read_bytes()
    data = json.loads(original)
    entries = [p for p in data["plugins"] if p.get("name") == "keys-keeper"]
    if len(entries) != 1 or plugin["name"] != "keys-keeper":
        raise ValueError("expected exactly one Keys Keeper entry")
    entry = entries[0]
    expected_source = {"source": "url", "url": "https://github.com/kyzdes/keys-keeper-skill.git", "sha": sha}
    changed = entry.get("description") != plugin["description"] or entry.get("source") != expected_source
    if not changed:
        print(f"Keys Keeper {plugin['version']}: marketplace pin and description match {sha}")
        sys.exit(0)
    if not args.write:
        print(f"Keys Keeper {plugin['version']}: marketplace differs from {sha}; use --write to update the local manifest", file=sys.stderr)
        sys.exit(1)
    entry["description"] = plugin["description"]
    entry["source"] = expected_source
    if manifest.is_symlink():
        raise ValueError("manifest must not be a symlink")
    mode = manifest.stat().st_mode & 0o777
    fd, temporary = tempfile.mkstemp(prefix=".marketplace-", dir=manifest.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            if hasattr(os, "fchmod"):
                os.fchmod(out.fileno(), mode)
            json.dump(data, out, indent=2, ensure_ascii=False)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if manifest.read_bytes() != original:
            raise ValueError("manifest changed while preparing update")
        os.replace(temporary, manifest)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    print(f"Updated local Keys Keeper {plugin['version']} entry to {sha}; review, commit and push explicitly")
except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
    print(f"Marketplace verification failed ({type(exc).__name__}); no commit or push performed", file=sys.stderr)
    sys.exit(2)
PYTHON
