"""Release pin checks never publish or absorb unrelated marketplace edits."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="maintainer shell helper is POSIX-only")
SCRIPT = Path(__file__).resolve().parents[1] / "scripts/sync-marketplace.sh"


@pytest.fixture
def release_repo(tmp_path):
    repo, market = tmp_path / "source", tmp_path / "market"
    (repo / "scripts").mkdir(parents=True)
    (repo / ".claude-plugin").mkdir()
    (market / ".claude-plugin").mkdir(parents=True)
    shutil.copy(SCRIPT, repo / "scripts/sync-marketplace.sh")
    plugin = {"name": "keys-keeper", "version": "1.2.3", "description": "Reviewed release"}
    (repo / ".claude-plugin/plugin.json").write_text(json.dumps(plugin))
    env = {**os.environ, "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.invalid",
           "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.invalid",
           "KEYS_KEEPER_MARKETPLACE_DIR": str(market)}
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], env=env, text=True).strip()
    git("init", "-q")
    git("add", ".")
    git("commit", "-qm", "synthetic release")
    sha = git("rev-parse", "HEAD")
    git("tag", "v1.2.3")
    manifest = market / ".claude-plugin/marketplace.json"
    unrelated = {"name": "other", "description": "uncommitted edit", "source": "./other"}
    data = {"name": "test", "plugins": [unrelated, {
        "name": "keys-keeper", "description": plugin["description"], "category": "Tools",
        "source": {"source": "url", "url": "https://github.com/kyzdes/keys-keeper-skill.git", "sha": sha},
    }]}
    manifest.write_text(json.dumps(data, indent=2) + "\n")
    def run(*args):
        return subprocess.run(["sh", str(repo / "scripts/sync-marketplace.sh"), *args],
                              env=env, text=True, capture_output=True, timeout=15)
    return manifest, data, run, git


def test_matching_pin_is_read_only(release_repo):
    manifest, _, run, _ = release_repo
    original = manifest.read_bytes()
    info = manifest.stat()
    result = run("--ref", "v1.2.3")
    assert result.returncode == 0, result.stderr
    assert manifest.read_bytes() == original
    assert manifest.stat().st_mtime_ns == info.st_mtime_ns


def test_stale_pin_fails_without_rewriting(release_repo):
    manifest, data, run, _ = release_repo
    data["plugins"][1]["source"]["sha"] = "0" * 40
    manifest.write_text(json.dumps(data))
    original = manifest.read_bytes()
    assert run("--ref", "v1.2.3").returncode == 1
    assert manifest.read_bytes() == original


def test_explicit_write_updates_pin_and_preserves_other_fields(release_repo):
    manifest, data, run, git = release_repo
    before = git("rev-list", "--count", "HEAD")
    data["plugins"][1]["source"]["sha"] = "0" * 40
    data["plugins"][1]["description"] = "obsolete"
    manifest.write_text(json.dumps(data))
    result = run("--ref", "v1.2.3", "--write")
    assert result.returncode == 0, result.stderr
    after = json.loads(manifest.read_text())
    assert after["plugins"][0] == data["plugins"][0]
    assert after["plugins"][1]["category"] == "Tools"
    assert after["plugins"][1]["source"]["sha"] == git("rev-parse", "HEAD")
    assert after["plugins"][1]["description"] == "Reviewed release"
    assert git("rev-list", "--count", "HEAD") == before
    assert run("--ref", "v1.2.3").returncode == 0


def test_invalid_ref_or_ambiguous_entry_never_mutates(release_repo):
    manifest, data, run, _ = release_repo
    original = manifest.read_bytes()
    assert run("--write", "--ref=--invalid").returncode == 2
    assert manifest.read_bytes() == original
    data["plugins"].append(data["plugins"][1].copy())
    manifest.write_text(json.dumps(data))
    original = manifest.read_bytes()
    assert run("--write", "--ref", "v1.2.3").returncode == 2
    assert manifest.read_bytes() == original
