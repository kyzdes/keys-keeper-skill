"""Regression tests for the public threat-model and release contract."""
from __future__ import annotations

import json
import re
from pathlib import Path

from keys_keeper import __version__


ROOT = Path(__file__).resolve().parent.parent

PUBLIC_SECURITY_SURFACES = (
    ROOT / "README.md",
    ROOT / "pyproject.toml",
    ROOT / ".claude-plugin" / "plugin.json",
    ROOT / "docs" / "landing" / "index.html",
    ROOT / "src" / "keys_keeper" / "agent_rules" / "canonical.py",
    ROOT / "src" / "keys_keeper" / "agent_rules" / "render.py",
)

OVERCLAIMS = (
    re.compile(r"architecturally cannot", re.IGNORECASE),
    re.compile(r"agents? (?:have|has) no path to set", re.IGNORECASE),
    re.compile(r"agents? can(?:not|'t) leak", re.IGNORECASE),
    re.compile(r"agent never possessed", re.IGNORECASE),
)


def test_public_copy_does_not_claim_same_user_isolation():
    for path in PUBLIC_SECURITY_SURFACES:
        text = path.read_text(encoding="utf-8")
        for pattern in OVERCLAIMS:
            assert not pattern.search(text), (
                f"{path.relative_to(ROOT)} contains the unsupported security "
                f"claim {pattern.pattern!r}"
            )


def test_release_versions_are_consistent():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    plugin = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    match = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__
    assert plugin["version"] == __version__


def test_cryptography_floor_contains_the_patched_wheel_release():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"(cryptography[^"]+)"', project)
    assert match is not None
    cryptography = match.group(1)
    assert ">=48.0.1" in cryptography
    assert "<49" in cryptography


def test_readme_installs_a_reviewed_release_not_repository_head():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "keys-keeper-skill.git@v0.7.2" in readme
    assert "pipx install git+https://github.com/kyzdes/keys-keeper-skill.git\n" not in readme
