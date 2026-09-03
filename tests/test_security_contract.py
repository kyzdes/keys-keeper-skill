"""Regression tests for the public threat-model and release contract."""
from __future__ import annotations

import json
import re
from pathlib import Path

from keys_keeper import __version__


ROOT = Path(__file__).resolve().parent.parent
CODEX_PLUGIN_ROOT = ROOT / "plugins" / "keys-keeper"
CODEX_MARKETPLACE_PATH = ROOT / ".agents" / "plugins" / "marketplace.json"

PUBLIC_SECURITY_SURFACES = (
    ROOT / "README.md",
    ROOT / "pyproject.toml",
    ROOT / ".claude-plugin" / "plugin.json",
    CODEX_PLUGIN_ROOT / ".codex-plugin" / "plugin.json",
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
    claude_plugin = json.loads(
        (ROOT / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    codex_plugin = json.loads(
        (CODEX_PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    match = re.search(r'^version = "([^"]+)"$', project, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__
    assert claude_plugin["version"] == __version__
    assert codex_plugin["version"] == __version__


def test_public_current_version_surfaces_match():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    landing = (ROOT / "docs" / "landing" / "index.html").read_text(encoding="utf-8")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    source_skill = (ROOT / "skills" / "keys-keeper" / "references" / "install.md").read_text(
        encoding="utf-8"
    )

    assert f"**Status:** v{__version__}" in readme
    assert f"keys-keeper-skill.git@v{__version__}" in readme
    assert f"v{__version__}" in landing
    first_release = re.search(r"^## \[(\d+\.\d+\.\d+)]", changelog, re.MULTILINE)
    assert first_release is not None
    assert first_release.group(1) == __version__
    assert f"keys-keeper-skill.git@v{__version__}" in source_skill


def test_codex_plugin_is_skill_only_and_implicitly_invokable():
    plugin = json.loads(
        (CODEX_PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    assert plugin["name"] == "keys-keeper"
    assert plugin["skills"] == "./skills/"
    assert "hooks" not in plugin
    assert "mcpServers" not in plugin
    assert "apps" not in plugin

    prompts = plugin["interface"]["defaultPrompt"]
    assert 1 <= len(prompts) <= 3
    assert all(len(prompt) <= 128 for prompt in prompts)

    for forbidden_path in ("hooks", "scripts", "src", ".git", ".venv"):
        assert not (CODEX_PLUGIN_ROOT / forbidden_path).exists()

    source_skill_root = ROOT / "skills" / "keys-keeper"
    packaged_skill_root = CODEX_PLUGIN_ROOT / "skills" / "keys-keeper"
    for relative_path in (
        Path("SKILL.md"),
        Path("agents/openai.yaml"),
        Path("references/diagnostics.md"),
        Path("references/install.md"),
        Path("references/keychain-bypass.md"),
        Path("references/save-and-route.md"),
        Path("references/sync.md"),
        Path("references/temporary-sinks.md"),
    ):
        assert (packaged_skill_root / relative_path).read_bytes() == (
            source_skill_root / relative_path
        ).read_bytes()

    assert not (source_skill_root / "references" / "examples.md").exists()
    assert not (packaged_skill_root / "references" / "examples.md").exists()

    agent_manifest = (packaged_skill_root / "agents" / "openai.yaml").read_text(
        encoding="utf-8"
    )
    assert "allow_implicit_invocation: true" in agent_manifest


def test_repository_is_an_installable_codex_marketplace():
    marketplace = json.loads(CODEX_MARKETPLACE_PATH.read_text(encoding="utf-8"))
    assert marketplace["name"] == "keys-keeper"

    entries = [
        entry
        for entry in marketplace["plugins"]
        if entry.get("name") == "keys-keeper"
    ]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["source"] == {
        "source": "local",
        "path": "./plugins/keys-keeper",
    }
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert entry["category"] == "Developer Tools"

    source_path = (ROOT / entry["source"]["path"]).resolve()
    assert source_path == CODEX_PLUGIN_ROOT.resolve()
    assert (source_path / ".codex-plugin" / "plugin.json").is_file()


def test_readme_documents_github_marketplace_install():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert (
        "codex plugin marketplace add "
        "https://github.com/kyzdes/keys-keeper-skill" in readme
    )
    assert "codex plugin add keys-keeper@keys-keeper" in readme
    assert "/plugin update keys-keeper@claude-skills" in readme


def test_cryptography_floor_contains_the_patched_wheel_release():
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'"(cryptography[^"]+)"', project)
    assert match is not None
    cryptography = match.group(1)
    assert ">=48.0.1" in cryptography
    assert "<49" in cryptography


def test_readme_installs_a_reviewed_release_not_repository_head():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"keys-keeper-skill.git@v{__version__}" in readme
    assert "pipx install git+https://github.com/kyzdes/keys-keeper-skill.git\n" not in readme
