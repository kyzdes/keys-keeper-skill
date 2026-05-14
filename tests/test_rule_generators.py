"""Byte-for-byte golden tests for per-target rule renderers.

When you intentionally change `agent_rules/canonical.py` (the source of
truth), regenerate the fixtures with:

    pytest tests/test_rule_generators.py --regen

That rewrites the files under `tests/fixtures/rules/` from the current
render output. Review the diff with `git diff tests/fixtures/rules/`
before committing.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from keys_keeper.agent_rules import render


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "rules"


# (fixture filename, render callable)
RENDERS = [
    ("claude.md", render.render_claude_skill_md),
    ("cursor.mdc", render.render_cursor_mdc),
    ("aider_conventions.md", render.render_aider_conventions),
    ("codex_agents.md", render.render_codex_agents),
    ("cline.md", render.render_cline_md),
    ("generic.md", render.render_generic),
]


@pytest.mark.parametrize("filename, render_fn", RENDERS, ids=[r[0] for r in RENDERS])
def test_render_matches_golden(filename: str, render_fn, request: pytest.FixtureRequest):
    fixture = FIXTURES_DIR / filename
    actual = render_fn()
    if request.config.getoption("--regen"):
        fixture.write_text(actual, encoding="utf-8", newline="\n")
        pytest.skip(f"regenerated {fixture}")
    expected = fixture.read_text(encoding="utf-8")
    assert actual == expected, (
        f"{filename}: render output drifted from golden.\n"
        f"Run `pytest tests/test_rule_generators.py --regen` to update fixtures "
        f"if the change is intentional."
    )


def test_all_fixtures_present():
    """Guard against a fixture being deleted without a corresponding test removal."""
    expected = {filename for filename, _ in RENDERS}
    actual = {p.name for p in FIXTURES_DIR.iterdir() if p.is_file()}
    assert expected == actual, (
        f"fixtures/rules/ mismatch:\n"
        f"  expected: {sorted(expected)}\n"
        f"  found:    {sorted(actual)}\n"
        f"  missing:  {sorted(expected - actual)}\n"
        f"  extra:    {sorted(actual - expected)}"
    )


def test_renderers_are_deterministic():
    """Two consecutive renders return byte-identical output (no clock, no env reads)."""
    for filename, render_fn in RENDERS:
        a = render_fn()
        b = render_fn()
        assert a == b, f"{filename}: render is non-deterministic"


def test_no_plaintext_markers_leak_into_single_file_renders():
    """Marker tokens are appended by the writer, not embedded in renderers'
    output. If they appear in a single-file render (claude/cursor/cline/generic),
    the writer would double-wrap on append.
    """
    single_file_renders = [
        ("claude.md", render.render_claude_skill_md),
        ("cursor.mdc", render.render_cursor_mdc),
        ("cline.md", render.render_cline_md),
        ("generic.md", render.render_generic),
    ]
    for filename, render_fn in single_file_renders:
        out = render_fn()
        assert render.MARKER_BEGIN not in out, f"{filename}: render contains MARKER_BEGIN"
        assert render.MARKER_END not in out, f"{filename}: render contains MARKER_END"
