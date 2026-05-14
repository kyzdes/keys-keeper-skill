"""Canonical agent-facing prose + renderers for per-agent rule files.

Single source of truth: edit `canonical.py`, then regenerate downstream
files via `keys init <target> --force` (or `keys init claude --force` for
the shipped SKILL.md).
"""
from keys_keeper.agent_rules import canonical, render

__all__ = ["canonical", "render"]
