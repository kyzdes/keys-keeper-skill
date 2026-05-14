"""`keys init <target>` — emit an agent rule file for the given target.

Renders are pure (see `agent_rules.render`); this module owns the
filesystem and CLI-shaped concerns: target → destination resolution,
write modes, --force / --check / --stdout flags, post-write hints
printed to stderr.

File I/O is funnelled through `_safe_read` / `_safe_atomic_write` so
permission / not-found / disk-full errors surface as readable CLI
messages (exit 2) instead of raw tracebacks.
"""
from __future__ import annotations

import argparse
import difflib
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from keys_keeper.agent_rules import render


WriteMode = str  # "single-file" | "marker-append" | "stdout"


class _InitError(Exception):
    """Raised by helpers for user-facing errors; caught at cmd_init boundary
    and emitted as `error: <msg>` + exit code 2."""


@dataclass(frozen=True)
class TargetSpec:
    # All renderers accept Optional[Path]. Only claude actually uses it
    # (to read existing frontmatter); other targets ignore the argument.
    # Uniform signature kills the old lambda-with-hardcoded-path pattern.
    render_fn: Callable[[Path | None], str]
    default_path: str | None  # relative to cwd; None for stdout-only
    write_mode: WriteMode
    post_write_hint: str | None = None


# ---------------------------------------------------------------------------
# Per-target render shims. All have the same signature so the registry can
# dispatch uniformly. Non-claude shims ignore `path` since their content is
# a pure function of canonical prose.
# ---------------------------------------------------------------------------


def _render_claude(path: Path | None = None) -> str:
    """Render SKILL.md, preserving existing name/description if present.

    If `path` is given AND exists, read its frontmatter and reuse any
    user-customized `name` / `description`. Otherwise fall back to defaults
    from `render.CLAUDE_SKILL_NAME` / `CLAUDE_SKILL_DESCRIPTION`.
    """
    name = render.CLAUDE_SKILL_NAME
    description = render.CLAUDE_SKILL_DESCRIPTION
    if path is not None and path.exists():
        try:
            text = _safe_read(path)
        except _InitError:
            # Existing file is unreadable — fall back to defaults rather
            # than failing the render. Writers will surface the I/O error
            # at write time.
            text = ""
        m = _FRONTMATTER_RE.match(text)
        if m:
            fm = m.group(1)
            n = _NAME_RE.search(fm)
            d = _DESCRIPTION_RE.search(fm)
            if n:
                name = n.group(1)
            if d:
                description = d.group(1)
    return render.render_claude_skill_md(name=name, description=description)


def _render_cursor(_path: Path | None = None) -> str:
    return render.render_cursor_mdc()


def _render_aider(_path: Path | None = None) -> str:
    return render.render_aider_conventions()


def _render_codex(_path: Path | None = None) -> str:
    return render.render_codex_agents()


def _render_cline(_path: Path | None = None) -> str:
    return render.render_cline_md()


def _render_generic(_path: Path | None = None) -> str:
    return render.render_generic()


# ---------------------------------------------------------------------------
# Registry. Order here = order shown in `keys init --help`.
# ---------------------------------------------------------------------------

TARGETS: dict[str, TargetSpec] = {
    "claude": TargetSpec(
        render_fn=_render_claude,
        default_path="skills/keys-keeper/SKILL.md",
        write_mode="single-file",
        post_write_hint=None,
    ),
    "cursor": TargetSpec(
        render_fn=_render_cursor,
        default_path=".cursor/rules/keys-keeper.mdc",
        write_mode="single-file",
        post_write_hint=None,
    ),
    "aider": TargetSpec(
        render_fn=_render_aider,
        default_path="CONVENTIONS.md",
        write_mode="marker-append",
        post_write_hint=(
            "Aider does not auto-discover CONVENTIONS.md. To wire it up:\n"
            "  one-shot:   aider --read CONVENTIONS.md\n"
            "  persistent: add `read: CONVENTIONS.md` to .aider.conf.yml\n"
            "  in-session: /read CONVENTIONS.md"
        ),
    ),
    "codex": TargetSpec(
        render_fn=_render_codex,
        default_path="AGENTS.md",
        write_mode="marker-append",
        post_write_hint=(
            "AGENTS.md is auto-loaded by Codex CLI and (in 2026) by Cursor, "
            "Amp, Jules, and other agents following the AGENTS.md open spec."
        ),
    ),
    "cline": TargetSpec(
        render_fn=_render_cline,
        default_path=".clinerules/00-keys-keeper.md",
        write_mode="single-file",
        post_write_hint=None,
    ),
    "generic": TargetSpec(
        render_fn=_render_generic,
        default_path=None,
        write_mode="stdout",
        post_write_hint=None,
    ),
}


# ---------------------------------------------------------------------------
# Claude frontmatter parsing — used only by _render_claude.
# ---------------------------------------------------------------------------


_FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)
_NAME_RE = re.compile(r"^name:\s*(.+?)\s*$", re.MULTILINE)
_DESCRIPTION_RE = re.compile(r"^description:\s*(.+?)\s*$", re.MULTILINE)


# ---------------------------------------------------------------------------
# Safe file I/O — raises _InitError with friendly messages on failure.
# ---------------------------------------------------------------------------


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise _InitError(f"cannot read {path}: file does not exist")
    except PermissionError:
        raise _InitError(f"cannot read {path}: permission denied")
    except IsADirectoryError:
        raise _InitError(f"cannot read {path}: is a directory, not a file")
    except UnicodeDecodeError as ex:
        raise _InitError(f"cannot read {path}: not valid UTF-8 ({ex.reason})")
    except OSError as ex:
        raise _InitError(f"cannot read {path}: {ex}")


def _safe_atomic_write(path: Path, content: str) -> None:
    """Write UTF-8 with LF newlines, via temp file + os.replace.

    Catches the common I/O failures (permission, not-a-directory,
    cross-device, disk-full) and re-raises as _InitError. The temp file
    is cleaned up on any failure so we don't leave .tmp turds.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        raise _InitError(f"cannot create parent directory of {path}: permission denied")
    except FileExistsError:
        # parent path component is a file, not a directory
        raise _InitError(f"cannot create parent directory of {path}: a file exists at that path")
    except OSError as ex:
        raise _InitError(f"cannot create parent directory of {path}: {ex}")

    if path.is_dir():
        raise _InitError(f"cannot write {path}: target is a directory, not a file")

    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(content, encoding="utf-8", newline="\n")
    except PermissionError:
        raise _InitError(f"cannot write {path}: permission denied")
    except IsADirectoryError:
        raise _InitError(f"cannot write {path}: target is a directory, not a file")
    except OSError as ex:
        # disk full, read-only filesystem, etc.
        raise _InitError(f"cannot write {path}: {ex}")

    try:
        os.replace(tmp, path)
    except OSError as ex:
        # cross-device move, target replaced by directory mid-op, etc.
        try:
            tmp.unlink()
        except OSError:
            pass
        raise _InitError(f"cannot finalize write to {path}: {ex}")


# ---------------------------------------------------------------------------
# Write modes
# ---------------------------------------------------------------------------


def _wrap_with_markers(body: str) -> str:
    return f"{render.MARKER_BEGIN}\n{body.rstrip()}\n{render.MARKER_END}\n"


def _marker_section_pattern() -> re.Pattern[str]:
    return re.compile(
        re.escape(render.MARKER_BEGIN) + r".*?" + re.escape(render.MARKER_END) + r"\n?",
        re.DOTALL,
    )


def _splice_marked_section(existing: str, body: str) -> str:
    """Replace the keys-keeper marked section in `existing`, or append it.

    Preserves everything outside the markers byte-for-byte (except the
    sole `\\n` boundary between pre-existing content and the appended
    section, which is normalized to one blank line). A truncated/
    malformed marker pair (e.g. begin without end) is treated as "no
    section present" — we append a fresh one rather than corrupting
    the file silently.
    """
    wrapped = _wrap_with_markers(body)
    pattern = _marker_section_pattern()
    if pattern.search(existing):
        return pattern.sub(wrapped, existing, count=1)
    # No existing markers (or malformed) — append.
    sep = "\n\n" if existing and not existing.endswith("\n\n") else ""
    return f"{existing}{sep}{wrapped}" if existing else wrapped


# ---------------------------------------------------------------------------
# Drift detection (--check)
# ---------------------------------------------------------------------------


def _check_single_file(path: Path, expected: str) -> tuple[bool, str]:
    actual = _safe_read(path) if path.exists() else ""
    if actual == expected:
        return True, ""
    diff = "".join(
        difflib.unified_diff(
            actual.splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile=f"{path} (current)",
            tofile=f"{path} (expected)",
            n=3,
        )
    )
    return False, diff


def _check_marker_section(path: Path, body: str) -> tuple[bool, str]:
    expected = _wrap_with_markers(body)
    if not path.exists():
        return False, (
            f"{path}: file does not exist; would create marked section "
            f"({len(body)} bytes).\n"
        )
    existing = _safe_read(path)
    m = _marker_section_pattern().search(existing)
    if not m:
        return False, (
            f"{path}: file exists but has no keys-keeper marked section; "
            f"would append.\n"
        )
    if m.group(0) == expected:
        return True, ""
    diff = "".join(
        difflib.unified_diff(
            m.group(0).splitlines(keepends=True),
            expected.splitlines(keepends=True),
            fromfile=f"{path}:keys-keeper (current)",
            tofile=f"{path}:keys-keeper (expected)",
            n=3,
        )
    )
    return False, diff


# ---------------------------------------------------------------------------
# Public entrypoint — called by cli.cmd_init
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    """Thin error-boundary wrapper. All real logic in _cmd_init_inner."""
    try:
        return _cmd_init_inner(args)
    except _InitError as ex:
        sys.stderr.write(f"error: {ex}\n")
        return 2


def _cmd_init_inner(args: argparse.Namespace) -> int:
    spec = TARGETS[args.target]

    # Resolve destination. --stdout forces stdout for any target; generic
    # is stdout-only by definition.
    if args.stdout or spec.write_mode == "stdout":
        # For --stdout + claude + --out, render reads frontmatter from the
        # named path so the output reflects what would be written there.
        path = Path(args.out) if args.out else None
        content = spec.render_fn(path)
        sys.stdout.write(content)
        return 0

    dest = Path(args.out) if args.out else Path(spec.default_path)

    # Special-case claude default path: if we're not in this repo (no
    # skills/keys-keeper/), fall back to .claude/skills/keys-keeper/SKILL.md
    # so external user projects get a sensible default.
    if args.target == "claude" and not args.out and not dest.parent.exists():
        dest = Path(".claude/skills/keys-keeper/SKILL.md")

    content = spec.render_fn(dest)

    # Warn (once) if cwd is not a git project. Doesn't block.
    if not Path(".git").exists() and not args.out:
        print(
            f"warning: no .git in CWD; writing {dest} anyway",
            file=sys.stderr,
        )

    if args.check:
        return _do_check(spec, dest, content)

    if spec.write_mode == "single-file":
        return _do_single_file(dest, content, force=args.force, spec=spec)
    elif spec.write_mode == "marker-append":
        return _do_marker_append(dest, content, spec=spec)
    else:
        # Should not reach — stdout handled above, no other modes exist.
        raise _InitError(f"unknown write mode {spec.write_mode!r}")


def _do_check(spec: TargetSpec, dest: Path, content: str) -> int:
    if spec.write_mode == "single-file":
        ok, diff = _check_single_file(dest, content)
    elif spec.write_mode == "marker-append":
        ok, diff = _check_marker_section(dest, content)
    else:
        sys.stderr.write(f"--check is not meaningful for {spec.write_mode}\n")
        return 2
    if ok:
        print(f"{dest}: up to date")
        return 0
    sys.stderr.write(diff)
    print(f"{dest}: out of date (see diff above)", file=sys.stderr)
    return 1


def _do_single_file(dest: Path, content: str, *, force: bool, spec: TargetSpec) -> int:
    # Pointing at a directory is a usage error, not a "needs --force" case.
    # _safe_atomic_write would catch it too, but checking here gives a
    # specific message and the right exit code (2 = invalid input).
    if dest.is_dir():
        raise _InitError(f"cannot write {dest}: target is a directory, not a file")
    if dest.exists() and not force:
        sys.stderr.write(f"error: {dest} exists; pass --force to overwrite\n")
        return 1
    _safe_atomic_write(dest, content)
    print(f"wrote {dest}")
    if spec.post_write_hint:
        print(spec.post_write_hint, file=sys.stderr)
    return 0


def _do_marker_append(dest: Path, body: str, *, spec: TargetSpec) -> int:
    if dest.is_dir():
        raise _InitError(f"cannot append to {dest}: target is a directory, not a file")
    existing = _safe_read(dest) if dest.exists() else ""
    new_content = _splice_marked_section(existing, body)
    _safe_atomic_write(dest, new_content)
    action = "updated" if existing else "created"
    print(f"{action} {dest} (keys-keeper section)")
    if spec.post_write_hint:
        print(spec.post_write_hint, file=sys.stderr)
    return 0
