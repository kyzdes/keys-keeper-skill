"""Parser for the bulk paste format.

Grammar (line-oriented, with multi-line values via triple-quote):
  line          = blank | comment | entry
  blank         = whitespace-only
  comment       = "#" rest-of-line
  entry         = name [ "(" type ")" ] sep value [ "[" tags "]" ]
  sep           = "=" | ":"
  value         = single-line-string | triple-quoted-block
  triple-quote  = '"""' newline ... '"""'
  tags          = comma-separated identifiers
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Iterator
from keys_keeper.models import validate_name, ValidationError, EntryType


@dataclass
class ParsedEntry:
    line: int
    name: str
    type: str
    value: str
    tags: list[str] = field(default_factory=list)
    error: str | None = None


class ParseError(RuntimeError):
    pass


_HEADER_RE = re.compile(
    r"""^
    (?P<name>[a-z0-9][a-z0-9._-]*[a-z0-9]) \s*
    (?: \( (?P<type>[a-z_]+) \) \s* )?
    (?P<sep>[=:])
    \s*
    (?P<value>.*?)
    \s*
    (?: \[ (?P<tags>[^\]]+) \] \s* )?
    $""",
    re.VERBOSE,
)


def parse_bulk(text: str) -> list[ParsedEntry]:
    out: list[ParsedEntry] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        # Detect multi-line: line ends with `= """` or `: """`.
        m_open = re.match(
            r"""^
            (?P<name>[a-z0-9A-Z][\w.-]*[a-z0-9A-Z]) \s*
            (?: \( (?P<type>[a-z_]+) \) \s* )?
            [=:]
            \s* \"\"\" \s* $""",
            raw, re.VERBOSE,
        )
        if m_open:
            name = m_open.group("name")
            type_ = m_open.group("type") or _guess_type(name, "")
            buf: list[str] = []
            j = i + 1
            closed = False
            tags: list[str] = []
            while j < len(lines):
                line_raw = lines[j]
                m_close = re.match(r'^\s*"""(?:\s*\[\s*([^\]]+)\s*\])?\s*$', line_raw)
                if m_close:
                    if m_close.group(1):
                        tags = [t.strip() for t in m_close.group(1).split(",") if t.strip()]
                    closed = True
                    break
                buf.append(line_raw)
                j += 1
            entry = ParsedEntry(
                line=i + 1,
                name=name,
                type=type_,
                value="\n".join(buf),
                tags=tags,
            )
            try:
                validate_name(name)
                EntryType(type_)
            except (ValidationError, ValueError) as ex:
                entry.error = str(ex)
            if not closed:
                entry.error = "unclosed multiline block (missing closing \"\"\")"
            out.append(entry)
            i = j + 1 if closed else len(lines)
            continue

        # Single-line entry
        m = _HEADER_RE.match(raw)
        if not m:
            out.append(ParsedEntry(line=i + 1, name="?", type="?", value="", error="unparseable line"))
            i += 1
            continue
        name = m.group("name")
        explicit_type = m.group("type")
        value = m.group("value")
        tags = [t.strip() for t in (m.group("tags") or "").split(",") if t.strip()]
        type_ = explicit_type or _guess_type(name, value)
        entry = ParsedEntry(line=i + 1, name=name, type=type_, value=value, tags=tags)
        try:
            validate_name(name)
            EntryType(type_)
        except (ValidationError, ValueError) as ex:
            entry.error = str(ex)
        out.append(entry)
        i += 1
    return out


def _guess_type(name: str, value: str) -> str:
    if value.startswith("ssh-") or "BEGIN OPENSSH" in value or "BEGIN RSA" in value:
        return "ssh_key"
    if "." in name and not value:
        return "domain"
    return "api_key"
