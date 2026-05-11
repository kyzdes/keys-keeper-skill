"""Ref resolution + cycle detection for entry → entry links."""
from __future__ import annotations
from collections import defaultdict
from keys_keeper.models import Entry


class RefError(RuntimeError):
    pass


class RefCycleError(RefError):
    pass


class RefMissingError(RefError):
    pass


def detect_cycles(entries: list[Entry]) -> None:
    """DFS-based cycle detection over the ref graph. Raises RefCycleError on any cycle."""
    by_name = {e.name: e for e in entries}
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {e.name: WHITE for e in entries}

    def dfs(name: str, path: list[str]) -> None:
        if name not in by_name:
            return
        color[name] = GRAY
        for ref in by_name[name].refs:
            target = ref.get("name")
            if target == name:
                raise RefCycleError(f"self-ref on {name}")
            if target in color and color[target] == GRAY:
                raise RefCycleError(f"cycle: {' -> '.join(path + [name, target])}")
            if target in color and color[target] == WHITE:
                dfs(target, path + [name])
        color[name] = BLACK

    for e in entries:
        if color[e.name] == WHITE:
            dfs(e.name, [])


def reverse_refs(entries: list[Entry]) -> dict[str, list[str]]:
    """Build {target_name: [dependent_name, ...]} from the ref graph."""
    rev: dict[str, list[str]] = defaultdict(list)
    for e in entries:
        for ref in e.refs:
            target = ref.get("name")
            if target:
                rev[target].append(e.name)
    return dict(rev)


def resolve_chain(entries: list[Entry], from_name: str, role: str) -> Entry:
    """Given entry name + ref role, return the linked target Entry."""
    by_name = {e.name: e for e in entries}
    src = by_name.get(from_name)
    if src is None:
        raise RefMissingError(f"no source entry {from_name!r}")
    for ref in src.refs:
        if ref.get("role") == role:
            target = by_name.get(ref.get("name"))
            if target is None:
                raise RefMissingError(
                    f"{from_name} → {role} → {ref.get('name')!r} (target missing)"
                )
            return target
    raise RefMissingError(f"{from_name} has no ref with role {role!r}")
