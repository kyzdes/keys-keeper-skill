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

    for e in entries:
        if color[e.name] != WHITE:
            continue
        color[e.name] = GRAY
        path = [e.name]
        stack = [(e.name, iter(by_name[e.name].refs))]
        while stack:
            name, refs = stack[-1]
            try:
                target = next(refs).get("name")
            except StopIteration:
                color[name] = BLACK
                stack.pop()
                path.pop()
                continue
            if target == name:
                raise RefCycleError(f"self-ref on {name}")
            if color.get(target) == GRAY:
                # Construct the diagnostic only on failure; valid deep graphs
                # require neither recursive calls nor repeated path copies.
                raise RefCycleError(f"cycle: {' -> '.join(path + [target])}")
            if color.get(target) == WHITE:
                color[target] = GRAY
                path.append(target)
                stack.append((target, iter(by_name[target].refs)))


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
