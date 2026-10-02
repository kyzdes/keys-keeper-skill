"""Small shared request contract for the authenticated local JSON API."""
from __future__ import annotations

import json


MAX_JSON_BODY_BYTES = 8 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_JSON_NODES = 100_000


class InvalidRequest(ValueError):
    def __init__(self):
        super().__init__("Invalid request")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidRequest()
        result[key] = value
    return result


def _invalid_constant(_value):
    raise InvalidRequest()


def _check_structure(value):
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > _MAX_JSON_DEPTH or visited > _MAX_JSON_NODES:
            raise InvalidRequest()
        children = item.values() if isinstance(item, dict) else item if isinstance(item, list) else ()
        if len(children) + len(pending) + visited > _MAX_JSON_NODES:
            raise InvalidRequest()
        pending.extend((child, depth + 1) for child in children)


def request_object(body: bytes | None, fields: dict[str, type | tuple[type, ...]],
                   *, required: set[str] | frozenset[str] = frozenset()) -> dict:
    """Reject ambiguous JSON before any mutation or credential access.

    ``fields`` contains the entire allowed top-level shape. Types are exact:
    JSON booleans cannot masquerade as integer settings. Domain validators own
    semantic/nested entry rules; duplicate keys are rejected at every depth.
    """
    if body is not None and (not isinstance(body, bytes) or len(body) > MAX_JSON_BODY_BYTES):
        raise InvalidRequest()
    try:
        value = json.loads(body or b"{}", object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise InvalidRequest() from None
    if not isinstance(value, dict) or set(value) - set(fields) or not required <= set(value):
        raise InvalidRequest()
    _check_structure(value)
    for key, item in value.items():
        expected = fields[key]
        allowed = expected if isinstance(expected, tuple) else (expected,)
        if type(item) not in allowed:
            raise InvalidRequest()
    return value
