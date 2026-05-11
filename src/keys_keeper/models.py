"""Domain models: Entry, EntryType, validation."""
from __future__ import annotations
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ValidationError(ValueError):
    """Raised for invalid entry data."""


class EntryType(str, Enum):
    API_KEY = "api_key"
    SSH_KEY = "ssh_key"
    SERVER = "server"
    DOMAIN = "domain"
    NOTE = "note"


_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*[a-z0-9]$")


def validate_name(name: str) -> None:
    if not isinstance(name, str):
        raise ValidationError("name must be a string")
    if not (2 <= len(name) <= 64):
        raise ValidationError(f"name length must be 2-64 (got {len(name)})")
    if not _NAME_RE.fullmatch(name):
        raise ValidationError(
            "name contains invalid characters; allowed: lowercase a-z, 0-9, dot, dash, underscore; "
            "must start and end with alphanumeric"
        )


_REQUIRED_FIELDS: dict[EntryType, set[str]] = {
    EntryType.API_KEY: set(),
    EntryType.SSH_KEY: {"public_key"},
    EntryType.SERVER: {"host", "user", "auth"},
    EntryType.DOMAIN: {"host"},
    EntryType.NOTE: {"secret_body"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Entry:
    id: str
    name: str
    type: EntryType
    fields: dict[str, Any]
    tags: list[str]
    note: str
    refs: list[dict[str, str]]
    created_at: str
    updated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type.value,
            "fields": self.fields,
            "tags": self.tags,
            "note": self.note,
            "refs": self.refs,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Entry:
        return cls(
            id=d["id"],
            name=d["name"],
            type=EntryType(d["type"]),
            fields=dict(d.get("fields", {})),
            tags=list(d.get("tags", [])),
            note=d.get("note", ""),
            refs=list(d.get("refs", [])),
            created_at=d["created_at"],
            updated_at=d["updated_at"],
        )

    @classmethod
    def new(
        cls,
        *,
        name: str,
        type: EntryType,
        fields: dict[str, Any] | None = None,
        tags: list[str] | None = None,
        note: str = "",
        refs: list[dict[str, str]] | None = None,
    ) -> Entry:
        validate_name(name)
        f = dict(fields or {})
        missing = _REQUIRED_FIELDS[type] - set(f)
        if missing:
            raise ValidationError(
                f"{type.value} requires fields: {sorted(missing)} (have: {sorted(f)})"
            )
        now = now_iso()
        return cls(
            id=f"kk:{uuid.uuid4()}",
            name=name,
            type=type,
            fields=f,
            tags=list(tags or []),
            note=note,
            refs=list(refs or []),
            created_at=now,
            updated_at=now,
        )
