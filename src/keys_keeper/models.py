"""Domain models: Entry, EntryType, validation."""
from __future__ import annotations
import json
import re
import uuid
from dataclasses import dataclass
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
_FIELD_KEY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
_REF_ROLE_RE = re.compile(r"^[a-z_][a-z0-9_]{0,31}$")
_SSH_USER_RE = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,63}$")
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9:\[][A-Za-z0-9._:\[\]%-]{0,252}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_LEGACY_ENTRY_KEYS = {
    "id", "name", "type", "fields", "tags", "note", "refs",
    "created_at", "updated_at",
}
_PROJECT_ENTRY_KEYS = {"folder_id", "distribution", "provenance", "content_revision"}
_SECRET_KEYS = {"_secret", "_secret_passphrase"}
_MAX_ENTRY_RECORDS = 10_000
_MAX_TOMBSTONES = 20_000
_MAX_SECRET_CHARS = 1_048_576

_REQUIRED_FIELDS: dict[EntryType, set[str]] = {
    EntryType.API_KEY: set(),
    EntryType.SSH_KEY: {"public_key"},
    EntryType.SERVER: {"host", "user", "auth"},
    EntryType.DOMAIN: {"host"},
    EntryType.NOTE: {"secret_body"},
}


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


def validate_entry_id(id_: str) -> None:
    """Validate an externally supplied logical entry id.

    Internal sync credentials use the reserved ``kk:sync-*`` namespace and
    must never be reachable through an imported/synced entry record.
    """
    if not isinstance(id_, str):
        raise ValidationError("id must be a string")
    if id_.startswith("kk:sync-"):
        raise ValidationError("id uses the reserved kk:sync-* namespace")
    if len(id_) != 39 or not id_.startswith("kk:"):
        raise ValidationError("id must have the form kk:<uuid4>")
    raw = id_[3:]
    try:
        parsed = uuid.UUID(raw)
    except (ValueError, AttributeError) as ex:
        raise ValidationError("id must have the form kk:<uuid4>") from ex
    if parsed.version != 4 or str(parsed) != raw:
        raise ValidationError("id must contain a canonical lowercase UUIDv4")


def _validate_uuid4(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as ex:
        raise ValidationError(f"{label} must be a UUID string") from ex
    if parsed.version != 4 or str(parsed) != value:
        raise ValidationError(f"{label} must be a canonical lowercase UUIDv4")
    return value


def _validate_provenance(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValidationError("provenance must be an object")
    source = value.get("source")
    if source not in {"local", "legacy_migration", "project_submission"}:
        raise ValidationError("provenance source is invalid")
    allowed = {"source"}
    if source == "project_submission":
        allowed |= {"scope_id", "device_id", "grant_id", "request_id"}
        required = {"source", "scope_id", "device_id", "grant_id", "request_id"}
        if set(value) != required:
            raise ValidationError("project_submission provenance fields are invalid")
        for key in sorted(required - {"source"}):
            _validate_uuid4(value[key], f"provenance {key}")
    elif set(value) != allowed:
        raise ValidationError("provenance fields are invalid")
    return dict(value)


def _validate_text(
    value: Any,
    label: str,
    *,
    max_length: int,
    allow_linebreaks: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string")
    if len(value) > max_length:
        raise ValidationError(f"{label} exceeds {max_length} characters")
    allowed_controls = "\n\r\t" if allow_linebreaks else ""
    if any((ord(ch) < 32 and ch not in allowed_controls) or ord(ch) == 127 for ch in value):
        raise ValidationError(f"{label} contains control characters")
    return value


def _validate_timestamp(value: Any, label: str) -> str:
    value = _validate_text(value, label, max_length=20)
    if not _TIMESTAMP_RE.fullmatch(value):
        raise ValidationError(f"{label} must be an RFC3339 UTC timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as ex:
        raise ValidationError(f"{label} is not a valid timestamp") from ex
    return value


def validate_ssh_target(*, host: Any, user: Any, port: Any) -> tuple[str, str, int]:
    host = _validate_text(host, "server host", max_length=253)
    user = _validate_text(user, "server user", max_length=64)
    if not _SSH_HOST_RE.fullmatch(host) or host.startswith("-") or "@" in host:
        raise ValidationError("server host contains unsafe characters")
    if not _SSH_USER_RE.fullmatch(user) or user.startswith("-"):
        raise ValidationError("server user contains unsafe characters")
    if isinstance(port, bool):
        raise ValidationError("server port must be an integer from 1 to 65535")
    if isinstance(port, int):
        normalized_port = port
    elif isinstance(port, str) and port.isascii() and port.isdigit():
        normalized_port = int(port)
    else:
        raise ValidationError("server port must be an integer from 1 to 65535")
    if not 1 <= normalized_port <= 65535:
        raise ValidationError("server port must be an integer from 1 to 65535")
    return host, user, normalized_port


def _validate_fields(type_: EntryType, fields: Any) -> dict[str, Any]:
    if not isinstance(fields, dict):
        raise ValidationError("fields must be an object")
    if len(fields) > 64:
        raise ValidationError("fields contains too many keys")
    for key in fields:
        if not isinstance(key, str) or not _FIELD_KEY_RE.fullmatch(key):
            raise ValidationError(f"invalid field name: {key!r}")
    try:
        encoded = json.dumps(fields, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as ex:
        raise ValidationError("fields must contain JSON-compatible values") from ex
    if len(encoded) > 131_072:
        raise ValidationError("fields payload exceeds 128 KiB")

    missing = _REQUIRED_FIELDS[type_] - set(fields)
    if missing:
        raise ValidationError(
            f"{type_.value} requires fields: {sorted(missing)} "
            f"(have: {sorted(fields)})"
        )
    if type_ is EntryType.SERVER:
        validate_ssh_target(
            host=fields["host"],
            user=fields.get("user", "root"),
            port=fields.get("port", 22),
        )
        auth = fields.get("auth")
        if not isinstance(auth, str) or auth not in {"ssh_key", "password", "none"}:
            raise ValidationError("server auth must be ssh_key, password, or none")
    elif type_ is EntryType.DOMAIN:
        host = _validate_text(fields["host"], "domain host", max_length=253)
        if not _SSH_HOST_RE.fullmatch(host) or host.startswith("-") or "@" in host:
            raise ValidationError("domain host contains unsafe characters")
    elif type_ is EntryType.SSH_KEY:
        _validate_text(
            fields["public_key"],
            "public_key",
            max_length=16_384,
            allow_linebreaks=True,
        )
    return dict(fields)


def _validate_refs(refs: Any) -> list[dict[str, str]]:
    if not isinstance(refs, list) or len(refs) > 64:
        raise ValidationError("refs must be a list with at most 64 items")
    result: list[dict[str, str]] = []
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {"role", "name"}:
            raise ValidationError("each ref must contain exactly role and name")
        role = ref["role"]
        name = ref["name"]
        if not isinstance(role, str) or not _REF_ROLE_RE.fullmatch(role):
            raise ValidationError("ref role contains unsafe characters")
        validate_name(name)
        result.append({"role": role, "name": name})
    return result


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
    # These fields are absent from legacy records.  ``to_dict`` retains the
    # legacy byte shape while they have their safe defaults; schema-v3 store
    # validation requires their explicit persisted form.
    folder_id: str | None = None
    distribution: str = "local_only"
    provenance: dict[str, Any] | None = None
    content_revision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        record = {
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
        if self.folder_id is not None:
            record["folder_id"] = self.folder_id
        if self.distribution != "local_only":
            record["distribution"] = self.distribution
        if self.provenance is not None:
            record["provenance"] = self.provenance
        if self.content_revision is not None:
            record["content_revision"] = self.content_revision
        return record

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
            folder_id=d.get("folder_id"),
            distribution=d.get("distribution", "local_only"),
            provenance=dict(d["provenance"]) if d.get("provenance") is not None else None,
            content_revision=d.get("content_revision"),
        )

    @classmethod
    def from_untrusted_dict(
        cls,
        d: Any,
        *,
        allow_secret_fields: bool = False,
        allow_project_fields: bool = False,
    ) -> Entry:
        """Parse an import/sync record before it can mutate local state."""
        if not isinstance(d, dict):
            raise ValidationError("entry record must be an object")
        if any(not isinstance(key, str) for key in d):
            raise ValidationError("entry field names must be strings")
        allowed = _LEGACY_ENTRY_KEYS | (_SECRET_KEYS if allow_secret_fields else set())
        if allow_project_fields:
            allowed |= _PROJECT_ENTRY_KEYS
        unknown = set(d) - allowed
        if unknown:
            raise ValidationError(f"entry contains unknown fields: {sorted(unknown)}")
        required = {"id", "name", "type", "created_at", "updated_at"}
        missing = required - set(d)
        if missing:
            raise ValidationError(f"entry is missing fields: {sorted(missing)}")

        validate_entry_id(d["id"])
        validate_name(d["name"])
        try:
            type_ = EntryType(d["type"])
        except (TypeError, ValueError) as ex:
            raise ValidationError(f"invalid entry type: {d.get('type')!r}") from ex
        fields = _validate_fields(type_, d.get("fields", {}))

        tags = d.get("tags", [])
        if not isinstance(tags, list) or len(tags) > 64:
            raise ValidationError("tags must be a list with at most 64 items")
        normalized_tags = [
            _validate_text(tag, "tag", max_length=64) for tag in tags
        ]
        note = _validate_text(
            d.get("note", ""),
            "note",
            max_length=16_384,
            allow_linebreaks=True,
        )
        refs = _validate_refs(d.get("refs", []))
        created_at = _validate_timestamp(d["created_at"], "created_at")
        updated_at = _validate_timestamp(d["updated_at"], "updated_at")
        folder_id = d.get("folder_id")
        if folder_id is not None:
            _validate_uuid4(folder_id, "folder_id")
        distribution = d.get("distribution", "local_only")
        if distribution not in {"local_only", "project_allowed"}:
            raise ValidationError("distribution must be local_only or project_allowed")
        provenance = _validate_provenance(d.get("provenance"))
        content_revision = d.get("content_revision")
        if content_revision is not None:
            _validate_uuid4(content_revision, "content_revision")

        if allow_secret_fields:
            for key in _SECRET_KEYS:
                value = d.get(key)
                if value is not None:
                    _validate_text(
                        value,
                        key,
                        max_length=_MAX_SECRET_CHARS,
                        allow_linebreaks=True,
                    )

        return cls(
            id=d["id"],
            name=d["name"],
            type=type_,
            fields=fields,
            tags=normalized_tags,
            note=note,
            refs=refs,
            created_at=created_at,
            updated_at=updated_at,
            folder_id=folder_id,
            distribution=distribution,
            provenance=provenance,
            content_revision=content_revision,
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
        if not isinstance(type, EntryType):
            raise ValidationError("type must be an EntryType")
        f = _validate_fields(type, dict(fields or {}))
        normalized_tags = [
            _validate_text(tag, "tag", max_length=64) for tag in list(tags or [])
        ]
        normalized_note = _validate_text(
            note,
            "note",
            max_length=16_384,
            allow_linebreaks=True,
        )
        normalized_refs = _validate_refs(list(refs or []))
        now = now_iso()
        return cls(
            id=f"kk:{uuid.uuid4()}",
            name=name,
            type=type,
            fields=f,
            tags=normalized_tags,
            note=normalized_note,
            refs=normalized_refs,
            created_at=now,
            updated_at=now,
        )


def validate_tombstone(d: Any) -> dict[str, str]:
    if not isinstance(d, dict) or set(d) != {"id", "name", "deleted_at"}:
        raise ValidationError("tombstone must contain exactly id, name, deleted_at")
    validate_entry_id(d["id"])
    validate_name(d["name"])
    deleted_at = _validate_timestamp(d["deleted_at"], "deleted_at")
    return {"id": d["id"], "name": d["name"], "deleted_at": deleted_at}


def validate_snapshot_payload(
    payload: Any,
) -> tuple[list[Entry], list[dict[str, str]]]:
    """Validate a decrypted import/sync payload before any local mutation."""
    if not isinstance(payload, dict):
        raise ValidationError("snapshot payload must be an object")
    unknown = set(payload) - {"schema_version", "entries", "tombstones"}
    if unknown:
        raise ValidationError(f"snapshot contains unknown fields: {sorted(unknown)}")
    if payload.get("schema_version") not in {1, 2}:
        raise ValidationError("unsupported snapshot schema_version")
    records = payload.get("entries")
    tombstone_records = payload.get("tombstones", [])
    if not isinstance(records, list) or len(records) > _MAX_ENTRY_RECORDS:
        raise ValidationError(
            f"entries must be a list with at most {_MAX_ENTRY_RECORDS} items"
        )
    if not isinstance(tombstone_records, list) or len(tombstone_records) > _MAX_TOMBSTONES:
        raise ValidationError(
            f"tombstones must be a list with at most {_MAX_TOMBSTONES} items"
        )

    entries = [
        Entry.from_untrusted_dict(record, allow_secret_fields=True)
        for record in records
    ]
    ids = [entry.id for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValidationError("snapshot contains duplicate entry ids")
    tombstones = [validate_tombstone(record) for record in tombstone_records]
    return entries, tombstones
