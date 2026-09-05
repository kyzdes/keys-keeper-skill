"""Strict, local-only models for the project catalog (metadata schema v3).

The catalog intentionally contains no secret values and no permission grants.
Folders are organizational only; a secret is included in a scope solely by an
explicit binding.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from keys_keeper.models import ValidationError


class CatalogValidationError(ValidationError):
    """Raised when project catalog metadata is malformed or inconsistent."""


_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}[a-z0-9]$|^[a-z0-9]$")
_ENV_RE = _SLUG_RE
_MAX_FOLDERS = 10_000
_MAX_PROJECTS = 10_000
_MAX_SCOPES = 20_000
_MAX_BINDINGS = 100_000


def new_catalog_id() -> str:
    return str(uuid.uuid4())


def _id(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise CatalogValidationError(f"{label} must be a UUID string")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as ex:
        raise CatalogValidationError(f"{label} must be a UUID string") from ex
    if parsed.version != 4 or str(parsed) != value:
        raise CatalogValidationError(f"{label} must be a canonical lowercase UUIDv4")
    return value


def _text(value: Any, label: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > max_length:
        raise CatalogValidationError(f"{label} must be a non-empty string up to {max_length} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise CatalogValidationError(f"{label} contains control characters")
    return value


def _slug(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SLUG_RE.fullmatch(value):
        raise CatalogValidationError(f"{label} must be a lowercase slug")
    return value


def _json_object(value: Any, label: str, *, max_bytes: int = 16_384) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CatalogValidationError(f"{label} must be an object")
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as ex:
        raise CatalogValidationError(f"{label} must be JSON-compatible") from ex
    if len(encoded.encode("utf-8")) > max_bytes:
        raise CatalogValidationError(f"{label} exceeds {max_bytes} bytes")
    return dict(value)


@dataclass(frozen=True)
class Folder:
    id: str
    name: str
    parent_id: str | None = None
    position: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "parent_id": self.parent_id, "position": self.position}

    @classmethod
    def from_dict(cls, value: Any) -> Folder:
        if not isinstance(value, dict) or set(value) != {"id", "name", "parent_id", "position"}:
            raise CatalogValidationError("folder must contain exactly id, name, parent_id, position")
        parent_id = value["parent_id"]
        if parent_id is not None:
            _id(parent_id, "folder parent_id")
        if isinstance(value["position"], bool) or not isinstance(value["position"], int) or value["position"] < 0:
            raise CatalogValidationError("folder position must be a non-negative integer")
        return cls(id=_id(value["id"], "folder id"), name=_text(value["name"], "folder name"), parent_id=parent_id, position=value["position"])


@dataclass(frozen=True)
class Project:
    id: str
    slug: str
    name: str
    state: str = "active"

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "slug": self.slug, "name": self.name, "state": self.state}

    @classmethod
    def from_dict(cls, value: Any) -> Project:
        if not isinstance(value, dict) or set(value) != {"id", "slug", "name", "state"}:
            raise CatalogValidationError("project must contain exactly id, slug, name, state")
        if value["state"] not in {"active", "archived"}:
            raise CatalogValidationError("project state must be active or archived")
        return cls(id=_id(value["id"], "project id"), slug=_slug(value["slug"], "project slug"), name=_text(value["name"], "project name"), state=value["state"])


@dataclass(frozen=True)
class Scope:
    id: str
    project_id: str
    environment: str
    vault_id: str
    epoch: int = 1
    policy_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "project_id": self.project_id, "environment": self.environment, "vault_id": self.vault_id, "epoch": self.epoch, "policy_version": self.policy_version}

    @classmethod
    def from_dict(cls, value: Any) -> Scope:
        if not isinstance(value, dict) or set(value) != {"id", "project_id", "environment", "vault_id", "epoch", "policy_version"}:
            raise CatalogValidationError("scope must contain exactly id, project_id, environment, vault_id, epoch, policy_version")
        for key in ("epoch", "policy_version"):
            if isinstance(value[key], bool) or not isinstance(value[key], int) or value[key] < 1:
                raise CatalogValidationError(f"scope {key} must be a positive integer")
        return cls(id=_id(value["id"], "scope id"), project_id=_id(value["project_id"], "scope project_id"), environment=_slug(value["environment"], "scope environment"), vault_id=_id(value["vault_id"], "scope vault_id"), epoch=value["epoch"], policy_version=value["policy_version"])


def _export_config(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"fields", "note", "refs", "tags"}:
        raise CatalogValidationError("binding export must contain exactly fields, note, refs, tags")
    fields = value["fields"]
    if not isinstance(fields, list) or len(fields) > 64 or any(not isinstance(key, str) or not key for key in fields):
        raise CatalogValidationError("binding export fields must be a list of field names")
    if len(fields) != len(set(fields)):
        raise CatalogValidationError("binding export fields must not contain duplicates")
    if any(not isinstance(value[key], bool) for key in ("note", "refs", "tags")):
        raise CatalogValidationError("binding export note, refs, and tags must be booleans")
    return {"fields": list(fields), "note": value["note"], "refs": value["refs"], "tags": value["tags"]}


@dataclass(frozen=True)
class ScopeEntry:
    scope_id: str
    entry_id: str
    local_name: str
    export: dict[str, Any]
    approval_revision: str

    def to_dict(self) -> dict[str, Any]:
        return {"scope_id": self.scope_id, "entry_id": self.entry_id, "local_name": self.local_name, "export": self.export, "approval_revision": self.approval_revision}

    @classmethod
    def from_dict(cls, value: Any) -> ScopeEntry:
        if not isinstance(value, dict) or set(value) != {"scope_id", "entry_id", "local_name", "export", "approval_revision"}:
            raise CatalogValidationError("binding must contain exactly scope_id, entry_id, local_name, export, approval_revision")
        revision = value["approval_revision"]
        if not isinstance(revision, str) or len(revision) != 64 or any(ch not in "0123456789abcdef" for ch in revision):
            raise CatalogValidationError("binding approval_revision must be a SHA-256 hex digest")
        return cls(scope_id=_id(value["scope_id"], "binding scope_id"), entry_id=_text(value["entry_id"], "binding entry_id", max_length=64), local_name=_text(value["local_name"], "binding local_name", max_length=64), export=_export_config(value["export"]), approval_revision=revision)


def default_export_config() -> dict[str, Any]:
    return {"fields": [], "note": False, "refs": False, "tags": False}


@dataclass(frozen=True)
class CatalogState:
    folders: list[Folder] = field(default_factory=list)
    projects: list[Project] = field(default_factory=list)
    scopes: list[Scope] = field(default_factory=list)
    bindings: list[ScopeEntry] = field(default_factory=list)
    dedup: list[dict[str, Any]] = field(default_factory=list)
    publication_intents: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"folders": [item.to_dict() for item in self.folders], "projects": [item.to_dict() for item in self.projects], "scopes": [item.to_dict() for item in self.scopes], "bindings": [item.to_dict() for item in self.bindings], "dedup": [dict(item) for item in self.dedup], "publication_intents": [dict(item) for item in self.publication_intents]}

    @classmethod
    def from_dict(cls, value: Any, *, entry_ids: set[str]) -> CatalogState:
        required = {"folders", "projects", "scopes", "bindings", "dedup", "publication_intents"}
        if not isinstance(value, dict) or set(value) != required:
            raise CatalogValidationError("catalog must contain exactly folders, projects, scopes, bindings, dedup, publication_intents")
        collections = (("folders", _MAX_FOLDERS), ("projects", _MAX_PROJECTS), ("scopes", _MAX_SCOPES), ("bindings", _MAX_BINDINGS))
        for key, limit in collections:
            if not isinstance(value[key], list) or len(value[key]) > limit:
                raise CatalogValidationError(f"catalog {key} must be a list with at most {limit} items")
        if not isinstance(value["dedup"], list) or not isinstance(value["publication_intents"], list):
            raise CatalogValidationError("catalog ledgers must be lists")
        folders = [Folder.from_dict(item) for item in value["folders"]]
        projects = [Project.from_dict(item) for item in value["projects"]]
        scopes = [Scope.from_dict(item) for item in value["scopes"]]
        bindings = [ScopeEntry.from_dict(item) for item in value["bindings"]]
        _validate_unique((item.id for item in folders), "folder id")
        _validate_unique((item.id for item in projects), "project id")
        _validate_unique((item.id for item in scopes), "scope id")
        _validate_unique(((item.scope_id, item.entry_id) for item in bindings), "scope binding")
        folder_ids = {item.id for item in folders}
        for item in folders:
            if item.parent_id is not None and item.parent_id not in folder_ids:
                raise CatalogValidationError("folder parent_id refers to a missing folder")
        _validate_folder_cycles(folders)
        project_ids = {item.id for item in projects}
        for item in scopes:
            if item.project_id not in project_ids:
                raise CatalogValidationError("scope project_id refers to a missing project")
        _validate_unique(((item.project_id, item.environment) for item in scopes), "project environment")
        scope_ids = {item.id for item in scopes}
        for item in bindings:
            if item.scope_id not in scope_ids:
                raise CatalogValidationError("binding scope_id refers to a missing scope")
            if item.entry_id not in entry_ids:
                raise CatalogValidationError("binding entry_id refers to a missing entry")
        dedup = [_json_object(item, "catalog dedup") for item in value["dedup"]]
        intents = [_json_object(item, "catalog publication_intents") for item in value["publication_intents"]]
        return cls(folders=folders, projects=projects, scopes=scopes, bindings=bindings, dedup=dedup, publication_intents=intents)


def _validate_unique(values: Any, label: str) -> None:
    values = list(values)
    if len(values) != len(set(values)):
        raise CatalogValidationError(f"duplicate {label}")


def _validate_folder_cycles(folders: list[Folder]) -> None:
    parents = {item.id: item.parent_id for item in folders}
    for folder_id in parents:
        seen: set[str] = set()
        current: str | None = folder_id
        while current is not None:
            if current in seen:
                raise CatalogValidationError("folder hierarchy contains a cycle")
            seen.add(current)
            current = parents[current]
