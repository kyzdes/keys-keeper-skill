"""Explicit local vault profiles.

Profile selection is an authorization input.  It is never inferred from the
working directory, hostname, a mutable slug, or a failed lookup.  The legacy
master profile deliberately retains its original paths and backend service so
introducing replicas does not move Keychain records or alter their ACLs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping
from uuid import UUID

from keys_keeper.paths import Paths, _canonical_uuid


MASTER_PROFILE_ID = UUID(int=0)
MASTER_BACKEND_SERVICE = "keys-keeper"


class ProfileKind(str, Enum):
    MASTER = "master"
    REPLICA = "replica"


@dataclass(frozen=True)
class ProfileContext:
    """Validated filesystem and backend namespace for exactly one vault."""

    kind: ProfileKind
    profile_id: UUID
    paths: Paths
    backend_service: str
    scope_id: UUID | None
    policy: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProfileKind):
            raise ValueError("profile kind must be explicit")
        if not isinstance(self.profile_id, UUID):
            raise ValueError("profile_id must be a UUID")
        if not isinstance(self.paths, Paths):
            raise ValueError("profile paths must be explicit")
        if self.kind is ProfileKind.MASTER:
            if self.profile_id != MASTER_PROFILE_ID or self.scope_id is not None:
                raise ValueError("master profile identity is fixed and has no scope")
            if self.backend_service != MASTER_BACKEND_SERVICE:
                raise ValueError("master backend service must preserve the legacy namespace")
        else:
            if self.profile_id == MASTER_PROFILE_ID or not isinstance(self.scope_id, UUID):
                raise ValueError("replica profile requires distinct profile and scope UUIDs")
            if (
                self.paths.root.name != str(self.profile_id)
                or self.paths.root.parent.name != "profiles"
            ):
                raise ValueError("replica paths must use its UUID profile directory")
            expected_service = f"keys-keeper:profile:{self.profile_id}"
            if self.backend_service != expected_service:
                raise ValueError("replica backend service must use its UUID namespace")
        if not isinstance(self.policy, MappingProxyType):
            if not isinstance(self.policy, Mapping):
                raise ValueError("profile policy must be a mapping")
            object.__setattr__(self, "policy", MappingProxyType(dict(self.policy)))

    @classmethod
    def master(
        cls,
        *,
        paths: Paths | None = None,
        policy: Mapping[str, object] | None = None,
    ) -> "ProfileContext":
        return cls(
            kind=ProfileKind.MASTER,
            profile_id=MASTER_PROFILE_ID,
            paths=paths or Paths(),
            backend_service=MASTER_BACKEND_SERVICE,
            scope_id=None,
            policy=MappingProxyType(dict(policy or {})),
        )

    @classmethod
    def replica(
        cls,
        profile_id: UUID | str,
        *,
        scope_id: UUID | str,
        base_paths: Paths | None = None,
        policy: Mapping[str, object] | None = None,
    ) -> "ProfileContext":
        parsed_profile = _canonical_uuid(profile_id, field_name="profile_id")
        parsed_scope = _canonical_uuid(scope_id, field_name="scope_id")
        if parsed_profile == MASTER_PROFILE_ID:
            raise ValueError("replica profile_id cannot use the master profile UUID")
        base = base_paths or Paths()
        return cls(
            kind=ProfileKind.REPLICA,
            profile_id=parsed_profile,
            paths=base.for_profile(parsed_profile),
            backend_service=f"keys-keeper:profile:{parsed_profile}",
            scope_id=parsed_scope,
            policy=MappingProxyType(dict(policy or {})),
        )

    @property
    def is_master(self) -> bool:
        return self.kind is ProfileKind.MASTER

    @property
    def is_replica(self) -> bool:
        return self.kind is ProfileKind.REPLICA
