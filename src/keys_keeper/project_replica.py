"""Read-only, generation-based local storage for one KK3 replica profile."""
from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from uuid import UUID

from keys_keeper import crypto
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, ValidationError
from keys_keeper.operation_journal import (
    JournalError,
    _atomic_write_bytes,
    _secure_read,
    profile_lock,
)
from keys_keeper.paths import Paths
from keys_keeper.refs import RefError, detect_cycles


_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PAYLOAD_FIELDS = {"schema_version", "scope_id", "source_revision", "entries"}
_ENTRY_FIELDS = {
    "id", "name", "type", "fields", "tags", "note", "refs",
    "created_at", "updated_at", "secret", "passphrase",
}
_CHECKPOINT_FIELDS = {
    "scope_id", "vault_id", "epoch", "policy_version", "policy_hash",
    "sequence", "parent_hash", "snapshot_hash",
}
_MAX_GENERATION_BYTES = 24 * 1024 * 1024


class ReplicaError(RuntimeError):
    """Safe replica failure without secret or untrusted metadata rendering."""


class NoReplicaGeneration(ReplicaError):
    pass


class ReplicaReadOnlyError(ReplicaError):
    pass


PasswordProvider = Callable[[], str | bytes | Sealed]


class ReplicaStore:
    """Install complete encrypted generations and expose read-only adapters."""

    def __init__(self, *, paths: Paths, password_provider: PasswordProvider):
        if not callable(password_provider):
            raise TypeError("password_provider must be callable")
        self.paths = paths
        self._password_provider = password_provider
        self._password_cache: Sealed | None = None

    def install(
        self,
        payload: dict,
        checkpoint: dict,
        *,
        verified_ancestor: dict | None = None,
    ) -> None:
        payload = validate_replica_payload(payload)
        checkpoint = validate_checkpoint(checkpoint)
        ancestor = (
            None if verified_ancestor is None else validate_checkpoint(verified_ancestor)
        )
        if payload["scope_id"] != checkpoint["scope_id"]:
            raise ReplicaError("replica payload and checkpoint scope mismatch")
        with profile_lock(self.paths):
            try:
                current_payload, current = self._load_unlocked()
            except NoReplicaGeneration:
                current_payload = None
                current = None
            if current is not None:
                if ancestor is None:
                    _validate_transition(current, checkpoint)
                else:
                    if ancestor != current:
                        raise ReplicaError(
                            "verified replica ancestor does not match active generation"
                        )
                    _validate_verified_descendant(current, checkpoint)
                if (
                    current["sequence"] == checkpoint["sequence"]
                    and current["snapshot_hash"] == checkpoint["snapshot_hash"]
                ):
                    if current_payload != payload:
                        raise ReplicaError("replica checkpoint payload does not match active generation")
                    return
            elif ancestor is not None:
                raise ReplicaError(
                    "verified replica ancestor requires an active generation"
                )
            generation = {
                "schema_version": 1,
                "payload": payload,
                "checkpoint": checkpoint,
            }
            plaintext = json.dumps(
                generation,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
            blob = crypto.encrypt_blob(plaintext, password=self._password())
            generation_path = self.paths.generations_dir / (
                checkpoint["snapshot_hash"] + ".enc"
            )
            _atomic_write_bytes(generation_path, blob)
            # The complete generation is durable before this commit pointer.
            _atomic_write_bytes(
                self.paths.active_generation,
                (checkpoint["snapshot_hash"] + "\n").encode("ascii"),
            )

    def load(self) -> tuple[dict, dict]:
        with profile_lock(self.paths):
            payload, checkpoint = self._load_unlocked()
        return copy.deepcopy(payload), copy.deepcopy(checkpoint)

    def metadata_store(self) -> "ReplicaMetadataView":
        return ReplicaMetadataView(self)

    def backend(self) -> "ReplicaBackend":
        return ReplicaBackend(self)

    def current_generation_path(self) -> Path:
        with profile_lock(self.paths):
            generation_id = self._read_pointer_unlocked()
        return self.paths.generations_dir / f"{generation_id}.enc"

    def _load_unlocked(self) -> tuple[dict, dict]:
        generation_id = self._read_pointer_unlocked()
        path = self.paths.generations_dir / f"{generation_id}.enc"
        try:
            blob = _secure_read(path)
            if len(blob) > _MAX_GENERATION_BYTES:
                raise ReplicaError("active replica generation exceeds size limit")
            plaintext = crypto.decrypt_blob(blob, password=self._password())
            if len(plaintext) > _MAX_GENERATION_BYTES:
                raise ReplicaError("active replica generation exceeds size limit")
            raw = json.loads(plaintext.decode("utf-8"))
        except (FileNotFoundError, JournalError, crypto.BadPassword, UnicodeError, ValueError) as ex:
            raise ReplicaError("cannot read active replica generation") from ex
        if not isinstance(raw, dict) or set(raw) != {
            "schema_version", "payload", "checkpoint"
        } or raw["schema_version"] != 1:
            raise ReplicaError("invalid replica generation schema")
        payload = validate_replica_payload(raw["payload"])
        checkpoint = validate_checkpoint(raw["checkpoint"])
        if (
            checkpoint["snapshot_hash"] != generation_id
            or payload["scope_id"] != checkpoint["scope_id"]
        ):
            raise ReplicaError("replica generation identity mismatch")
        return payload, checkpoint

    def _read_pointer_unlocked(self) -> str:
        try:
            raw = _secure_read(self.paths.active_generation)
        except FileNotFoundError as ex:
            raise NoReplicaGeneration("replica has no active generation") from ex
        except JournalError as ex:
            raise ReplicaError("cannot read replica generation pointer") from ex
        try:
            generation_id = raw.decode("ascii").rstrip("\n")
        except UnicodeDecodeError as ex:
            raise ReplicaError("invalid replica generation pointer") from ex
        if not _HASH.fullmatch(generation_id):
            raise ReplicaError("invalid replica generation pointer")
        return generation_id

    def _password(self) -> str:
        if self._password_cache is not None:
            return self._password_cache.unseal()
        try:
            supplied = self._password_provider()
        except Exception:
            raise ReplicaError("replica key provider failed") from None
        if isinstance(supplied, Sealed):
            value = supplied.unseal()
        elif isinstance(supplied, bytes):
            if not supplied:
                raise ReplicaError("replica key is empty")
            value = "key-bytes:" + supplied.hex()
        elif isinstance(supplied, str):
            value = supplied
        else:
            raise ReplicaError("replica key provider returned an unsupported type")
        if not value:
            raise ReplicaError("replica key is empty")
        self._password_cache = Sealed(value)
        return value

    def _entries_and_secrets(self) -> tuple[list[Entry], dict[str, str]]:
        payload, _ = self.load()
        entries: list[Entry] = []
        secrets: dict[str, str] = {}
        for raw in payload["entries"]:
            entries.append(Entry.from_untrusted_dict({
                key: raw[key] for key in (
                    "id", "name", "type", "fields", "tags", "note", "refs",
                    "created_at", "updated_at",
                )
            }))
            if raw["secret"] is not None:
                secrets[raw["id"]] = raw["secret"]
            if raw["passphrase"] is not None:
                secrets[raw["id"] + ":passphrase"] = raw["passphrase"]
        return entries, secrets


@dataclass(frozen=True)
class ReplicaMetadataView:
    _replica: ReplicaStore

    def list(self) -> list[Entry]:
        entries, _ = self._replica._entries_and_secrets()
        return entries

    def get_by_name(self, name: str) -> Entry | None:
        return next((entry for entry in self.list() if entry.name == name), None)

    def get_by_id(self, id_: str) -> Entry | None:
        return next((entry for entry in self.list() if entry.id == id_), None)

    def add(self, entry: Entry) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def update(self, entry: Entry) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def replace_by_name(self, entry: Entry) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def delete_by_name(self, name: str) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def replace_all(self, entries: list[Entry], tombstones: list[dict]) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def transaction(self) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")


class ReplicaBackend(KeychainBackend):
    def __init__(self, replica: ReplicaStore):
        self._replica = replica

    def get(self, account: str) -> Sealed:
        _, secrets = self._replica._entries_and_secrets()
        if account not in secrets:
            raise KeychainError(f"secret not found: {account}")
        return Sealed(secrets[account])

    def list_ids(self) -> list[str]:
        _, secrets = self._replica._entries_and_secrets()
        return list(secrets)

    def set(self, account: str, value: str) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")

    def delete(self, account: str) -> None:
        raise ReplicaReadOnlyError("replica generations are read-only")


def validate_replica_payload(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _PAYLOAD_FIELDS:
        raise ReplicaError("invalid replica payload fields")
    try:
        encoded_size = len(
            json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
        )
    except (TypeError, ValueError, UnicodeError):
        raise ReplicaError("invalid replica payload encoding") from None
    if encoded_size > 16 * 1024 * 1024:
        raise ReplicaError("replica payload exceeds size limit")
    if value["schema_version"] != 1 or isinstance(value["schema_version"], bool):
        raise ReplicaError("unsupported replica payload schema")
    _uuid4(value["scope_id"], "replica scope")
    _hash(value["source_revision"], "replica source revision")
    raw_entries = value["entries"]
    if not isinstance(raw_entries, list) or len(raw_entries) > 10_000:
        raise ReplicaError("invalid replica entry list")
    entries: list[Entry] = []
    normalized: list[dict] = []
    for raw in raw_entries:
        if not isinstance(raw, dict) or set(raw) != _ENTRY_FIELDS:
            raise ReplicaError("invalid replica entry fields")
        metadata = {
            key: raw[key] for key in (
                "id", "name", "type", "fields", "tags", "note", "refs",
                "created_at", "updated_at",
            )
        }
        try:
            entry = Entry.from_untrusted_dict(metadata)
        except ValidationError:
            raise ReplicaError("invalid replica entry metadata") from None
        for field in ("secret", "passphrase"):
            secret = raw[field]
            if secret is not None and (
                not isinstance(secret, str) or len(secret) > 1_048_576
            ):
                raise ReplicaError("invalid replica secret field")
        entries.append(entry)
        normalized.append(copy.deepcopy(raw))
    if len({entry.id for entry in entries}) != len(entries):
        raise ReplicaError("duplicate replica entry identity")
    if len({entry.name for entry in entries}) != len(entries):
        raise ReplicaError("duplicate replica entry name")
    names = {entry.name for entry in entries}
    if any(ref["name"] not in names for entry in entries for ref in entry.refs):
        raise ReplicaError("replica reference leaves the installed scope")
    try:
        detect_cycles(entries)
    except RefError:
        raise ReplicaError("replica reference graph is invalid") from None
    return {
        "schema_version": 1,
        "scope_id": value["scope_id"],
        "source_revision": value["source_revision"],
        "entries": normalized,
    }


def validate_checkpoint(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _CHECKPOINT_FIELDS:
        raise ReplicaError("invalid replica checkpoint fields")
    for field in ("scope_id", "vault_id"):
        _uuid4(value[field], "replica checkpoint identifier")
    for field in ("epoch", "policy_version", "sequence"):
        number = value[field]
        if type(number) is not int or number < 1:
            raise ReplicaError("invalid replica checkpoint counter")
    for field in ("policy_hash", "snapshot_hash"):
        _hash(value[field], "replica checkpoint hash")
    if value["parent_hash"] is not None:
        _hash(value["parent_hash"], "replica checkpoint parent")
    return copy.deepcopy(value)


def _validate_transition(old: dict, new: dict) -> None:
    if old["scope_id"] != new["scope_id"] or old["vault_id"] != new["vault_id"]:
        raise ReplicaError("replica checkpoint identity changed")
    if new["sequence"] < old["sequence"]:
        raise ReplicaError("replica checkpoint sequence regressed")
    if new["sequence"] == old["sequence"]:
        if new["snapshot_hash"] != old["snapshot_hash"]:
            raise ReplicaError("replica checkpoint sequence forked")
        return
    if new["parent_hash"] != old["snapshot_hash"]:
        raise ReplicaError("replica checkpoint does not extend active generation")
    if new["epoch"] < old["epoch"] or new["policy_version"] < old["policy_version"]:
        raise ReplicaError("replica checkpoint policy regressed")


def _validate_verified_descendant(old: dict, new: dict) -> None:
    """Accept a skipped checkpoint only after the caller verified full ancestry."""
    if old["scope_id"] != new["scope_id"] or old["vault_id"] != new["vault_id"]:
        raise ReplicaError("replica checkpoint identity changed")
    if new["sequence"] <= old["sequence"]:
        _validate_transition(old, new)
        return
    if new["epoch"] < old["epoch"] or new["policy_version"] < old["policy_version"]:
        raise ReplicaError("replica checkpoint policy regressed")


def _uuid4(value: object, label: str) -> None:
    if not isinstance(value, str):
        raise ReplicaError(f"{label} is invalid")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise ReplicaError(f"{label} is invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise ReplicaError(f"{label} is invalid")


def _hash(value: object, label: str) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ReplicaError(f"{label} is invalid")
