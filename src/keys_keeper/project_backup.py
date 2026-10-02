"""Encrypted schema-3 backup and recovery-only restore for project profiles."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from keys_keeper import crypto
from keys_keeper.backend import KeychainBackend, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.models import Entry, ValidationError, entry_requires_secret, validate_tombstone
from keys_keeper.operation_journal import (
    JournalError,
    OperationJournal,
    _fsync_parent,
    profile_lock,
)
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper.private_files import PrivateFileCommitError, PrivateFileError, atomic_write_bytes, secure_read
from keys_keeper.project_models import CatalogState, CatalogValidationError
from keys_keeper.project_replica import ReplicaStore, validate_checkpoint, validate_replica_payload
from keys_keeper.store import CATALOG_SCHEMA_VERSION, MetadataSnapshot, MetadataStore, MetadataTransaction


BACKUP_SCHEMA_VERSION = 3
_MAX_BACKUP_BYTES = 128 * 1024 * 1024
_MAX_STATE_BYTES = 16 * 1024 * 1024
_JOURNAL_FILE = re.compile(r"(?:[0-9a-f-]{36}\.enc|pending-index\.json|terminal-receipts\.kk1)\Z")
Password = str | bytes | Sealed
_RECOVERY_LOCKS_GUARD = threading.Lock()
_RECOVERY_LOCKS: dict[str, "_RecoveryRootLock"] = {}


class ProjectBackupError(RuntimeError):
    pass


class ProjectBackupCommitError(ProjectBackupError):
    """The file was published, but directory durability remains uncertain."""
    committed = True


class _RecoveryRootLock:
    """One reentrant in-process owner around the cross-process root lock."""

    def __init__(self, root: Path):
        self.root = root
        self.thread_lock = threading.RLock()
        self.depth = 0

    @contextmanager
    def locked(self):
        with self.thread_lock:
            if self.depth:
                self.depth += 1
                try:
                    yield
                finally:
                    self.depth -= 1
                return
            lock_root = self.root / "recovery-restore-lock"
            if lock_root.is_symlink() or (
                lock_root.exists() and not lock_root.is_dir()
            ):
                raise JournalError("recovery restore lock path is unsafe")
            with profile_lock(Paths(lock_root)):
                self.depth = 1
                try:
                    yield
                finally:
                    self.depth = 0


@contextmanager
def recovery_root_lock(root: Path):
    """Serialize restore and takeover mutations for one recovery root."""
    root = Path(root).absolute()
    key = str(root)
    with _RECOVERY_LOCKS_GUARD:
        lock = _RECOVERY_LOCKS.setdefault(key, _RecoveryRootLock(root))
    with lock.locked():
        yield


@dataclass(frozen=True)
class BackupManifest:
    kind: str
    schema_version: int
    content_hash: str
    metadata_revision: str | None
    entry_count: int
    created_at: str


@dataclass(frozen=True)
class RecoveryProfile:
    paths: Paths
    kind: str
    manifest: BackupManifest

    def metadata_store(self) -> MetadataStore:
        if self.kind != "master":
            raise ProjectBackupError("replica recovery has no mutable metadata store")
        return MetadataStore(self.paths)

    def open_master_backend(self, password: Password) -> EncryptedFileBackend:
        if self.kind != "master":
            raise ProjectBackupError("replica recovery has no master backend")
        return _file_backend(self.paths, password)

    def replica_store(self, password: Password) -> ReplicaStore:
        if self.kind != "replica":
            raise ProjectBackupError("master recovery has no replica generation")
        return ReplicaStore(paths=self.paths, password_provider=lambda: password)

    def project_state(self, password: Password) -> dict:
        path = self.paths.root / "recovery-project-state.enc"
        try:
            plaintext = crypto.decrypt_blob(_secure_read(path), password=_password(password))
            value = json.loads(plaintext.decode("utf-8"))
        except (FileNotFoundError, crypto.BadPassword, UnicodeError, ValueError) as ex:
            raise ProjectBackupError("cannot read recovery project state") from ex
        return _validate_project_state(value)


def create_master_backup(
    store: MetadataStore,
    backend: KeychainBackend,
    *,
    journal: OperationJournal,
    destination: Path,
    password: Password,
    project_state: Mapping[str, object] | None = None,
    service_accounts: tuple[str, ...] | None = None,
) -> BackupManifest:
    """Capture schema 2 or 3 while the profile mutation lock is held."""
    if store.paths.root != journal.paths.root:
        raise ValueError("master store and backup journal must share one profile root")
    _require_new_destination(destination)
    from keys_keeper.master_journal import MASTER_MUTATION_KIND, MASTER_UNLOCK_ACCOUNT

    with journal.locked():
        if journal.pending_refs(kind=MASTER_MUTATION_KIND):
            raise ProjectBackupError("master recovery is required before backup")
        with store.read_transaction() as tx:
            before = MetadataSnapshot(tx.list(), tx.tombstones(), tx.revision())
            records = tx.records()
            metadata_schema = tx.schema_version
            catalog = tx.catalog_state() if metadata_schema >= CATALOG_SCHEMA_VERSION else None
        journal_files = _capture_journal_files(journal.paths)
        service_accounts = service_accounts or ()
        # Schema 2 now shares durable mutations. Its encrypted journal/receipts
        # need the authority key on restore just as schema 3 does. An explicit
        # service-account selection cannot silently omit this prerequisite.
        if (metadata_schema == CATALOG_SCHEMA_VERSION or journal_files
                or MASTER_UNLOCK_ACCOUNT in backend.list_ids()):
            service_accounts = tuple(dict.fromkeys((*service_accounts, MASTER_UNLOCK_ACCOUNT)))
        entry_secrets = _capture_entry_secrets(backend, before.entries)
        service_secrets = _capture_service_secrets(backend, service_accounts)
        after = store.snapshot()
        if after.revision != before.revision:
            raise ProjectBackupError("master metadata changed during backup")
        payload = {
            "kind": "master",
            "metadata": {
                "schema_version": metadata_schema,
                "revision": before.revision,
                "entries": records,
                "tombstones": copy.deepcopy(before.tombstones),
                "catalog": copy.deepcopy(catalog),
            },
            "entry_secrets": entry_secrets,
            "service_secrets": service_secrets,
            "project_state": _validate_project_state(project_state or {}),
            "journal_files": journal_files,
        }
        return _write_bundle(destination, password, payload, before.revision)


def create_replica_backup(
    replica: ReplicaStore,
    *,
    destination: Path,
    password: Password,
    project_state: Mapping[str, object] | None = None,
    project_state_provider: Callable[[], Mapping[str, object]] | None = None,
) -> BackupManifest:
    """Capture one complete active generation and its durable local outbox state.

    The generation is read both before and after the state snapshot.  A change
    during capture aborts instead of pairing a checkpoint with another state.
    """
    _require_new_destination(destination)
    first_payload, first_checkpoint = replica.load()
    if project_state_provider is not None:
        if project_state is not None:
            raise ValueError("project_state and project_state_provider are mutually exclusive")
        project_state = project_state_provider()
    state = _validate_project_state(project_state or {})
    second_payload, second_checkpoint = replica.load()
    if first_checkpoint != second_checkpoint or first_payload != second_payload:
        raise ProjectBackupError("replica generation changed during backup")
    payload = {
        "kind": "replica",
        "generation": {
            "payload": validate_replica_payload(first_payload),
            "checkpoint": validate_checkpoint(first_checkpoint),
        },
        "project_state": state,
    }
    return _write_bundle(
        destination,
        password,
        payload,
        first_payload["source_revision"],
    )


def inspect_backup(source: Path, *, password: Password) -> BackupManifest:
    bundle = _read_bundle(source, password)
    return _manifest(bundle["manifest"])


def restore_backup(
    source: Path,
    *,
    password: Password,
    recovery_root: Path,
    recovery_password: Password,
    resume: bool = False,
) -> RecoveryProfile:
    """Restore to an isolated recovery-only root.

    ``resume`` is deliberately narrow: it accepts only a root already marked
    for the exact same authenticated bundle.  This makes re-running a restore
    after process death idempotent without allowing the option to overwrite an
    unrelated profile.
    """
    root = Path(recovery_root)
    bundle = _read_bundle(source, password)
    manifest = _manifest(bundle["manifest"])
    payload = bundle["payload"]
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ProjectBackupError("recovery root must be a real directory")
    ensure_private_dir(root)
    try:
        with recovery_root_lock(root):
            paths = Paths(root)
            populated = any(
                child.name != "recovery-restore-lock" for child in root.iterdir()
            )
            if populated:
                if not resume:
                    raise ProjectBackupError("recovery root must be new and empty")
                for takeover_path in (
                    root / "recovery-takeover",
                    root / "recovery-activation.json",
                ):
                    if takeover_path.exists() or takeover_path.is_symlink():
                        raise ProjectBackupError(
                            "recovery takeover already started; restore cannot resume"
                        )
                _require_matching_recovery_marker(root, manifest)
            elif resume:
                raise ProjectBackupError(
                    "resume requires a matching partial recovery root"
                )
            # Publish the fail-closed marker before restoring any mutable
            # state.  Merely pointing runtime at a partial root cannot activate
            # it, and the restore lock prevents two authenticated bundles from
            # interleaving their files under one marker.
            marker = {
                "schema_version": 1,
                "mode": "recovery_only",
                "kind": manifest.kind,
                "backup_hash": manifest.content_hash,
                "status": "restore_in_progress",
                "activation": "requires_trusted_history_verification",
            }
            _atomic_write(paths.root / "recovery-only", _canonical_bytes(marker))
            if manifest.kind == "master":
                _restore_master(paths, payload, recovery_password)
            elif manifest.kind == "replica":
                _restore_replica(paths, payload, recovery_password)
            else:  # validated by _read_bundle; defensive for type narrowing
                raise ProjectBackupError("unsupported project backup kind")
            state = _validate_project_state(payload["project_state"])
            _atomic_write(
                paths.root / "recovery-project-state.enc",
                crypto.encrypt_blob(
                    _canonical_bytes(state), password=_password(recovery_password)
                ),
            )
            marker["status"] = "restored"
            _atomic_write(paths.root / "recovery-only", _canonical_bytes(marker))
    except JournalError as ex:
        raise ProjectBackupError("cannot lock recovery restore") from ex
    return RecoveryProfile(paths=paths, kind=manifest.kind, manifest=manifest)


def _require_matching_recovery_marker(root: Path, manifest: BackupManifest) -> dict:
    try:
        marker = json.loads(_secure_read(root / "recovery-only", max_bytes=4096).decode("utf-8"))
    except (FileNotFoundError, UnicodeError, ValueError) as ex:
        raise ProjectBackupError("resume requires a valid recovery-only marker") from ex
    expected = {
        "schema_version", "mode", "kind", "backup_hash", "status", "activation"
    }
    if (
        not isinstance(marker, dict)
        or set(marker) != expected
        or marker["schema_version"] != 1
        or marker["mode"] != "recovery_only"
        or marker["kind"] != manifest.kind
        or marker["backup_hash"] != manifest.content_hash
        or marker["status"] not in {"restore_in_progress", "restored"}
        or marker["activation"] != "requires_trusted_history_verification"
    ):
        raise ProjectBackupError("recovery root does not match this backup")
    return marker


def _write_bundle(
    destination: Path,
    password: Password,
    payload: dict,
    metadata_revision: str | None,
) -> BackupManifest:
    # Reject oversized input before deep validation copies its state.
    if len(_canonical_bytes(payload)) > _MAX_BACKUP_BYTES:
        raise ProjectBackupError("project backup payload exceeds size limit")
    # The producer must satisfy the same contract as inspect/restore before
    # encrypting or publishing a destination, including legacy metadata.
    payload = _validate_payload(payload, expected_kind=payload["kind"])
    if metadata_revision != _payload_metadata_revision(payload):
        raise ProjectBackupError("project backup manifest revision mismatch")
    payload_bytes = _canonical_bytes(payload)
    if len(payload_bytes) > _MAX_BACKUP_BYTES:
        raise ProjectBackupError("project backup payload exceeds size limit")
    manifest_data = {
        "kind": payload["kind"],
        "schema_version": BACKUP_SCHEMA_VERSION,
        "content_hash": hashlib.sha256(payload_bytes).hexdigest(),
        "metadata_revision": metadata_revision,
        "entry_count": _entry_count(payload),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    bundle = {
        "backup_schema_version": BACKUP_SCHEMA_VERSION,
        "manifest": manifest_data,
        "payload": payload,
    }
    plaintext = _canonical_bytes(bundle)
    if len(plaintext) + 48 > _MAX_BACKUP_BYTES:
        raise ProjectBackupError("project backup exceeds size limit")
    blob = crypto.encrypt_blob(plaintext, password=_password(password))
    destination = Path(destination)
    if not destination.parent.exists():
        ensure_private_dir(destination.parent)
    _atomic_write(destination, blob, private_parent=False, replace_existing=False)
    return _manifest(manifest_data)


def _read_bundle(source: Path, password: Password) -> dict:
    try:
        blob = _secure_read(Path(source))
        if len(blob) > _MAX_BACKUP_BYTES:
            raise ProjectBackupError("project backup exceeds size limit")
        plaintext = crypto.decrypt_blob(blob, password=_password(password))
        if len(plaintext) > _MAX_BACKUP_BYTES:
            raise ProjectBackupError("project backup exceeds size limit")
        bundle = json.loads(plaintext.decode("utf-8"))
    except ProjectBackupError:
        raise
    except (FileNotFoundError, crypto.BadPassword, UnicodeError, ValueError) as ex:
        raise ProjectBackupError("cannot decrypt or decode project backup") from ex
    if not isinstance(bundle, dict) or set(bundle) != {
        "backup_schema_version", "manifest", "payload"
    } or bundle["backup_schema_version"] != BACKUP_SCHEMA_VERSION:
        raise ProjectBackupError("unsupported or invalid project backup schema")
    manifest = _manifest(bundle["manifest"])
    payload = _validate_payload(bundle["payload"], expected_kind=manifest.kind)
    if hashlib.sha256(_canonical_bytes(payload)).hexdigest() != manifest.content_hash:
        raise ProjectBackupError("project backup content hash mismatch")
    if _entry_count(payload) != manifest.entry_count:
        raise ProjectBackupError("project backup manifest count mismatch")
    if manifest.metadata_revision != _payload_metadata_revision(payload):
        raise ProjectBackupError("project backup manifest revision mismatch")
    bundle["payload"] = payload
    return bundle


def _payload_metadata_revision(payload: dict) -> str:
    if payload["kind"] == "master":
        return payload["metadata"]["revision"]
    return payload["generation"]["payload"]["source_revision"]


def _manifest(value: object) -> BackupManifest:
    fields = {
        "kind", "schema_version", "content_hash", "metadata_revision",
        "entry_count", "created_at",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ProjectBackupError("invalid project backup manifest")
    if value["kind"] not in {"master", "replica"} or value["schema_version"] != BACKUP_SCHEMA_VERSION:
        raise ProjectBackupError("invalid project backup manifest")
    if not isinstance(value["content_hash"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["content_hash"]):
        raise ProjectBackupError("invalid project backup manifest")
    if value["metadata_revision"] is not None and (
        not isinstance(value["metadata_revision"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["metadata_revision"])
    ):
        raise ProjectBackupError("invalid project backup manifest")
    if type(value["entry_count"]) is not int or value["entry_count"] < 0:
        raise ProjectBackupError("invalid project backup manifest")
    if not isinstance(value["created_at"], str):
        raise ProjectBackupError("invalid project backup manifest")
    return BackupManifest(**value)


def _validate_payload(value: object, *, expected_kind: str) -> dict:
    if not isinstance(value, dict) or value.get("kind") != expected_kind:
        raise ProjectBackupError("project backup payload kind mismatch")
    if expected_kind == "replica":
        if set(value) != {"kind", "generation", "project_state"}:
            raise ProjectBackupError("invalid replica backup fields")
        generation = value["generation"]
        if not isinstance(generation, dict) or set(generation) != {"payload", "checkpoint"}:
            raise ProjectBackupError("invalid replica backup generation")
        return {
            "kind": "replica",
            "generation": {
                "payload": validate_replica_payload(generation["payload"]),
                "checkpoint": validate_checkpoint(generation["checkpoint"]),
            },
            "project_state": _validate_project_state(value["project_state"]),
        }
    if set(value) != {
        "kind", "metadata", "entry_secrets", "service_secrets",
        "project_state", "journal_files",
    }:
        raise ProjectBackupError("invalid master backup fields")
    metadata = _validate_metadata(value["metadata"])
    entry_ids = {item["id"] for item in metadata["entries"]}
    entry_secrets = _validate_secret_map(value["entry_secrets"])
    allowed_accounts = entry_ids | {item + ":passphrase" for item in entry_ids}
    if set(entry_secrets) != allowed_accounts:
        raise ProjectBackupError("master backup entry secret set is incomplete")
    for raw in metadata["entries"]:
        entry = Entry.from_dict(raw)
        if entry_requires_secret(entry) and not entry_secrets[entry.id]["present"]:
            raise ProjectBackupError("master backup is missing a required entry secret")
    service_secrets = _validate_secret_map(value["service_secrets"])
    if (set(service_secrets).intersection(entry_secrets)
            or any(not re.fullmatch(r"kk:[a-z][a-z0-9-]{0,127}", account)
                   for account in service_secrets)):
        raise ProjectBackupError("master backup service accounts must be disjoint reserved identities")
    journal_files = _validate_journal_files(value["journal_files"])
    from keys_keeper.master_journal import MASTER_UNLOCK_ACCOUNT
    if ((metadata["schema_version"] == CATALOG_SCHEMA_VERSION or journal_files)
            and not service_secrets.get(MASTER_UNLOCK_ACCOUNT, {}).get("present")):
        raise ProjectBackupError("master backup is missing its journal authority key")
    return {
        "kind": "master",
        "metadata": metadata,
        "entry_secrets": entry_secrets,
        "service_secrets": service_secrets,
        "project_state": _validate_project_state(value["project_state"]),
        "journal_files": journal_files,
    }


def _validate_metadata(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "schema_version", "revision", "entries", "tombstones", "catalog"
    }:
        raise ProjectBackupError("invalid master backup metadata")
    schema = value["schema_version"]
    if schema not in {2, CATALOG_SCHEMA_VERSION}:
        raise ProjectBackupError("unsupported master metadata schema")
    records = value["entries"]
    tombstones = value["tombstones"]
    if not isinstance(records, list) or not isinstance(tombstones, list):
        raise ProjectBackupError("invalid master backup metadata")
    try:
        entries = [
            Entry.from_untrusted_dict(item, allow_project_fields=schema == CATALOG_SCHEMA_VERSION)
            for item in records
        ]
        normalized_tombstones = [validate_tombstone(item) for item in tombstones]
        if (len({item.id for item in entries}) != len(entries)
                or len({item.name for item in entries}) != len(entries)):
            raise ValidationError("duplicate entry identity")
        if schema == CATALOG_SCHEMA_VERSION:
            CatalogState.from_dict(value["catalog"], entry_ids={item.id for item in entries})
            catalog = copy.deepcopy(value["catalog"])
            folders = {folder["id"] for folder in catalog["folders"]}
            if any(entry.folder_id is not None and entry.folder_id not in folders for entry in entries):
                raise ValidationError("entry folder is unavailable")
        elif value["catalog"] is None:
            catalog = None
        else:
            raise ProjectBackupError("legacy master backup must not contain a catalog")
    except (ValidationError, CatalogValidationError) as ex:
        raise ProjectBackupError("invalid master backup metadata") from ex
    revision = value["revision"]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
        raise ProjectBackupError("invalid master metadata revision")
    normalized = {
        "schema_version": schema,
        "revision": revision,
        "entries": copy.deepcopy(records),
        "tombstones": normalized_tombstones,
        "catalog": catalog,
    }
    revision_data = {key: normalized[key] for key in ("schema_version", "entries", "tombstones")}
    if schema == CATALOG_SCHEMA_VERSION:
        revision_data["catalog"] = catalog
    if MetadataTransaction(revision_data).revision() != revision:
        raise ProjectBackupError("master backup metadata revision is inconsistent")
    return normalized


def _capture_entry_secrets(backend: KeychainBackend, entries: list[Entry]) -> dict:
    present = set(backend.list_ids())
    result = {}
    for entry in entries:
        for account, required in (
            (entry.id, entry_requires_secret(entry)),
            (entry.id + ":passphrase", False),
        ):
            if account not in present:
                if required:
                    raise ProjectBackupError("required entry secret is unavailable")
                result[account] = {"present": False}
                continue
            try:
                result[account] = {"present": True, "value": backend.get(account).unseal()}
            except Exception as ex:
                raise ProjectBackupError("cannot read entry secret for backup") from ex
    return result


def _capture_service_secrets(backend: KeychainBackend, accounts: tuple[str, ...]) -> dict:
    if any(not isinstance(item, str) or not item.startswith("kk:") for item in accounts):
        raise ValueError("service_accounts must contain explicit reserved account names")
    present = set(backend.list_ids())
    result = {}
    for account in accounts:
        if account not in present:
            raise ProjectBackupError("required project service secret is unavailable")
        try:
            result[account] = {"present": True, "value": backend.get(account).unseal()}
        except Exception as ex:
            raise ProjectBackupError("cannot read project service secret for backup") from ex
    return result


def _validate_secret_map(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict):
        raise ProjectBackupError("invalid project backup secret map")
    result = {}
    for account, image in value.items():
        if not isinstance(account, str) or not isinstance(image, dict):
            raise ProjectBackupError("invalid project backup secret map")
        if set(image) not in ({"present"}, {"present", "value"}) or type(image.get("present")) is not bool:
            raise ProjectBackupError("invalid project backup secret map")
        if image["present"]:
            if not isinstance(image.get("value"), str):
                raise ProjectBackupError("invalid project backup secret map")
        elif "value" in image:
            raise ProjectBackupError("invalid project backup secret map")
        result[account] = dict(image)
    return result


def _validate_project_state(value: object) -> dict:
    if not isinstance(value, Mapping):
        raise ProjectBackupError("project state must be an object")
    try:
        encoded = _canonical_bytes(dict(value))
    except (TypeError, ValueError) as ex:
        raise ProjectBackupError("project state is not JSON serializable") from ex
    if len(encoded) > _MAX_STATE_BYTES:
        raise ProjectBackupError("project state exceeds size limit")
    return json.loads(encoded)


def _capture_journal_files(paths: Paths) -> dict[str, str]:
    if not paths.operations_dir.exists():
        return {}
    result = {}
    for path in sorted(paths.operations_dir.iterdir()):
        if not _JOURNAL_FILE.fullmatch(path.name):
            continue
        data = _secure_read(path, max_bytes=_MAX_STATE_BYTES)
        if len(data) > _MAX_STATE_BYTES:
            raise ProjectBackupError("journal file exceeds backup size limit")
        result[path.name] = base64.b64encode(data).decode("ascii")
    return result


def _validate_journal_files(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ProjectBackupError("invalid backup journal set")
    result = {}
    for name, encoded in value.items():
        if not isinstance(name, str) or not _JOURNAL_FILE.fullmatch(name) or not isinstance(encoded, str):
            raise ProjectBackupError("invalid backup journal set")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except ValueError as ex:
            raise ProjectBackupError("invalid backup journal set") from ex
        if len(raw) > _MAX_STATE_BYTES:
            raise ProjectBackupError("invalid backup journal set")
        result[name] = base64.b64encode(raw).decode("ascii")
    return result


def _restore_master(paths: Paths, payload: dict, password: Password) -> None:
    checked = _validate_payload(payload, expected_kind="master")
    metadata = checked["metadata"]
    raw_metadata = {
        "schema_version": metadata["schema_version"],
        "entries": metadata["entries"],
        "tombstones": metadata["tombstones"],
    }
    if metadata["schema_version"] == CATALOG_SCHEMA_VERSION:
        raw_metadata["catalog"] = metadata["catalog"]
    _atomic_write(paths.data_json, json.dumps(raw_metadata, indent=2).encode("utf-8"))
    # Re-open through the production parser before restoring any value.
    restored = MetadataStore(paths)
    if restored.snapshot().revision != metadata["revision"]:
        raise ProjectBackupError("restored master metadata revision mismatch")
    backend = _file_backend(paths, password)
    for secret_map in (checked["entry_secrets"], checked["service_secrets"]):
        for account, image in secret_map.items():
            if image["present"]:
                backend.set(account, image["value"])
    ensure_private_dir(paths.operations_dir)
    for name, encoded in checked["journal_files"].items():
        _atomic_write(paths.operations_dir / name, base64.b64decode(encoded))


def _restore_replica(paths: Paths, payload: dict, password: Password) -> None:
    checked = _validate_payload(payload, expected_kind="replica")
    generation = checked["generation"]
    ReplicaStore(paths=paths, password_provider=lambda: password).install(
        generation["payload"], generation["checkpoint"]
    )


def _file_backend(paths: Paths, password: Password) -> EncryptedFileBackend:
    value = _password(password).encode("utf-8")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, value)
    finally:
        os.close(write_fd)
    try:
        backend = EncryptedFileBackend(
            paths=paths,
            password_fd=read_fd,
            allow_env_password=False,
        )
        backend._password()  # Cache before the ephemeral descriptor is closed.
        return backend
    finally:
        os.close(read_fd)


def _password(value: Password) -> str:
    if isinstance(value, Sealed):
        value = value.unseal()
    elif isinstance(value, bytes):
        if not value:
            raise ProjectBackupError("backup password is empty")
        value = "key-bytes:" + value.hex()
    if not isinstance(value, str) or not value:
        raise ProjectBackupError("backup password is empty")
    return value


def _entry_count(payload: dict) -> int:
    if payload["kind"] == "master":
        return len(payload["metadata"]["entries"])
    return len(payload["generation"]["payload"]["entries"])


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _secure_read(path: Path, *, max_bytes: int | None = None) -> bytes:
    maximum = _MAX_BACKUP_BYTES if max_bytes is None else min(max_bytes, _MAX_BACKUP_BYTES)
    try:
        return secure_read(path, max_bytes=maximum)
    except PrivateFileError:
        raise ProjectBackupError("project backup file is unsafe, changed, or exceeds size limit") from None


def _require_new_destination(path: Path) -> None:
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise ProjectBackupError("cannot inspect backup destination") from None
    raise ProjectBackupError("backup destination already exists; choose an unused path")


def _atomic_write(path: Path, data: bytes, *, private_parent: bool = True,
                  replace_existing: bool = True) -> None:
    try:
        atomic_write_bytes(path, data, sync_parent=_fsync_parent,
                           ensure_parent_private=private_parent,
                           replace_existing=replace_existing)
    except FileExistsError:
        raise ProjectBackupError("backup destination already exists; choose an unused path") from None
    except PrivateFileCommitError:
        raise ProjectBackupCommitError(
            "project backup file was published but durability is uncertain; inspect before retrying"
        ) from None
    except PrivateFileError:
        raise ProjectBackupError("project backup publication could not be confirmed") from None
