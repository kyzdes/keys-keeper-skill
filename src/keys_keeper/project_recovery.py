"""Durable recovery takeover into a fresh project authority.

The restored master stays blocked by ``recovery-only`` while this module
creates new scope/vault identities, fresh signing/inbox/scope keys and empty
grant histories.  The old authority is retained only in an encrypted archive;
it is never installed as an active writer.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

from keys_keeper import crypto, project_protocol as wire
from keys_keeper.backend import KeychainError, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.operation_journal import JournalNotFound, OperationJournal, _secure_read
from keys_keeper.paths import Paths
from keys_keeper.project_backup import ProjectBackupError, RecoveryProfile, _atomic_write
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_models import CatalogState
from keys_keeper.project_sync import ProjectState, new_master_state
from keys_keeper.store import MetadataStore, StoreError


PROJECT_RUNTIME_KEY_ACCOUNT = "kk:project-runtime-key"
TAKEOVER_KIND = "recovery_takeover"
_TAKEOVER_ID = "3bc972f7-77ce-4e49-9ef3-474f08fd7e5e"
_PLAN_SCHEMA = 1
_BACKEND_SETTINGS = {"schema_version": 1, "backend": "encrypted_file"}


class ProjectRecoveryError(RuntimeError):
    """A recovery cannot safely become a new active authority."""


@dataclass(frozen=True)
class TakeoverPlan:
    metadata: dict
    profile_registry: dict
    new_states: dict = field(repr=False)
    file_backend_settings: dict = field(default_factory=dict)
    scope_map: dict = field(default_factory=dict)


@dataclass(frozen=True)
class TakeoverResult:
    status: str
    source_backup_hash: str
    profiles: tuple[dict, ...]


def prepare_takeover(
    profile: RecoveryProfile,
    *,
    recovery_password: str | bytes | Sealed,
    endpoint: str,
) -> TakeoverPlan:
    """Persist one immutable takeover plan before any relay request."""
    marker = _recovery_marker(profile.paths)
    if profile.kind != "master" or marker["kind"] != "master":
        raise ProjectRecoveryError("takeover requires a restored master profile")
    if marker["status"] not in {"restored", "takeover_ready"}:
        raise ProjectRecoveryError("recovery restore must finish before takeover")
    if marker["backup_hash"] != profile.manifest.content_hash:
        raise ProjectRecoveryError("recovery profile does not match its backup manifest")
    journal = _takeover_journal(profile.paths, recovery_password)
    with journal.locked():
        try:
            record = journal.read(_TAKEOVER_ID)
        except JournalNotFound:
            if marker["status"] != "restored":
                raise ProjectRecoveryError("takeover plan is unavailable") from None
            state = _new_plan_state(profile, recovery_password, endpoint)
            record = journal.begin(TAKEOVER_KIND, operation_id=_TAKEOVER_ID, state=state)
        state = _validate_plan_state(record.state)
        if state["endpoint"] != endpoint:
            raise ProjectRecoveryError("takeover endpoint cannot change after preparation")
        if state["source_backup_hash"] != marker["backup_hash"]:
            raise ProjectRecoveryError("takeover plan does not match recovery source")
    return _public_plan(state)


def recover_takeover(
    profile: RecoveryProfile,
    *,
    recovery_password: str | bytes | Sealed,
    endpoint: str,
    admin_token: Sealed,
) -> TakeoverResult:
    """Create fresh relay scopes, install the new local authority and activate.

    Re-running this function after process death uses the exact same signed
    policies.  Relay scope creation is idempotent for identical version-one
    policy bytes.
    """
    if not isinstance(admin_token, Sealed):
        raise TypeError("admin_token must be sealed")
    activation_path = profile.paths.root / "recovery-activation.json"
    if not (profile.paths.root / "recovery-only").exists():
        return _completed_result(profile.paths, activation_path)
    if activation_path.exists():
        # The activation record is written only after a full local validation.
        # A process may die before advancing the recovery-only marker.
        marker = _recovery_marker(profile.paths)
        activation = _read_activation(activation_path)
        _verify_installed_takeover(profile.paths, activation)
        if marker["status"] != "takeover_ready":
            marker["status"] = "takeover_ready"
            _atomic_write(
                profile.paths.root / "recovery-only", _canonical(marker)
            )
        return activate_takeover(profile)
    prepare_takeover(
        profile, recovery_password=recovery_password, endpoint=endpoint
    )
    journal = _takeover_journal(profile.paths, recovery_password)
    while True:
        with journal.locked():
            record = journal.read(_TAKEOVER_ID)
            state = _validate_plan_state(record.state)
            remaining = [
                scope_id for scope_id in sorted(state["new_states"])
                if scope_id not in state["remote_created"]
            ]
        if not remaining:
            break
        scope_id = remaining[0]
        client = ProjectClient(base_url=endpoint, token=admin_token)
        response = client.create_scope(copy.deepcopy(state["new_states"][scope_id]["policy"]))
        if not isinstance(response, dict) or response.get("scope_id") != scope_id:
            raise ProjectRecoveryError("relay takeover acknowledgement mismatch")
        with journal.locked():
            latest = journal.read(_TAKEOVER_ID)
            updated = _validate_plan_state(latest.state)
            if scope_id not in updated["remote_created"]:
                updated["remote_created"].append(scope_id)
                updated["remote_created"].sort()
                journal.stage(_TAKEOVER_ID, "remote_scope_created", state=updated)

    with journal.locked():
        record = journal.read(_TAKEOVER_ID)
        state = _validate_plan_state(record.state)
        if set(state["remote_created"]) != set(state["new_states"]):
            raise ProjectRecoveryError("not every fresh scope exists on the relay")
        _install_local_takeover(profile.paths, state)
        journal.stage(_TAKEOVER_ID, "takeover_ready", state=state)
        marker = _recovery_marker(profile.paths)
        marker["status"] = "takeover_ready"
        _atomic_write(profile.paths.root / "recovery-only", _canonical(marker))
    return activate_takeover(profile)


def activate_takeover(profile: RecoveryProfile) -> TakeoverResult:
    """Verify the concrete fresh authority, then remove the runtime block."""
    marker_path = profile.paths.root / "recovery-only"
    activation_path = profile.paths.root / "recovery-activation.json"
    if not marker_path.exists():
        return _completed_result(profile.paths, activation_path)
    marker = _recovery_marker(profile.paths)
    if marker["status"] != "takeover_ready":
        raise ProjectRecoveryError("takeover is not ready for activation")
    activation = _read_activation(activation_path)
    _verify_installed_takeover(profile.paths, activation)
    _remove_takeover_journal(profile.paths)
    try:
        marker_path.unlink()
        _fsync_dir(profile.paths.root)
    except OSError as ex:
        raise ProjectRecoveryError("cannot activate recovered profile") from ex
    return _result(activation)


def _new_plan_state(
    profile: RecoveryProfile,
    recovery_password: str | bytes | Sealed,
    endpoint: str,
) -> dict:
    store = profile.metadata_store()
    try:
        source_catalog = store.catalog_state()
    except StoreError as ex:
        raise ProjectRecoveryError("takeover requires catalog schema 3") from ex
    entries = store.list()
    catalog = CatalogState.from_dict(source_catalog, entry_ids={item.id for item in entries})
    projects = {item.id: item for item in catalog.projects}
    runtime_key = wire.encode_key(wire.generate_key())
    backend_password = wire.encode_key(wire.generate_key())
    scope_map: dict[str, dict[str, str]] = {}
    new_states: dict[str, dict] = {}
    profiles: list[dict] = []
    new_scopes = []
    for old in sorted(catalog.scopes, key=lambda item: item.id):
        scope_id = str(uuid4())
        vault_id = str(uuid4())
        state = new_master_state(scope_id, vault_id, endpoint)
        project = projects[old.project_id]
        scope_map[old.id] = {"scope_id": scope_id, "vault_id": vault_id}
        new_states[scope_id] = state
        new_scopes.append({
            "id": scope_id,
            "project_id": old.project_id,
            "environment": old.environment,
            "vault_id": vault_id,
            "epoch": 1,
            "policy_version": 1,
        })
        profiles.append({
            "id": scope_id,
            "kind": "master_scope",
            "scope_id": scope_id,
            "vault_id": vault_id,
            "project": project.slug,
            "environment": old.environment,
            "endpoint": endpoint,
            "device_id": state["device_id"],
            "status": "active",
        })
    new_catalog = {
        "folders": [item.to_dict() for item in catalog.folders],
        "projects": [item.to_dict() for item in catalog.projects],
        "scopes": new_scopes,
        "bindings": [
            {**item.to_dict(), "scope_id": scope_map[item.scope_id]["scope_id"]}
            for item in catalog.bindings
        ],
        # Old create receipts, grant IDs and publication intents belong to the
        # retired authority.  They remain in the encrypted history below.
        "dedup": [],
        "publication_intents": [],
    }
    CatalogState.from_dict(new_catalog, entry_ids={item.id for item in entries})
    try:
        backend = profile.open_master_backend(recovery_password)
        accounts = {
            account: backend.get(account).unseal()
            for account in sorted(backend.list_ids())
        }
    except (KeychainError, ProjectBackupError) as ex:
        raise ProjectRecoveryError("cannot read restored secrets for takeover") from ex
    accounts[PROJECT_RUNTIME_KEY_ACCOUNT] = runtime_key
    history = {
        "schema_version": 1,
        "source_backup_hash": profile.manifest.content_hash,
        "catalog": source_catalog,
        "project_state": profile.project_state(recovery_password),
    }
    return _validate_plan_state({
        "schema_version": _PLAN_SCHEMA,
        "source_backup_hash": profile.manifest.content_hash,
        "source_metadata_revision": profile.manifest.metadata_revision,
        "endpoint": endpoint,
        "metadata": {"catalog": new_catalog},
        "profile_registry": {
            "schema_version": 1, "default_profile": "master", "profiles": profiles
        },
        "new_states": new_states,
        "file_backend_settings": dict(_BACKEND_SETTINGS),
        "scope_map": scope_map,
        "accounts": accounts,
        "runtime_key": runtime_key,
        "backend_password": backend_password,
        "history": history,
        "remote_created": [],
    })


def _install_local_takeover(paths: Paths, state: dict) -> None:
    store = MetadataStore(paths)
    with store.transaction() as tx:
        current = tx.catalog_state()
        target = state["metadata"]["catalog"]
        if current != target:
            tx.set_catalog_state(copy.deepcopy(target))
    _atomic_write(paths.root / "profile-registry.json", _canonical(state["profile_registry"]))
    for scope_id, item in state["new_states"].items():
        project_state = ProjectState(
            Paths(paths.root / "project-sync" / scope_id / "state"),
            lambda key=state["runtime_key"]: key,
        )
        project_state.save(copy.deepcopy(item))
    archive = crypto.encrypt_blob(
        _canonical(state["history"]), password=state["runtime_key"]
    )
    _atomic_write(paths.root / "recovery-history.enc", archive)
    secrets_blob = crypto.encrypt_blob(
        json.dumps(state["accounts"], ensure_ascii=False).encode("utf-8"),
        password=state["backend_password"],
    )
    _atomic_write(paths.secrets_enc, secrets_blob)
    _atomic_write(paths.backend_password_file, state["backend_password"].encode("utf-8"))
    _atomic_write(paths.root / "runtime-backend.json", _canonical(_BACKEND_SETTINGS))
    activation = _activation_from_state(state)
    _verify_installed_takeover(paths, activation)
    _atomic_write(paths.root / "recovery-activation.json", _canonical(activation))


def _activation_from_state(state: dict) -> dict:
    profiles = []
    for item in sorted(state["profile_registry"]["profiles"], key=lambda value: value["scope_id"]):
        project_state = state["new_states"][item["scope_id"]]
        profiles.append({
            "scope_id": item["scope_id"],
            "vault_id": item["vault_id"],
            "pin": project_state["pin"],
            "device_id": item["device_id"],
        })
    return {
        "schema_version": 1,
        "mode": "takeover",
        "source_backup_hash": state["source_backup_hash"],
        "scope_map": copy.deepcopy(state["scope_map"]),
        "account_ids": sorted(state["accounts"]),
        "profiles": profiles,
        "activated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _verify_installed_takeover(paths: Paths, activation: dict) -> None:
    activation = _validate_activation(activation)
    try:
        settings = json.loads(_secure_read(paths.root / "runtime-backend.json"))
        if settings != _BACKEND_SETTINGS:
            raise ProjectRecoveryError("recovered runtime backend settings are invalid")
        backend = EncryptedFileBackend(
            paths=paths,
            password_file=paths.backend_password_file,
            allow_env_password=False,
        )
        if sorted(backend.list_ids()) != activation["account_ids"]:
            raise ProjectRecoveryError("recovered secret account set is incomplete")
        runtime_key = backend.get(PROJECT_RUNTIME_KEY_ACCOUNT).unseal()
        wire.decode_key(runtime_key)
        catalog = MetadataStore(paths).catalog_state()
        if catalog["dedup"] or catalog["publication_intents"]:
            raise ProjectRecoveryError("fresh takeover catalog contains an old active ledger")
        registry = json.loads(_secure_read(paths.root / "profile-registry.json"))
    except (FileNotFoundError, UnicodeError, ValueError, KeychainError, StoreError) as ex:
        if isinstance(ex, ProjectRecoveryError):
            raise
        raise ProjectRecoveryError("cannot verify recovered runtime composition") from ex
    expected = {item["scope_id"]: item for item in activation["profiles"]}
    scopes = {item["id"]: item for item in catalog["scopes"]}
    records = registry.get("profiles") if isinstance(registry, dict) else None
    if not isinstance(records, list) or {item.get("scope_id") for item in records} != set(expected):
        raise ProjectRecoveryError("recovered profile registry does not match takeover")
    for item in records:
        scope_id = item["scope_id"]
        proof = expected[scope_id]
        if (
            item.get("kind") != "master_scope"
            or item.get("status") != "active"
            or item.get("vault_id") != proof["vault_id"]
            or item.get("device_id") != proof["device_id"]
            or scopes.get(scope_id, {}).get("vault_id") != proof["vault_id"]
        ):
            raise ProjectRecoveryError("recovered profile identity is invalid")
        state = ProjectState(
            Paths(paths.root / "project-sync" / scope_id / "state"),
            lambda key=runtime_key: key,
        ).load()
        policy = wire.verify_policy(
            state["policy"],
            wire.decode_key(state["pin"]),
            expected_scope_id=scope_id,
            expected_vault_id=proof["vault_id"],
        )
        if state["pin"] != proof["pin"] or policy["grants"]:
            raise ProjectRecoveryError("fresh takeover authority is invalid")
    try:
        history = json.loads(
            crypto.decrypt_blob(
                _secure_read(paths.root / "recovery-history.enc"),
                password=runtime_key,
            )
        )
    except (FileNotFoundError, UnicodeError, ValueError, crypto.BadPassword) as ex:
        raise ProjectRecoveryError("cannot verify encrypted retired authority") from ex
    old_credentials = _history_credentials(history)
    for proof in activation["profiles"]:
        state = ProjectState(
            Paths(paths.root / "project-sync" / proof["scope_id"] / "state"),
            lambda key=runtime_key: key,
        ).load()
        if _state_credentials(state) & old_credentials:
            raise ProjectRecoveryError("takeover reused retired authority material")


def _validate_plan_state(value) -> dict:
    fields = {
        "schema_version", "source_backup_hash", "source_metadata_revision",
        "endpoint", "metadata", "profile_registry", "new_states",
        "file_backend_settings", "scope_map", "accounts", "runtime_key",
        "backend_password", "history", "remote_created",
    }
    if not isinstance(value, dict) and not hasattr(value, "keys"):
        raise ProjectRecoveryError("invalid recovery takeover plan")
    state = copy.deepcopy(dict(value))
    if set(state) != fields or state["schema_version"] != _PLAN_SCHEMA:
        raise ProjectRecoveryError("invalid recovery takeover plan")
    if state["file_backend_settings"] != _BACKEND_SETTINGS:
        raise ProjectRecoveryError("invalid recovery backend settings")
    if not isinstance(state["endpoint"], str) or not state["endpoint"]:
        raise ProjectRecoveryError("invalid recovery takeover endpoint")
    ProjectClient(base_url=state["endpoint"], token=Sealed("validation-only"))
    for field_name in ("source_backup_hash",):
        value = state[field_name]
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
            raise ProjectRecoveryError("invalid recovery takeover identity")
    if state["source_metadata_revision"] is not None and (
        not isinstance(state["source_metadata_revision"], str)
        or len(state["source_metadata_revision"]) != 64
        or any(ch not in "0123456789abcdef" for ch in state["source_metadata_revision"])
    ):
        raise ProjectRecoveryError("invalid recovery takeover identity")
    if not isinstance(state["metadata"], dict) or set(state["metadata"]) != {"catalog"}:
        raise ProjectRecoveryError("invalid recovery takeover metadata")
    if not isinstance(state["new_states"], dict) or not isinstance(state["scope_map"], dict):
        raise ProjectRecoveryError("invalid recovery takeover scopes")
    if not isinstance(state["accounts"], dict) or not all(
        isinstance(key, str) and isinstance(item, str)
        for key, item in state["accounts"].items()
    ):
        raise ProjectRecoveryError("invalid recovery takeover accounts")
    for key_name in ("runtime_key", "backend_password"):
        if not isinstance(state[key_name], str):
            raise ProjectRecoveryError("invalid recovery takeover key")
        wire.decode_key(state[key_name])
    if state["accounts"].get(PROJECT_RUNTIME_KEY_ACCOUNT) != state["runtime_key"]:
        raise ProjectRecoveryError("invalid recovery runtime key")
    if not isinstance(state["remote_created"], list) or len(state["remote_created"]) != len(set(state["remote_created"])):
        raise ProjectRecoveryError("invalid recovery relay progress")
    old_ids = set(state["scope_map"])
    new_ids = {item.get("scope_id") for item in state["scope_map"].values() if isinstance(item, dict)}
    if len(new_ids) != len(old_ids) or old_ids & new_ids or new_ids != set(state["new_states"]):
        raise ProjectRecoveryError("takeover must use disjoint fresh scope identities")
    if not set(state["remote_created"]).issubset(new_ids):
        raise ProjectRecoveryError("invalid recovery relay progress")
    catalog = state["metadata"]["catalog"]
    entry_ids = {binding["entry_id"] for binding in catalog.get("bindings", [])} if isinstance(catalog, dict) else set()
    parsed = CatalogState.from_dict(catalog, entry_ids=entry_ids)
    if parsed.dedup or parsed.publication_intents or {item.id for item in parsed.scopes} != new_ids:
        raise ProjectRecoveryError("fresh recovery catalog is invalid")
    registry = state["profile_registry"]
    if not isinstance(registry, dict) or set(registry) != {"schema_version", "default_profile", "profiles"}:
        raise ProjectRecoveryError("invalid recovery profile registry")
    if registry["schema_version"] != 1 or registry["default_profile"] != "master" or not isinstance(registry["profiles"], list):
        raise ProjectRecoveryError("invalid recovery profile registry")
    if {item.get("scope_id") for item in registry["profiles"]} != new_ids:
        raise ProjectRecoveryError("invalid recovery profile registry")
    for scope_id, project_state in state["new_states"].items():
        mapping = next(item for item in state["scope_map"].values() if item["scope_id"] == scope_id)
        body = wire.verify_policy(
            project_state["policy"], wire.decode_key(project_state["pin"]),
            expected_scope_id=scope_id, expected_vault_id=mapping["vault_id"],
        )
        if body["grants"] or project_state["checkpoint"] is not None or project_state["used_grants"]:
            raise ProjectRecoveryError("fresh recovery authority contains inherited history")
    if not isinstance(state["history"], dict) or not isinstance(state["history"].get("project_state"), dict):
        raise ProjectRecoveryError("invalid recovery history")
    old_credentials = _history_credentials(state["history"])
    if any(_state_credentials(item) & old_credentials for item in state["new_states"].values()):
        raise ProjectRecoveryError("takeover reused retired authority material")
    return state


def _public_plan(state: dict) -> TakeoverPlan:
    return TakeoverPlan(
        metadata=copy.deepcopy(state["metadata"]),
        profile_registry=copy.deepcopy(state["profile_registry"]),
        new_states=copy.deepcopy(state["new_states"]),
        file_backend_settings=copy.deepcopy(state["file_backend_settings"]),
        scope_map=copy.deepcopy(state["scope_map"]),
    )


def _takeover_journal(paths: Paths, password) -> OperationJournal:
    return OperationJournal(
        paths=Paths(paths.root / "recovery-takeover"),
        password_provider=lambda: password,
    )


def _recovery_marker(paths: Paths) -> dict:
    try:
        marker = json.loads(_secure_read(paths.root / "recovery-only"))
    except (FileNotFoundError, UnicodeError, ValueError) as ex:
        raise ProjectRecoveryError("recovery-only marker is unavailable") from ex
    fields = {"schema_version", "mode", "kind", "backup_hash", "status", "activation"}
    if (
        not isinstance(marker, dict) or set(marker) != fields
        or marker["schema_version"] != 1 or marker["mode"] != "recovery_only"
        or marker["activation"] != "requires_trusted_history_verification"
        or marker["status"] not in {"restored", "takeover_ready", "restore_in_progress"}
    ):
        raise ProjectRecoveryError("invalid recovery-only marker")
    return marker


def _read_activation(path: Path) -> dict:
    try:
        value = json.loads(_secure_read(path))
    except (FileNotFoundError, UnicodeError, ValueError) as ex:
        raise ProjectRecoveryError("takeover activation record is unavailable") from ex
    return _validate_activation(value)


def _validate_activation(value) -> dict:
    fields = {
        "schema_version", "mode", "source_backup_hash", "scope_map",
        "account_ids", "profiles", "activated_at",
    }
    if not isinstance(value, dict) or set(value) != fields or value["schema_version"] != 1 or value["mode"] != "takeover":
        raise ProjectRecoveryError("invalid takeover activation record")
    if not isinstance(value["account_ids"], list) or any(not isinstance(item, str) for item in value["account_ids"]):
        raise ProjectRecoveryError("invalid takeover activation record")
    if not isinstance(value["profiles"], list) or not isinstance(value["scope_map"], dict):
        raise ProjectRecoveryError("invalid takeover activation record")
    digest = value["source_backup_hash"]
    if not isinstance(digest, str) or len(digest) != 64 or any(
        ch not in "0123456789abcdef" for ch in digest
    ):
        raise ProjectRecoveryError("invalid takeover activation record")
    old_ids = set(value["scope_map"])
    new_ids = {item.get("scope_id") for item in value["scope_map"].values() if isinstance(item, dict)}
    if old_ids & new_ids or {item.get("scope_id") for item in value["profiles"]} != new_ids:
        raise ProjectRecoveryError("invalid takeover activation record")
    for item in value["profiles"]:
        if not isinstance(item, dict) or set(item) != {"scope_id", "vault_id", "pin", "device_id"}:
            raise ProjectRecoveryError("invalid takeover activation record")
        for field_name in ("scope_id", "vault_id", "device_id"):
            try:
                parsed = UUID(item[field_name])
            except (TypeError, ValueError, AttributeError) as ex:
                raise ProjectRecoveryError("invalid takeover activation record") from ex
            if str(parsed) != item[field_name] or parsed.version != 4:
                raise ProjectRecoveryError("invalid takeover activation record")
        wire.decode_key(item["pin"])
    return copy.deepcopy(value)


def _history_credentials(history: dict) -> set[str]:
    if not isinstance(history, dict) or not isinstance(history.get("project_state"), dict):
        raise ProjectRecoveryError("invalid encrypted retired authority")
    project_state = history["project_state"]
    states = project_state.get("states", {})
    if not isinstance(states, dict):
        raise ProjectRecoveryError("invalid encrypted retired authority")
    result: set[str] = set()
    for item in states.values():
        if not isinstance(item, dict):
            raise ProjectRecoveryError("invalid encrypted retired authority")
        result.update(_state_credentials(item))
    return result


def _state_credentials(state: dict) -> set[str]:
    if not isinstance(state, dict):
        raise ProjectRecoveryError("invalid project authority state")
    result = {
        value for key, value in state.items()
        if key in {
            "scope_id", "vault_id", "device_id", "token", "pin",
            "signing_private", "inbox_private", "scope_key",
        } and isinstance(value, str)
    }
    policy = state.get("policy")
    payload = policy.get("payload") if isinstance(policy, dict) else None
    if isinstance(payload, dict):
        for key in ("master_public_key", "master_device_id", "inbox_public_key"):
            if isinstance(payload.get(key), str):
                result.add(payload[key])
    return result


def _completed_result(paths: Paths, activation_path: Path) -> TakeoverResult:
    activation = _read_activation(activation_path)
    _verify_installed_takeover(paths, activation)
    return _result(activation)


def _result(activation: dict) -> TakeoverResult:
    return TakeoverResult(
        status="active",
        source_backup_hash=activation["source_backup_hash"],
        profiles=tuple(copy.deepcopy(activation["profiles"])),
    )


def _remove_takeover_journal(paths: Paths) -> None:
    directory = paths.root / "recovery-takeover"
    if not directory.exists():
        return
    try:
        if directory.is_symlink():
            raise ProjectRecoveryError("takeover journal path is unsafe")
        shutil.rmtree(directory)
        _fsync_dir(paths.root)
    except OSError as ex:
        raise ProjectRecoveryError("cannot retire takeover journal") from ex


def _fsync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _canonical(value) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
