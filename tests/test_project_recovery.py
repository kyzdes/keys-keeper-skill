from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

from keys_keeper import crypto, project_protocol as wire
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.master_journal import MasterMutationManager
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal, _secure_read
from keys_keeper.paths import Paths
from keys_keeper.project_backup import create_master_backup, restore_backup
from keys_keeper.project_recovery import (
    PROJECT_RUNTIME_KEY_ACCOUNT,
    prepare_takeover,
    recover_takeover,
)
from keys_keeper.project_runtime import ProjectRuntime
from keys_keeper.project_service import ProjectService
from keys_keeper.project_sync import ProjectState, new_master_state
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}

    def get(self, account: str) -> Sealed:
        if account not in self.values:
            raise KeychainError("missing")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


def _recovery(tmp_path):
    source_paths = Paths(tmp_path / "source")
    store = MetadataStore(source_paths)
    store.migrate_catalog_v3()
    backend = MemoryBackend()
    old_runtime_key = wire.encode_key(wire.generate_key())
    backend.set(PROJECT_RUNTIME_KEY_ACCOUNT, old_runtime_key)
    journal = OperationJournal(
        paths=source_paths, password_provider=lambda: old_runtime_key
    )
    manager = MasterMutationManager(store, backend, journal)
    service = VaultService(store, backend, master_mutations=manager)
    entry = Entry.new(name="takeover-secret", type=EntryType.API_KEY)
    service.create_entry(entry, secrets=SecretInput(value="SYNTHETIC-TAKEOVER-SECRET"))
    projects = ProjectService(store)
    project = projects.create_project("recovered", "Recovered")
    old_scope = projects.create_scope(project.id, "prod")
    projects.set_entry_distribution(entry.id, "project_allowed")
    projects.assign(old_scope.id, entry.id)
    with store.transaction() as tx:
        catalog = tx.catalog_state()
        catalog["dedup"].append({"request_id": "old-receipt", "entry_id": entry.id})
        catalog["publication_intents"].append({
            "scope_id": old_scope.id, "entry_id": entry.id, "reason": "old-intent"
        })
        tx.set_catalog_state(catalog)
    old_state = new_master_state(old_scope.id, old_scope.vault_id, "https://old.example")
    old_registry = {
        "schema_version": 1,
        "default_profile": old_scope.id,
        "profiles": [{
            "id": old_scope.id,
            "kind": "master_scope",
            "scope_id": old_scope.id,
            "vault_id": old_scope.vault_id,
            "project": project.slug,
            "environment": old_scope.environment,
            "endpoint": "https://old.example",
            "device_id": old_state["device_id"],
            "status": "active",
        }],
    }
    backup = tmp_path / "master.kk3"
    create_master_backup(
        store,
        backend,
        journal=journal,
        destination=backup,
        password="backup-password",
        project_state={"registry": old_registry, "states": {old_scope.id: old_state}},
        service_accounts=(PROJECT_RUNTIME_KEY_ACCOUNT,),
    )
    profile = restore_backup(
        backup,
        password="backup-password",
        recovery_root=tmp_path / "recovery",
        recovery_password="recovery-password",
    )
    return profile, backup, entry, old_scope, old_state, old_runtime_key


class _ReplayRelay:
    records: dict[str, dict] = {}

    def __init__(self, *, base_url, token, **_kwargs):
        assert base_url == "https://new.example"
        assert isinstance(token, Sealed)

    def create_scope(self, policy):
        scope_id = policy["payload"]["scope_id"]
        previous = self.records.setdefault(scope_id, policy)
        assert previous == policy
        return {"scope_id": scope_id}


def test_takeover_uses_fresh_authority_empty_ledgers_and_explicit_file_backend(
    tmp_path, monkeypatch
):
    profile, _backup, entry, old_scope, old_state, old_runtime_key = _recovery(tmp_path)
    plan = prepare_takeover(
        profile,
        recovery_password="recovery-password",
        endpoint="https://new.example",
    )
    mapping = plan.scope_map[old_scope.id]
    assert mapping["scope_id"] != old_scope.id
    assert mapping["vault_id"] != old_scope.vault_id
    new_state = plan.new_states[mapping["scope_id"]]
    assert new_state["pin"] != old_state["pin"]
    assert new_state["signing_private"] != old_state["signing_private"]
    assert new_state["inbox_private"] != old_state["inbox_private"]
    assert new_state["scope_key"] != old_state["scope_key"]
    assert new_state["policy"]["payload"]["grants"] == []
    assert plan.metadata["catalog"]["dedup"] == []
    assert plan.metadata["catalog"]["publication_intents"] == []

    _ReplayRelay.records = {}
    monkeypatch.setattr("keys_keeper.project_recovery.ProjectClient", _ReplayRelay)
    result = recover_takeover(
        profile,
        recovery_password="recovery-password",
        endpoint="https://new.example",
        admin_token=Sealed("SYNTHETIC-ADMIN-TOKEN"),
    )
    assert result.status == "active"
    assert not (profile.paths.root / "recovery-only").exists()
    assert json.loads((profile.paths.root / "runtime-backend.json").read_text()) == {
        "schema_version": 1, "backend": "encrypted_file"
    }
    if os.name == "posix":
        assert stat.S_IMODE(profile.paths.backend_password_file.stat().st_mode) == 0o600
    backend = EncryptedFileBackend(
        paths=profile.paths,
        password_file=profile.paths.backend_password_file,
        allow_env_password=False,
    )
    assert backend.get(entry.id).unseal() == "SYNTHETIC-TAKEOVER-SECRET"
    runtime_key = backend.get(PROJECT_RUNTIME_KEY_ACCOUNT).unseal()
    assert runtime_key != old_runtime_key
    active_catalog = MetadataStore(profile.paths).catalog_state()
    assert {item["id"] for item in active_catalog["scopes"]} == {mapping["scope_id"]}
    assert active_catalog["dedup"] == [] and active_catalog["publication_intents"] == []
    installed = ProjectState(
        Paths(profile.paths.root / "project-sync" / mapping["scope_id"] / "state"),
        lambda: runtime_key,
    ).load()
    assert installed == new_state
    history = json.loads(
        crypto.decrypt_blob(
            _secure_read(profile.paths.root / "recovery-history.enc"),
            password=runtime_key,
        )
    )
    assert history["catalog"]["dedup"][0]["request_id"] == "old-receipt"
    assert history["project_state"]["states"][old_scope.id] == old_state
    assert not (profile.paths.root / "recovery-takeover").exists()
    runtime = ProjectRuntime(
        profile.paths,
        backend_factory=lambda: pytest.fail("takeover called the native backend"),
    )
    assert isinstance(runtime.master_backend, EncryptedFileBackend)
    assert runtime.context("master").backend.get(entry.id).unseal() == "SYNTHETIC-TAKEOVER-SECRET"
    assert runtime.status(mapping["scope_id"])["delivery"] == "idle"


def test_takeover_replays_identical_policy_after_process_exit(tmp_path, monkeypatch):
    profile, backup, _entry, old_scope, _old_state, _old_runtime_key = _recovery(tmp_path)
    relay_record = tmp_path / "relay-policy.json"
    child = r'''
import json
import os
from pathlib import Path
from keys_keeper.backend import Sealed
from keys_keeper.paths import Paths
from keys_keeper.project_backup import RecoveryProfile, inspect_backup
import keys_keeper.project_recovery as recovery

class StopRelay:
    def __init__(self, **kwargs):
        pass
    def create_scope(self, policy):
        path = Path(os.environ["RELAY_RECORD"])
        with path.open("w", encoding="utf-8") as handle:
            json.dump(policy, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os._exit(77)

recovery.ProjectClient = StopRelay
manifest = inspect_backup(Path(os.environ["BACKUP"]), password=os.environ["BACKUP_PASSWORD"])
profile = RecoveryProfile(Paths(Path(os.environ["RECOVERY_ROOT"])), "master", manifest)
recovery.recover_takeover(
    profile,
    recovery_password=os.environ["RECOVERY_PASSWORD"],
    endpoint="https://new.example",
    admin_token=Sealed(os.environ["ADMIN_TOKEN"]),
)
'''
    environment = os.environ.copy()
    environment.update(
        BACKUP=str(backup),
        BACKUP_PASSWORD="backup-password",
        RECOVERY_ROOT=str(profile.paths.root),
        RECOVERY_PASSWORD="recovery-password",
        ADMIN_TOKEN="SYNTHETIC-ADMIN-TOKEN",
        RELAY_RECORD=str(relay_record),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    stopped = subprocess.run(
        [sys.executable, "-c", child], env=environment, check=False
    )
    assert stopped.returncode == 77
    accepted_policy = json.loads(relay_record.read_text())
    accepted_scope = accepted_policy["payload"]["scope_id"]
    assert accepted_scope != old_scope.id
    assert (profile.paths.root / "recovery-only").exists()

    class ReplayAccepted(_ReplayRelay):
        records = {accepted_scope: accepted_policy}

    monkeypatch.setattr("keys_keeper.project_recovery.ProjectClient", ReplayAccepted)
    result = recover_takeover(
        profile,
        recovery_password="recovery-password",
        endpoint="https://new.example",
        admin_token=Sealed("SYNTHETIC-ADMIN-TOKEN"),
    )
    assert result.status == "active"
    assert ReplayAccepted.records[accepted_scope] == accepted_policy
    assert not (profile.paths.root / "recovery-only").exists()


def test_takeover_activates_after_exit_between_local_validation_and_marker(tmp_path):
    profile, backup, _entry, _old_scope, _old_state, _old_runtime_key = _recovery(tmp_path)
    child = r'''
import json
import os
from pathlib import Path
from keys_keeper.backend import Sealed
from keys_keeper.paths import Paths
from keys_keeper.project_backup import RecoveryProfile, inspect_backup
import keys_keeper.project_recovery as recovery

class Relay:
    def __init__(self, **kwargs):
        pass
    def create_scope(self, policy):
        return {"scope_id": policy["payload"]["scope_id"]}

original_write = recovery._atomic_write
def stopping_write(path, data):
    original_write(path, data)
    if path.name == "recovery-activation.json":
        os._exit(78)
recovery.ProjectClient = Relay
recovery._atomic_write = stopping_write
manifest = inspect_backup(Path(os.environ["BACKUP"]), password=os.environ["BACKUP_PASSWORD"])
profile = RecoveryProfile(Paths(Path(os.environ["RECOVERY_ROOT"])), "master", manifest)
recovery.recover_takeover(
    profile,
    recovery_password=os.environ["RECOVERY_PASSWORD"],
    endpoint="https://new.example",
    admin_token=Sealed(os.environ["ADMIN_TOKEN"]),
)
'''
    environment = os.environ.copy()
    environment.update(
        BACKUP=str(backup),
        BACKUP_PASSWORD="backup-password",
        RECOVERY_ROOT=str(profile.paths.root),
        RECOVERY_PASSWORD="recovery-password",
        ADMIN_TOKEN="SYNTHETIC-ADMIN-TOKEN",
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    stopped = subprocess.run(
        [sys.executable, "-c", child], env=environment, check=False
    )
    assert stopped.returncode == 78
    assert (profile.paths.root / "recovery-activation.json").exists()
    assert (profile.paths.root / "recovery-only").exists()

    result = recover_takeover(
        profile,
        recovery_password="recovery-password",
        endpoint="https://new.example",
        admin_token=Sealed("unused-on-local-resume"),
    )
    assert result.status == "active"
    assert not (profile.paths.root / "recovery-only").exists()
