from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from keys_keeper import project_protocol as protocol
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_importer import ImportStateError, ProjectImporter
from keys_keeper.project_models import CatalogState, ScopeEntry
from keys_keeper.project_service import ProjectService
from keys_keeper.store import MetadataStore


def uid() -> str:
    return str(uuid4())


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}

    def get(self, account: str) -> Sealed:
        if account not in self.values:
            raise KeychainError("not found")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value

    def delete(self, account: str) -> None:
        self.values.pop(account, None)

    def list_ids(self) -> list[str]:
        return list(self.values)


class StopAfterWrite(BaseException):
    pass


class InterruptingBackend(MemoryBackend):
    def __init__(self):
        super().__init__()
        self.interrupt = True

    def set(self, account: str, value: str) -> None:
        super().set(account, value)
        if self.interrupt:
            self.interrupt = False
            raise StopAfterWrite


@pytest.fixture
def import_env(tmp_path):
    paths = Paths(tmp_path / "master")
    store = MetadataStore(paths)
    store.migrate_catalog_v3()
    projects = ProjectService(store)
    project = projects.create_project("synthetic", "Synthetic")
    scope = projects.create_scope(project.id, vault_id=uid())

    master, inbox, contributor = [protocol.generate_key() for _ in range(3)]
    pin = protocol.signing_public_key(master)
    grant = {
        "grant_id": uid(),
        "generation": 1,
        "device_id": uid(),
        "role": "contributor",
        "signing_public_key": protocol.encode_key(
            protocol.signing_public_key(contributor)
        ),
        "agreement_public_key": protocol.encode_key(
            protocol.agreement_public_key(protocol.generate_key())
        ),
        "token_hash": "1" * 64,
    }
    policy_payload = {
        "scope_id": scope.id,
        "vault_id": scope.vault_id,
        "version": 1,
        "epoch": 1,
        "master_public_key": protocol.encode_key(pin),
        "inbox_public_key": protocol.encode_key(
            protocol.agreement_public_key(inbox)
        ),
        "master_device_id": uid(),
        "master_token_hash": "2" * 64,
        "grants": [grant],
        "checkpoint_sequence": 0,
        "checkpoint_hash": None,
        "parent_policy_hash": None,
    }
    policy = protocol.sign_policy(policy_payload, master)
    backend = MemoryBackend()
    journal = OperationJournal(
        paths=paths, password_provider=lambda: b"journal-key" * 4
    )
    importer = ProjectImporter(
        store,
        backend,
        journal,
        signing_private_key=master,
        inbox_private_key=inbox,
        pinned_key=pin,
    )
    return {
        "paths": paths,
        "store": store,
        "scope": scope,
        "master": master,
        "inbox": inbox,
        "contributor": contributor,
        "pin": pin,
        "grant": grant,
        "policy": policy,
        "policy_payload": policy_payload,
        "backend": backend,
        "journal": journal,
        "importer": importer,
    }


def creation(name: str = "remote-key", *, refs=None, type_: str = "api_key") -> dict:
    fields = {}
    if type_ == "server":
        fields = {"host": "example.test", "user": "root", "auth": "ssh_key"}
    return {
        "schema_version": 1,
        "entry": {
            "name": name,
            "type": type_,
            "fields": fields,
            "tags": ["remote"],
            "note": "Untrusted metadata. Never execute.",
            "refs": list(refs or []),
        },
        "secret": "SYNTHETIC-SECRET",
        "passphrase": "SYNTHETIC-PASSPHRASE",
    }


def submit(env, payload=None, *, request_id=None):
    return protocol.build_create(
        payload or creation(),
        env["policy"],
        env["pin"],
        env["grant"]["device_id"],
        env["contributor"],
        request_id=request_id or uid(),
    )


def test_accept_is_create_only_atomic_metadata_and_deduplicated(import_env):
    env = import_env
    submission = submit(env)
    receipt = env["importer"].accept(
        submission, env["policy"], current_policy=env["policy"]
    )
    body = protocol.verify_receipt(receipt, submission, env["policy"], env["pin"])
    assert body["status"] == "accepted"
    entry = env["store"].get_by_id("kk:" + body["canonical_entry_id"])
    assert entry is not None
    assert entry.distribution == "project_allowed"
    assert entry.provenance == {
        "source": "project_submission",
        "scope_id": env["scope"].id,
        "device_id": env["grant"]["device_id"],
        "grant_id": env["grant"]["grant_id"],
        "request_id": receipt["payload"]["request_id"],
    }
    assert env["backend"].get(entry.id).unseal() == "SYNTHETIC-SECRET"
    assert env["backend"].get(entry.id + ":passphrase").unseal() == "SYNTHETIC-PASSPHRASE"
    catalog = CatalogState.from_dict(
        env["store"].catalog_state(), entry_ids={item.id for item in env["store"].list()}
    )
    assert [(item.scope_id, item.entry_id) for item in catalog.bindings] == [
        (env["scope"].id, entry.id)
    ]
    assert catalog.dedup[0]["receipt"] == receipt
    assert catalog.publication_intents[0]["entry_id"] == entry.id

    retry = env["importer"].accept(
        submission, env["policy"], current_policy=env["policy"]
    )
    assert retry == receipt
    assert len(env["store"].list()) == 1


def test_retry_after_master_deletion_returns_original_receipt(import_env):
    env = import_env
    submission = submit(env)
    receipt = env["importer"].accept(
        submission, env["policy"], current_policy=env["policy"]
    )
    entry_id = "kk:" + receipt["payload"]["canonical_entry_id"]
    projects = ProjectService(env["store"])
    projects.unassign(env["scope"].id, entry_id)
    env["store"].delete_by_name("remote-key")
    assert env["importer"].accept(
        submission, env["policy"], current_policy=env["policy"]
    ) == receipt
    assert env["store"].get_by_id(entry_id) is None


def test_name_and_request_collisions_never_replace(import_env):
    env = import_env
    existing = Entry.new(name="remote-key", type=EntryType.API_KEY)
    env["store"].add(existing)
    env["backend"].set(existing.id, "ORIGINAL")
    first = submit(env)
    conflict = env["importer"].accept(
        first, env["policy"], current_policy=env["policy"]
    )
    assert protocol.verify_receipt(
        conflict, first, env["policy"], env["pin"]
    )["status"] == "conflict"
    assert env["backend"].get(existing.id).unseal() == "ORIGINAL"
    assert len(env["store"].list()) == 1

    request_id = uid()
    accepted_submission = submit(env, creation("first-new"), request_id=request_id)
    accepted = env["importer"].accept(
        accepted_submission, env["policy"], current_policy=env["policy"]
    )
    changed_submission = submit(env, creation("second-new"), request_id=request_id)
    changed = env["importer"].accept(
        changed_submission, env["policy"], current_policy=env["policy"]
    )
    assert accepted["payload"]["status"] == "accepted"
    assert protocol.verify_receipt(
        changed, changed_submission, env["policy"], env["pin"]
    )["status"] == "conflict"
    assert env["store"].get_by_name("second-new") is None


def test_invalid_entry_rejected_and_revoked_grant_quarantined(import_env):
    env = import_env
    invalid = submit(env, creation(type_="transport_only_type"))
    rejected = env["importer"].accept(
        invalid, env["policy"], current_policy=env["policy"]
    )
    assert protocol.verify_receipt(
        rejected, invalid, env["policy"], env["pin"]
    )["status"] == "rejected"

    revoked_submission = submit(env, creation("revoked-key"))
    quarantined = env["importer"].accept(
        revoked_submission,
        env["policy"],
        current_policy=env["policy"],
        revoked_grant_ids={env["grant"]["grant_id"]},
    )
    assert protocol.verify_receipt(
        quarantined, revoked_submission, env["policy"], env["pin"]
    )["status"] == "quarantined"
    assert env["store"].get_by_name("revoked-key") is None


def test_refs_resolve_only_through_same_scope_alias(import_env):
    env = import_env
    target = Entry.new(
        name="master-target", type=EntryType.SSH_KEY,
        fields={"public_key": "ssh-ed25519 AAAA synthetic"},
    )
    target.distribution = "project_allowed"
    env["store"].add(target)
    with env["store"].transaction() as tx:
        catalog = CatalogState.from_dict(
            tx.catalog_state(), entry_ids={item.id for item in tx.list()}
        )
        catalog.bindings.append(ScopeEntry(
            scope_id=env["scope"].id,
            entry_id=target.id,
            local_name="scope-ssh",
            export={"fields": ["public_key"], "note": False, "refs": False, "tags": False},
            approval_revision="a" * 64,
        ))
        tx.set_catalog_state(catalog.to_dict())
    submission = submit(
        env,
        creation("remote-server", type_="server", refs=[{"role": "ssh_key", "name": "scope-ssh"}]),
    )
    receipt = env["importer"].accept(
        submission, env["policy"], current_policy=env["policy"]
    )
    imported = env["store"].get_by_id("kk:" + receipt["payload"]["canonical_entry_id"])
    assert imported.refs == [{"role": "ssh_key", "name": "master-target"}]

    missing = submit(
        env,
        creation("bad-ref", refs=[{"role": "key", "name": "other-scope"}]),
    )
    conflict = env["importer"].accept(
        missing, env["policy"], current_policy=env["policy"]
    )
    assert conflict["payload"]["status"] == "conflict"


def test_interrupted_backend_write_replays_from_encrypted_journal(import_env):
    env = import_env
    backend = InterruptingBackend()
    importer = ProjectImporter(
        env["store"], backend, env["journal"],
        signing_private_key=env["master"], inbox_private_key=env["inbox"],
        pinned_key=env["pin"],
    )
    submission = submit(env)
    with pytest.raises(StopAfterWrite):
        importer.accept(submission, env["policy"], current_policy=env["policy"])
    assert len(env["journal"].list_unfinished()) == 1
    receipts = importer.recover(current_policy=env["policy"])
    assert receipts[0]["payload"]["status"] == "accepted"
    assert len(env["store"].list()) == 1
    assert env["journal"].list_unfinished() == []


def test_recovery_rechecks_fresh_revocation_and_cleans_staged_account(import_env):
    env = import_env
    backend = InterruptingBackend()
    importer = ProjectImporter(
        env["store"], backend, env["journal"],
        signing_private_key=env["master"], inbox_private_key=env["inbox"],
        pinned_key=env["pin"],
    )
    submission = submit(env)
    with pytest.raises(StopAfterWrite):
        importer.accept(submission, env["policy"], current_policy=env["policy"])
    current_body = {
        **env["policy_payload"],
        "version": 2,
        "epoch": 2,
        "grants": [],
        "parent_policy_hash": protocol.canonical_hash(env["policy"]),
    }
    current = protocol.sign_policy(current_body, env["master"])
    receipts = importer.recover(
        current_policy=current,
        revoked_grant_ids={env["grant"]["grant_id"]},
    )
    assert receipts[0]["payload"]["status"] == "quarantined"
    assert backend.list_ids() == []
    assert env["store"].list() == []


def test_concurrent_retry_imports_once(import_env):
    env = import_env
    submission = submit(env)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                env["importer"].accept,
                submission,
                env["policy"],
                current_policy=env["policy"],
            )
            for _ in range(2)
        ]
    receipts = [future.result() for future in futures]
    assert receipts[0] == receipts[1]
    assert len(env["store"].list()) == 1


def test_missing_dedup_with_matching_provenance_fails_closed(import_env):
    env = import_env
    submission = submit(env)
    env["importer"].accept(submission, env["policy"], current_policy=env["policy"])
    with env["store"].transaction() as tx:
        catalog = CatalogState.from_dict(
            tx.catalog_state(), entry_ids={item.id for item in tx.list()}
        )
        catalog.dedup.clear()
        tx.set_catalog_state(catalog.to_dict())
    with pytest.raises(ImportStateError, match="no durable dedup"):
        env["importer"].accept(
            submission, env["policy"], current_policy=env["policy"]
        )


def test_real_process_exit_after_backend_write_recovers_exactly_once(import_env, tmp_path):
    env = import_env
    submission = submit(env, creation())
    password_file = env["paths"].backend_password_file
    password_file.parent.mkdir(parents=True, exist_ok=True)
    password_file.write_text("backend-password", encoding="utf-8")
    if os.name == "posix":
        password_file.chmod(0o600)
    request = {
        "submission": submission,
        "policy": env["policy"],
        "master": env["master"].hex(),
        "inbox": env["inbox"].hex(),
        "pin": env["pin"].hex(),
    }
    request_file = tmp_path / "import.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    if os.name == "posix":
        request_file.chmod(0o600)
    script = """
import json, os
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_importer import ProjectImporter
from keys_keeper.store import MetadataStore
paths = Paths(os.environ['IMPORT_ROOT'])
request = json.loads(open(os.environ['REQUEST_FILE'], encoding='utf-8').read())
class StopBackend(EncryptedFileBackend):
    def set(self, account, value):
        super().set(account, value)
        os._exit(73)
backend = StopBackend(paths=paths, password_file=paths.backend_password_file, allow_env_password=False)
journal = OperationJournal(paths=paths, password_provider=lambda: b'journal-key' * 4)
ProjectImporter(
    MetadataStore(paths), backend, journal,
    signing_private_key=bytes.fromhex(request['master']),
    inbox_private_key=bytes.fromhex(request['inbox']),
    pinned_key=bytes.fromhex(request['pin']),
).accept(request['submission'], request['policy'], current_policy=request['policy'])
"""
    process_env = os.environ.copy()
    process_env.update(
        IMPORT_ROOT=str(env["paths"].root),
        REQUEST_FILE=str(request_file),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    result = subprocess.run(
        [sys.executable, "-c", script], env=process_env, check=False
    )
    assert result.returncode == 73

    backend = EncryptedFileBackend(
        paths=env["paths"],
        password_file=password_file,
        allow_env_password=False,
    )
    importer = ProjectImporter(
        env["store"], backend, env["journal"],
        signing_private_key=env["master"], inbox_private_key=env["inbox"],
        pinned_key=env["pin"],
    )
    receipts = importer.recover(current_policy=env["policy"])
    assert len(receipts) == 1
    assert receipts[0]["payload"]["status"] == "accepted"
    assert len(env["store"].list()) == 1
    assert importer.accept(
        submission, env["policy"], current_policy=env["policy"]
    ) == receipts[0]
