from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from keys_keeper.backend import KeychainError
from keys_keeper.paths import Paths
from keys_keeper.project_replica import (
    NoReplicaGeneration,
    ReplicaError,
    ReplicaReadOnlyError,
    ReplicaStore,
)


def uid() -> str:
    return str(uuid4())


def entry(name: str = "replica-key", *, id_: str | None = None, refs=None) -> dict:
    return {
        "id": id_ or "kk:" + uid(),
        "name": name,
        "type": "api_key",
        "fields": {},
        "tags": ["projected"],
        "note": "Untrusted projected metadata",
        "refs": list(refs or []),
        "created_at": "2026-09-05T10:00:00Z",
        "updated_at": "2026-09-05T10:00:00Z",
        "secret": "SYNTHETIC-REPLICA-SECRET",
        "passphrase": None,
    }


def payload(scope_id: str, *, entries=None, revision: str = "a" * 64) -> dict:
    return {
        "schema_version": 1,
        "scope_id": scope_id,
        "source_revision": revision,
        "entries": [entry()] if entries is None else entries,
    }


def checkpoint(
    scope_id: str,
    vault_id: str,
    *,
    sequence: int = 1,
    snapshot_hash: str = "1" * 64,
    parent_hash: str | None = None,
) -> dict:
    return {
        "scope_id": scope_id,
        "vault_id": vault_id,
        "epoch": 1,
        "policy_version": 1,
        "policy_hash": "2" * 64,
        "sequence": sequence,
        "parent_hash": parent_hash,
        "snapshot_hash": snapshot_hash,
    }


@pytest.fixture
def replica(tmp_path):
    return ReplicaStore(
        paths=Paths(tmp_path / "replica"),
        password_provider=lambda: b"r" * 32,
    )


def test_empty_replica_and_install_read_only_adapters(replica):
    with pytest.raises(NoReplicaGeneration):
        replica.load()
    scope_id, vault_id = uid(), uid()
    projected = payload(scope_id)
    trusted = checkpoint(scope_id, vault_id)
    replica.install(projected, trusted)

    loaded, loaded_checkpoint = replica.load()
    assert loaded == projected
    assert loaded_checkpoint == trusted
    metadata = replica.metadata_store()
    item = metadata.get_by_name("replica-key")
    assert item is not None
    assert metadata.get_by_id(item.id) == item
    with pytest.raises(ReplicaReadOnlyError):
        metadata.add(item)
    with pytest.raises(ReplicaReadOnlyError):
        metadata.transaction()
    backend = replica.backend()
    assert backend.get(item.id).unseal() == "SYNTHETIC-REPLICA-SECRET"
    assert backend.list_ids() == [item.id]
    with pytest.raises(ReplicaReadOnlyError):
        backend.set(item.id, "replacement")
    with pytest.raises(ReplicaReadOnlyError):
        backend.delete(item.id)
    with pytest.raises(KeychainError):
        backend.get(item.id + ":passphrase")

    generation = replica.current_generation_path()
    assert generation.name == "1" * 64 + ".enc"
    assert b"SYNTHETIC-REPLICA-SECRET" not in generation.read_bytes()
    if os.name == "posix":
        assert stat.S_IMODE(generation.stat().st_mode) == 0o600
        assert stat.S_IMODE(replica.paths.root.stat().st_mode) == 0o700


def test_snapshot_allowlist_refs_and_identity_are_strict(replica):
    scope_id, vault_id = uid(), uid()
    extra = payload(scope_id)
    extra["other_projects"] = []
    with pytest.raises(ReplicaError, match="payload fields"):
        replica.install(extra, checkpoint(scope_id, vault_id))

    outside = payload(
        scope_id,
        entries=[entry("server-key", refs=[{"role": "key", "name": "missing"}])],
    )
    with pytest.raises(ReplicaError, match="leaves"):
        replica.install(outside, checkpoint(scope_id, vault_id))

    duplicate = entry("duplicate")
    with pytest.raises(ReplicaError, match="identity"):
        replica.install(
            payload(scope_id, entries=[duplicate, dict(duplicate)]),
            checkpoint(scope_id, vault_id),
        )

    reserved = entry(id_="kk:sync-passphrase")
    with pytest.raises(ReplicaError, match="metadata"):
        replica.install(
            payload(scope_id, entries=[reserved]), checkpoint(scope_id, vault_id)
        )

    with pytest.raises(ReplicaError, match="scope mismatch"):
        replica.install(payload(scope_id), checkpoint(uid(), vault_id))


def test_generation_transition_rejects_replay_fork_and_wrong_parent(replica):
    scope_id, vault_id = uid(), uid()
    replica.install(payload(scope_id), checkpoint(scope_id, vault_id))
    with pytest.raises(ReplicaError, match="forked"):
        replica.install(
            payload(scope_id, revision="b" * 64),
            checkpoint(scope_id, vault_id, snapshot_hash="3" * 64),
        )
    with pytest.raises(ReplicaError, match="does not extend"):
        replica.install(
            payload(scope_id, revision="c" * 64),
            checkpoint(
                scope_id,
                vault_id,
                sequence=2,
                snapshot_hash="4" * 64,
                parent_hash="9" * 64,
            ),
        )

    second = checkpoint(
        scope_id,
        vault_id,
        sequence=2,
        snapshot_hash="4" * 64,
        parent_hash="1" * 64,
    )
    replica.install(payload(scope_id, revision="d" * 64), second)
    with pytest.raises(ReplicaError, match="regressed"):
        replica.install(payload(scope_id), checkpoint(scope_id, vault_id))


def test_verified_ancestor_allows_checked_multi_snapshot_skip_only_from_active(replica):
    scope_id, vault_id = uid(), uid()
    first = checkpoint(scope_id, vault_id)
    replica.install(payload(scope_id), first)
    skipped = checkpoint(
        scope_id,
        vault_id,
        sequence=3,
        snapshot_hash="5" * 64,
        parent_hash="4" * 64,
    )
    replica.install(
        payload(scope_id, revision="e" * 64),
        skipped,
        verified_ancestor=first,
    )
    assert replica.load()[1] == skipped

    wrong_anchor = {**skipped, "snapshot_hash": "6" * 64}
    fourth = checkpoint(
        scope_id,
        vault_id,
        sequence=4,
        snapshot_hash="7" * 64,
        parent_hash="5" * 64,
    )
    with pytest.raises(ReplicaError, match="does not match active"):
        replica.install(
            payload(scope_id, revision="f" * 64),
            fourth,
            verified_ancestor=wrong_anchor,
        )


def test_same_checkpoint_cannot_install_different_plaintext(replica):
    scope_id, vault_id = uid(), uid()
    trusted = checkpoint(scope_id, vault_id)
    replica.install(payload(scope_id), trusted)
    with pytest.raises(ReplicaError, match="does not match"):
        replica.install(payload(scope_id, entries=[entry("different")]), trusted)


def test_pointer_failure_keeps_old_generation_and_outbox(replica, monkeypatch):
    scope_id, vault_id = uid(), uid()
    first = payload(scope_id)
    replica.install(first, checkpoint(scope_id, vault_id))
    replica.paths.pending_dir.mkdir(mode=0o700)
    outbox = replica.paths.pending_dir / "outbox.enc"
    outbox.write_bytes(b"opaque-outbox")

    from keys_keeper import project_replica

    real_write = project_replica._atomic_write_bytes

    def fail_pointer(path, data):
        if path == replica.paths.active_generation:
            raise OSError("injected pointer failure")
        return real_write(path, data)

    monkeypatch.setattr(project_replica, "_atomic_write_bytes", fail_pointer)
    with pytest.raises(OSError, match="pointer failure"):
        replica.install(
            payload(scope_id, revision="b" * 64),
            checkpoint(
                scope_id,
                vault_id,
                sequence=2,
                snapshot_hash="3" * 64,
                parent_hash="1" * 64,
            ),
        )
    assert replica.load()[0] == first
    assert outbox.read_bytes() == b"opaque-outbox"


def test_real_process_exit_before_pointer_preserves_old_generation(tmp_path):
    root = tmp_path / "replica"
    store = ReplicaStore(paths=Paths(root), password_provider=lambda: b"r" * 32)
    scope_id, vault_id = uid(), uid()
    first = payload(scope_id)
    store.install(first, checkpoint(scope_id, vault_id))
    request = {
        "payload": payload(scope_id, revision="b" * 64),
        "checkpoint": checkpoint(
            scope_id,
            vault_id,
            sequence=2,
            snapshot_hash="3" * 64,
            parent_hash="1" * 64,
        ),
    }
    request_file = tmp_path / "install.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    if os.name == "posix":
        request_file.chmod(0o600)
    script = """
import json, os
from keys_keeper.paths import Paths
from keys_keeper.project_replica import ReplicaStore
import keys_keeper.project_replica as module
root = Paths(os.environ['REPLICA_ROOT'])
request = json.loads(open(os.environ['REQUEST_FILE'], encoding='utf-8').read())
real = module._atomic_write_bytes
def stop_before_pointer(path, data):
    if path == root.active_generation:
        os._exit(72)
    return real(path, data)
module._atomic_write_bytes = stop_before_pointer
ReplicaStore(paths=root, password_provider=lambda: b'r' * 32).install(
    request['payload'], request['checkpoint']
)
"""
    env = os.environ.copy()
    env.update(
        REPLICA_ROOT=str(root),
        REQUEST_FILE=str(request_file),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    result = subprocess.run([sys.executable, "-c", script], env=env, check=False)
    assert result.returncode == 72
    assert store.load()[0] == first
    assert (root / "generations" / ("3" * 64 + ".enc")).exists()


def test_wrong_at_rest_key_and_corrupt_pointer_fail_closed(tmp_path):
    root = Paths(tmp_path / "replica")
    scope_id, vault_id = uid(), uid()
    ReplicaStore(paths=root, password_provider=lambda: b"right").install(
        payload(scope_id), checkpoint(scope_id, vault_id)
    )
    with pytest.raises(ReplicaError, match="cannot read"):
        ReplicaStore(paths=root, password_provider=lambda: b"wrong").load()
    root.active_generation.write_text("../master\n", encoding="ascii")
    root.active_generation.chmod(0o600)
    with pytest.raises(ReplicaError, match="pointer"):
        ReplicaStore(paths=root, password_provider=lambda: b"right").load()
