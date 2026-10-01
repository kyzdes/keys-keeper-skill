"""Replica KDF reuse never substitutes stale plaintext for fresh GCM reads."""
import json
import os
import pickle
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys_keeper import crypto
from keys_keeper.operation_journal import _atomic_write_bytes
from keys_keeper.paths import Paths
from keys_keeper.project_replica import ReplicaError, ReplicaStore
from keys_keeper.project_runtime import ProjectRuntime
from keys_keeper.personal_sync import PersonalSync, _save_settings


@pytest.fixture
def replica(tmp_path):
    paths = Paths(tmp_path / "replica")
    scope, vault = str(uuid4()), str(uuid4())
    payload = {"schema_version": 1, "scope_id": scope, "source_revision": "a" * 64, "entries": []}
    checkpoint = {"scope_id": scope, "vault_id": vault, "epoch": 1, "policy_version": 1,
                  "policy_hash": "b" * 64, "sequence": 1, "parent_hash": None, "snapshot_hash": "c" * 64}
    writer = ReplicaStore(paths=paths, password_provider=lambda: "synthetic-key")
    writer.install(payload, checkpoint)
    reader = ReplicaStore(paths=paths, password_provider=lambda: "synthetic-key",
                          expected_identity={"scope_id": scope, "vault_id": vault})
    return reader, writer, payload, checkpoint


def test_concurrent_replica_reads_derive_once_and_authenticate_each_read(replica, monkeypatch):
    reader, _, payload, checkpoint = replica
    derive, decrypt = crypto._derive_key, crypto._decrypt_blob_with_key
    calls, authentications = [], []
    def counted(*args):
        calls.append(True)
        return derive(*args)
    def authenticate(*args, **kwargs):
        authentications.append(True)
        return decrypt(*args, **kwargs)
    monkeypatch.setattr(crypto, "_derive_key", counted)
    monkeypatch.setattr(crypto, "_decrypt_blob_with_key", authenticate)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: reader.load(), range(8)))
    assert all(result == (payload, checkpoint) for result in results)
    assert len(calls) == 1 and len(authentications) == 8
    results[0][0]["source_revision"] = "mutable-result"
    assert reader.load()[0] == payload
    with pytest.raises(TypeError, match="process-local"):
        pickle.dumps(reader)


def test_external_generation_install_is_visible_with_one_new_salt_kdf(replica, monkeypatch):
    reader, writer, payload, checkpoint = replica
    reader.load()
    updated_payload = {**payload, "source_revision": "d" * 64}
    updated_checkpoint = {**checkpoint, "sequence": 2, "snapshot_hash": "e" * 64,
                          "parent_hash": checkpoint["snapshot_hash"]}
    writer.install(updated_payload, updated_checkpoint)
    calls = []
    derive = crypto._derive_key
    monkeypatch.setattr(crypto, "_derive_key", lambda *args: calls.append(True) or derive(*args))
    assert reader.load() == (updated_payload, updated_checkpoint)
    assert len(calls) == 1


def test_same_salt_rewrite_and_same_stat_corruption_never_return_cached_payload(replica):
    reader, _, payload, checkpoint = replica
    reader.load()
    path = reader.current_generation_path()
    before, blob = path.stat(), path.read_bytes()
    key = crypto._derive_key("synthetic-key", blob[4:20])
    raw = json.loads(crypto._decrypt_blob_with_key(blob, key=key))
    raw["payload"]["source_revision"] = "f" * 64
    nonce = b"q" * 12
    updated = blob[:20] + nonce + AESGCM(key).encrypt(nonce, json.dumps(raw).encode(), blob[:4])
    _atomic_write_bytes(path, updated)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert reader.load()[0]["source_revision"] == "f" * 64
    damaged = bytearray(updated)
    damaged[-1] ^= 1
    path.write_bytes(damaged)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    with pytest.raises(ReplicaError):
        reader.load()
    assert reader._derived_key_cache is None
    _atomic_write_bytes(path, blob)
    assert reader.load() == (payload, checkpoint)


def test_authenticated_generation_wrong_selected_scope_is_rejected(replica):
    reader, _, payload, checkpoint = replica
    wrong = ReplicaStore(paths=reader.paths, password_provider=lambda: "synthetic-key",
                         expected_identity={"scope_id": str(uuid4()), "vault_id": checkpoint["vault_id"]})
    with pytest.raises(ReplicaError, match="selected profile"):
        wrong.load()
    assert wrong._derived_key_cache is None
    with pytest.raises(ReplicaError, match="selected profile"):
        wrong.install(payload, checkpoint)


def test_runtime_replica_cache_bounded_by_immutable_identity(tmp_path):
    runtime = ProjectRuntime(Paths(tmp_path))
    def item():
        return {"id": str(uuid4()), "kind": "replica", "scope_id": str(uuid4()), "vault_id": str(uuid4()),
                "device_id": str(uuid4()), "endpoint": "https://relay.example"}
    first_item = item()
    first = runtime.replica_store(first_item)
    assert runtime.replica_store(dict(first_item)) is first
    changed = {**first_item, "vault_id": str(uuid4())}
    assert runtime.replica_store(changed) is not first
    for _ in range(32):
        runtime.replica_store(item())
    assert len(runtime._replica_stores) == 32
    assert runtime.replica_store(first_item) is not first
    assert ProjectRuntime(Paths(tmp_path)).replica_store(first_item) is not first
    current = runtime.replica_store(first_item)
    runtime.paths = Paths(tmp_path / "other-root")
    assert runtime.replica_store(first_item) is not current


def test_actual_personal_worker_context_reuses_shared_child_runtime(tmp_path):
    paths = Paths(tmp_path)
    root = ProjectRuntime(paths)
    scope, replica_id = str(uuid4()), str(uuid4())
    settings = {"version": 1, "role": "replica", "scope_id": scope,
                "endpoint": "https://relay.example", "auto": False,
                "name": "Synthetic", "replica_id": replica_id}
    _save_settings(paths, settings)
    child = PersonalSync(paths, root).runtime()
    item = {"id": replica_id, "kind": "replica", "scope_id": scope, "vault_id": str(uuid4()),
            "device_id": str(uuid4()), "endpoint": settings["endpoint"], "project": "synthetic",
            "environment": "personal", "status": "active"}
    child.registry.put(item, make_default=True)
    assert root.context().runtime is child
    assert root.context().runtime is child
    assert PersonalSync(paths, root).runtime() is child
    settings["replica_id"] = str(uuid4())
    _save_settings(paths, settings)
    replacement = PersonalSync(paths, root).runtime()
    replacement.registry.put({**item, "id": settings["replica_id"]}, make_default=True)
    assert root.context().runtime is replacement
    assert replacement is not child
    (paths.root / "personal-sync.json").unlink()
    assert root.context().runtime is root
    assert root._personal_child_runtime is None
