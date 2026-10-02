"""Authenticated state from another selected profile is still unauthorized."""
from uuid import uuid4

import pytest

from keys_keeper.operation_journal import _atomic_write_bytes
from keys_keeper.paths import Paths
from keys_keeper.project_runtime import ProjectRuntime, RuntimeErrorSafe
from keys_keeper.project_sync import ProjectSyncError, _STATE_ID, new_master_state


def _profile():
    scope, vault = str(uuid4()), str(uuid4())
    state = new_master_state(scope, vault, "http://127.0.0.1:1")
    item = {"id": scope, "kind": "master_scope", "scope_id": scope, "vault_id": vault,
            "device_id": state["device_id"], "endpoint": state["endpoint"]}
    return item, state


def test_swapped_authenticated_ciphertext_cannot_cross_selected_profile(tmp_path, monkeypatch):
    runtime = ProjectRuntime(Paths(tmp_path))
    monkeypatch.setattr(runtime, "_profile_password", lambda item: "synthetic-shared-master-key")
    first, second = _profile(), _profile()
    left, right = runtime.state(first[0]), runtime.state(second[0])
    left.save(first[1])
    right.save(second[1])
    assert left.load()["scope_id"] == first[0]["scope_id"]
    _atomic_write_bytes(left.paths.operations_dir / f"{_STATE_ID}.enc",
                        (right.paths.operations_dir / f"{_STATE_ID}.enc").read_bytes())
    with pytest.raises(ProjectSyncError, match="selected profile"):
        left.load()
    with pytest.raises(ProjectSyncError, match="selected profile"):
        left.save(second[1])


@pytest.mark.parametrize("field,value", [("mode", "replica"), ("scope_id", "wrong"), ("vault_id", "wrong")])
def test_wrong_identity_save_rejected_before_password(tmp_path, monkeypatch, field, value):
    runtime = ProjectRuntime(Paths(tmp_path))
    monkeypatch.setattr(runtime, "_profile_password", lambda item: pytest.fail("wrong state unlocked"))
    item, data = _profile()
    data[field] = value
    with pytest.raises(ProjectSyncError):
        runtime.state(item).save(data)


def test_mutation_manager_retained_but_backend_role_and_root_always_rechecked(tmp_path, monkeypatch):
    backend = object()
    runtime = ProjectRuntime(Paths(tmp_path), backend=backend)
    first = runtime.mutations()
    assert runtime.mutations() is first
    runtime._backend = object()
    second = runtime.mutations()
    assert second is not first
    assert runtime.mutations() is second
    monkeypatch.setattr(runtime.registry, "list", lambda: [{"kind": "replica"}])
    with pytest.raises(RuntimeErrorSafe, match="worker root"):
        runtime.mutations()
    assert runtime._mutation_manager is None
    monkeypatch.setattr(runtime.registry, "list", lambda: [])
    _atomic_write_bytes(runtime.paths.root / "recovery-only", b"synthetic marker")
    with pytest.raises(RuntimeErrorSafe, match="recovery"):
        runtime.mutations()
    assert runtime._mutation_manager is None
    (runtime.paths.root / "recovery-only").unlink()
    runtime.paths = Paths(tmp_path / "other-root")
    with pytest.raises(RuntimeErrorSafe, match="root changed"):
        runtime.mutations()
    assert runtime._mutation_manager is None
