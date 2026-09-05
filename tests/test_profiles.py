from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest

from keys_keeper import composition
from keys_keeper.backend import KeychainError
from keys_keeper.paths import Paths
from keys_keeper.profiles import (
    MASTER_BACKEND_SERVICE,
    MASTER_PROFILE_ID,
    ProfileContext,
    ProfileKind,
)


def _password_file(profile: ProfileContext, value: str) -> None:
    profile.paths.service_keys_dir.mkdir(parents=True, mode=0o700)
    profile.paths.backend_password_file.write_text(value, encoding="utf-8")
    if os.name == "posix":
        profile.paths.backend_password_file.chmod(0o600)


def test_default_master_preserves_legacy_paths_and_service(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    profile = ProfileContext.master()
    assert profile.kind is ProfileKind.MASTER
    assert profile.profile_id == MASTER_PROFILE_ID
    assert profile.scope_id is None
    assert profile.paths == Paths()
    assert profile.backend_service == MASTER_BACKEND_SERVICE == "keys-keeper"


def test_replica_uses_uuid_paths_and_backend_namespace(tmp_path):
    profile_id = UUID("11111111-1111-4111-8111-111111111111")
    scope_id = UUID("22222222-2222-4222-8222-222222222222")
    profile = ProfileContext.replica(
        profile_id, scope_id=scope_id, base_paths=Paths(tmp_path / "kk")
    )
    assert profile.paths.root == tmp_path / "kk" / "profiles" / str(profile_id)
    assert profile.backend_service == f"keys-keeper:profile:{profile_id}"
    assert profile.scope_id == scope_id


@pytest.mark.parametrize(
    "invalid",
    ["../master", "not-a-uuid", "11111111111141118111111111111111", "../../etc/passwd"],
)
def test_invalid_profile_id_refuses_without_fallback(tmp_path, invalid):
    base = Paths(tmp_path / "kk")
    with pytest.raises(ValueError, match="canonical UUID"):
        ProfileContext.replica(invalid, scope_id=str(uuid4()), base_paths=base)
    assert not base.root.exists()


def test_invalid_scope_id_refuses_without_creating_profile(tmp_path):
    base = Paths(tmp_path / "kk")
    with pytest.raises(ValueError, match="canonical UUID"):
        ProfileContext.replica(uuid4(), scope_id="../master", base_paths=base)
    assert not base.root.exists()


def test_explicit_profile_rejects_paths_or_service_override(tmp_path):
    profile = ProfileContext.replica(
        uuid4(), scope_id=uuid4(), base_paths=Paths(tmp_path / "kk")
    )
    with pytest.raises(ValueError, match="owns its paths"):
        composition.build_backend(profile=profile, service="other")
    with pytest.raises(ValueError, match="owns its paths"):
        composition.build_backend(profile=profile, paths=Paths(tmp_path / "other"))


def test_two_replica_namespaces_isolate_same_logical_account(tmp_path, monkeypatch):
    monkeypatch.setattr(composition.sys, "platform", "linux")
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "file")
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", "must-not-unlock-replicas")
    base = Paths(tmp_path / "kk")
    left = ProfileContext.replica(uuid4(), scope_id=uuid4(), base_paths=base)
    right = ProfileContext.replica(uuid4(), scope_id=uuid4(), base_paths=base)
    _password_file(left, "left-password")
    _password_file(right, "right-password")

    left_backend = composition.build_backend(profile=left)
    right_backend = composition.build_backend(profile=right)
    left_backend.set("kk:same-account", "left-value")
    right_backend.set("kk:same-account", "right-value")

    assert left_backend.get("kk:same-account").unseal() == "left-value"
    assert right_backend.get("kk:same-account").unseal() == "right-value"
    assert left_backend.service != right_backend.service
    assert left_backend.paths.secrets_enc != right_backend.paths.secrets_enc


def test_replica_does_not_reuse_master_environment_password(tmp_path, monkeypatch):
    monkeypatch.setattr(composition.sys, "platform", "linux")
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "file")
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", "master-password")
    profile = ProfileContext.replica(
        uuid4(), scope_id=uuid4(), base_paths=Paths(tmp_path / "kk")
    )
    backend = composition.build_backend(profile=profile)
    with pytest.raises(KeychainError, match="unlock source"):
        backend.set("kk:test", "value")
    assert not profile.paths.secrets_enc.exists()


def test_profile_ui_forbidden_backend_never_enables_dialog(tmp_path, monkeypatch):
    captured = {}

    class FakeBackend:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(composition, "MacOSKeychainBackend", FakeBackend)
    monkeypatch.setattr(composition.sys, "platform", "darwin")
    profile = ProfileContext.replica(
        uuid4(), scope_id=uuid4(), base_paths=Paths(tmp_path / "kk")
    )
    composition.build_backend(
        profile=profile, access=composition.AccessContext.UI_FORBIDDEN
    )
    assert captured["service"] == profile.backend_service
    assert captured["allow_interaction"] is False
    assert captured["allow_legacy_bridge"] is False
