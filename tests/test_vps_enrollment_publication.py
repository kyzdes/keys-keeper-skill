"""Enrollment compensation follows actual config publication, with fake keys."""
from __future__ import annotations

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from _vault_fakes import FakeBackend
from test_sync_vps import config
from keys_keeper import cli_sync_vps, secure_io
from keys_keeper.paths import Paths
from keys_keeper.private_files import PrivateFileCommitError
from keys_keeper.secure_io import SecureFileCommitError, SecureFileError
from keys_keeper.sync_protocol_v2 import generate_device_identity
from keys_keeper.sync_vps import SYNC_VPS_TOKEN, VpsSyncError, load_vps_config, save_vps_config


SENTINEL = "synthetic-post-publication-error-detail"


@pytest.mark.parametrize("stage", ["init", "join", "finish"])
def test_matching_credentials_survive_known_config_postpublication_error(tmp_path, monkeypatch, stage):
    identity = generate_device_identity("root-device")
    cfg = config("synthetic-vault", identity, identity, "root-device")
    paths = Paths(root=tmp_path / stage)
    backend = FakeBackend()
    if stage == "join":
        cfg = replace(cfg, status="pending", invite_id="synthetic-invite")
    elif stage == "finish":
        save_vps_config(replace(cfg, status="pending", invite_id="synthetic-invite"), paths)
        backend.d[SYNC_VPS_TOKEN] = "old-value"
    def fail_directory_sync(_directory):
        raise OSError(SENTINEL)
    monkeypatch.setattr(secure_io, "_fsync_parent_best_effort", fail_directory_sync)
    with pytest.raises(SecureFileCommitError) as raised:
        cli_sync_vps._save_enrollment(cfg, paths, backend, {SYNC_VPS_TOKEN: "matching-new-value"})
    assert raised.value.committed is True
    assert SENTINEL not in str(raised.value)
    assert load_vps_config(paths) == cfg
    assert backend.d == {SYNC_VPS_TOKEN: "matching-new-value"}


def test_config_prepublication_failure_restores_credential_beforeimage(tmp_path, monkeypatch):
    identity = generate_device_identity("root-device")
    cfg = config("synthetic-vault", identity, identity, "root-device")
    paths = Paths(root=tmp_path / "prepublication")
    backend = FakeBackend()
    backend.d[SYNC_VPS_TOKEN] = "previous"
    def before_publish(*_args):
        raise SecureFileError("configuration cannot be published")
    monkeypatch.setattr(cli_sync_vps, "save_vps_config", before_publish)
    with pytest.raises(SecureFileError):
        cli_sync_vps._save_enrollment(cfg, paths, backend,
                                      {SYNC_VPS_TOKEN: "new", "kk:other-synthetic-account": "new"})
    assert backend.d == {SYNC_VPS_TOKEN: "previous"}
    assert not (paths.root / "vps-sync.json").exists()


def test_marked_backend_set_failure_still_compensates_before_config_publication(tmp_path, monkeypatch):
    identity = generate_device_identity("root-device")
    cfg = config("synthetic-vault", identity, identity, "root-device")
    paths = Paths(root=tmp_path / "backend-fault")
    backend = FakeBackend()
    backend.d[SYNC_VPS_TOKEN] = "previous"
    original_set = backend.set
    failed = False
    def set_then_fail(account, value):
        nonlocal failed
        original_set(account, value)
        if not failed:
            failed = True
            raise PrivateFileCommitError("fake backend wrote before its completion fault")
    monkeypatch.setattr(backend, "set", set_then_fail)
    with pytest.raises(VpsSyncError) as raised:
        cli_sync_vps._save_enrollment(cfg, paths, backend, {SYNC_VPS_TOKEN: "new"})
    assert getattr(raised.value, "committed", None) is not True
    assert backend.d == {SYNC_VPS_TOKEN: "previous"}
    assert not (paths.root / "vps-sync.json").exists()


@pytest.mark.parametrize("rollback_complete", [True, False])
def test_cli_join_does_not_report_compensated_backend_marker_as_committed(kk_home, tmp_path, monkeypatch, capsys, rollback_complete):
    root = generate_device_identity("root-device")
    cfg = config("synthetic-vault", root, root, "root-device")
    invite = {
        "protocol": "KK2", "type": "device-invite", "endpoint": cfg.endpoint,
        "vault_id": cfg.vault_id, "root_device_id": cfg.root_device_id,
        "root_sign_public_key": cfg.root_sign_public_key, "inviter_device_id": cfg.device_id,
        "inviter_sign_public_key": cfg.sign_public_key, "invite_id": "synthetic-invite",
        "invite_secret": "s" * 43, "checkpoint_commit_id": None,
        "checkpoint_manifest_hash": None, "checkpoint_sequence": 0,
    }
    target = tmp_path / "join-invite.json"
    target.write_text(json.dumps(invite), encoding="utf-8")
    backend = FakeBackend()
    if not rollback_complete:
        backend.d[SYNC_VPS_TOKEN] = "previous"
    original_set = backend.set
    def set_then_fault(account, value):
        original_set(account, value)
        raise PrivateFileCommitError(SENTINEL)
    monkeypatch.setattr(backend, "set", set_then_fault)
    monkeypatch.setattr(cli_sync_vps, "build_backend", lambda: backend)
    monkeypatch.setattr(cli_sync_vps, "VpsSyncClient", lambda **_: pytest.fail("failed staging reached the network"))
    events = []
    monkeypatch.setattr(cli_sync_vps, "_audit", lambda _paths, **event: (events.append(event), "recorded")[1])
    args = SimpleNamespace(invite=str(target), proxy="direct",
                           trust_fingerprint=cli_sync_vps._invite_trust_fingerprint(invite))
    assert cli_sync_vps.cmd_vps_join(args) == 1
    output = capsys.readouterr()
    assert SENTINEL not in output.out + output.err
    receipt = next(json.loads(line) for line in output.err.splitlines() if line.startswith("{"))
    assert receipt["committed"] is None
    assert events[-1]["success"] is False
    assert backend.d == ({} if rollback_complete else {SYNC_VPS_TOKEN: "previous"})
    assert not (Paths(kk_home).root / "vps-sync.json").exists()


def test_cli_init_receipt_reports_published_enrollment_without_rolling_back_keys(kk_home, tmp_path, monkeypatch, capsys):
    identity = generate_device_identity("root-device")
    backend = FakeBackend()
    events = []
    monkeypatch.setattr(cli_sync_vps, "build_backend", lambda: backend)
    monkeypatch.setattr(cli_sync_vps, "generate_device_identity", lambda: identity)
    monkeypatch.setattr(cli_sync_vps.getpass, "getpass", lambda *_: "synthetic-admin-token")
    monkeypatch.setattr(cli_sync_vps, "_audit", lambda _paths, **event: (events.append(event), "recorded")[1])
    monkeypatch.setattr(cli_sync_vps, "VpsSyncClient", lambda **_kwargs: SimpleNamespace(
        create_vault=lambda **_payload: {"vault_id": "synthetic-vault", "device_id": "root-device"}))
    original_replace = secure_io.replace_secure_text
    def config_then_fault(state, text, **kwargs):
        original_replace(state, text, **kwargs)
        if state.path.name == "vps-sync.json":
            raise SecureFileCommitError(SENTINEL)
    monkeypatch.setattr("keys_keeper.sync_vps.replace_secure_text", config_then_fault)
    args = SimpleNamespace(recovery_file=str(tmp_path / "synthetic-recovery.json"),
                           endpoint="http://127.0.0.1:9419", proxy="direct", admin_token_entry=None)
    assert cli_sync_vps.cmd_vps_init(args) == 1
    output = capsys.readouterr()
    assert SENTINEL not in output.out + output.err
    receipt = next(json.loads(line) for line in output.err.splitlines() if line.startswith("{"))
    assert receipt["committed"] is True
    assert events[-1]["committed"] is True
    assert load_vps_config(Paths(kk_home)).device_id == "root-device"
    assert len(backend.d) == 4


@pytest.mark.parametrize("text", ['{"protocol":"KK2","type":"device-invite","type":"device-invite"}',
                                '{"protocol":"KK2","type":"device-invite","bad":NaN}'])
def test_ambiguous_invitation_json_rejected_before_provider_access(tmp_path, text):
    target = tmp_path / "synthetic-invite.json"
    target.write_text(text, encoding="utf-8")
    with pytest.raises(VpsSyncError, match="cannot read a valid device-invite"):
        cli_sync_vps._read_json_file(str(target), expected_type="device-invite")
