"""Committed outcomes stay honest at every CLI adapter, with synthetic sinks."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from keys_keeper import cli, cli_catalog, cli_devices, cli_keychain, cli_project_sync, cli_sync_vps, ssh_runner
from keys_keeper.backend import Sealed, SecretAccessDenied, SecretUnavailable
from keys_keeper.composition import AccessContext
from keys_keeper.keychain_config import BYPASS, load_keychain_config
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.private_files import PrivateFileCommitError
from keys_keeper.project_backup import ProjectBackupCommitError
from keys_keeper.project_service import ProjectService
from keys_keeper.store import MetadataStore


SENTINEL = "synthetic-exception-detail-must-not-cross-adapters"


class Audit:
    events = []
    unavailable = False

    def __init__(self, *_args):
        pass

    def record(self, **event):
        if self.unavailable:
            raise OSError(SENTINEL)
        self.events.append(event)


@pytest.fixture
def isolated(kk_home, monkeypatch):
    monkeypatch.setattr(cli_keychain, "_require_macos", lambda: True)
    Audit.events = []
    Audit.unavailable = False
    for adapter in (cli_keychain, cli_catalog, cli_sync_vps):
        monkeypatch.setattr(adapter, "AuditLog", Audit)
    return Paths(kk_home)


def receipt(captured):
    assert SENTINEL not in captured.out + captured.err
    return [json.loads(line) for line in captured.err.splitlines() if line.startswith("{")][-1]


def test_keychain_policy_commit_survives_audit_failure(isolated, capsys):
    Audit.unavailable = True
    assert cli_keychain._set_mode(BYPASS) == 0
    assert load_keychain_config(isolated).mode == BYPASS
    assert receipt(capsys.readouterr())["committed"] is True


def _prepare(isolated, monkeypatch, *, preflight_error=None, commit_error=None):
    entry = Entry.new(name="prepared-key", type=EntryType.API_KEY)
    MetadataStore(isolated).add(entry)
    calls = []

    def build(*, access):
        calls.append(access)
        if access is AccessContext.UI_FORBIDDEN:
            def preflight(_account):
                if preflight_error:
                    raise preflight_error
                return "needs-preparation"
            return SimpleNamespace(native_access_state=preflight)
        def commit(_account):
            if commit_error:
                raise commit_error
            calls.append("committed")
            return True
        return SimpleNamespace(prepare_native_access=commit)
    monkeypatch.setattr("keys_keeper.composition.build_backend", build)
    return SimpleNamespace(name=entry.name, check=False), calls


def test_keychain_acl_commit_survives_audit_failure(isolated, capsys, monkeypatch):
    args, calls = _prepare(isolated, monkeypatch)
    Audit.unavailable = True
    assert cli_keychain.cmd_keychain_prepare(args) == 0
    assert "committed" in calls
    assert receipt(capsys.readouterr())["committed"] is True


def test_keychain_prepare_preflight_denial_stops_before_interactive_access(isolated, capsys, monkeypatch):
    args, calls = _prepare(isolated, monkeypatch, preflight_error=SecretAccessDenied(SENTINEL))
    assert cli_keychain.cmd_keychain_prepare(args) == 1
    assert calls == [AccessContext.UI_FORBIDDEN]
    assert receipt(capsys.readouterr())["committed"] is False
    assert Audit.events[-1]["error"] == "operation failed"


def test_keychain_prepare_typed_commit_error_is_preserved(isolated, capsys, monkeypatch):
    args, _calls = _prepare(isolated, monkeypatch, commit_error=PrivateFileCommitError(SENTINEL))
    assert cli_keychain.cmd_keychain_prepare(args) == 1
    assert receipt(capsys.readouterr())["committed"] is True
    assert Audit.events[-1]["success"] is True


def test_keychain_metadata_probe_hides_provider_error(isolated, capsys, monkeypatch):
    monkeypatch.setattr("keys_keeper.composition.build_backend",
                        lambda **_kwargs: (_ for _ in ()).throw(SecretAccessDenied(SENTINEL)))
    assert cli_keychain.cmd_keychain_status(SimpleNamespace(check=True)) == 1
    captured = capsys.readouterr()
    assert "metadata probe failed" in captured.err
    assert SENTINEL not in captured.out + captured.err


@pytest.mark.parametrize("error,committed", [
    (ProjectBackupCommitError(SENTINEL), True), (RuntimeError(SENTINEL), None),
])
def test_project_adapter_preserves_publication_outcome(isolated, capsys, monkeypatch, error, committed):
    monkeypatch.setattr(cli_project_sync, "_run", lambda *_: (_ for _ in ()).throw(error))
    assert cli_project_sync.command(SimpleNamespace(project_action="backup")) == 1
    assert receipt(capsys.readouterr())["committed"] is committed


def test_personal_adapter_preserves_publication_outcome(isolated, capsys, monkeypatch):
    monkeypatch.setattr(cli_devices, "PersonalSync", lambda *_: SimpleNamespace(
        sync=lambda: (_ for _ in ()).throw(PrivateFileCommitError(SENTINEL))))
    assert cli_devices.command(SimpleNamespace(devices_command="sync")) == 1
    assert receipt(capsys.readouterr())["committed"] is True


@pytest.mark.parametrize("action", ["push", "pull"])
def test_vps_committed_sync_survives_audit_failure(isolated, capsys, monkeypatch, action):
    calls = []
    engine = SimpleNamespace(**{action: lambda: calls.append(action) or 2})
    monkeypatch.setattr(cli_sync_vps, "_engine", lambda *_: (engine, SimpleNamespace(endpoint="https://example.test"), None))
    Audit.unavailable = True
    assert getattr(cli_sync_vps, "cmd_vps_" + action)(SimpleNamespace()) == 0
    assert calls == [action]
    assert receipt(capsys.readouterr())["committed"] is True


def test_vps_provider_failure_is_redacted_and_audited(isolated, capsys, monkeypatch):
    monkeypatch.setattr(cli_sync_vps, "_engine",
                        lambda *_: (_ for _ in ()).throw(SecretAccessDenied(SENTINEL)))
    assert cli_sync_vps.cmd_vps_push(SimpleNamespace()) == 1
    assert receipt(capsys.readouterr())["committed"] is None
    assert Audit.events[-1]["success"] is False
    assert Audit.events[-1]["error"] == "operation failed"


def test_vps_revoke_local_refresh_failure_reports_remote_commit(isolated, capsys, monkeypatch):
    calls = []
    engine = SimpleNamespace(verified_head=lambda: None,
                             signing_private_key=b"x" * 32,
                             client=SimpleNamespace(revoke_device=lambda *_args, **_kwargs: calls.append("remote-committed")),
                             refresh_trust_anchor=lambda: (_ for _ in ()).throw(RuntimeError(SENTINEL)))
    config = SimpleNamespace(device_id="root", root_device_id="root", vault_id="vault",
                             endpoint="https://example.test")
    backend = SimpleNamespace(get=lambda _account: Sealed(SENTINEL))
    monkeypatch.setattr(cli_sync_vps, "_engine", lambda *_: (engine, config, backend))
    monkeypatch.setattr(cli_sync_vps, "make_revocation_statement", lambda **_kwargs: {})
    monkeypatch.setattr(cli_sync_vps, "_unb64", lambda *_args, **_kwargs: b"x" * 32)
    monkeypatch.setattr(cli_sync_vps, "sign_revocation", lambda *_args: "synthetic-signature")
    assert cli_sync_vps.cmd_vps_revoke(SimpleNamespace(device_id="worker")) == 1
    assert calls == ["remote-committed"]
    assert receipt(capsys.readouterr())["committed"] is True
    assert Audit.events[-1]["success"] is True


def test_folder_assignment_uses_shared_service_and_survives_audit_failure(isolated, capsys):
    store = MetadataStore(isolated)
    store.migrate_catalog_v3()
    entry = Entry.new(name="catalog-domain", type=EntryType.DOMAIN, fields={"host": "example.test"})
    store.add(entry)
    folder = ProjectService(store).create_folder("Test folder")
    Audit.unavailable = True
    assert cli_catalog.cmd_folders(SimpleNamespace(folders_command="assign-entry", entry_id=entry.name,
                                                  folder_id=folder.id, json=True)) == 0
    assert store.get_by_id(entry.id).folder_id == folder.id
    assert receipt(capsys.readouterr())["committed"] is True


def test_catalog_output_failure_keeps_committed_receipt(isolated, capsys, monkeypatch):
    store = MetadataStore(isolated)
    store.migrate_catalog_v3()
    monkeypatch.setattr(cli_catalog, "_emit", lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError(SENTINEL)))
    assert cli_catalog.cmd_folders(SimpleNamespace(folders_command="create", name="New folder",
                                                  parent=None, position=None, json=True)) == 1
    assert len([folder for folder in ProjectService(store).list_folders()
                if folder.name == "New folder"]) == 1
    assert receipt(capsys.readouterr())["committed"] is True


def test_catalog_provider_exception_is_redacted(isolated, capsys, monkeypatch):
    monkeypatch.setattr(cli_catalog, "_service", lambda: (_ for _ in ()).throw(RuntimeError(SENTINEL)))
    assert cli_catalog.cmd_projects(SimpleNamespace(projects_command="list", json=True)) == 1
    assert receipt(capsys.readouterr())["committed"] is False


@pytest.mark.parametrize("error", [SecretAccessDenied(SENTINEL), SecretUnavailable(SENTINEL), RuntimeError(SENTINEL)])
def test_ssh_provider_failure_is_audited_and_stops_before_key_file_or_process(
    isolated, capsys, monkeypatch, error,
):
    store = MetadataStore(isolated)
    key = Entry.new(name="ssh-credential", type=EntryType.SSH_KEY,
                    fields={"public_key": "ssh-ed25519 synthetic"})
    server = Entry.new(name="ssh-server", type=EntryType.SERVER,
                       fields={"host": "example.test", "user": "tester", "auth": "ssh_key"},
                       refs=[{"role": "ssh_key", "name": key.name}])
    store.add(key)
    store.add(server)
    reads = []

    def failed_read(account):
        reads.append(account)
        raise error

    context = SimpleNamespace(store=store, backend=SimpleNamespace(get=failed_read), audit=Audit())
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args, **_kwargs: context)
    monkeypatch.setattr(ssh_runner, "_resolve_ssh_executable", lambda: "/synthetic/ssh")
    monkeypatch.setattr(ssh_runner, "create_private_temp",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("key file created")))
    monkeypatch.setattr(ssh_runner.subprocess, "run",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("SSH process started")))
    assert cli.main(["ssh", server.name]) == 1
    assert reads == [key.id]
    assert receipt(capsys.readouterr())["committed"] is None
    assert Audit.events[-1]["op"] == "ssh" and Audit.events[-1]["id_"] == server.id
    assert Audit.events[-1]["success"] is False
    assert Audit.events[-1]["error"] == "operation failed"


def test_ssh_value_error_never_prints_provider_text_and_records_failure(isolated, capsys, monkeypatch):
    store = MetadataStore(isolated)
    server = Entry.new(name="ssh-server", type=EntryType.SERVER,
                       fields={"host": "example.test", "user": "tester", "auth": "none"})
    store.add(server)
    context = SimpleNamespace(store=store, backend=object(), audit=Audit())
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args, **_kwargs: context)
    monkeypatch.setattr(ssh_runner, "run_ssh", lambda **_kwargs: (_ for _ in ()).throw(ValueError(SENTINEL)))
    assert cli.main(["ssh", server.name]) == 1
    captured = capsys.readouterr()
    assert "unsafe or unavailable" in captured.err
    assert SENTINEL not in captured.out + captured.err
    assert Audit.events[-1]["op"] == "ssh" and Audit.events[-1]["success"] is False
    assert Audit.events[-1]["error"] == "operation failed"
