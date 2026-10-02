"""Real command effects with synthetic credentials and an isolated installer."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from keys_keeper import cli, cli_devices, cli_sync_vps, project_runtime
from keys_keeper.backend import SecretAccessDenied
from keys_keeper.paths import Paths
from keys_keeper.personal_sync import PersonalSync, _save_settings
from keys_keeper.project_runtime import ProjectRuntime
from keys_keeper.project_service import ProjectService
from keys_keeper.project_sync import new_master_state
from test_project_sync_e2e import FakeBackend


@pytest.mark.parametrize("option", ["--version", "--help"])
def test_installation_checks_never_construct_vault_or_backend(monkeypatch, capsys, option):
    def forbidden(*_args, **_kwargs):
        pytest.fail("installation probe accessed a vault")
    monkeypatch.setattr(cli, "_context", forbidden)
    monkeypatch.setattr(cli, "build_backend", forbidden)
    monkeypatch.setattr(project_runtime.ProjectRuntime, "__init__", forbidden)
    with pytest.raises(SystemExit) as exit_code:
        cli.main([option])
    assert exit_code.value.code == 0
    assert capsys.readouterr().out


def test_configured_devices_status_reads_unlock_material_and_stops_on_denial(tmp_path, monkeypatch, capsys):
    paths = Paths(tmp_path / "synthetic-status")
    backend = FakeBackend()
    runtime = ProjectRuntime(paths, backend)
    runtime.master_store.migrate_catalog_v3()
    catalog = ProjectService(runtime.master_store)
    project = catalog.create_project("synthetic", "Synthetic")
    scope = catalog.create_scope(project.id, "personal")
    state = new_master_state(scope.id, scope.vault_id, "https://synthetic.invalid")
    state["personal_vault"] = True
    item = dict(id=scope.id, kind="master_scope", scope_id=scope.id, vault_id=scope.vault_id,
                project=project.slug, environment=scope.environment, endpoint=state["endpoint"],
                device_id=state["device_id"], status="active")
    runtime._master_password(create=True)
    runtime.state(item).save(state)
    runtime.registry.put(item)
    _save_settings(paths, dict(version=1, role="master", scope_id=scope.id, endpoint=state["endpoint"],
                               auto=True, name="Synthetic", replica_id=None))
    def forbidden(*_args, **_kwargs):
        pytest.fail("local status accessed network or native backend")
    monkeypatch.setattr(project_runtime, "build_backend", forbidden)
    monkeypatch.setattr(project_runtime.ProjectClient, "_request", forbidden)
    manager = PersonalSync(paths, ProjectRuntime(paths, backend))
    monkeypatch.setattr(cli_devices, "PersonalSync", lambda _paths: manager)
    backend.gets.clear()
    assert cli.main(["devices", "status", "--home", str(paths.root)]) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "active"
    assert backend.gets == ["kk:project-runtime-key"]
    manager = PersonalSync(paths, ProjectRuntime(paths, backend))
    reads = []
    def denied(account):
        reads.append(account)
        raise SecretAccessDenied("synthetic-private-provider-detail")
    monkeypatch.setattr(backend, "get", denied)
    assert cli.main(["devices", "status", "--home", str(paths.root)]) == 1
    captured = capsys.readouterr()
    assert reads == ["kk:project-runtime-key"]
    assert "synthetic-private-provider-detail" not in captured.out + captured.err


def test_vps_status_persists_fresh_verified_revocation_but_does_not_rewrite_unchanged_state(
    tmp_path, monkeypatch, capsys,
):
    from test_sync_vps import two_devices
    from keys_keeper.sync_protocol_v2 import canonical_json_bytes
    from keys_keeper.sync_vps import make_revocation_statement, sign_revocation

    remote, (engine, paths, store, backend), _peer = two_devices(tmp_path)
    monkeypatch.setattr(cli_sync_vps, "_engine", lambda _paths: (engine, engine.config, backend))
    metadata_revision = store.snapshot().revision
    writes = []
    original_write = engine._write_state

    def observe_write(*args, **kwargs):
        writes.append(True)
        return original_write(*args, **kwargs)

    monkeypatch.setattr(engine, "_write_state", observe_write)
    assert cli.main(["sync", "vps", "status"]) == 0
    assert writes == []
    state_path = paths.root / "vps-sync-state.json"
    assert not state_path.exists()
    statement = make_revocation_statement(
        vault_id=remote.vault_id, device_id="peer-device",
        revoked_by_device_id=engine.config.root_device_id,
        checkpoint_commit_id=None, checkpoint_manifest_hash=None, checkpoint_sequence=0,
    )
    remote.devices[1].update(
        status="revoked", revoked_by_device_id=engine.config.root_device_id,
        revocation_statement=canonical_json_bytes(statement).decode(),
        revocation_signature=sign_revocation(statement, engine.signing_private_key),
    )
    assert cli.main(["sync", "vps", "status"]) == 0
    assert writes == [True]
    published = state_path.read_bytes()
    assert json.loads(published)["revocations"]["peer-device"]["statement"] == canonical_json_bytes(statement).decode()
    assert cli.main(["sync", "vps", "status"]) == 0
    assert writes == [True]
    assert state_path.read_bytes() == published
    assert store.snapshot().revision == metadata_revision
    assert remote.commits == {} and backend.list_ids() == []
    assert "remote sequence:" in capsys.readouterr().out


@pytest.mark.skipif(os.name != "nt", reason="Windows installer uses native PowerShell paths")
def test_windows_installer_flow_only_uses_version_for_health_probe(tmp_path, monkeypatch):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        pytest.skip("PowerShell unavailable")
    install = tmp_path / "install"
    scripts = install / "venv" / "Scripts"
    scripts.mkdir(parents=True)
    for name in ("python.exe", "keys.exe"):
        (scripts / name).write_bytes(b"synthetic external-command placeholder")
    installer = Path(__file__).parents[1] / "scripts/install-windows.ps1"
    calls = tmp_path / "calls.jsonl"
    monkeypatch.setenv("KK_PROBE_INSTALLER", str(installer))
    monkeypatch.setenv("KK_PROBE_PYTHON", str(scripts / "python.exe"))
    monkeypatch.setenv("KK_PROBE_ROOT", str(install))
    monkeypatch.setenv("KK_PROBE_CALLS", str(calls))
    # Stub external processes through the actual script's function AST. The
    # installer flow runs unchanged; no pip install, vault or OS shortcut runs.
    driver = tmp_path / "probe.ps1"
    driver.write_text(r'''
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($env:KK_PROBE_INSTALLER,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'installer parse failed' }
$text=[IO.File]::ReadAllText($env:KK_PROBE_INSTALLER)
$functions=$ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Find-Python','Invoke-Checked')},$true)
foreach ($f in ($functions | Sort-Object {$_.Body.Extent.StartOffset} -Descending)) {
    $body=if ($f.Name -eq 'Find-Python') {'{ return $env:KK_PROBE_PYTHON }'} else {'{ param([string]$Program,[string[]]$Arguments) ConvertTo-Json -Compress -InputObject $Arguments | Add-Content -LiteralPath $env:KK_PROBE_CALLS }'}
    $start=$f.Body.Extent.StartOffset; $length=$f.Body.Extent.EndOffset-$start
    $text=$text.Remove($start,$length).Insert($start,$body)
}
& ([ScriptBlock]::Create($text)) -Source 'synthetic-package' -InstallRoot $env:KK_PROBE_ROOT -NoLaunch -NoPathUpdate
''', encoding="utf-8")
    subprocess.run([shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(driver)],
                   check=True, capture_output=True, timeout=30)
    operations = [json.loads(line) for line in calls.read_text(encoding="utf-8-sig").splitlines()]
    module_calls = [args for args in operations if args[:2] == ["-m", "keys_keeper"]]
    assert module_calls == [["-m", "keys_keeper", "app", "install", "--force"],
                            ["-m", "keys_keeper", "--version"]]
