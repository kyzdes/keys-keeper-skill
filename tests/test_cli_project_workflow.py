"""Actual CLI processes, isolated native master keychain, clean replica root."""
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.sync_server import SyncServerApp
from test_project_sync_e2e import _running


@pytest.mark.macos
def test_cli_project_lifecycle_with_native_master_and_file_replica(tmp_path, test_keychain):
    master_root, worker_root = tmp_path / "master", tmp_path / "worker"
    password_file = tmp_path / "recovery-password"
    password_file.write_text("synthetic-offline-recovery-password")
    password_file.chmod(0o600)
    base_env = {**os.environ, "KEYS_KEEPER_TEST_KEYCHAIN": str(test_keychain),
                "KEYS_KEEPER_TEST_SERVICE": "keys-project-native-e2e"}
    outputs = []

    def run(root, *arguments, stdin=None, success=True, parsed=False):
        proc = subprocess.run([os.environ.get("KEYS_KEEPER_ARTIFACT_PYTHON", sys.executable),
            "-m", "keys_keeper", *map(str, arguments)], cwd=tmp_path,
            env={**base_env, "KEYS_KEEPER_HOME": str(root)}, input=stdin, capture_output=True, text=True, timeout=45)
        outputs.append(proc.stdout + proc.stderr)
        assert (proc.returncode == 0) == success, proc.stderr
        return json.loads(proc.stdout) if parsed else proc.stdout

    run(master_root, "add", "bootstrap", "--stdin", stdin="SYNTHETIC-RELAY-ADMIN")
    run(master_root, "add", "project-key", "--stdin", stdin="SYNTHETIC-PROJECT-SECRET")
    run(master_root, "add", "private-key", "--stdin", stdin="SYNTHETIC-PRIVATE-CANARY")
    run(master_root, "project-sync", "migrate", "--out", tmp_path / "before.enc", "--password-file", password_file)
    project = run(master_root, "projects", "create", "alpha", "Alpha", "--json", parsed=True)
    scope = run(master_root, "projects", "scopes", project["id"], "--create", "--json", parsed=True)
    key = MetadataStore(Paths(master_root)).get_by_name("project-key")
    run(master_root, "projects", "distribution", key.id, "--distribution", "project_allowed")
    run(master_root, "projects", "add", key.id, "--scope-id", scope["id"])
    app = SyncServerApp(tmp_path / "relay.sqlite", "SYNTHETIC-RELAY-ADMIN")
    with _running(app) as endpoint:
        initialized = run(master_root, "project-sync", "init", "--scope", scope["id"], "--endpoint", endpoint,
                          "--admin-token-entry", "bootstrap", parsed=True)
        run(master_root, "project-sync", "backup", "--out", tmp_path / "authority.enc", "--password-file", password_file)
        invitation = tmp_path / "invite.json"
        request = tmp_path / "request.json"
        response = tmp_path / "response.json"
        run(master_root, "project-sync", "invite", "--scope", scope["id"], "--out", invitation)
        joined = run(worker_root, "project-sync", "join", "--invite", invitation,
                     "--fingerprint", initialized["fingerprint"], "--out", request, parsed=True)
        run(master_root, "project-sync", "approve", "--request", request, "--fingerprint", joined["fingerprint"], "--out", response)
        run(worker_root, "project-sync", "finish", "--scope", joined["profile_id"], "--bundle", response)
        listed = run(worker_root, "list")
        assert "project-key" in listed and "private-key" not in listed and "bootstrap" not in listed
        injected = tmp_path / "worker.env"
        run(worker_root, "inject", "project-key", "--file", injected, "--as", "PROJECT_KEY")
        assert "SYNTHETIC-PROJECT-SECRET" in injected.read_text()
        run(worker_root, "add", "worker-key", "--stdin", stdin="SYNTHETIC-WORKER-SECRET")
        run(worker_root, "inject", "worker-key", "--file", injected, "--as", "WORKER_KEY")
        assert "SYNTHETIC-WORKER-SECRET" in injected.read_text()
        run(worker_root, "add", "project-key", "--stdin", "--replace", stdin="BAD-OVERWRITE", success=False)
        run(worker_root, "rm", "project-key", success=False)
        run(worker_root, "project-sync", "sync")
        run(master_root, "project-sync", "sync", "--scope", scope["id"])
        run(worker_root, "project-sync", "sync")
        run(worker_root, "--project", "alpha", "--env", "default", "info", "worker-key")
        assert MetadataStore(Paths(master_root)).get_by_name("worker-key") is not None
    output = "\n".join(outputs)
    for value in ("SYNTHETIC-PROJECT-SECRET", "SYNTHETIC-PRIVATE-CANARY", "SYNTHETIC-RELAY-ADMIN", "SYNTHETIC-WORKER-SECRET", "BAD-OVERWRITE"):
        assert value not in output
