"""Retired paths fail safely while explicit VPS and local UI remain available."""
from __future__ import annotations

import http.client
import json
import threading
from html.parser import HTMLParser
from types import SimpleNamespace

import pytest

from keys_keeper import api, auto_worker, cli, cli_sync_vps
from keys_keeper.pages import render_settings
from keys_keeper.paths import Paths
from keys_keeper.server import AdminServer


SENTINEL = "synthetic-obsolete-credential-must-not-be-printed"


@pytest.mark.parametrize("prefix", [[], ["--profile", "worker"],
                                    ["--project=synthetic", "--env", "test"]])
@pytest.mark.parametrize("command", ["setup", "push", "pull", "status", "mode", "rollback", "auto"])
def test_retired_cli_commands_fail_before_config_vault_or_credentials(tmp_path, monkeypatch, capsys, prefix, command):
    root = tmp_path / "untouched"
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(root))
    monkeypatch.setattr(cli, "_context_or_error", lambda *_a, **_kw: pytest.fail("retired command opened a vault"))
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_a, **_kw: pytest.fail("retired command prompted"))
    result = cli.main(prefix + ["sync", command, "--secret-key", SENTINEL])
    captured = capsys.readouterr()
    assert result == 2
    assert "S3 synchronization has been removed" in captured.err
    assert SENTINEL not in captured.out + captured.err
    assert not root.exists()


def test_retired_webvault_command_is_explicit_and_does_not_start_server(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_context_or_error", lambda *_a, **_kw: pytest.fail("retired reader opened a vault"))
    assert cli.main(["webvault", "serve", "--secret-key", SENTINEL]) == 2
    captured = capsys.readouterr()
    assert "WebVault has been removed" in captured.err
    assert SENTINEL not in captured.out + captured.err


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/sync/setup"), ("POST", "/api/sync/push"),
    ("POST", "/api/sync/pull"), ("POST", "/api/sync/mode"),
    ("GET", "/api/sync/status"), ("GET", "/api/sync"),
])
def test_retired_api_routes_return_gone_without_resolving_backend(method, path, tmp_path):
    results = []
    handler = SimpleNamespace(_send_json=lambda status, body: results.append((status, body)))
    class ForbiddenRuntime:
        def context(self, *_a, **_kw):
            pytest.fail("retired API resolved a vault")
    api.handle_api(handler, paths=Paths(tmp_path / "untouched"), method=method,
                   path=path + "?profile=invalid", body=SENTINEL.encode(), runtime=ForbiddenRuntime())
    assert len(results) == 1
    status, body = results[0]
    assert status == 410
    assert "S3 synchronization has been removed" in body["error"]
    assert SENTINEL not in json.dumps(body)
    assert not (tmp_path / "untouched").exists()


def test_retired_api_keeps_session_authentication_before_response(tmp_path):
    class ForbiddenRuntime:
        def context(self, *_a, **_kw):
            pytest.fail("retired API resolved a vault")
    server = AdminServer(paths=Paths(tmp_path / "untouched"), port=0,
                         project_runtime=ForbiddenRuntime())
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for token, expected in [(None, 403), ("wrong-token", 403), (server.token, 410)]:
            connection = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=2)
            try:
                headers = {"Sec-Keys-Token": token} if token else {}
                connection.request("POST", "/api/sync/setup", body=SENTINEL, headers=headers)
                response = connection.getresponse()
                assert response.status == expected
                assert SENTINEL.encode() not in response.read()
            finally:
                connection.close()
    finally:
        server.stop()
        thread.join(2)
        assert not thread.is_alive()
    assert not (tmp_path / "untouched").exists()


def test_explicit_vps_command_runs_with_retained_obsolete_config(tmp_path, monkeypatch):
    paths = Paths(tmp_path)
    original = ("[sync]\nmode='auto'\nendpoint='https://retired.example.test'\n"
                "secret='" + SENTINEL + "'\n").encode()
    paths.config_toml.write_bytes(original)
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(paths.root))
    monkeypatch.setattr(cli, "_context_or_error", lambda *_a, **_kw: SimpleNamespace(kind="master"))
    calls = []
    monkeypatch.setattr(cli_sync_vps, "cmd_vps_status", lambda args: calls.append(args.vps_sync_command) or 0)
    assert cli.main(["sync", "vps", "status"]) == 0
    assert calls == ["status"]
    assert paths.config_toml.read_bytes() == original


@pytest.mark.parametrize("mode", ["run", "detach", "entrypoint"])
def test_retired_automatic_mode_never_starts_a_process(tmp_path, monkeypatch, mode):
    monkeypatch.setattr(auto_worker.subprocess, "Popen", lambda *_a, **_kw: pytest.fail("retired automatic mode spawned"))
    if mode == "entrypoint":
        with pytest.raises(SystemExit) as failure:
            auto_worker.main(["s3", "--home", str(tmp_path)])
        assert failure.value.code == 2
    else:
        call = auto_worker.run_auto_worker if mode == "run" else auto_worker.start_auto_worker
        with pytest.raises(ValueError, match="invalid automatic worker"):
            call("s3", Paths(tmp_path))


def test_settings_render_preserves_personal_vps_and_maintenance_controls(tmp_path):
    class Controls(HTMLParser):
        def __init__(self):
            super().__init__()
            self.ids = set()
            self.scripts = set()
        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if "id" in values:
                self.ids.add(values["id"])
            if tag == "script" and "src" in values:
                self.scripts.add(values["src"])
    controls = Controls()
    controls.feed(render_settings(paths=Paths(tmp_path), token="synthetic-session"))
    assert {"card-personal-sync", "personal-body", "status-body", "security-body", "shutdown-btn"} <= controls.ids
    assert "card-sync" not in controls.ids and "sync-body" not in controls.ids
    assert "/static/personal-sync.js" in controls.scripts
