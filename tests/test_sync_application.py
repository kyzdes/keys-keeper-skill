"""S3 adapter boundaries and receipts using only synthetic in-memory secrets."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from _sync_fakes import FakeBackend, FakeRemote

from keys_keeper import cli_sync, sync_application as application
from keys_keeper.audit import AuditLog
from keys_keeper.backend import SecretAccessDenied, SecretUnavailable
from keys_keeper.config import SyncConfig, SyncConfigCommitError, load_sync_config
from keys_keeper.paths import Paths


SECRET_MARKER = "synthetic-value-must-not-appear"


@pytest.fixture
def prepared(kk_home, monkeypatch):
    backend = FakeBackend()
    backend.set(application.SYNC_PASS, SECRET_MARKER)
    cfg = SyncConfig(mode="auto", endpoint="https://s3.example.test", bucket="synthetic").with_device_id()
    calls = []
    engine = SimpleNamespace(push=lambda pw: calls.append("push") or 3,
                             pull=lambda pw: calls.append("pull") or 2,
                             rollback=lambda version, pw: calls.append("rollback") or 7)
    monkeypatch.setattr(application, "_build_engine", lambda *_a, **_kw: (engine, cfg, backend))
    monkeypatch.setattr(application, "load_sync_config", lambda _paths: cfg)
    return SimpleNamespace(paths=Paths(), backend=backend, cfg=cfg, engine=engine, calls=calls)


def _break_audit(monkeypatch):
    def failed(_self, **_kwargs):
        raise OSError(SECRET_MARKER)
    monkeypatch.setattr(AuditLog, "record", failed)


@pytest.mark.parametrize("operation", ["push", "pull", "rollback"])
def test_action_remains_committed_when_audit_is_unavailable(prepared, monkeypatch, operation):
    _break_audit(monkeypatch)
    result = application.run_action(prepared.paths, operation, version=4)
    assert result["committed"] is True
    assert result["audit_status"] == "unavailable"
    assert prepared.calls == [operation]
    assert SECRET_MARKER not in json.dumps(result)


def test_automatic_pull_and_push_are_not_repeated_for_audit_failure(prepared, monkeypatch):
    _break_audit(monkeypatch)
    assert application._run_auto_worker(prepared.paths) is True
    assert prepared.calls == ["pull", "push"]
    assert SECRET_MARKER not in (prepared.paths.root / "sync.log").read_text()


def test_push_does_not_query_remote_tip_after_commit(prepared, monkeypatch):
    prepared.engine._tip_version = lambda: pytest.fail("committed push made another remote query")
    monkeypatch.setattr(application, "_read_timing_state", lambda _p: (_ for _ in ()).throw(OSError(SECRET_MARKER)))
    result = application.web_push(prepared.paths)
    assert result["committed"] is True and result["version"] is None
    assert prepared.calls == ["push"]


def test_push_does_not_emit_untrusted_informational_version(prepared, monkeypatch):
    monkeypatch.setattr(application, "_read_timing_state", lambda _p: {"last_version": SECRET_MARKER})
    result = application.web_push(prepared.paths)
    assert result["committed"] is True and result["version"] is None
    assert SECRET_MARKER not in json.dumps(result)


def test_setup_and_mode_keep_commit_receipts_with_broken_audit(kk_home, monkeypatch):
    backend = FakeBackend()
    paths = Paths()
    bindings = []
    def build(*, paths, access):
        bindings.append(paths)
        return backend
    monkeypatch.setattr(application, "build_backend", build)
    monkeypatch.setattr(application, "_build_remote", lambda cfg, backend: FakeRemote())
    _break_audit(monkeypatch)
    cfg = SyncConfig(mode="manual", endpoint="https://s3.example.test", bucket="synthetic").with_device_id()
    setup = application.setup(paths, cfg, access_key_id="synthetic-access", secret_key=SECRET_MARKER,
                              passphrase=SECRET_MARKER)
    mode = application.web_set_mode(paths, "off")
    assert bindings == [paths]
    for result in (setup, mode):
        assert result["committed"] is True and result["audit_status"] == "unavailable"
        assert SECRET_MARKER not in json.dumps(result)
    assert load_sync_config(paths).mode == "off"


def test_published_config_failure_preserves_matching_new_credentials(kk_home, monkeypatch):
    from keys_keeper import config
    backend = FakeBackend()
    paths = Paths()
    monkeypatch.setattr(application, "build_backend", lambda **_kw: backend)
    monkeypatch.setattr(application, "_build_remote", lambda cfg, backend: FakeRemote())
    def publish_then_fail(cfg, paths):
        config.save_sync_config(cfg, paths)
        raise SyncConfigCommitError(SECRET_MARKER)
    monkeypatch.setattr(application, "save_sync_config", publish_then_fail)
    cfg = SyncConfig(mode="manual", endpoint="https://s3.example.test", bucket="synthetic").with_device_id()
    with pytest.raises(SyncConfigCommitError) as captured:
        application.setup(paths, cfg, access_key_id="synthetic-access", secret_key=SECRET_MARKER,
                          passphrase=SECRET_MARKER)
    assert captured.value.committed is True
    assert captured.value.audit_status == "recorded"
    assert backend.get(application.SYNC_SECRET).unseal() == SECRET_MARKER
    assert backend.get(application.SYNC_PASS).unseal() == SECRET_MARKER
    assert load_sync_config(paths).bucket == "synthetic"
    events = list(AuditLog(paths).search(op="sync.setup"))
    assert len(events) == 1 and events[0]["success"] is True
    assert SECRET_MARKER not in paths.audit_jsonl.read_text()


@pytest.mark.parametrize("error", [SecretAccessDenied, SecretUnavailable])
def test_present_passphrase_read_failure_stops_without_prompt_or_retry(monkeypatch, error):
    calls = []
    class Backend:
        def list_ids(self):
            calls.append("list")
            return [application.SYNC_PASS]
        def get(self, account):
            calls.append("get")
            raise error(SECRET_MARKER)
    monkeypatch.setattr(cli_sync.getpass, "getpass", lambda *_: pytest.fail("denied passphrase prompted"))
    with pytest.raises(error):
        cli_sync._sync_passphrase(Backend(), allow_prompt=True)
    assert calls == ["list", "get"]


def test_metadata_presence_failure_is_not_a_missing_passphrase(monkeypatch):
    class Backend:
        def list_ids(self):
            raise SecretUnavailable(SECRET_MARKER)
        def get(self, account):
            pytest.fail("ambiguous presence triggered credential read")
    monkeypatch.setattr(cli_sync.getpass, "getpass", lambda *_: pytest.fail("ambiguous presence prompted"))
    with pytest.raises(SecretUnavailable):
        cli_sync._sync_passphrase(Backend(), allow_prompt=True)


def test_only_positive_absence_allows_manual_prompt(monkeypatch):
    backend = FakeBackend()
    monkeypatch.setattr(cli_sync.getpass, "getpass", lambda *_: SECRET_MARKER)
    assert cli_sync._sync_passphrase(backend, allow_prompt=True) == SECRET_MARKER


def test_api_worker_and_application_import_without_any_cli_module():
    source = """
import importlib.abc
import sys
class ForbidCli(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'keys_keeper.cli' or fullname.startswith('keys_keeper.cli_'):
            raise AssertionError('non-CLI consumer imported ' + fullname)
sys.meta_path.insert(0, ForbidCli())
from keys_keeper import api, auto_worker, sync_application
from keys_keeper.webvault import remote
assert api._sync_mod() is sync_application
assert not any(name == 'keys_keeper.cli' or name.startswith('keys_keeper.cli_') for name in sys.modules)
"""
    environment = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-c", source], env=environment,
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
