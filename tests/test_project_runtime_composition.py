from __future__ import annotations

from pathlib import Path
from io import StringIO
from uuid import uuid4

import pytest

from keys_keeper import api, cli
from keys_keeper.models import Entry, EntryType
from keys_keeper.project_runtime import RuntimeErrorSafe
from keys_keeper.store import StoreError


def test_cli_explicit_background_context_preserves_no_ui_policy(tmp_path, monkeypatch):
    from argparse import Namespace
    from keys_keeper.composition import AccessContext
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path))
    seen = []
    backend = object()
    def factory(*, access):
        seen.append(access)
        return backend
    monkeypatch.setattr(cli, "build_backend", factory)
    context = cli._context(Namespace(), access=AccessContext.UI_FORBIDDEN)
    assert not seen
    assert context.backend is backend
    assert seen == [AccessContext.UI_FORBIDDEN]


class Handler:
    def __init__(self):
        self.responses = []

    def _send_json(self, status, payload):
        self.responses.append((status, payload))


class Audit:
    def __init__(self):
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)

    def search(self, **kwargs):
        return []


class Store:
    def __init__(self, entries=()):
        self.entries = list(entries)

    def list(self):
        return list(self.entries)

    def get_by_id(self, entry_id):
        return next((item for item in self.entries if item.id == entry_id), None)

    def get_by_name(self, name):
        return next((item for item in self.entries if item.name == name), None)

    def catalog_state(self):
        raise StoreError("explicit schema-v3 migration is required")


class Service:
    def __init__(self):
        self.created = []

    def create_entry(self, entry, *, secrets=None, replace=False):
        self.created.append((entry, secrets, replace))
        return entry


class Context:
    def __init__(self, kind="replica", *, entries=()):
        self.kind = kind
        self.profile_id = "profile-id" if kind != "master" else "master"
        self.scope_id = "scope-id" if kind != "master" else None
        self.paths = type("ProfilePaths", (), {
            "root": Path("/safe/profile"),
            "data_json": Path("/safe/profile/data.json"),
            "audit_jsonl": Path("/safe/profile/audit.jsonl"),
        })()
        self.store = Store(entries)
        self.audit = Audit()
        self.service = Service()
        self.backend_touched = False

    @property
    def backend(self):
        self.backend_touched = True
        raise AssertionError("backend must not be opened")


class Runtime:
    def __init__(self, context):
        self.context_value = context
        self.selectors = []

    def context(self, selector=None):
        self.selectors.append(selector)
        return self.context_value


def call(runtime, method, path, body=None, *, selector=None):
    handler = Handler()
    api.handle_api(handler, paths=PathLike(), method=method, path=path, body=body,
                   runtime=runtime, server_selector=selector)
    return handler.responses[-1]


class PathLike:
    """Only a marker: fake contexts ensure API never reaches this root."""


def test_api_resolves_project_selector_before_using_selected_context():
    context = Context(entries=[Entry.new(name="worker-only", type=EntryType.API_KEY)])
    runtime = Runtime(context)

    status, body = call(runtime, "GET", "/api/entries?project=alpha&env=dev")

    assert status == 200
    assert runtime.selectors == ["alpha/dev"]
    assert [item["name"] for item in body["entries"]] == ["worker-only"]
    assert context.backend_touched is False


@pytest.mark.parametrize("method,path", [
    ("PATCH", "/api/entries/id"),
    ("DELETE", "/api/entries/id"),
    ("POST", "/api/entries/id/replace-secret"),
    ("POST", "/api/bulk-import"),
    ("GET", "/api/sync/status"),
    ("POST", "/api/projects/folders"),
])
def test_replica_rejects_mutating_and_legacy_sync_routes_without_backend(method, path):
    context = Context()
    runtime = Runtime(context)

    status, body = call(runtime, method, path, b"{}")

    assert status == 403
    assert "read-only" in body["error"] or "master" in body["error"]
    assert context.backend_touched is False


def test_replica_allows_create_only_and_never_reads_master_catalog():
    context = Context()
    runtime = Runtime(context)

    status, body = call(runtime, "POST", "/api/entries", b'{"name":"draft","type":"api_key"}')
    assert status == 201
    assert body["name"] == "draft"
    assert len(context.service.created) == 1

    status, body = call(runtime, "GET", "/api/projects")
    assert status == 200
    assert body["enabled"] is False
    assert body["entries"] == []
    assert "catalog" not in body
    assert context.backend_touched is False


def test_unknown_or_conflicting_selector_fails_before_runtime_backend_access():
    context = Context()
    runtime = Runtime(context)

    status, body = call(runtime, "GET", "/api/entries?profile=")
    assert status == 400
    assert "empty" in body["error"]
    assert runtime.selectors == []

    status, body = call(runtime, "GET", "/api/entries?profile=one", selector="two")
    assert status == 400
    assert "fixed" in body["error"]
    assert runtime.selectors == []


def test_cli_blocks_catalog_writer_for_selected_worker(monkeypatch, capsys):
    worker = Context()
    monkeypatch.setattr(cli, "_context_or_error", lambda args, **kwargs: worker)

    assert cli.main(["--profile", "worker", "projects", "list"]) == 1
    assert "master profile" in capsys.readouterr().err


def test_replica_server_password_create_uses_secret_sink_and_prints_pending_id(monkeypatch, capsys, kk_home):
    context = Context()
    persisted = Entry.new(name="worker-server", type=EntryType.SERVER,
                          fields={"host": "host.example", "user": "deploy", "auth": "password"})
    persisted.id = "kk:" + str(uuid4())
    captured = {}

    def create(entry, *, secrets=None, replace=False):
        captured.update(entry=entry, secrets=secrets, replace=replace)
        return persisted

    context.service.create_entry = create
    monkeypatch.setattr(cli, "_context_or_error", lambda args, **kwargs: context)
    monkeypatch.setattr("sys.stdin", StringIO("server-password\n"))

    assert cli.main(["add", "worker-server", "--type", "server", "--field", "host=host.example", "--field", "user=deploy", "--field", "auth=password", "--stdin"]) == 0
    assert captured["secrets"].value == "server-password"
    assert persisted.id in capsys.readouterr().out


class DeliveryRuntime(Runtime):
    def __init__(self):
        self.master = Context("master")
        self.scope = Context("master_scope")
        self.scope.profile_id = "scope-profile"
        self.scope.scope_id = "scope-id"
        self.scope.item = {"scope_id": "scope-id"}
        self.selectors = []

    def context(self, selector=None):
        self.selectors.append(selector)
        return self.master if selector in (None, "master") else self.scope

    def status(self, selector=None):
        if selector == "master":
            return {"kind": "master", "profiles": [{"id": "scope-profile"}]}
        return {"id": "scope-profile", "profile_id": "scope-profile", "scope_id": "scope-id",
                "project": "alpha", "environment": "dev", "kind": "master_scope",
                "delivery": "idle", "pending": 0, "recipients": [{"device_id": "dev-1", "role": "reader", "grant_id": "grant-1"}], "outbox": []}

    def preview(self, selector):
        assert selector == "scope-profile"
        return {"scope_id": "scope-id", "source_revision": "revision", "catalog_revision": "catalog",
                "count": 1, "policy_hash": "policy", "recipients": [],
                "entries": [{"id": "entry", "name": "safe-name", "type": "note", "fields": {"secret_body": "never expose"}, "note": "private"}]}

    def sync(self, selector):
        return {"profile": selector, "status": "synced"}


def test_project_delivery_preview_is_metadata_only_and_sync_uses_explicit_scope():
    runtime = DeliveryRuntime()
    handler = Handler()
    api.handle_api(handler, paths=PathLike(), method="GET", path="/api/project-sync/preview?scope=scope-profile", body=None, runtime=runtime)
    status, payload = handler.responses[-1]
    assert status == 200
    assert payload["entries"] == [{"id": "entry", "name": "safe-name", "type": "note"}]
    assert "never expose" not in str(payload)

    handler = Handler()
    api.handle_api(handler, paths=PathLike(), method="POST", path="/api/project-sync/sync", body=b'{"scope_id":"scope-profile"}', runtime=runtime)
    assert handler.responses[-1] == (200, {"ok": True, "profile_id": "scope-profile", "result": {"profile": "scope-profile", "status": "synced"}})
