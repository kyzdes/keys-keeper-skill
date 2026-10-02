"""Actual isolated HTTP/form contracts; no OS keychain or clipboard access."""
from __future__ import annotations

import http.client
import json
import shutil
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from keys_keeper.audit import AuditLog, record_outcome
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.request_json import InvalidRequest, request_object
from keys_keeper.server import AdminServer
from keys_keeper.service import VaultService
from keys_keeper.store import MetadataStore


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values = {}
        self.reads = []
        self.denied = False

    def get(self, account):
        self.reads.append(account)
        if self.denied:
            raise KeychainError("synthetic-private-marker")
        return Sealed(self.values[account])

    def set(self, account, value):
        self.values[account] = value

    def delete(self, account):
        self.values.pop(account, None)

    def list_ids(self):
        return list(self.values)


@pytest.fixture
def admin_contract(tmp_path):
    paths = Paths(tmp_path / "synthetic-vault")
    paths.ensure()
    backend = MemoryBackend()
    store, audit = MetadataStore(paths), AuditLog(paths)
    context = SimpleNamespace(kind="master", profile_id="master", scope_id=None,
                              store=store, audit=audit, paths=paths, backend=backend,
                              service=VaultService(store, backend))
    calls = []

    def resolve(selector):
        calls.append(selector)
        return context

    runtime = SimpleNamespace(context=resolve)
    server = AdminServer(paths=paths, port=0, project_runtime=runtime)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(method, path, body=None, *, authenticated=True):
        raw = json.dumps(body).encode() if isinstance(body, dict) else body
        connection = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if authenticated:
            headers["Sec-Keys-Token"] = server.token
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, (json.loads(data) if response.getheader("Content-Type") == "application/json" else data)

    yield SimpleNamespace(request=request, backend=backend, store=store, audit=audit,
                          context=context, runtime=runtime, calls=calls)
    server.stop()
    thread.join(timeout=3)


def api_key(name="synthetic-key"):
    return {"name": name, "type": "api_key", "value": "synthetic-value"}


@pytest.mark.parametrize("raw", [
    b"{", b"[]", b"null", b'"scalar"', b"1", b"true", b"\xff",
    b'{"name":"aa","name":"bb","type":"api_key","value":"synthetic"}',
    b'{"name":"aa","type":"api_key","fields":{"x":1,"x":2},"value":"synthetic"}',
    b'{"name":"aa","type":"api_key","fields":{"x":NaN},"value":"synthetic"}',
])
def test_bad_json_is_structured_400_without_mutation_and_connection_survives(admin_contract, raw):
    status, body = admin_contract.request("POST", "/api/entries", raw)
    assert (status, body) == (400, {"error": "Invalid request"})
    assert admin_contract.backend.values == {}
    assert admin_contract.store.list() == []
    assert admin_contract.request("GET", "/api/entries") == (200, {"entries": []})


@pytest.mark.parametrize("extra", [
    {"name": True}, {"fields": []}, {"tags": "string"}, {"note": []},
    {"refs": {}}, {"value": 12}, {"unknown": "synthetic-private-marker"},
])
def test_wrong_type_or_unknown_fields_rejected_before_backend(admin_contract, extra):
    status, body = admin_contract.request("POST", "/api/entries", {**api_key(), **extra})
    assert status == 400
    assert "synthetic-private-marker" not in json.dumps(body)
    assert admin_contract.backend.values == {}
    assert admin_contract.backend.reads == []


def test_authorization_precedes_json_and_runtime_access(admin_contract):
    assert admin_contract.request("POST", "/api/entries", b"{", authenticated=False) == (403, b"forbidden")
    assert admin_contract.calls == []


@pytest.mark.parametrize("path", ["/", "/new", "/entry/synthetic", "/entry/synthetic/edit"])
def test_page_auth_precedes_context_or_provider_work(admin_contract, path):
    assert admin_contract.request("GET", path, authenticated=False) == (403, b"forbidden")
    assert admin_contract.calls == [] and admin_contract.backend.reads == []


@pytest.mark.parametrize("path", ["/", "/index.html", "/new", "/entry/synthetic", "/entry/synthetic/edit"])
def test_all_page_groups_have_one_safe_provider_error_boundary(admin_contract, monkeypatch, capsys, path):
    def failed(_selector):
        raise KeychainError("synthetic-private-page-error")
    previous = admin_contract.runtime.context
    monkeypatch.setattr(admin_contract.runtime, "context", failed)
    assert admin_contract.request("GET", path) == (503, b"Page unavailable")
    monkeypatch.setattr(admin_contract.runtime, "context", previous)
    assert admin_contract.request("GET", "/api/entries") == (200, {"entries": []})
    captured = capsys.readouterr()
    assert "synthetic-private-page-error" not in captured.out + captured.err
    assert "Traceback" not in captured.err


@pytest.mark.parametrize("path", ["/entry/synthetic", "/entry/synthetic/edit"])
def test_entry_lookup_provider_failure_is_fixed_and_connection_survives(admin_contract, monkeypatch, path):
    def failed(_identifier):
        raise KeychainError("synthetic-private-entry-error")
    monkeypatch.setattr(admin_contract.store, "get_by_id", failed)
    assert admin_contract.request("GET", path) == (503, b"Page unavailable")
    assert admin_contract.request("GET", "/api/entries") == (200, {"entries": []})


def test_page_type_error_never_disconnects_http_or_exposes_exception(admin_contract, monkeypatch):
    from keys_keeper import pages
    def failed(**_kwargs):
        raise TypeError("synthetic-private-template-error")
    monkeypatch.setattr(pages, "render_new_edit", failed)
    assert admin_contract.request("GET", "/new") == (503, b"Page unavailable")
    assert admin_contract.request("GET", "/api/entries") == (200, {"entries": []})


def test_invalid_page_selector_is_fixed_400(admin_contract):
    assert admin_contract.request("GET", "/?profile=one&profile=synthetic-private-selector") == (400, b"Invalid page request")
    assert admin_contract.calls == []


def test_committed_provider_exception_remains_explicit_at_http_boundaries(admin_contract, monkeypatch):
    class PublishedFailure(RuntimeError):
        committed = True
        audit_status = {"untrusted": "synthetic-private-commit-error"}
    def failed(_selector):
        raise PublishedFailure("synthetic-private-commit-error")
    monkeypatch.setattr(admin_contract.runtime, "context", failed)
    status, receipt = admin_contract.request("GET", "/api/entries")
    assert status == 503 and receipt["committed"] is True and receipt["audit_status"] == "unknown"
    assert "synthetic-private-commit-error" not in json.dumps(receipt)
    assert admin_contract.request("GET", "/") == (503, b"Change was published; confirm state before retrying")


@pytest.mark.parametrize("payload", [{"name": "new-name"}, {"type": "note"}, {"value": False}])
def test_patch_rejects_unsupported_or_wrong_type_mutation(admin_contract, payload):
    _, created = admin_contract.request("POST", "/api/entries", api_key())
    status, body = admin_contract.request("PATCH", "/api/entries/" + created["id"], payload)
    assert (status, body) == (400, {"error": "Invalid request"})
    assert admin_contract.store.get_by_id(created["id"]).name == "synthetic-key"


def test_successful_create_retains_committed_receipt_when_audit_is_unavailable(admin_contract, monkeypatch):
    def fail(**_event):
        raise OSError("synthetic-private-marker")
    monkeypatch.setattr(admin_contract.audit, "record", fail)
    status, body = admin_contract.request("POST", "/api/entries", api_key())
    assert status == 201
    assert body["committed"] is True and body["audit_status"] == "unavailable"
    assert body["name"] == "synthetic-key"
    assert admin_contract.backend.values[body["id"]] == "synthetic-value"
    assert "synthetic-private-marker" not in json.dumps(body)


def test_denied_copy_stops_before_clipboard_and_records_one_fixed_failure(admin_contract, monkeypatch):
    _, created = admin_contract.request("POST", "/api/entries", api_key())
    admin_contract.backend.denied = True
    clipboard_calls = []
    monkeypatch.setattr("keys_keeper.api.clipboard.write", lambda value: clipboard_calls.append(value))
    status, body = admin_contract.request("POST", "/api/copy", {"id": created["id"]})
    assert status == 503 and body["committed"] is False
    assert body["audit_status"] == "recorded"
    events = list(admin_contract.audit.search(op="copy"))
    assert len(events) == 1 and not events[0]["success"]
    assert events[0]["error"] == "operation failed"
    assert clipboard_calls == []
    assert "synthetic-private-marker" not in json.dumps(body) + json.dumps(events)


def test_copy_commit_survives_audit_and_clear_scheduler_failure(admin_contract, monkeypatch):
    _, created = admin_contract.request("POST", "/api/entries", api_key())
    def fail(*_args, **_kwargs):
        raise OSError("synthetic-private-marker")
    monkeypatch.setattr(admin_contract.audit, "record", fail)
    copied = []
    monkeypatch.setattr("keys_keeper.api.clipboard.write", lambda value: copied.append(value) or True)
    monkeypatch.setattr("keys_keeper.api.clipboard.schedule_clear_after", fail)
    status, body = admin_contract.request("POST", "/api/copy", {"id": created["id"]})
    assert status == 200 and body["committed"] is True
    assert body["audit_status"] == body["clear_status"] == "unavailable"
    assert copied == ["synthetic-value"]


def test_unclassified_mutation_failure_does_not_claim_rollback_or_disclose_error(admin_contract, monkeypatch):
    def fail(*_args, **_kwargs):
        raise OSError("synthetic-private-marker")
    monkeypatch.setattr(admin_contract.context.service, "create_entry", fail)
    status, body = admin_contract.request("POST", "/api/entries", api_key())
    assert status == 503 and body["committed"] is None
    assert "recovery" in body["error"] and "synthetic-private-marker" not in json.dumps(body)
    assert len(list(admin_contract.audit.search(op="add"))) == 1


def test_unexpected_read_failure_is_structured_and_redacted(admin_contract, monkeypatch):
    def fail():
        raise OSError("synthetic-private-marker")
    monkeypatch.setattr(admin_contract.store, "list", fail)
    assert admin_contract.request("GET", "/api/entries") == (503, {"error": "Operation unavailable"})


def test_recent_events_track_immutable_id_and_multi_entry_usage_newest_first(admin_contract):
    entry = Entry.new(name="renamed-key", type=EntryType.API_KEY)
    admin_contract.store.add(entry)
    for index in range(7):
        admin_contract.audit.record(op=f"read-{index}", name="old-name", id_=entry.id)
    admin_contract.audit.record(op="resolve", name="<file>", id_="synthetic-target",
                                affected_entry_ids=[entry.id])
    status, payload = admin_contract.request("GET", "/api/entries/" + entry.id)
    assert status == 200
    assert [event["op"] for event in payload["recent_events"]] == ["resolve", "read-6", "read-5", "read-4", "read-3"]


def test_bulk_scope_and_fields_validated_before_any_commit(admin_contract):
    bad = {"source": "first-key = synthetic\nsecond-key (ssh_key) = synthetic"}
    status, body = admin_contract.request("POST", "/api/bulk-import", bad)
    assert status == 400 and body["rows"][1]["error"]
    assert admin_contract.backend.values == {}
    assert admin_contract.store.list() == []
    status, body = admin_contract.request("POST", "/api/bulk-import", {
        "source": "first-key = synthetic\nsecret-note (note) = synthetic-note",
    })
    assert status == 200 and body["committed"] is True
    assert body["imported"] == 2
    note = admin_contract.store.get_by_name("secret-note")
    assert note.fields == {"secret_body": True}
    assert admin_contract.backend.values[note.id] == "synthetic-note"
    assert len(list(admin_contract.audit.search(entry_id=note.id))) == 1


@pytest.mark.parametrize("payload", [
    {"fields": {"secret_body": True, "body": "synthetic-sensitive-value"}, "value": "synthetic-sensitive-value"},
    {"fields": {"secret_body": "true"}, "value": "synthetic-sensitive-value"},
    {"fields": {"body": "synthetic-public-value"}},
    {"fields": {"secret_body": True}},
    {"fields": {"secret_body": False, "body": "public"}, "value": "synthetic-sensitive-value"},
])
def test_note_storage_mode_cannot_be_ambiguous_or_leak_body_to_metadata(admin_contract, payload):
    status, body = admin_contract.request("POST", "/api/entries", {
        "name": "synthetic-note", "type": "note", **payload,
    })
    assert (status, body) == (400, {"error": "Invalid entry"})
    assert admin_contract.store.list() == [] and admin_contract.backend.values == {}


def test_metadata_edit_cannot_convert_public_note_into_secret_without_migration(admin_contract):
    _, created = admin_contract.request("POST", "/api/entries", {
        "name": "public-note", "type": "note", "fields": {"secret_body": False, "body": "public"},
    })
    previous_backend = dict(admin_contract.backend.values)
    status, _ = admin_contract.request("PATCH", "/api/entries/" + created["id"], {
        "fields": {"secret_body": True}, "value": "synthetic-value",
    })
    assert status == 400
    assert admin_contract.store.get_by_id(created["id"]).fields == {"secret_body": False, "body": "public"}
    assert admin_contract.backend.values == previous_backend


@pytest.mark.parametrize("data", [{"name": "renamed", "parent_id": None},
                                 {"parent_id": None, "position": True},
                                 {"name": "a", "unknown": "synthetic-private-marker"}])
def test_project_adapter_uses_same_strict_types_and_rejects_ignored_mutations(admin_contract, data):
    admin_contract.store.migrate_catalog_v3()
    status, body = admin_contract.request("PATCH", "/api/projects/folders/synthetic-id", data)
    assert status == 400 and body == {"error": "Invalid project request"}
    assert "synthetic-private-marker" not in json.dumps(body)


@pytest.mark.parametrize("raw", [b'{"value":"a","value":"b"}', b'{"enabled":1}', b'{}'])
def test_shared_parser_exact_types_duplicates_and_required_fields(raw):
    with pytest.raises(InvalidRequest):
        request_object(raw, {"enabled": bool}, required={"enabled"})


def test_shared_parser_bounds_direct_call_and_excess_nesting():
    with pytest.raises(InvalidRequest):
        request_object(b" " * (8 * 1024 * 1024 + 1), {})
    with pytest.raises(InvalidRequest):
        request_object(b'{"nested":' + b"[" * 1500 + b"0" + b"]" * 1500 + b"}", {"nested": list})


def test_safe_audit_helper_fixed_failures_and_distinct_unavailable_state():
    events = []
    audit = SimpleNamespace(record=lambda **event: events.append(event))
    assert record_outcome(audit, op="resolve", name="<file>", id_="synthetic", success=False,
                          error="synthetic-secret", affected_entry_ids=["kk:one", "kk:one"]) == "recorded"
    assert events[0]["error"] == "operation failed"
    assert events[0]["affected_entry_ids"] == ["kk:one"]
    assert "synthetic-secret" not in json.dumps(events)
    def fail(**_event):
        raise OSError("synthetic-secret")
    assert record_outcome(SimpleNamespace(record=fail), op="copy", name="synthetic", id_="synthetic") == "unavailable"


def test_real_browser_form_serializer_matches_http_and_storage_contracts(admin_contract):
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js required for actual admin form serializer")
    script = Path(__file__).parents[1] / "src/keys_keeper/static/app.js"
    harness = Path(__file__).with_name("admin_form_harness.cjs")
    result = subprocess.run([node, str(harness), str(script)], capture_output=True,
                            text=True, check=True, timeout=20)
    forms = json.loads(result.stdout)
    assert len(forms) == 7
    for form in forms:
        status, created = admin_contract.request("POST", "/api/entries", form["payload"])
        assert status == 201, (form, created)
        entry = admin_contract.store.get_by_id(created["id"])
        if entry.type == EntryType.NOTE:
            if entry.fields["secret_body"]:
                assert "body" not in entry.fields
                assert admin_contract.backend.values[entry.id] == form["payload"]["value"]
                assert form["secret_field_cleared"]
                assert form["payload"]["value"] not in json.dumps(entry.to_dict())
            else:
                assert entry.fields["body"] == "  public\nbody  "
                assert entry.id not in admin_contract.backend.values
        patch = form["edit_payload"]
        assert "name" not in patch and "type" not in patch and "value" not in patch
        status, updated = admin_contract.request("PATCH", "/api/entries/" + entry.id, patch)
        assert status == 200, (form, updated)
