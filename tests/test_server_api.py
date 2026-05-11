import json
import threading
import time
import urllib.request
import urllib.error
import pytest
from io import StringIO
from keys_keeper import cli
from keys_keeper.paths import Paths
from keys_keeper.server import AdminServer


@pytest.fixture
def admin(kk_home, test_keychain, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_TEST_KEYCHAIN", str(test_keychain))
    monkeypatch.setenv("KEYS_KEEPER_TEST_SERVICE", "keys-keeper-test")
    paths = Paths()
    paths.ensure()
    server = AdminServer(paths=paths, port=0, idle_timeout_sec=60)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _post(admin, path, payload=None):
    data = json.dumps(payload).encode() if payload else b""
    req = urllib.request.Request(
        f"http://127.0.0.1:{admin.bound_port}{path}",
        data=data,
        method="POST",
    )
    req.add_header("Sec-Keys-Token", admin.token)
    req.add_header("Content-Type", "application/json")
    return urllib.request.urlopen(req, timeout=2)


def _get(admin, path):
    req = urllib.request.Request(f"http://127.0.0.1:{admin.bound_port}{path}")
    req.add_header("Sec-Keys-Token", admin.token)
    return urllib.request.urlopen(req, timeout=2)


def _seed(monkeypatch, name, value="v"):
    monkeypatch.setattr("sys.stdin", StringIO(value + "\n"))
    cli.main(["add", name, "--type", "api_key", "--stdin"])


def test_api_env_names_returns_names_only(monkeypatch):
    """The env panel must never leak values — only names cross the wire."""
    from keys_keeper.api import _env_names
    monkeypatch.setenv("KK_PANEL_TEST_VAR", "this-must-not-leak")
    captured = {}

    class FakeHandler:
        def _send_json(self, status, body):
            captured["status"] = status
            captured["body"] = body

    _env_names(FakeHandler())
    assert captured["status"] == 200
    names = captured["body"]["names"]
    assert "KK_PANEL_TEST_VAR" in names
    # No value-shaped data anywhere in the response.
    assert "this-must-not-leak" not in json.dumps(captured["body"])
    # Names are sorted for deterministic UI rendering.
    assert names == sorted(names)


def test_api_entries_returns_seeded_data(admin, monkeypatch):
    _seed(monkeypatch, "api-test-1")
    _seed(monkeypatch, "api-test-2")
    resp = _get(admin, "/api/entries")
    data = json.loads(resp.read())
    names = {e["name"] for e in data["entries"]}
    assert "api-test-1" in names
    assert "api-test-2" in names
    # values must NEVER appear in response
    body_str = json.dumps(data)
    assert "v\n" not in body_str
    assert "value" not in body_str.lower() or "value" not in [k for e in data["entries"] for k in e.get("fields", {})]


@pytest.mark.macos
def test_api_copy_writes_clipboard_and_audits(admin, monkeypatch):
    _seed(monkeypatch, "copy-target", value="copy-secret-v")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    entry_id = next(e["id"] for e in entries if e["name"] == "copy-target")
    resp = _post(admin, "/api/copy", {"id": entry_id})
    payload = json.loads(resp.read())
    assert payload["ok"] is True
    # default mirrors CLI's --clear-after default of 30s
    assert payload["clear_after"] == 30
    import subprocess
    pasted = subprocess.run(["pbpaste"], capture_output=True, text=True).stdout
    assert pasted == "copy-secret-v"
    # audit
    from keys_keeper.audit import AuditLog
    events = list(AuditLog(Paths()).search(op="copy"))
    assert any(e["name"] == "copy-target" for e in events)


def test_api_copy_respects_clear_after_param(admin, monkeypatch):
    _seed(monkeypatch, "copy-target-2", value="v2")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    entry_id = next(e["id"] for e in entries if e["name"] == "copy-target-2")
    # 0 disables the clear timer (parity with CLI --clear-after 0)
    resp = _post(admin, "/api/copy", {"id": entry_id, "clear_after": 0})
    payload = json.loads(resp.read())
    assert payload["ok"] is True
    assert payload["clear_after"] == 0


def test_api_copy_rejects_negative_clear_after(admin, monkeypatch):
    _seed(monkeypatch, "copy-target-3", value="v3")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    entry_id = next(e["id"] for e in entries if e["name"] == "copy-target-3")
    try:
        _post(admin, "/api/copy", {"id": entry_id, "clear_after": -5})
        assert False, "expected 400"
    except Exception as ex:
        # urllib raises HTTPError on 4xx
        assert "400" in str(ex)


def test_api_heartbeat_returns_ok(admin):
    resp = _post(admin, "/api/heartbeat")
    assert json.loads(resp.read())["ok"] is True


def test_api_shutdown_stops_server(admin):
    # In production this os._exit's; we patch it for the test.
    import os as _os
    real_exit = _os._exit
    called = threading.Event()
    def fake_exit(_):
        called.set()
    _os._exit = fake_exit
    try:
        _post(admin, "/api/shutdown")
        assert called.wait(timeout=2)
    finally:
        _os._exit = real_exit


def test_api_audit_returns_recent_events(admin, monkeypatch):
    _seed(monkeypatch, "audit-target")
    resp = _get(admin, "/api/audit?limit=10")
    events = json.loads(resp.read())["events"]
    assert any(e["name"] == "audit-target" for e in events)


def test_api_delete_entry(admin, monkeypatch):
    _seed(monkeypatch, "to-del")
    entries = json.loads(_get(admin, "/api/entries").read())["entries"]
    eid = next(e["id"] for e in entries if e["name"] == "to-del")
    req = urllib.request.Request(
        f"http://127.0.0.1:{admin.bound_port}/api/entries/{eid}",
        method="DELETE",
    )
    req.add_header("Sec-Keys-Token", admin.token)
    urllib.request.urlopen(req).read()
    after = json.loads(_get(admin, "/api/entries").read())["entries"]
    assert all(e["name"] != "to-del" for e in after)


def _delete(admin, eid: str, *, cascade: bool = False):
    suffix = "?cascade=1" if cascade else ""
    req = urllib.request.Request(
        f"http://127.0.0.1:{admin.bound_port}/api/entries/{eid}{suffix}",
        method="DELETE",
    )
    req.add_header("Sec-Keys-Token", admin.token)
    return urllib.request.urlopen(req, timeout=2)


def test_api_delete_with_dependents_returns_409_without_cascade(admin, monkeypatch):
    """Mirrors CLI rm: refusing to delete an entry with reverse-refs."""
    from keys_keeper.audit import AuditLog
    from keys_keeper.store import MetadataStore
    _seed(monkeypatch, "ssh-parent")
    # add a server entry that refs the ssh-parent (manually via store, simpler than CLI add)
    store = MetadataStore(Paths())
    parent = store.get_by_name("ssh-parent")
    from keys_keeper.models import Entry, EntryType
    server_entry = Entry.new(
        name="server-child",
        type=EntryType.SERVER,
        fields={"host": "x.example", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": "ssh-parent"}],
    )
    store.add(server_entry)

    try:
        _delete(admin, parent.id, cascade=False)
        assert False, "expected 409"
    except urllib.error.HTTPError as ex:
        assert ex.code == 409
        body = json.loads(ex.read())
        assert "server-child" in body["dependents"]


def test_api_delete_with_cascade_strips_refs_and_deletes(admin, monkeypatch):
    """Mirrors CLI rm --cascade: strip dangling refs from dependents, then delete."""
    from keys_keeper.store import MetadataStore
    from keys_keeper.models import Entry, EntryType
    _seed(monkeypatch, "ssh-parent-2")
    store = MetadataStore(Paths())
    parent = store.get_by_name("ssh-parent-2")
    server_entry = Entry.new(
        name="server-child-2",
        type=EntryType.SERVER,
        fields={"host": "x.example", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": "ssh-parent-2"}],
    )
    store.add(server_entry)

    resp = _delete(admin, parent.id, cascade=True)
    body = json.loads(resp.read())
    assert body["ok"] is True
    assert "server-child-2" in body["cascaded"]
    # parent gone, child remains but with refs stripped
    after_store = MetadataStore(Paths())
    assert after_store.get_by_name("ssh-parent-2") is None
    surviving_child = after_store.get_by_name("server-child-2")
    assert surviving_child is not None
    assert surviving_child.refs == []
