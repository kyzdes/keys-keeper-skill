"""Web admin sync API (/api/sync/*) — fakes, cross-platform, no-leak."""
import io
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keys_keeper import cli
from keys_keeper.api import handle_api
from keys_keeper.paths import Paths
from keys_keeper.config import load_sync_config
from keys_keeper.cli_sync import SYNC_PASS
from _sync_fakes import FakeRemote, FakeBackend

AKID, S3SECRET, PW = "AKID-WEBLEAK", "s3secret-WEBLEAK", "passphrase-WEBLEAK"


class FakeHandler:
    def __init__(self):
        self.status = None
        self.body = None

    def _send_json(self, status, body):
        self.status = status
        self.body = body


@pytest.fixture
def sync_web(kk_home, monkeypatch):
    backend = FakeBackend()
    remote = FakeRemote()
    monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync.build_backend", lambda: backend)
    monkeypatch.setattr("keys_keeper.cli_sync._build_remote", lambda cfg, b: remote)
    return SimpleNamespace(backend=backend, remote=remote)


def _setup(auto=False):
    args = ["sync", "setup", "--endpoint", "https://s3.example.com", "--bucket", "b",
            "--access-key-id", AKID]
    if auto:
        args.append("--auto")
    with patch("getpass.getpass", side_effect=[S3SECRET, PW, PW]):
        return cli.main(args)


def _add(name, secret):
    with patch("sys.stdin", io.StringIO(secret + "\n")):
        cli.main(["add", name, "--type", "api_key", "--stdin"])


def _call(method, route, body=None):
    h = FakeHandler()
    handle_api(h, paths=Paths(), method=method, path=route, body=body)
    return h


def test_status_unconfigured(sync_web):
    h = _call("GET", "/api/sync/status")
    assert h.status == 200
    assert h.body["configured"] is False
    assert h.body["mode"] == "off"


def test_status_after_setup_and_push(sync_web):
    _setup()
    _add("api-1", "sk-AAA")
    cli.main(["sync", "push"])
    h = _call("GET", "/api/sync/status")
    assert h.body["configured"] is True
    assert h.body["mode"] == "manual"
    assert h.body["remote_version"] == 1


def test_web_push_and_pull(sync_web):
    _setup()
    _add("api-1", "sk-AAA")
    h = _call("POST", "/api/sync/push")
    assert h.status == 200 and h.body["ok"] is True
    assert any(k.startswith("versions/000001") for k in sync_web.remote.objs)
    h2 = _call("POST", "/api/sync/pull")
    assert h2.status == 200 and h2.body["ok"] is True


def test_web_mode_toggle_persists(sync_web):
    _setup()
    h = _call("POST", "/api/sync/mode", body=b'{"mode":"auto"}')
    assert h.status == 200 and h.body["mode"] == "auto"
    assert load_sync_config(Paths()).mode == "auto"


def test_push_without_stored_passphrase_is_clean_400(sync_web):
    _setup()
    sync_web.backend.delete(SYNC_PASS)
    h = _call("POST", "/api/sync/push")
    assert h.status == 400
    assert "error" in h.body
    # the safe error must not contain any secret
    raw = str(h.body)
    for s in (S3SECRET, PW, AKID):
        assert s not in raw


def test_no_secret_in_any_sync_api_response(sync_web):
    _setup()
    _add("api-1", "sk-AAA")
    cli.main(["sync", "push"])
    blobs = []
    for method, route in [("GET", "/api/sync/status"), ("POST", "/api/sync/push"),
                          ("POST", "/api/sync/pull")]:
        blobs.append(str(_call(method, route).body))
    joined = "\n".join(blobs)
    for s in (AKID, S3SECRET, PW, "sk-AAA"):
        assert s not in joined


def test_web_setup_configures_and_stores_secrets(sync_web):
    import json
    from keys_keeper.cli_sync import SYNC_ACCESS, SYNC_SECRET
    body = json.dumps({
        "endpoint": "https://s3.example.com", "bucket": "b",
        "access_key_id": AKID, "secret_key": S3SECRET, "passphrase": PW,
        "region": "auto", "prefix": "kk", "mode": "manual",
    }).encode()
    h = _call("POST", "/api/sync/setup", body=body)
    assert h.status == 200 and h.body["ok"] is True
    # secrets landed in the keychain, not the response or config
    assert sync_web.backend.get(SYNC_SECRET).unseal() == S3SECRET
    assert sync_web.backend.get(SYNC_ACCESS).unseal() == AKID
    cfg = load_sync_config(Paths())
    assert cfg.mode == "manual" and cfg.bucket == "b" and cfg.region == "auto"
    raw = str(h.body) + Paths().config_toml.read_text()
    for s in (S3SECRET, PW, AKID):
        assert s not in raw


def test_web_setup_missing_fields_is_400(sync_web):
    import json
    h = _call("POST", "/api/sync/setup",
              body=json.dumps({"endpoint": "https://x", "bucket": "b"}).encode())
    assert h.status == 400 and "error" in h.body
