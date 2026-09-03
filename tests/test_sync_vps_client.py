"""VPS sync HTTP client tests; every network operation is monkeypatched."""
from __future__ import annotations

import base64
import hashlib
import io
import json
from urllib.error import HTTPError, URLError

import pytest

import keys_keeper.sync_vps_client as vc
from keys_keeper.backend import Sealed


AUTH_TOKEN = "auth_" + "a" * 43
DEVICE_TOKEN = "device_" + "d" * 43
INVITE_SECRET = "invite_" + "i" * 43


class FakeResponse:
    def __init__(self, body=b"{}", *, status=200, headers=None):
        self.status = status
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            **(headers or {}),
        }
        self._stream = io.BytesIO(body)
        self.closed = False

    def read(self, n=-1):
        return self._stream.read(n)

    def close(self):
        self.closed = True


def _client(**overrides):
    options = {
        "base_url": "https://sync.example.test",
        "device_id": "dev-01",
        "token": Sealed(AUTH_TOKEN),
    }
    options.update(overrides)
    return vc.VpsSyncClient(**options)


def _headers(req):
    return {key.lower(): value for key, value in req.header_items()}


def _json_body(req):
    return json.loads(req.data.decode("utf-8"))


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).digest()


def _install_capture(monkeypatch, result=None):
    captured = []

    def fake_urlopen(req, timeout=None, *, proxy="missing"):
        captured.append((req, timeout, proxy))
        return result if result is not None else FakeResponse()

    monkeypatch.setattr(vc, "urlopen", fake_urlopen)
    return captured, result


@pytest.mark.parametrize(
    "url",
    [
        "http://sync.example.test",
        "ftp://sync.example.test",
        "https://user:password@sync.example.test",
        "https://sync.example.test?token=bad",
        "https://sync.example.test/#fragment",
    ],
)
def test_https_is_required_and_url_credentials_are_rejected(url):
    with pytest.raises(vc.VpsConfigurationError):
        vc.VpsSyncClient(base_url=url)


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8080", "http://worker.localhost:8080", "http://127.0.0.2", "http://[::1]:9000"],
)
def test_plain_http_is_allowed_only_for_loopback_testing(url):
    assert vc.VpsSyncClient(base_url=url).base_url == url


@pytest.mark.parametrize(
    "proxy",
    ["socks5://127.0.0.1:1080", "http://user:secret@127.0.0.1:8080", "https://proxy.test/path"],
)
def test_proxy_configuration_rejects_credentials_and_unsupported_urls(proxy):
    with pytest.raises(vc.VpsConfigurationError):
        _client(proxy=proxy)


def test_commit_list_limit_matches_server_contract():
    with pytest.raises(vc.VpsValidationError, match="between 1 and 100"):
        _client().list_commits("vault", limit=101)


def test_token_must_be_sealed_or_callback():
    with pytest.raises(vc.VpsConfigurationError):
        vc.VpsSyncClient(base_url="https://sync.example.test", token=AUTH_TOKEN)


def test_repr_and_configuration_errors_never_render_bearer_token():
    client = _client()
    rendered = repr(client)
    assert AUTH_TOKEN not in rendered
    assert "token=<sealed>" in rendered

    def broken_provider():
        raise RuntimeError(AUTH_TOKEN)

    broken = _client(token=broken_provider)
    with pytest.raises(vc.VpsAuthenticationError) as raised:
        broken.get_head("vault-1")
    assert AUTH_TOKEN not in str(raised.value)


def test_authenticated_request_uses_device_header_and_direct_proxy(monkeypatch):
    captured, _ = _install_capture(
        monkeypatch,
        FakeResponse(json.dumps({"commit_id": "c1"}).encode()),
    )
    client = _client(timeout=3.5)
    assert client.get_head("vault-1") == {"commit_id": "c1"}

    req, timeout, proxy = captured[0]
    headers = _headers(req)
    assert req.full_url == "https://sync.example.test/v1/vaults/vault-1/head"
    assert req.get_method() == "GET"
    assert headers["x-device-id"] == "dev-01"
    assert headers["authorization"].startswith("Bearer ")
    transmitted = headers["authorization"].removeprefix("Bearer ")
    assert _digest(transmitted) == _digest(AUTH_TOKEN)
    assert timeout == 3.5
    assert proxy == "direct"


def test_default_opener_bypasses_environment_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    vc._OPENERS.clear()
    opener = vc._opener_for("direct")
    active = [
        handler
        for handler in opener.handlers
        if isinstance(handler, vc.ProxyHandler) and handler.proxies
    ]
    assert active == []
    assert any(isinstance(handler, vc._NoRedirectHandler) for handler in opener.handlers)
    vc._OPENERS.clear()


def test_create_vault_uses_admin_bearer_without_device_header(monkeypatch):
    captured, _ = _install_capture(
        monkeypatch,
        FakeResponse(b'{"vault_id":"v1","device_id":"d1"}', status=201),
    )
    result = _client().create_vault(
        device_token=Sealed(DEVICE_TOKEN),
        sign_public_key="sign-pub",
        wrap_public_key="wrap-pub",
    )
    assert result == {"vault_id": "v1", "device_id": "d1"}

    req = captured[0][0]
    headers = _headers(req)
    payload = _json_body(req)
    assert req.full_url.endswith("/v1/vaults")
    assert req.get_method() == "POST"
    assert "x-device-id" not in headers
    assert set(payload) == {"device_token", "sign_public_key", "wrap_public_key"}
    assert _digest(payload["device_token"]) == _digest(DEVICE_TOKEN)
    assert payload["sign_public_key"] == "sign-pub"
    assert payload["wrap_public_key"] == "wrap-pub"


def test_append_commit_encodes_opaque_blobs_and_expected_parent(monkeypatch):
    captured, _ = _install_capture(
        monkeypatch,
        FakeResponse(b'{"commit_id":"next"}', status=201),
    )
    result = _client().append_commit(
        "vault/with slash",
        commit_blob=b'{"signed":true}',
        snapshot_ciphertext=b"\x00encrypted\xff",
        expected_parent="parent-1",
    )
    assert result == {"commit_id": "next"}

    req = captured[0][0]
    payload = _json_body(req)
    assert req.full_url.endswith("/v1/vaults/vault%2Fwith%20slash/commits")
    assert payload == {
        "expected_parent_commit_id": "parent-1",
        "commit_blob": base64.urlsafe_b64encode(b'{"signed":true}').rstrip(b"=").decode("ascii"),
        "snapshot_ciphertext": base64.urlsafe_b64encode(b"\x00encrypted\xff").rstrip(b"=").decode("ascii"),
    }


def test_commit_list_get_and_device_request_shapes(monkeypatch):
    captured, _ = _install_capture(monkeypatch)
    client = _client()
    client.get_commit("v1", "commit/1")
    client.list_commits("v1", after_sequence=7, limit=25)
    client.list_devices("v1")
    client.revoke_device(
        "v1",
        "lost/device",
        expected_head="a" * 64,
        revocation_statement='{"device_id":"lost/device"}',
        revocation_signature="signature",
    )

    requests = [item[0] for item in captured]
    assert requests[0].full_url.endswith("/v1/vaults/v1/commits/commit%2F1")
    assert requests[1].full_url.endswith(
        "/v1/vaults/v1/commits?limit=25&after_sequence=7"
    )
    assert requests[2].full_url.endswith("/v1/vaults/v1/devices")
    assert requests[3].full_url.endswith("/v1/vaults/v1/devices/lost%2Fdevice/revoke")
    assert _json_body(requests[3]) == {
        "expected_head_commit_id": "a" * 64,
        "revocation_statement": '{"device_id":"lost/device"}',
        "revocation_signature": "signature",
    }


def test_invite_request_shapes_and_claim_is_unauthenticated(monkeypatch):
    captured, _ = _install_capture(monkeypatch)
    client = _client()
    client.create_invite("v1", secret_hash="f" * 64, expires_in_seconds=300)
    client.claim_invite(
        "invite/1",
        secret=Sealed(INVITE_SECRET),
        device_id="dev-new",
        device_token=Sealed(DEVICE_TOKEN),
        sign_public_key="new-sign-pub",
        wrap_public_key="new-wrap-pub",
    )
    client.invite_status("invite/1")
    client.get_invite("v1", "invite/1")
    wrapped = '{"ciphertext":"opaque-envelope","kem":"X25519"}'
    returned = {"status": "active", "wrapped_vault_key": wrapped}
    captured_response = FakeResponse(json.dumps(returned).encode())
    monkeypatch.setattr(vc, "urlopen", lambda *_a, **_kw: captured_response)
    result = client.approve_invite(
        "v1",
        "invite/1",
        wrapped_vault_key=wrapped,
        membership_statement='{"device_id":"dev-new"}',
        membership_signature="member-signature",
    )
    assert result["wrapped_vault_key"] is not None

    create, claim, status, inspect = [item[0] for item in captured]
    assert create.full_url.endswith("/v1/vaults/v1/invites")
    assert _json_body(create) == {"secret_hash": "f" * 64, "expires_in_seconds": 300}
    assert claim.full_url.endswith("/v1/invites/invite%2F1/claim")
    claim_headers = _headers(claim)
    assert "authorization" not in claim_headers
    assert "x-device-id" not in claim_headers
    claim_payload = _json_body(claim)
    assert _digest(claim_payload.pop("secret")) == _digest(INVITE_SECRET)
    assert _digest(claim_payload.pop("device_token")) == _digest(DEVICE_TOKEN)
    assert claim_payload == {
        "device_id": "dev-new",
        "sign_public_key": "new-sign-pub",
        "wrap_public_key": "new-wrap-pub",
    }
    assert status.full_url.endswith("/v1/invites/invite%2F1/status")
    assert _headers(status)["x-device-id"] == "dev-01"
    assert inspect.full_url.endswith("/v1/vaults/v1/invites/invite%2F1")


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (401, vc.VpsAuthenticationError),
        (403, vc.VpsAuthenticationError),
        (404, vc.VpsNotFoundError),
        (409, vc.VpsConflictError),
        (410, vc.VpsInviteExpiredError),
        (413, vc.VpsPayloadTooLargeError),
        (422, vc.VpsValidationError),
        (500, vc.VpsTransportError),
    ],
)
def test_http_status_mapping_does_not_include_server_body(monkeypatch, status, error_type):
    error_body = b'{"error":{"message":"opaque-wrapped-key-material"}}'

    def fail(req, **_kwargs):
        raise HTTPError(req.full_url, status, "failure", {}, io.BytesIO(error_body))

    monkeypatch.setattr(vc, "urlopen", fail)
    with pytest.raises(error_type) as raised:
        _client().get_commit("v1", "missing")
    assert "opaque-wrapped-key-material" not in str(raised.value)
    assert AUTH_TOKEN not in str(raised.value)


def test_http_error_exposes_only_allowlisted_server_code(monkeypatch):
    error_body = b'{"error":{"code":"root_required","message":"untrusted details"}}'

    def fail(req, **_kwargs):
        raise HTTPError(req.full_url, 403, "failure", {}, io.BytesIO(error_body))

    monkeypatch.setattr(vc, "urlopen", fail)
    with pytest.raises(vc.VpsAuthenticationError) as raised:
        _client().create_invite("v1", secret_hash="f" * 64, expires_in_seconds=300)
    assert "root_required" in str(raised.value)
    assert "untrusted details" not in str(raised.value)


def test_missing_head_is_none_but_other_404s_remain_typed(monkeypatch):
    def fail(req, **_kwargs):
        raise HTTPError(req.full_url, 404, "missing", {}, io.BytesIO())

    monkeypatch.setattr(vc, "urlopen", fail)
    assert _client().get_head("v1") is None
    with pytest.raises(vc.VpsNotFoundError):
        _client().get_commit("v1", "missing")


def test_network_error_is_redacted_even_if_provider_echoes_token(monkeypatch):
    def fail(_req, **_kwargs):
        raise URLError(f"upstream accidentally echoed {AUTH_TOKEN}")

    monkeypatch.setattr(vc, "urlopen", fail)
    with pytest.raises(vc.VpsTransportError) as raised:
        _client().get_head("v1")
    assert AUTH_TOKEN not in str(raised.value)
    assert "<redacted>" in str(raised.value)


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b"not-json", None),
        (b'{"a":1,"a":2}', None),
        (b'{"n":NaN}', None),
        (b"{} trailing", None),
        (b"{}", {"Content-Type": "text/plain"}),
        (b"{}", {"Content-Type": "application/json; charset=utf-16"}),
        (b"{}", {"Content-Type": "application/json", "Content-Encoding": "gzip"}),
    ],
)
def test_strict_json_response_validation(monkeypatch, body, headers):
    _install_capture(monkeypatch, FakeResponse(body, headers=headers))
    with pytest.raises(vc.VpsProtocolError):
        _client().get_head("v1")


def test_response_must_be_a_json_object(monkeypatch):
    _install_capture(monkeypatch, FakeResponse(b"[]"))
    with pytest.raises(vc.VpsProtocolError):
        _client().get_head("v1")


def test_declared_and_actual_response_limits(monkeypatch):
    _install_capture(
        monkeypatch,
        FakeResponse(b"{}", headers={"Content-Length": "1000"}),
    )
    with pytest.raises(vc.VpsPayloadTooLargeError):
        _client(max_response_bytes=10).get_head("v1")

    _install_capture(
        monkeypatch,
        FakeResponse(b'{"padding":"xxxxxxxxxxxxxxxx"}', headers={"Content-Length": ""}),
    )
    with pytest.raises(vc.VpsProtocolError):
        _client(max_response_bytes=10).get_head("v1")

    _install_capture(
        monkeypatch,
        FakeResponse(b'{"padding":"xxxxxxxxxxxxxxxx"}', headers={"Content-Length": "29"}),
    )
    with pytest.raises(vc.VpsPayloadTooLargeError):
        _client(max_response_bytes=10).get_head("v1")


def test_actual_response_limit_when_content_length_is_absent(monkeypatch):
    response = FakeResponse(b'{"padding":"xxxxxxxxxxxxxxxx"}')
    del response.headers["Content-Length"]
    _install_capture(monkeypatch, response)
    with pytest.raises(vc.VpsPayloadTooLargeError):
        _client(max_response_bytes=10).get_head("v1")


def test_request_body_limit_is_enforced_before_network(monkeypatch):
    called = False

    def should_not_run(*_args, **_kwargs):
        nonlocal called
        called = True
        return FakeResponse()

    monkeypatch.setattr(vc, "urlopen", should_not_run)
    with pytest.raises(vc.VpsPayloadTooLargeError):
        _client(max_request_bytes=40).append_commit(
            "v1",
            commit_blob=b"x" * 100,
            snapshot_ciphertext=b"y" * 100,
            expected_parent=None,
        )
    assert called is False


def test_callback_token_and_explicit_proxy(monkeypatch):
    captured, _ = _install_capture(monkeypatch)
    _client(token=lambda: Sealed(AUTH_TOKEN), proxy="http://127.0.0.1:8888").get_head("v1")
    assert captured[0][2] == "http://127.0.0.1:8888"


def test_timeout_is_a_transport_error(monkeypatch):
    monkeypatch.setattr(
        vc,
        "urlopen",
        lambda *_a, **_kw: (_ for _ in ()).throw(TimeoutError("timed out")),
    )
    with pytest.raises(vc.VpsTransportError, match="timed out"):
        _client().get_head("v1")
