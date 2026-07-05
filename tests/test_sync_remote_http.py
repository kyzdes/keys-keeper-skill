"""S3Remote verb behaviour with a monkeypatched urlopen — no live bucket.

Captures the signed request and returns canned responses to assert: signing
headers, If-None-Match emission, status->error mapping, timeout handling, XML
list parsing, and the CAS probe. (F24-F27, S5)
"""
import hashlib
import io
import pytest
from urllib.error import HTTPError

import keys_keeper.sync_remote as sr
from keys_keeper.backend import Sealed
from keys_keeper.sync_remote import (
    S3Signer, S3Remote, TransportError, AuthError, NotFound, PreconditionFailed,
)


class FakeResp:
    def __init__(self, status=200, headers=None, body=b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=-1):
        return self._body


def _remote(handler):
    """Build an S3Remote whose urlopen is driven by `handler(req) -> FakeResp`."""
    captured = []

    def fake_urlopen(req, timeout=None, **_kw):  # **_kw absorbs proxy= (see _request)
        captured.append(req)
        return handler(req, captured)

    return (
        S3Remote(
            signer=S3Signer("AKIDEXAMPLE", Sealed("secretkey"), region="us-east-1"),
            endpoint="https://s3.example.com", bucket="mybucket", prefix="kk",
        ),
        captured,
        fake_urlopen,
    )


def _headers(req):
    return {k.lower(): v for k, v in req.header_items()}


def _http_error(req, code):
    return HTTPError(req.full_url, code, "err", {}, io.BytesIO(b"<Error/>"))


def test_F25_put_signs_and_emits_if_none_match(monkeypatch):
    body = b"\x00\x01encrypted-snapshot"
    remote, captured, fake = _remote(lambda req, c: FakeResp(201, {"ETag": '"abc123"'}))
    monkeypatch.setattr(sr, "urlopen", fake)
    etag = remote.put_object("versions/000001.json", body, if_none_match="*")
    assert etag == "abc123"
    req = captured[-1]
    h = _headers(req)
    assert h["if-none-match"] == "*"
    assert h["authorization"].startswith("AWS4-HMAC-SHA256 ")
    assert "x-amz-date" in h
    assert h["x-amz-content-sha256"] == hashlib.sha256(body).hexdigest()
    assert req.full_url == "https://s3.example.com/mybucket/kk/versions/000001.json"
    assert req.get_method() == "PUT"
    # S5: the secret key value never appears in any header or the URL
    assert "secretkey" not in req.full_url
    assert all("secretkey" not in v for v in h.values())


def test_F25_get_returns_body(monkeypatch):
    remote, captured, fake = _remote(lambda req, c: FakeResp(200, {}, b"payload-bytes"))
    monkeypatch.setattr(sr, "urlopen", fake)
    assert remote.get_object("HEAD") == b"payload-bytes"


@pytest.mark.parametrize("code,exc", [
    (404, NotFound), (403, AuthError), (401, AuthError),
    (412, PreconditionFailed), (409, PreconditionFailed), (500, TransportError),
])
def test_F26_status_mapping(monkeypatch, code, exc):
    remote, _, fake = _remote(lambda req, c: (_ for _ in ()).throw(_http_error(req, code)))
    monkeypatch.setattr(sr, "urlopen", fake)
    with pytest.raises(exc):
        remote.get_object("x")


def test_head_returns_none_on_404(monkeypatch):
    remote, _, fake = _remote(lambda req, c: (_ for _ in ()).throw(_http_error(req, 404)))
    monkeypatch.setattr(sr, "urlopen", fake)
    assert remote.head_object("missing") is None


def test_F27_timeout_becomes_transport_error(monkeypatch):
    def boom(req, c):
        raise TimeoutError("timed out")
    remote, _, fake = _remote(boom)
    monkeypatch.setattr(sr, "urlopen", fake)
    with pytest.raises(TransportError):
        remote.get_object("x")


def test_F24_list_objects_parses_xml_and_strips_prefix(monkeypatch):
    xml = (
        '<?xml version="1.0"?>'
        '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
        "<IsTruncated>false</IsTruncated>"
        "<Contents><Key>kk/versions/000001.json</Key></Contents>"
        "<Contents><Key>kk/versions/000002.json</Key></Contents>"
        "</ListBucketResult>"
    ).encode()
    remote, captured, fake = _remote(lambda req, c: FakeResp(200, {}, xml))
    monkeypatch.setattr(sr, "urlopen", fake)
    keys = remote.list_objects("versions/")
    assert keys == ["versions/000001.json", "versions/000002.json"]
    # bucket-level list request carries list-type=2 in the query
    assert "list-type=2" in captured[-1].full_url


def test_probe_cas_true_when_second_put_rejected(monkeypatch):
    state = {"n": 0}

    def handler(req, c):
        if req.get_method() == "DELETE":
            return FakeResp(204)
        state["n"] += 1
        if state["n"] == 2:  # second PUT must be rejected by a compliant provider
            raise _http_error(req, 412)
        return FakeResp(201, {"ETag": '"x"'})

    remote, _, fake = _remote(handler)
    monkeypatch.setattr(sr, "urlopen", fake)
    assert remote.probe_cas() is True


def test_probe_cas_false_when_precondition_ignored(monkeypatch):
    def handler(req, c):
        if req.get_method() == "DELETE":
            return FakeResp(204)
        return FakeResp(201, {"ETag": '"x"'})  # both PUTs succeed -> not honored

    remote, _, fake = _remote(handler)
    monkeypatch.setattr(sr, "urlopen", fake)
    assert remote.probe_cas() is False


# ---------------- proxy policy (default = direct/bypass) ----------------

def _proxyhandler(opener):
    return next(h for h in opener.handlers if isinstance(h, sr.ProxyHandler))


def test_proxy_default_is_direct_bypass(monkeypatch):
    # Even with a system/env proxy present, "direct" must apply NO proxy.
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1082")
    sr._OPENERS.clear()
    op = sr._opener_for("direct")
    active = [h for h in op.handlers if isinstance(h, sr.ProxyHandler) and h.proxies]
    assert active == []          # no proxy applied → straight to S3
    sr._OPENERS.clear()          # don't leak the cached opener to other tests


def test_proxy_explicit_url_builds_handler():
    sr._OPENERS.clear()
    ph = _proxyhandler(sr._opener_for("http://127.0.0.1:8080"))
    assert ph.proxies.get("https") == "http://127.0.0.1:8080"
    assert ph.proxies.get("http") == "http://127.0.0.1:8080"


def test_proxy_system_honours_env(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9999")
    sr._OPENERS.pop("system", None)
    ph = _proxyhandler(sr._opener_for("system"))
    assert "127.0.0.1:9999" in (ph.proxies.get("https", "") + ph.proxies.get("http", ""))


def test_request_passes_proxy_and_defaults_to_direct(monkeypatch):
    seen = {}

    def fake(req, timeout=None, *, proxy="MISSING"):
        seen["proxy"] = proxy
        return FakeResp(200, {}, b"")

    monkeypatch.setattr(sr, "urlopen", fake)
    remote = S3Remote(
        signer=S3Signer("AKIDEXAMPLE", Sealed("secretkey"), region="us-east-1"),
        endpoint="https://s3.example.com", bucket="b", prefix="kk",
    )
    remote._request("GET", "/b/kk/x")
    assert seen["proxy"] == "direct"          # default never inherits the OS proxy


def test_proxy_tunnel_error_adds_actionable_hint(monkeypatch):
    from urllib.error import URLError

    def boom(req, timeout=None, **_kw):
        raise URLError("Tunnel connection failed: 503 Service Unavailable")

    monkeypatch.setattr(sr, "urlopen", boom)
    remote = S3Remote(
        signer=S3Signer("AKIDEXAMPLE", Sealed("secretkey"), region="us-east-1"),
        endpoint="https://s3.example.com", bucket="b", prefix="kk", proxy="system",
    )
    with pytest.raises(TransportError) as ei:
        remote._request("GET", "/b/kk/x")
    assert 'sync.proxy="direct"' in str(ei.value)
