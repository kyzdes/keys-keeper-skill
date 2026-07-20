import threading
import time
import http.cookiejar
import urllib.request
import urllib.error
import pytest
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
    # wait for bind
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _fetch(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header("Sec-Keys-Token", token)
    return urllib.request.urlopen(req, timeout=2)


def test_request_without_token_returns_403(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    with pytest.raises(urllib.error.HTTPError) as ex:
        _fetch(url)
    assert ex.value.code == 403


def test_request_with_correct_token_succeeds(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    resp = _fetch(url, token=admin.token)
    assert resp.status == 200


def test_request_with_wrong_token_returns_403(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    with pytest.raises(urllib.error.HTTPError) as ex:
        _fetch(url, token="wrong-token")
    assert ex.value.code == 403


def test_initial_html_response_includes_token_in_query(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    resp = _fetch(url)
    assert resp.status == 200
    body = resp.read().decode("utf-8")
    assert '/static/bootstrap.js' in body
    assert "sessionStorage" not in body
    cookie = resp.headers.get("Set-Cookie", "")
    assert f"kk_session_{admin.bound_port}=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie

    bootstrap = _fetch(
        f"http://127.0.0.1:{admin.bound_port}/static/bootstrap.js"
    ).read().decode("utf-8")
    assert "history.replaceState" in bootstrap
    assert "sessionStorage" not in bootstrap


def test_browser_cookie_authenticates_api_without_js_readable_token(admin):
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    root = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    assert opener.open(root, timeout=2).status == 200
    api = f"http://127.0.0.1:{admin.bound_port}/api/entries"
    assert opener.open(api, timeout=2).status == 200


def test_admin_csp_blocks_inline_script_execution(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    response = _fetch(url)
    csp = response.headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "script-src 'self' 'unsafe-inline'" not in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


def test_no_cache_headers_on_responses(admin):
    url = f"http://127.0.0.1:{admin.bound_port}/?t={admin.token}"
    resp = _fetch(url)
    assert "no-store" in resp.headers.get("Cache-Control", "")
