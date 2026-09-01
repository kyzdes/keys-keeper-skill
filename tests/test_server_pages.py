import threading
import time
import urllib.request
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
    threading.Thread(target=server.serve_forever, daemon=True).start()
    while server.bound_port == 0:
        time.sleep(0.01)
    yield server
    server.stop()


def _get(admin, path):
    req = urllib.request.Request(f"http://127.0.0.1:{admin.bound_port}{path}")
    req.add_header("Sec-Keys-Token", admin.token)
    return urllib.request.urlopen(req, timeout=2).read().decode("utf-8")


def _seed(monkeypatch, name, type_="api_key"):
    monkeypatch.setattr("sys.stdin", StringIO("v\n"))
    cli.main(["add", name, "--type", type_, "--stdin"])


def test_dashboard_returns_html_with_topbar(admin):
    body = _get(admin, "/")
    assert "<title>keys-keeper" in body
    assert "Dashboard" in body
    assert "Bulk import" in body


def test_dashboard_has_unified_table_markup(admin):
    body = _get(admin, "/")
    # The locked variant per ux-spec § 8.4 DIM 1 is unified-table
    assert "unified-table-head" in body or 'class="unified-table-head"' in body or 'data-grouping="unified"' in body


def test_dashboard_includes_search_and_palette_trigger(admin):
    body = _get(admin, "/")
    assert "search" in body.lower()
    assert "cmdk" in body.lower() or "⌘K" in body
    assert 'id="theme-toggle"' in body
    assert "Names only · values stay in the backend" not in body


def test_app_js_fetches_entries_with_token(admin):
    js = _get(admin, "/static/app.js")
    assert "fetch" in js or "XMLHttpRequest" in js
    assert "keys-keeper-theme" in js
    assert "Sec-Keys-Token" not in js
    assert "KK_TOKEN" not in js
    assert "sessionStorage" not in js


def test_theme_bootstrap_is_external_and_csp_compatible(admin):
    body = _get(admin, "/")
    theme_js = _get(admin, "/static/theme.js")
    assert '<script src="/static/theme.js"></script>' in body
    assert "keys-keeper-theme" in theme_js


def test_settings_status_uses_dom_text_not_untrusted_html(admin):
    js = _get(admin, "/static/app.js")
    assert "${s.config_dir}" not in js
    assert "kvRow('config_dir', s.config_dir" in js
    assert "getElementById('status-body').innerHTML" not in js


def test_entry_detail_renders(admin, monkeypatch):
    _seed(monkeypatch, "detail-target")
    body = _get(admin, "/entry/detail-target")
    assert "detail-target" in body
    assert "Copy value" in body
    assert "Linked entries" in body or "fields-mount" in body
