"""Tests for the live-admin-URL handoff used by the macOS quick-launch app.

`keys serve` writes its tokened URL to `paths.serve_url_file` on start and
removes it on shutdown, so a second launch of the shortcut can re-open the
running tab instead of failing to bind :7777.
"""
from __future__ import annotations

import errno
import stat
import sys
from types import SimpleNamespace

import pytest

from keys_keeper.paths import Paths


def test_serve_url_file_under_home(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    p = Paths()
    assert p.serve_url_file == tmp_path / "kk" / "serve-url"


def test_write_then_clear_serve_url(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    from keys_keeper import cli

    p = Paths()
    p.ensure()
    url = "http://127.0.0.1:7777/?t=deadbeef"

    cli._write_serve_url(p, url)
    assert p.serve_url_file.read_text(encoding="utf-8") == url

    cli._clear_serve_url(p)
    assert not p.serve_url_file.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_serve_url_is_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    from keys_keeper import cli

    p = Paths()
    p.ensure()
    cli._write_serve_url(p, "http://127.0.0.1:7777/?t=abc")
    mode = stat.S_IMODE(p.serve_url_file.stat().st_mode)
    assert mode == 0o600


def test_clear_serve_url_is_safe_when_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    from keys_keeper import cli

    p = Paths()
    p.ensure()
    # Should not raise even though the file was never written.
    cli._clear_serve_url(p)


def test_busy_serve_port_preserves_live_url_and_never_opens_dead_token(
    monkeypatch, tmp_path, capsys
):
    """A failed second launch must leave the first session recoverable."""
    from keys_keeper import cli
    import keys_keeper.server as server_module

    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    paths = Paths()
    paths.ensure()
    original_url = "http://127.0.0.1:7777/?t=existing-session"
    cli._write_serve_url(paths, original_url)

    class BusyServer:
        def __init__(self, **_kwargs):
            self.token = "dead-session"

        def start(self):
            raise OSError(errno.EADDRINUSE, "Address already in use")

    opened = []
    monkeypatch.setattr(server_module, "AdminServer", BusyServer)
    monkeypatch.setattr(cli, "_context_or_error", lambda _args: SimpleNamespace(paths=paths))
    monkeypatch.setattr(cli.webbrowser, "open", opened.append)
    args = SimpleNamespace(port=7777, no_open=False, profile_selector=None, profile_environment=None)

    assert cli.cmd_serve(args) == 1
    captured = capsys.readouterr()
    assert "already using 127.0.0.1:7777" in captured.err
    assert "dead-session" not in captured.out + captured.err
    assert opened == []
    assert paths.serve_url_file.read_text(encoding="utf-8") == original_url


def test_serve_uses_bound_port_after_start(monkeypatch, tmp_path, capsys):
    """An OS-selected port must be reflected in the one URL the CLI opens."""
    from keys_keeper import cli
    import keys_keeper.server as server_module

    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    paths = Paths()
    paths.ensure()

    class StartedServer:
        token = "test-session"
        bound_port = 49123

        def __init__(self, **_kwargs):
            self.started = False

        def start(self):
            self.started = True

        def serve_forever(self):
            assert self.started

        def stop(self):
            return None

    written_urls = []
    monkeypatch.setattr(server_module, "AdminServer", StartedServer)
    monkeypatch.setattr(cli, "_context_or_error", lambda _args: SimpleNamespace(paths=paths))
    monkeypatch.setattr(cli, "_maybe_suggest_app_install", lambda: None)
    monkeypatch.setattr(cli, "_write_serve_url", lambda _paths, url: written_urls.append(url))
    monkeypatch.setattr(cli, "_clear_serve_url", lambda _paths: None)
    args = SimpleNamespace(port=0, no_open=True, profile_selector=None, profile_environment=None)

    assert cli.cmd_serve(args) == 0
    assert written_urls == ["http://127.0.0.1:49123/?t=test-session"]
    assert "http://127.0.0.1:49123/?t=test-session" in capsys.readouterr().out
