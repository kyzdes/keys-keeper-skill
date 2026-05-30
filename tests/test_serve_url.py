"""Tests for the live-admin-URL handoff used by the macOS quick-launch app.

`keys serve` writes its tokened URL to `paths.serve_url_file` on start and
removes it on shutdown, so a second launch of the shortcut can re-open the
running tab instead of failing to bind :7777.
"""
from __future__ import annotations

import stat
import sys

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
