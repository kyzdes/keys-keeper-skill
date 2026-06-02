"""Tests for `keys quickstart` and the empty-store hint in `keys list`.

quickstart is the friendly onboarding entry point — it must be read-only and
never surface a secret value. These run on every platform via the file backend.
"""
from __future__ import annotations

import io
import sys

import pytest

from keys_keeper import cli


@pytest.fixture
def file_home(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_BACKEND", "file")
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", "test-master")
    # Force the Linux branch so build_backend() honors KEYS_KEEPER_BACKEND on
    # any host running the suite (macOS/Windows otherwise ignore the override).
    from keys_keeper import composition
    monkeypatch.setattr(composition.sys, "platform", "linux")
    return tmp_path


def _add(name: str, value: str):
    sys.stdin = io.StringIO(value)
    rc = cli.main(["add", name, "--type", "api_key", "--stdin"])
    assert rc == 0


def test_quickstart_empty_store(file_home, capsys):
    rc = cli.main(["quickstart"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "quickstart" in out
    assert "entries:    0" in out
    assert "let's add your first key" in out
    assert "keys add my-first-key --from-clipboard" in out


def test_quickstart_populated_store(file_home, capsys):
    _add("demo-key", "sk-demo")
    capsys.readouterr()
    rc = cli.main(["quickstart"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "entries:    1" in out
    assert "You already have 1 entry" in out
    # never leaks the value
    assert "sk-demo" not in out


def test_quickstart_shows_no_secret_value(file_home, capsys):
    _add("kk-key", "super-secret-value")
    capsys.readouterr()
    cli.main(["quickstart"])
    assert "super-secret-value" not in capsys.readouterr().out


def test_list_empty_points_to_quickstart(file_home, capsys):
    rc = cli.main(["list"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "quickstart" in out


def test_list_empty_with_filter_says_no_match(file_home, capsys):
    _add("kk-key", "v")
    capsys.readouterr()
    rc = cli.main(["list", "--tag", "nonexistent"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "no entries match those filters" in out
    assert "quickstart" not in out  # don't nudge quickstart when store is non-empty
