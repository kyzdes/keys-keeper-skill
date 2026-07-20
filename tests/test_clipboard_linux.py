"""Tests for Linux clipboard tool resolution.

Pure-function tests over the tool-priority logic (wl-copy → xclip → xsel) and
the headless error. Run on every platform via shutil.which mocking — no real
clipboard tool needed.
"""
from __future__ import annotations

import pytest

from keys_keeper import clipboard


def _only(*present):
    avail = set(present)
    return lambda name: ("/usr/bin/" + name) if name in avail else None


def test_prefers_wayland(monkeypatch):
    monkeypatch.setattr(
        clipboard.shutil,
        "which",
        _only("wl-copy", "wl-paste", "xclip", "xsel"),
    )
    assert clipboard._linux_copy_cmd()[0] == "/usr/bin/wl-copy"
    assert clipboard._linux_paste_cmd()[0] == "/usr/bin/wl-paste"


def test_falls_back_to_xclip(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", _only("xclip", "xsel"))
    assert clipboard._linux_copy_cmd()[0] == "/usr/bin/xclip"
    assert clipboard._linux_paste_cmd() == [
        "/usr/bin/xclip", "-selection", "clipboard", "-o",
    ]


def test_falls_back_to_xsel(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", _only("xsel"))
    assert clipboard._linux_copy_cmd() == [
        "/usr/bin/xsel", "--clipboard", "--input",
    ]
    assert clipboard._linux_paste_cmd() == [
        "/usr/bin/xsel", "--clipboard", "--output",
    ]


def test_headless_raises_clear_error(monkeypatch):
    monkeypatch.setattr(clipboard.shutil, "which", _only())  # nothing present
    with pytest.raises(clipboard.ClipboardUnavailable) as exc:
        clipboard._linux_copy_cmd()
    assert "inject" in str(exc.value)
    with pytest.raises(clipboard.ClipboardUnavailable):
        clipboard._linux_paste_cmd()
