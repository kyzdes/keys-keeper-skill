import plistlib
import subprocess
from pathlib import Path

import pytest

from keys_keeper import macos_app


@pytest.fixture
def fake_macos_build(monkeypatch):
    monkeypatch.setattr(macos_app, "is_macos", lambda: True)
    monkeypatch.setattr(macos_app, "_spotlight_reindex", lambda _path: None)
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: True if self.as_posix() == "/usr/bin/xcrun" else real_exists(self))
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        if "swiftc" in command:
            executable = Path(command[command.index("-o") + 1])
            executable.write_bytes(b"synthetic-native-binary")
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(macos_app.subprocess, "run", run)
    return calls


def test_native_bundle_has_private_bridge_and_recorded_runtime(tmp_path, fake_macos_build):
    result = macos_app.install_menubar_app(tmp_path)
    contents = result.bundle_path / "Contents"
    info = plistlib.loads((contents / "Info.plist").read_bytes())
    assert info["CFBundleExecutable"] == "keys-keeper-menubar"
    assert info["LSUIElement"] is True
    assert info["LSMinimumSystemVersion"] == "13.0"
    assert (contents / "Resources/python/keys_keeper/desktop_bridge.py").exists()
    assert info["KKPythonExecutable"]
    assert fake_macos_build[-1][0] == "/usr/bin/codesign"


def test_failed_compilation_preserves_working_app(tmp_path, fake_macos_build, monkeypatch):
    original = macos_app.install_app(tmp_path).bundle_path
    original_info = (original / "Contents/Info.plist").read_bytes()
    def failure(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "swiftc")
    monkeypatch.setattr(macos_app.subprocess, "run", failure)
    with pytest.raises(RuntimeError, match="native app build failed"):
        macos_app.install_menubar_app(tmp_path, force=True)
    assert (original / "Contents/Info.plist").read_bytes() == original_info
    assert (original / "Contents/MacOS/keys-keeper-launcher").exists()


def test_different_bundle_cannot_be_overwritten(tmp_path, fake_macos_build):
    contents = tmp_path / "Keys Keeper.app/Contents"
    contents.mkdir(parents=True)
    (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "another.app"}))
    with pytest.raises(RuntimeError, match="different bundle"):
        macos_app.install_menubar_app(tmp_path, force=True)
