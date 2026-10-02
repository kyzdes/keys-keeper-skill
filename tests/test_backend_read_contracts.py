"""Typed read failures; no platform provider or real vault is accessed."""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from keys_keeper.backend import (
    MacOSKeychainBackend, Sealed,
    SecretAccessDenied, SecretNotFound, SecretUnavailable,
)
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.macos_keychain import SecurityFrameworkError
from keys_keeper.paths import Paths


MARKER = "synthetic-secret-must-not-be-in-errors"


@pytest.mark.parametrize("value", [None, b"synthetic", 123, {"unexpected": "value"}])
def test_provider_cannot_construct_a_non_string_sealed_value(value):
    with pytest.raises(TypeError, match="must be a string"):
        Sealed(value)


@pytest.mark.parametrize("status,error_type", [
    (-25300, SecretNotFound), (-128, SecretAccessDenied),
    (-25293, SecretAccessDenied), (-25308, SecretAccessDenied),
    (-50, SecretUnavailable),
])
def test_native_macos_status_has_explicit_absence_denial_or_unavailability(status, error_type):
    def failed_read(_account):
        raise SecurityFrameworkError(MARKER, status)
    backend = MacOSKeychainBackend.__new__(MacOSKeychainBackend)
    backend._native = SimpleNamespace(get=failed_read, allow_interaction=True)
    with pytest.raises(error_type) as caught:
        backend.get("kk:synthetic")
    assert MARKER not in str(caught.value)
    assert caught.value.__cause__ is None


def test_macos_failed_legacy_acl_probe_is_unavailable_and_never_tries_child_read():
    def failed_read(_account):
        raise SecurityFrameworkError(MARKER, -25308)
    def failed_probe(_account):
        raise SecurityFrameworkError(MARKER, -50)
    backend = MacOSKeychainBackend.__new__(MacOSKeychainBackend)
    backend.allow_legacy_bridge = True
    backend._native = SimpleNamespace(get=failed_read, allow_interaction=False,
                                     legacy_security_read_allowed=failed_probe)
    backend._read_legacy_security_bridge = lambda *_: (_ for _ in ()).throw(AssertionError("child read attempted"))
    with pytest.raises(SecretUnavailable) as caught:
        backend.get("kk:synthetic")
    assert MARKER not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("status", [1, 2, 127])
def test_linux_lookup_status_is_conservative_and_does_not_emit_helper_diagnostics(monkeypatch, status):
    from keys_keeper import backend_linux
    monkeypatch.setattr(backend_linux, "_secret_tool_path", lambda: "/synthetic/secret-tool")
    monkeypatch.setattr(backend_linux, "_run_tool", lambda *_args, **_kwargs:
                        SimpleNamespace(returncode=status, stdout="", stderr=MARKER))
    with pytest.raises(SecretUnavailable) as caught:
        backend_linux.SecretToolBackend().get("kk:synthetic")
    assert MARKER not in str(caught.value)
    assert not isinstance(caught.value, SecretNotFound)


def test_linux_timeout_is_unavailable_and_hides_captured_value(monkeypatch):
    from keys_keeper import backend_linux
    monkeypatch.setattr(backend_linux, "_secret_tool_path", lambda: "/synthetic/secret-tool")
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["synthetic-tool"], 10, output=MARKER)
    monkeypatch.setattr(backend_linux.subprocess, "run", timeout)
    with pytest.raises(SecretUnavailable) as caught:
        backend_linux.SecretToolBackend().get("kk:synthetic")
    assert MARKER not in str(caught.value)


@pytest.mark.parametrize("code,error_type", [
    (1168, SecretNotFound), (5, SecretAccessDenied), (1312, SecretUnavailable),
])
def test_windows_read_status_is_typed_without_running_credential_manager(monkeypatch, code, error_type):
    from keys_keeper import backend_windows
    monkeypatch.setattr(backend_windows, "_CredReadW", lambda *_args: False, raising=False)
    monkeypatch.setattr(backend_windows.ctypes, "get_last_error", lambda: code, raising=False)
    with pytest.raises(error_type):
        backend_windows._read_blob("synthetic-target")


@pytest.mark.parametrize("chunks", [-1, 0, True, "2", 1.5, 100_000_000])
def test_windows_invalid_chunk_header_fails_before_any_chunk_read(monkeypatch, chunks):
    from keys_keeper import backend_windows
    calls = []
    def read_header(target):
        calls.append(target)
        return bytes([backend_windows._FMT_CHUNKED]) + json.dumps({"chunks": chunks}).encode()
    monkeypatch.setattr(backend_windows, "_read_blob", read_header)
    with pytest.raises(SecretUnavailable):
        backend_windows.WindowsCredentialBackend(service="synthetic").get("kk:entry")
    assert calls == ["synthetic:kk:entry"]


def test_windows_missing_chunk_is_corruption_of_existing_secret_not_absence(monkeypatch):
    from keys_keeper import backend_windows
    def read(target):
        if target.startswith("synthetic-chunk:"):
            raise SecretNotFound("missing chunk")
        return bytes([backend_windows._FMT_CHUNKED]) + b'{"chunks":1}'
    monkeypatch.setattr(backend_windows, "_read_blob", read)
    with pytest.raises(SecretUnavailable):
        backend_windows.WindowsCredentialBackend(service="synthetic").get("kk:entry")


def test_encrypted_file_absence_and_authentication_failure_are_distinct(tmp_path, monkeypatch):
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", "synthetic-password")
    paths = Paths(root=tmp_path / "isolated-file-backend")
    backend = EncryptedFileBackend(paths=paths)
    with pytest.raises(SecretNotFound):
        backend.get("kk:entry")
    backend.set("kk:entry", MARKER)
    assert backend.get("kk:entry") == Sealed(MARKER)
    blob = paths.secrets_enc.read_bytes()
    paths.secrets_enc.write_bytes(blob[:-1] + bytes([blob[-1] ^ 1]))
    with pytest.raises(SecretUnavailable) as caught:
        backend.get("kk:entry")
    assert MARKER not in str(caught.value)


def test_serve_token_handoff_refuses_symlink_without_mutating_victim(tmp_path):
    from keys_keeper import cli
    victim = tmp_path / "unrelated-file"
    victim.write_text("original")
    paths = Paths(root=tmp_path / "isolated-server")
    paths.ensure()
    try:
        paths.serve_url_file.symlink_to(victim)
    except OSError:
        pytest.skip("unprivileged symlinks unavailable")
    cli._write_serve_url(paths, "http://127.0.0.1:7777/?t=" + MARKER)
    assert victim.read_text() == "original"
