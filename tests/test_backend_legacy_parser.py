"""Byte-level Apple security -g contracts; no OS store or credential is read."""
import subprocess
import traceback
from types import SimpleNamespace

import pytest

from keys_keeper.backend import KeychainError, MacOSKeychainBackend, _decode_legacy_security_password
from keys_keeper.macos_keychain import SecurityFrameworkError


@pytest.mark.parametrize(("record", "expected"), [
    (b'password: "plain"\n', "plain"),
    (b'password: "616263646566"\n', "616263646566"),
    (b'password: "0xDEADBEEF"\n', "0xDEADBEEF"),
    (b'password: "a"b"\n', 'a"b'),
    (b'password: \n', ""),
    (b'password: 0x610A  "a\\012"\n', "a\n"),
    (b'password: 0x0A0A \n', "\n\n"),
    (b'password: 0x610D0A620D0A  "a\\015\\012b\\015\\012"\n', "a\r\nb\r\n"),
    (b'password: 0x615C62  "a\\134b"\n', "a\\b"),
    (b'password: 0xCEBB \n', "λ"),
    (b'password: 0x61CEBB  "a\\316\\273"\n', "aλ"),
    (b'password: 0x6122620A  "a"b\\012"\n', 'a"b\n'),
    (b'password: 0x00 \n', "\x00"),
])
def test_tagged_password_record_preserves_exact_bytes(record, expected):
    assert _decode_legacy_security_password(record) == expected


@pytest.mark.parametrize("record", [
    b"", b'"plain"\n', b'password: "plain"', b'password: "unterminated\n',
    b'password: ""\n', b'password: "a\\b"\n', b'password: "\xff"\n',
    b'password: "first"\npassword: "second"\n', b'warning\npassword: "x"\n',
    b'password: "x"\nwarning\n', b'password: 0xA \n', b'password: 0xGG \n',
    b'password: 0xff \n', b'password: 0xFF \n', b'password: 0x0A\n',
    b'password: 0x610A  "different"\n', b'password: 0x61  "a"\n',
    b'password: 0x61 62 \n', b'password: 0x610A "a\\012"\n',
])
def test_malformed_or_non_utf8_record_fails_closed(record):
    assert _decode_legacy_security_password(record) is None


def fake_legacy_backend():
    backend = object.__new__(MacOSKeychainBackend)
    backend.service = "synthetic-test-service"
    backend.keychain_path = "/synthetic/test.keychain-db"
    backend.allow_legacy_bridge = True

    def denied(_account):
        raise SecurityFrameworkError("read keychain item", -25308)

    backend._native = SimpleNamespace(
        allow_interaction=False, get=denied, legacy_security_read_allowed=lambda _account: True,
    )
    return backend


def test_legacy_bridge_uses_one_tagged_read_with_all_streams_private(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, b"ignored metadata\n", b'password: 0x610A  "a\\012"\n')

    monkeypatch.setattr(subprocess, "run", run)
    result = fake_legacy_backend().get("kk:synthetic")
    assert result.unseal() == "a\n"
    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command == ["/usr/bin/security", "find-generic-password", "-s", "synthetic-test-service",
                       "-a", "kk:synthetic", "-g", "/synthetic/test.keychain-db"]
    assert kwargs == {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
                      "check": False, "timeout": 5}


@pytest.mark.parametrize("failure", ["timeout", "oserror", "exit", "malformed", "utf8"])
@pytest.mark.parametrize("public_get", [False, True])
def test_legacy_bridge_errors_have_no_secret_bearing_exception_chain(monkeypatch, failure, public_get):
    marker = b"SYNTHETIC-SENSITIVE-ERROR-PAYLOAD"
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 5, output=marker, stderr=marker)
        if failure == "oserror":
            raise OSError(marker.decode())
        if failure == "exit":
            return subprocess.CompletedProcess(command, 1, marker, marker)
        record = b'password: "' + marker + b'"\nextra\n' if failure == "malformed" else b'password: 0xFF \n'
        return subprocess.CompletedProcess(command, 0, marker, record)

    monkeypatch.setattr(subprocess, "run", run)
    backend = fake_legacy_backend()
    with pytest.raises(KeychainError) as caught:
        if public_get:
            backend.get("kk:synthetic")
        else:
            backend._read_legacy_security_bridge("kk:synthetic")
    assert len(calls) == 1
    assert caught.value.__cause__ is None
    if public_get:
        assert isinstance(caught.value.__context__, SecurityFrameworkError)
    else:
        assert caught.value.__context__ is None
    error = caught.value
    while error is not None:
        assert not isinstance(error, (UnicodeDecodeError, subprocess.TimeoutExpired, OSError))
        assert marker.decode() not in str(error)
        error = error.__cause__ or error.__context__
    assert marker.decode() not in "".join(traceback.format_exception(caught.type, caught.value, caught.tb))
