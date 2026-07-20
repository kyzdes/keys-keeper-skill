import subprocess

import pytest
from keys_keeper import backend as backend_module
from keys_keeper.backend import (
    MacOSKeychainBackend,
    KeychainError,
    Sealed,
)


@pytest.fixture
def backend(test_keychain):
    return MacOSKeychainBackend(
        service="keys-keeper-test",
        keychain_path=str(test_keychain),
        allow_interaction=False,
    )


def test_set_and_get_round_trip(backend):
    backend.set("kk:abc", "sk-test-secret")
    assert backend.get("kk:abc").unseal() == "sk-test-secret"


def test_get_returns_sealed_not_str(backend):
    backend.set("kk:abc", "sk-secret")
    result = backend.get("kk:abc")
    assert isinstance(result, Sealed)
    # bare-string comparison fails by construction (catches code that forgot
    # to .unseal())
    assert result != "sk-secret"


def test_get_missing_raises(backend):
    with pytest.raises(KeychainError, match="not found"):
        backend.get("kk:does-not-exist")


def test_set_overwrites_existing(backend):
    backend.set("kk:abc", "first")
    backend.set("kk:abc", "second")
    assert backend.get("kk:abc").unseal() == "second"


def test_delete_removes_entry(backend):
    backend.set("kk:abc", "x")
    backend.delete("kk:abc")
    with pytest.raises(KeychainError):
        backend.get("kk:abc")


def test_delete_missing_is_noop(backend):
    # idempotent delete
    backend.delete("kk:never-set")  # must not raise


def test_delete_propagates_non_missing_keychain_failure(backend, monkeypatch):
    class Result:
        returncode = 1
        stdout = ""
        stderr = "interaction denied"

    monkeypatch.setattr(
        backend_module.subprocess,
        "run",
        lambda *args, **kwargs: Result(),
    )
    with pytest.raises(KeychainError, match="failed to delete"):
        backend.delete("kk:blocked")


def test_list_ids_returns_only_our_service(backend):
    backend.set("kk:a", "1")
    backend.set("kk:b", "2")
    backend.set("kk:b:passphrase", "p")
    ids = set(backend.list_ids())
    assert ids == {"kk:a", "kk:b", "kk:b:passphrase"}


def test_set_multiline_value(backend):
    pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nlinetwo\n-----END-----\n"
    backend.set("kk:multi", pem)
    assert backend.get("kk:multi").unseal() == pem


def test_set_does_not_spawn_secret_in_process_argv(backend, monkeypatch):
    calls = []

    class Result:
        returncode = 44
        stdout = ""
        stderr = ""

    def capture_subprocess(args, **kwargs):
        calls.append(args)
        return Result()

    with monkeypatch.context() as context:
        context.setattr(backend_module.subprocess, "run", capture_subprocess)
        backend.set("kk:no-argv", "short-low-entropy-secret")

    assert calls
    assert all("short-low-entropy-secret" not in command for command in calls)
    assert backend.get("kk:no-argv").unseal() == "short-low-entropy-secret"


def test_native_backend_reads_and_updates_legacy_cli_item(backend, test_keychain):
    """Existing items written by releases that used `security -w` remain valid."""
    subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-s",
            "keys-keeper-test",
            "-a",
            "kk:legacy-cli",
            "-w",
            "non-sensitive-test-value",
            str(test_keychain),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert backend.get("kk:legacy-cli").unseal() == "non-sensitive-test-value"
    backend.set("kk:legacy-cli", "updated-natively")
    assert backend.get("kk:legacy-cli").unseal() == "updated-natively"
