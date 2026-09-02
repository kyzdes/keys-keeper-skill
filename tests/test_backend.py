import subprocess

import pytest
from keys_keeper.backend import (
    MacOSKeychainBackend,
    KeychainError,
    Sealed,
)
from keys_keeper.macos_keychain import SecurityFrameworkError


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
    def fail(_account):
        raise SecurityFrameworkError("delete keychain item", -25293)

    monkeypatch.setattr(backend._native, "delete", fail)
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


def test_native_operations_do_not_spawn_security_process(backend, monkeypatch):
    calls = []

    def capture_subprocess(args, **kwargs):
        calls.append(args)
        raise AssertionError(f"unexpected subprocess: {args}")

    with monkeypatch.context() as context:
        context.setattr(subprocess, "run", capture_subprocess)
        backend.set("kk:no-argv", "short-low-entropy-secret")
        assert backend.get("kk:no-argv").unseal() == "short-low-entropy-secret"
        assert "kk:no-argv" in backend.list_ids()
        backend.delete("kk:no-argv")

    assert calls == []


def test_bypass_reads_original_legacy_cli_only_acl_without_rewriting(
    backend, test_keychain
):
    """An ACL-proven security-only item stays in place and reads silently."""
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
    assert "kk:legacy-cli" in backend.list_ids()


def test_bypass_unknown_acl_fails_before_security_process(backend, monkeypatch):
    def fail_native(_account):
        raise SecurityFrameworkError("read keychain item", -25308)

    monkeypatch.setattr(backend._native, "get", fail_native)
    monkeypatch.setattr(
        backend._native,
        "legacy_security_read_allowed",
        lambda _account: False,
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("security process must not start for an unknown ACL")
        ),
    )
    with pytest.raises(KeychainError, match="bypass blocked the authorization dialog"):
        backend.get("kk:untrusted")


def test_bypass_locked_keychain_fails_before_legacy_bridge(
    backend, test_keychain, monkeypatch
):
    subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-s",
            "keys-keeper-test",
            "-a",
            "kk:legacy-locked",
            "-w",
            "non-sensitive-test-value",
            str(test_keychain),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["/usr/bin/security", "lock-keychain", str(test_keychain)],
        check=True,
        capture_output=True,
        text=True,
    )
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("legacy bridge must not start for a locked Keychain")
        ),
    )
    with pytest.raises(KeychainError, match="bypass blocked the authorization dialog"):
        backend.get("kk:legacy-locked")
