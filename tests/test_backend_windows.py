"""Smoke tests for the Windows Credential Manager backend.

We hit the real CredMan (no mocking — there's no `security create-keychain`
equivalent), and isolate by using a unique `service` per test run that
namespaces TargetNames in CredMan. The fixture cleans up everything under
that namespace at teardown.
"""
import sys
import uuid
import pytest

pytestmark = pytest.mark.windows


@pytest.fixture
def backend():
    if sys.platform != "win32":
        pytest.skip("Windows-only")
    from keys_keeper.backend_windows import (
        WindowsCredentialBackend, _enumerate_targets, _delete_target,
    )
    service = f"keys-keeper-test-{uuid.uuid4().hex[:8]}"
    be = WindowsCredentialBackend(service=service)
    yield be
    # Cleanup: remove anything that matched our prefixes.
    for t in _enumerate_targets(f"{service}:*"):
        _delete_target(t)
    for t in _enumerate_targets(f"{service}-chunk:*"):
        _delete_target(t)


def test_roundtrip_short_value(backend):
    backend.set("kk:abc", "sk-test-secret")
    assert backend.get("kk:abc").unseal() == "sk-test-secret"


def test_roundtrip_non_ascii(backend):
    # Cyrillic + emoji — exercises UTF-8 round-trip through the CredentialBlob.
    val = "пароль-🔑-секрет"
    backend.set("kk:utf8", val)
    assert backend.get("kk:utf8").unseal() == val


def test_roundtrip_large_value_chunked(backend):
    # 4KB exceeds the 2000-byte chunk threshold → exercises chunking path.
    val = "x" * 4096
    backend.set("kk:big", val)
    got = backend.get("kk:big").unseal()
    assert got == val
    assert len(got) == 4096


def test_overwrite_large_with_small_cleans_chunks(backend):
    from keys_keeper.backend_windows import _enumerate_targets
    backend.set("kk:shrink", "y" * 4096)
    backend.set("kk:shrink", "small")
    assert backend.get("kk:shrink").unseal() == "small"
    # No stray chunks left behind from the previous larger write.
    stragglers = _enumerate_targets(f"{backend.service}-chunk:kk:shrink#*")
    assert stragglers == []


def test_list_ids_excludes_chunks(backend):
    backend.set("kk:one", "short")
    backend.set("kk:two", "y" * 4096)  # chunked
    ids = sorted(backend.list_ids())
    assert ids == ["kk:one", "kk:two"]


def test_delete_missing_is_noop(backend):
    # Should not raise.
    backend.delete("kk:never-existed")


def test_delete_chunked_removes_all(backend):
    from keys_keeper.backend_windows import _enumerate_targets
    backend.set("kk:gone", "z" * 4096)
    backend.delete("kk:gone")
    assert _enumerate_targets(f"{backend.service}:kk:gone") == []
    assert _enumerate_targets(f"{backend.service}-chunk:kk:gone#*") == []


def test_get_missing_raises(backend):
    from keys_keeper.backend import KeychainError
    with pytest.raises(KeychainError):
        backend.get("kk:nothing")
