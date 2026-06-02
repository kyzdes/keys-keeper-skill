"""Tests for EncryptedFileBackend — the headless-Linux (no keyring) backend.

Pure-Python AES-256-GCM file storage, so these run on every platform.
The master passphrase comes from KEYS_KEEPER_MASTER_KEY.
"""
from __future__ import annotations

import stat
import sys

import pytest

from keys_keeper.backend import KeychainError, Sealed
from keys_keeper.backend_file import EncryptedFileBackend
from keys_keeper.paths import Paths

MASTER = "correct horse battery staple"


@pytest.fixture
def backend(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)
    return EncryptedFileBackend(service="keys-keeper-test")


def test_set_then_get_roundtrip(backend):
    backend.set("kk:abc", "sk-or-v1-secret")
    assert backend.get("kk:abc") == Sealed("sk-or-v1-secret")
    # value is sealed, not leaked via str/repr
    assert str(backend.get("kk:abc")) == "<sealed>"


def test_get_unseals_to_plaintext(backend):
    backend.set("kk:abc", "plaintext-value")
    assert backend.get("kk:abc").unseal() == "plaintext-value"


def test_multiline_ssh_key_value(backend):
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\n"
    backend.set("kk:sshkey", key)
    assert backend.get("kk:sshkey").unseal() == key


def test_unicode_value(backend):
    backend.set("kk:u", "naïve—café—🔑")
    assert backend.get("kk:u").unseal() == "naïve—café—🔑"


def test_get_missing_raises(backend):
    with pytest.raises(KeychainError):
        backend.get("kk:does-not-exist")


def test_overwrite_value(backend):
    backend.set("kk:abc", "first")
    backend.set("kk:abc", "second")
    assert backend.get("kk:abc").unseal() == "second"
    assert backend.list_ids() == ["kk:abc"]  # not duplicated


def test_delete_removes(backend):
    backend.set("kk:abc", "v")
    backend.delete("kk:abc")
    assert "kk:abc" not in backend.list_ids()
    with pytest.raises(KeychainError):
        backend.get("kk:abc")


def test_delete_missing_is_noop(backend):
    backend.delete("kk:nope")  # must not raise


def test_list_ids(backend):
    backend.set("kk:a", "1")
    backend.set("kk:b", "2")
    backend.set("kk:c:passphrase", "3")
    assert sorted(backend.list_ids()) == ["kk:a", "kk:b", "kk:c:passphrase"]


def test_list_ids_empty_when_no_file(backend):
    assert backend.list_ids() == []


def test_persists_across_instances(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)
    EncryptedFileBackend(service="keys-keeper-test").set("kk:abc", "persisted")
    # fresh instance, same home + key — should decrypt the same file
    again = EncryptedFileBackend(service="keys-keeper-test")
    assert again.get("kk:abc").unseal() == "persisted"


def test_missing_master_key_raises_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.delenv("KEYS_KEEPER_MASTER_KEY", raising=False)
    b = EncryptedFileBackend(service="keys-keeper-test")
    with pytest.raises(KeychainError) as exc:
        b.set("kk:abc", "v")
    assert "KEYS_KEEPER_MASTER_KEY" in str(exc.value)


def test_wrong_master_key_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)
    EncryptedFileBackend(service="keys-keeper-test").set("kk:abc", "v")
    # reopen with a different key
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", "wrong-key")
    b = EncryptedFileBackend(service="keys-keeper-test")
    with pytest.raises(KeychainError):
        b.get("kk:abc")


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_secrets_file_is_owner_only(backend):
    backend.set("kk:abc", "v")
    mode = stat.S_IMODE(Paths().secrets_enc.stat().st_mode)
    assert mode == 0o600


def test_paths_secrets_enc_location(monkeypatch, tmp_path):
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    assert Paths().secrets_enc == tmp_path / "kk" / "secrets.enc"


def test_concurrent_writers_do_not_clobber(monkeypatch, tmp_path):
    """Two independent backend instances (simulating two `keys` processes) each
    add a distinct key. The read-modify-write is under an exclusive lock and
    re-reads from disk, so neither write may be lost.

    This is the regression test for the lost-update bug: a cache-trusting
    implementation would drop whichever instance wrote first.
    """
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)

    a = EncryptedFileBackend(service="keys-keeper-test")
    b = EncryptedFileBackend(service="keys-keeper-test")

    a.set("kk:a", "1")          # instance A writes; B's cache (if any) is now stale
    b.set("kk:b", "2")          # instance B must re-read under lock, not clobber kk:a

    fresh = EncryptedFileBackend(service="keys-keeper-test")
    assert sorted(fresh.list_ids()) == ["kk:a", "kk:b"]
    assert fresh.get("kk:a").unseal() == "1"
    assert fresh.get("kk:b").unseal() == "2"


def test_delete_sees_other_instance_writes(monkeypatch, tmp_path):
    """A delete from one instance must operate on the latest on-disk state, not a
    stale in-memory cache, so it can't resurrect or drop unrelated keys."""
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)

    a = EncryptedFileBackend(service="keys-keeper-test")
    b = EncryptedFileBackend(service="keys-keeper-test")
    a.set("kk:x", "1")
    a.get("kk:x")               # prime A's cache
    b.set("kk:y", "2")          # B adds another key behind A's back
    a.delete("kk:x")            # A deletes x; must NOT drop y

    fresh = EncryptedFileBackend(service="keys-keeper-test")
    assert fresh.list_ids() == ["kk:y"]


def test_corrupt_non_dict_blob_raises(monkeypatch, tmp_path):
    """A blob that decrypts to valid-but-non-object JSON is corruption, not an
    empty store — must raise rather than silently reset (which would overwrite)."""
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(tmp_path / "kk"))
    monkeypatch.setenv("KEYS_KEEPER_MASTER_KEY", MASTER)
    from keys_keeper import crypto

    p = Paths()
    p.ensure()
    p.secrets_enc.write_bytes(crypto.encrypt_blob(b"[1, 2, 3]", password=MASTER))
    b = EncryptedFileBackend(service="keys-keeper-test")
    with pytest.raises(KeychainError):
        b.list_ids()
