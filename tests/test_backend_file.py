"""Tests for EncryptedFileBackend — the headless-Linux (no keyring) backend.

Pure-Python AES-256-GCM file storage, so these run on every platform.
The master passphrase comes from KEYS_KEEPER_MASTER_KEY.
"""
from __future__ import annotations

import os
import stat
import sys
import pickle

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


def test_explicit_password_file_is_owner_only_and_not_symlinked(tmp_path):
    paths = Paths(tmp_path / "profile")
    paths.ensure()
    password = tmp_path / "password"
    password.write_text(MASTER, encoding="utf-8")
    password.chmod(0o644)
    backend = EncryptedFileBackend(paths=paths, password_file=password, allow_env_password=False)
    if os.name == "posix":
        with pytest.raises(KeychainError, match="permissions"):
            backend.set("kk:test", "value")

    password.chmod(0o600)
    symlink = tmp_path / "password-link"
    symlink.symlink_to(password)
    linked = EncryptedFileBackend(paths=paths, password_file=symlink, allow_env_password=False)
    with pytest.raises(KeychainError, match="symlink"):
        linked.set("kk:test", "value")


def test_password_fd_is_cached_for_repeated_operations(tmp_path):
    paths = Paths(tmp_path / "profile")
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (MASTER + "\n").encode("utf-8"))
        os.close(write_fd)
        write_fd = -1
        backend = EncryptedFileBackend(
            paths=paths, password_fd=read_fd, allow_env_password=False
        )
        backend.set("kk:first", "one")
        backend.set("kk:second", "two")
        assert backend.get("kk:first").unseal() == "one"
        assert backend.get("kk:second").unseal() == "two"
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def test_live_reads_see_external_rewrite_and_new_accounts(backend):
    backend.set("kk:one", "before")
    assert backend.get("kk:one").unseal() == "before"
    other = EncryptedFileBackend(paths=backend.paths)
    other.set("kk:one", "after")
    other.set("kk:two", "second")
    assert backend.get("kk:one").unseal() == "after"
    assert sorted(backend.list_ids()) == ["kk:one", "kk:two"]


def test_each_warm_read_authenticates_same_stat_ciphertext_and_clears_bad_key(backend, monkeypatch):
    from keys_keeper import crypto
    backend.set("kk:one", "value")
    path = backend.paths.secrets_enc
    original, info = path.read_bytes(), path.stat()
    calls = []
    real_authenticate = crypto._decrypt_blob_with_key
    def authenticate(*args, **kwargs):
        calls.append(True)
        return real_authenticate(*args, **kwargs)
    monkeypatch.setattr(crypto, "_decrypt_blob_with_key", authenticate)
    assert backend.get("kk:one").unseal() == "value"
    tampered = original[:-1] + bytes([original[-1] ^ 1])
    path.write_bytes(tampered)
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert path.stat().st_size == info.st_size
    assert path.stat().st_mtime_ns == info.st_mtime_ns
    with pytest.raises(KeychainError, match="corrupted"):
        backend.get("kk:one")
    assert len(calls) == 2
    assert backend._derived_key_cache is None
    path.write_bytes(original)
    assert backend.get("kk:one").unseal() == "value"


def test_external_delete_never_returns_old_values(backend):
    backend.set("kk:one", "value")
    backend.paths.secrets_enc.unlink()
    assert backend.list_ids() == []
    assert backend._derived_key_cache is None
    with pytest.raises(KeychainError, match="not found"):
        backend.get("kk:one")


def test_warm_reads_and_unchanged_mutations_do_not_kdf_encrypt_or_write(backend, monkeypatch):
    from keys_keeper import crypto
    backend.set("kk:one", "value")
    before = backend.paths.secrets_enc.read_bytes()
    def forbidden(*_args, **_kwargs):
        pytest.fail("unchanged warm operation derived/encrypted/wrote ciphertext")
    monkeypatch.setattr(crypto, "_derive_key", forbidden)
    monkeypatch.setattr(crypto, "_encrypt_blob_with_key", forbidden)
    monkeypatch.setattr(backend, "_atomic_write_bytes", forbidden)
    for _ in range(3):
        assert backend.get("kk:one").unseal() == "value"
        assert backend.list_ids() == ["kk:one"]
        backend.set("kk:one", "value")
        backend.delete("kk:absent")
    assert backend.paths.secrets_enc.read_bytes() == before
    assert not hasattr(backend, "_cache")


def test_missing_delete_does_not_unlock_or_create_ciphertext(backend, monkeypatch):
    from keys_keeper import crypto
    monkeypatch.delenv("KEYS_KEEPER_MASTER_KEY")
    monkeypatch.setattr(crypto, "_derive_key", lambda *_a: pytest.fail("empty no-op derived a key"))
    monkeypatch.setattr(backend, "_atomic_write_bytes", lambda *_a: pytest.fail("empty no-op wrote ciphertext"))
    backend.delete("kk:absent")
    assert not backend.paths.secrets_enc.exists()


@pytest.mark.parametrize("binding", ["paths", "service", "password_file"])
def test_cached_unlock_material_does_not_cross_backend_identity(backend, monkeypatch, tmp_path, binding):
    backend.set("kk:one", "value")
    if binding == "paths":
        other = Paths(tmp_path / "other-profile")
        other.ensure()
        other.secrets_enc.write_bytes(backend.paths.secrets_enc.read_bytes())
        other.secrets_enc.chmod(0o600)
        backend.paths = other
    elif binding == "service":
        backend.service = "different-profile"
    else:
        password = tmp_path / "other-password"
        password.write_text("different-password")
        password.chmod(0o600)
        backend.password_file = password
    monkeypatch.delenv("KEYS_KEEPER_MASTER_KEY")
    with pytest.raises(KeychainError):
        backend.get("kk:one")
    assert backend._derived_key_cache is None


def test_ciphertext_read_cap_rejects_before_reading_or_kdf(backend, monkeypatch):
    from keys_keeper import backend_file, crypto
    backend.paths.ensure()
    with backend.paths.secrets_enc.open("wb") as stream:
        stream.truncate(backend_file._MAX_BLOB_BYTES + 1)
    backend.paths.secrets_enc.chmod(0o600)
    monkeypatch.setattr(crypto, "_derive_key", lambda *_a: pytest.fail("oversized file derived a key"))
    monkeypatch.setattr(backend_file.os, "open", lambda *_a: pytest.fail("oversized file opened for reading"))
    with pytest.raises(KeychainError, match="size limit"):
        backend.list_ids()


def test_ciphertext_write_cap_preserves_previous_file_and_key(backend, monkeypatch):
    from keys_keeper import backend_file, crypto
    backend.set("kk:one", "value")
    before, cached = backend.paths.secrets_enc.read_bytes(), backend._derived_key_cache
    monkeypatch.setattr(backend_file, "_MAX_BLOB_BYTES", len(before) + 5)
    monkeypatch.setattr(crypto, "_encrypt_blob_with_key", lambda *_a, **_kw: pytest.fail("oversized write encrypted"))
    monkeypatch.setattr(crypto, "_derive_key", lambda *_a: pytest.fail("oversized write derived a key"))
    with pytest.raises(KeychainError, match="size limit"):
        backend.set("kk:two", "x" * 100)
    assert backend.paths.secrets_enc.read_bytes() == before
    assert backend._derived_key_cache == cached
    assert backend.get("kk:one").unseal() == "value"


def test_backend_unlock_cache_cannot_be_pickled(backend):
    with pytest.raises(TypeError, match="process-local"):
        pickle.dumps(backend)
