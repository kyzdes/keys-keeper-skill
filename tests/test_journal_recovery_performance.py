"""Terminal history caching authenticates content, not filesystem timestamps."""
import json
import os
from uuid import UUID

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys_keeper import crypto, operation_journal as module
from keys_keeper.operation_journal import JournalError, OperationJournal
from keys_keeper.paths import Paths


@pytest.fixture
def history(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "journal")
    writer = OperationJournal(paths=paths, password_provider=lambda: "synthetic-test-password")
    identifiers = []
    for identifier in (
        UUID("10000000-0000-4000-8000-000000000001"),
        UUID("20000000-0000-4000-8000-000000000001"),
        UUID("30000000-0000-4000-8000-000000000001"),
    ):
        record = writer.begin("test_history", operation_id=identifier)
        writer.finish(record.operation_id)
        identifiers.append(record.operation_id)
    reader = OperationJournal(paths=paths, password_provider=lambda: "synthetic-test-password")
    calls = []
    derive = crypto._derive_key
    def counted(*args):
        calls.append(True)
        return derive(*args)
    monkeypatch.setattr(crypto, "_derive_key", counted)
    assert reader.list_unfinished() == []
    assert len(calls) == 3
    calls.clear()
    yield reader, writer, identifiers, calls


def test_unchanged_terminal_history_uses_fresh_reads_with_zero_kdf(history, monkeypatch):
    reader, _, _, calls = history
    read = module._secure_read
    reads = []
    def fresh(*args, **kwargs):
        reads.append(args[0])
        return read(*args, **kwargs)
    monkeypatch.setattr(module, "_secure_read", fresh)
    for _ in range(4):
        assert reader.list_unfinished() == []
    assert len(reads) == 12
    assert not calls


@pytest.mark.parametrize("change", ["remove", "new_pending", "same_stat_corrupt", "rename"])
def test_warm_history_change_reauthenticates_instead_of_reusing_empty_result(history, monkeypatch, change):
    reader, writer, identifiers, calls = history
    path = reader._record_path(identifiers[0])
    expected_error = change in {"same_stat_corrupt", "rename"}
    if change == "remove":
        path.unlink()
    elif change == "new_pending":
        pending = writer.begin("test_pending", state={"not_finished": True})
        calls.clear()
    elif change == "rename":
        destination = reader._record_path(UUID("00000000-0000-4000-8000-000000000001"))
        assert not destination.exists()
        path.rename(destination)
    else:
        before = path.stat()
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 1
        path.write_bytes(damaged)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    decrypt = crypto._decrypt_blob_with_key
    authentications = []
    def authenticated_read(*args, **kwargs):
        authentications.append(True)
        return decrypt(*args, **kwargs)
    monkeypatch.setattr(crypto, "_decrypt_blob_with_key", authenticated_read)
    if expected_error:
        message = "identity mismatch" if change == "rename" else "cannot decrypt or decode"
        with pytest.raises(JournalError, match=message):
            reader.list_unfinished()
        assert reader._terminal_manifest is None
    else:
        result = reader.list_unfinished()
        assert [record.operation_id for record in result] == ([pending.operation_id] if change == "new_pending" else [])
    assert authentications  # Changed ciphertext/name cannot reuse the terminal result.
    if change != "rename":
        assert calls


def test_renamed_cached_key_record_rejects_identity_with_one_gcm_and_zero_kdf(history, monkeypatch):
    reader, _, identifiers, calls = history
    # Fixed IDs put this record last in the authenticated cold scan. Renaming
    # it before the other records then exercises reuse of that exact salt/key.
    path = reader._record_path(identifiers[-1])
    assert reader._derived_key_cache[0] == crypto._blob_salt(path.read_bytes())
    assert reader._terminal_manifest is not None
    destination = reader._record_path(UUID("00000000-0000-4000-8000-000000000001"))
    assert not destination.exists()
    path.rename(destination)
    decrypt = crypto._decrypt_blob_with_key
    authentications = []
    def authenticated_read(*args, **kwargs):
        authentications.append(True)
        return decrypt(*args, **kwargs)
    monkeypatch.setattr(crypto, "_decrypt_blob_with_key", authenticated_read)

    with pytest.raises(JournalError, match="journal record identity mismatch"):
        reader.list_unfinished()
    assert not calls
    assert len(authentications) == 1
    assert reader._terminal_manifest is None


def test_authenticated_same_salt_pending_rewrite_never_hits_terminal_cache(history):
    reader, _, identifiers, calls = history
    path = reader._record_path(identifiers[0])
    before = path.stat()
    blob = path.read_bytes()
    key = crypto._derive_key("synthetic-test-password", blob[4:20])
    raw = json.loads(crypto._decrypt_blob_with_key(blob, key=key))
    raw.update(status="pending", stage="prepared")
    plaintext = json.dumps(raw, separators=(",", ":")).encode()
    # A fixture-authorized rewrite deliberately keeps the salt. GCM must still
    # authenticate the actual new record and expose its unfinished state.
    nonce = b"n" * 12
    updated = blob[:20] + nonce + AESGCM(key).encrypt(nonce, plaintext, blob[:4])
    module._atomic_write_bytes(path, updated)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    calls.clear()
    assert [record.operation_id for record in reader.list_unfinished()] == [identifiers[0]]
    assert reader._terminal_manifest is None


def test_directory_changed_during_fresh_scan_fails_closed(history, monkeypatch):
    reader, _, identifiers, _ = history
    read = module._secure_read
    changed = []
    def concurrent(*args, **kwargs):
        blob = read(*args, **kwargs)
        if not changed:
            changed.append(True)
            reader._record_path(identifiers[-1]).unlink()
        return blob
    monkeypatch.setattr(module, "_secure_read", concurrent)
    with pytest.raises((JournalError, FileNotFoundError)):
        reader.list_unfinished()
    assert reader._terminal_manifest is None


def test_recovery_aggregate_resource_limit_rejects_before_io_or_kdf(history, monkeypatch):
    reader, _, _, calls = history
    monkeypatch.setattr(module, "_MAX_RECOVERY_BYTES", 1)
    monkeypatch.setattr(module, "_secure_read", lambda *args, **kwargs: pytest.fail("oversized history read"))
    with pytest.raises(JournalError, match="resource limit"):
        reader.list_unfinished()
    assert not calls
