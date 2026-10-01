"""Terminal history caching authenticates content, not filesystem timestamps."""
import json
import os
from uuid import uuid4

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
    for _ in range(3):
        record = writer.begin("test_history")
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
def test_warm_history_change_reauthenticates_instead_of_reusing_empty_result(history, change):
    reader, writer, identifiers, calls = history
    path = reader._record_path(identifiers[0])
    expected_error = change in {"same_stat_corrupt", "rename"}
    if change == "remove":
        path.unlink()
    elif change == "new_pending":
        pending = writer.begin("test_pending", state={"not_finished": True})
        calls.clear()
    elif change == "rename":
        path.rename(reader._record_path(uuid4()))
    else:
        before = path.stat()
        damaged = bytearray(path.read_bytes())
        damaged[-1] ^= 1
        path.write_bytes(damaged)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    if expected_error:
        with pytest.raises(JournalError):
            reader.list_unfinished()
        assert reader._terminal_manifest is None
    else:
        result = reader.list_unfinished()
        assert [record.operation_id for record in result] == ([pending.operation_id] if change == "new_pending" else [])
    assert calls  # metadata-only or pending-index trust cannot authorize a hit


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
