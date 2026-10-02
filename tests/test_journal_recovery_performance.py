"""Bounded receipts retain no recovery values; fresh GCM protects every lookup."""
import json
import os
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from keys_keeper import crypto, operation_journal as module
from keys_keeper.operation_journal import JournalError, JournalNotFound, OperationJournal
from keys_keeper.paths import Paths


def _journal(root):
    return OperationJournal(paths=Paths(root), password_provider=lambda: "synthetic-test-password")


def _count_kdf(monkeypatch):
    calls = []
    derive = crypto._derive_key
    def counted(*args):
        calls.append(True)
        return derive(*args)
    monkeypatch.setattr(crypto, "_derive_key", counted)
    return calls


def _legacy_terminal(writer, *, ordinal=0):
    record = writer.begin("test_history", state={"secret": "SYNTHETIC-RECOVERY-CANARY"})
    record = replace(record, stage="finished", status="completed", result={"ordinal": ordinal})
    with writer.locked():
        writer._write_unlocked(record)
    # Model the old format or a crash tail, with its terminal index marker.
    return record


@pytest.fixture
def history(tmp_path):
    writer = _journal(tmp_path / "journal")
    records = []
    for ordinal in range(4):
        record = writer.begin("test_history", state={"secret": "SYNTHETIC-RECOVERY-CANARY"})
        writer.finish(record.operation_id, result={"ordinal": ordinal})
        records.append(record)
    return _journal(writer.paths.root), writer, records


def test_finished_history_has_one_cold_kdf_zero_warm_kdf_and_no_active_images(history, monkeypatch):
    reader, _, records = history
    calls = _count_kdf(monkeypatch)
    reads = []
    original = module._secure_read
    def observed(*args, **kwargs):
        reads.append(args[0])
        return original(*args, **kwargs)
    monkeypatch.setattr(module, "_secure_read", observed)
    assert reader.list_unfinished() == []
    assert len(calls) == 1
    calls.clear()
    for _ in range(4):
        assert reader.list_unfinished() == []
    assert not calls
    assert sum(path.name == module._RECEIPTS_NAME for path in reads) == 5
    assert not list(reader.paths.operations_dir.glob("*.enc"))
    for record in records:
        assert reader.read(record.operation_id).state == {}


def test_receipt_retention_is_bounded_64_and_drops_recovery_state(tmp_path):
    writer = _journal(tmp_path / "journal")
    active = writer.begin("test_history", state={"secret": "SYNTHETIC-RECOVERY-CANARY"})
    writer.finish(active.operation_id)
    # Exercise the production64 boundary without paying65 unrelated KDF cycles.
    records = [replace(active, operation_id=uuid4(), status="completed", stage="finished", result={"ordinal": i})
               for i in range(65)]
    with writer.locked():
        writer._write_receipts_unlocked(records)
    reader = _journal(writer.paths.root)
    receipts = reader._read_receipts_unlocked()
    assert len(receipts) == 64
    assert [record.result["ordinal"] for record in receipts] == list(range(1, 65))
    assert all(record.state == {} for record in receipts)
    with pytest.raises(JournalNotFound):
        reader.read(records[0].operation_id)
    blob = (writer.paths.operations_dir / module._RECEIPTS_NAME).read_bytes()
    assert b"SYNTHETIC-RECOVERY-CANARY" not in crypto.decrypt_blob(blob, password="synthetic-test-password")


@pytest.mark.parametrize("change", ["corrupt_same_stat", "valid_same_salt_result", "invalid_same_salt_pending"])
def test_receipt_cache_authenticates_actual_bytes_with_same_salt_and_stat(history, monkeypatch, change):
    reader, _, records = history
    assert reader.read(records[-1].operation_id).result == {"ordinal": 3}
    path = reader.paths.operations_dir / module._RECEIPTS_NAME
    before, blob = path.stat(), path.read_bytes()
    salt, key = reader._receipt_key_cache
    calls = _count_kdf(monkeypatch)
    if change == "corrupt_same_stat":
        modified = bytearray(blob)
        modified[-1] ^= 1
        path.write_bytes(modified)
    else:
        raw = json.loads(crypto._decrypt_blob_with_key(blob, key=key))
        if change == "valid_same_salt_result":
            raw["records"][-1]["result"] = {"ordinal": 9}
        else:
            raw["records"][-1]["status"] = "pending"
        plaintext = json.dumps(raw, separators=(",", ":")).encode()
        plaintext = plaintext.ljust(len(crypto._decrypt_blob_with_key(blob, key=key)), b" ")
        nonce = b"n" * 12
        path.write_bytes(blob[:20] + nonce + AESGCM(key).encrypt(nonce, plaintext, blob[:4]))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_size == before.st_size
    assert path.stat().st_mtime_ns == before.st_mtime_ns
    assert path.read_bytes()[4:20] == salt
    if change == "valid_same_salt_result":
        assert reader.read(records[-1].operation_id).result == {"ordinal": 9}
    else:
        with pytest.raises(JournalError, match="receipts are corrupt"):
            reader.list_unfinished()
        assert reader._receipt_key_cache is None
    assert not calls


def test_pending_rewrite_with_reused_salt_is_authenticated_fresh(history, monkeypatch):
    reader, writer, _ = history
    pending = writer.begin("test_pending", state={"revision": "old"})
    assert reader.list_unfinished()[0].state == {"revision": "old"}
    path = writer._record_path(pending.operation_id)
    blob = path.read_bytes()
    key = reader._derived_key_cache[1]
    raw = json.loads(crypto._decrypt_blob_with_key(blob, key=key))
    raw["state"] = {"revision": "new"}
    nonce = b"n" * 12
    module._atomic_write_bytes(path, blob[:20] + nonce + AESGCM(key).encrypt(nonce, json.dumps(raw).encode(), blob[:4]))
    calls = _count_kdf(monkeypatch)
    assert reader.list_unfinished()[0].state == {"revision": "new"}
    assert not calls


def test_renamed_active_record_rejects_cached_key_identity(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    pending = writer.begin("test_pending")
    reader = _journal(writer.paths.root)
    assert reader.list_unfinished()[0].operation_id == pending.operation_id
    writer._record_path(pending.operation_id).rename(writer._record_path(uuid4()))
    calls = _count_kdf(monkeypatch)
    with pytest.raises(JournalError, match="identity mismatch"):
        reader.list_unfinished()
    assert not calls


def test_crash_after_receipt_publication_before_image_delete_is_reconciled(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    record = writer.begin("test_pending", state={"secret": "SYNTHETIC-RECOVERY-CANARY"})
    original = type(writer.paths.root).unlink
    def crash(path, *args, **kwargs):
        if path == writer._record_path(record.operation_id):
            raise OSError("synthetic crash before deletion")
        return original(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(type(writer.paths.root), "unlink", crash)
        with pytest.raises(OSError, match="synthetic crash"):
            writer.finish(record.operation_id, result={"status": "applied"})
    assert writer._record_path(record.operation_id).exists()
    assert writer.pending_refs() == ()
    reader = _journal(writer.paths.root)
    assert reader.list_unfinished() == []
    assert not writer._record_path(record.operation_id).exists()
    assert reader.read(record.operation_id).result == {"status": "applied"}
    assert reader.read(record.operation_id).state == {}


def test_crash_before_receipt_write_retains_terminal_image_and_pending_marker(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    record = writer.begin("test_pending", state={"secret": "SYNTHETIC-RECOVERY-CANARY"})
    original = module._atomic_write_bytes
    def fail_receipt(path, data):
        if path.name == module._RECEIPTS_NAME:
            raise OSError("synthetic ledger write failure")
        return original(path, data)
    with monkeypatch.context() as patch:
        patch.setattr(module, "_atomic_write_bytes", fail_receipt)
        with pytest.raises(OSError, match="synthetic ledger"):
            writer.finish(record.operation_id)
    assert writer.read(record.operation_id).finished
    assert writer.pending_refs()[0]["operation_id"] == str(record.operation_id)
    reader = _journal(writer.paths.root)
    assert reader.list_unfinished() == []
    assert reader.pending_refs() == ()
    assert reader.read(record.operation_id).state == {}


def test_legacy_terminals_are_compacted_before_active_pending_caps(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    legacy = [_legacy_terminal(writer, ordinal=i) for i in range(3)]
    pending = writer.begin("test_pending", state={"active": True})
    monkeypatch.setattr(module, "_MAX_RECOVERY_RECORDS", 1)
    # Old stale terminal index markers were already cleared in normal legacy close.
    with writer.locked():
        for record in legacy:
            writer._remove_pending_unlocked(record.operation_id)
    reader = _journal(writer.paths.root)
    assert [record.operation_id for record in reader.list_unfinished()] == [pending.operation_id]
    assert list(reader.paths.operations_dir.glob("*.enc")) == [reader._record_path(pending.operation_id)]
    assert all(reader.read(record.operation_id).state == {} for record in legacy)


def test_unindexed_pending_records_still_consume_active_limit_and_are_not_deleted(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    first, second = writer.begin("test_pending"), writer.begin("test_pending")
    with writer.locked():
        writer._remove_pending_unlocked(first.operation_id)
        writer._remove_pending_unlocked(second.operation_id)
    monkeypatch.setattr(module, "_MAX_RECOVERY_RECORDS", 1)
    with pytest.raises(JournalError, match="resource limit"):
        _journal(writer.paths.root).list_unfinished()
    assert writer._record_path(first.operation_id).exists()
    assert writer._record_path(second.operation_id).exists()


@pytest.mark.parametrize("limit", ["count", "aggregate", "single"])
def test_migration_preflight_resource_limit_rejects_before_any_io_or_kdf(tmp_path, monkeypatch, limit):
    writer = _journal(tmp_path / "journal")
    _legacy_terminal(writer)
    if limit == "count":
        monkeypatch.setattr(module, "_MAX_MIGRATION_RECORDS", 0)
    elif limit == "aggregate":
        monkeypatch.setattr(module, "_MAX_MIGRATION_BYTES", 1)
    else:
        monkeypatch.setattr(module, "_MAX_JOURNAL_BYTES", 1)
    monkeypatch.setattr(module, "_secure_read", lambda *a, **kw: pytest.fail("oversized migration read"))
    monkeypatch.setattr(crypto, "_derive_key", lambda *a: pytest.fail("oversized migration KDF"))
    with pytest.raises(JournalError, match="resource limit"):
        _journal(writer.paths.root).list_unfinished()


def test_directory_change_during_scan_fails_before_compaction_deletes_anything(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "journal")
    legacy = _legacy_terminal(writer)
    original = module._secure_read
    changes = []
    def changed(path, **kwargs):
        blob = original(path, **kwargs)
        if path.suffix == ".enc" and not changes:
            changes.append(True)
            module._atomic_write_bytes(writer._record_path(uuid4()), b"synthetic-concurrent-file")
        return blob
    monkeypatch.setattr(module, "_secure_read", changed)
    with pytest.raises(JournalError, match="changed during recovery"):
        _journal(writer.paths.root).list_unfinished()
    assert writer._record_path(legacy.operation_id).exists()
    assert not (writer.paths.operations_dir / module._RECEIPTS_NAME).exists()


@pytest.mark.parametrize("result", [{"large": "SYNTHETIC-CANARY" * 100}, {"invalid": float("nan")}, {"invalid": object()}])
def test_result_bounds_reject_before_terminalization_or_pending_marker_removal(tmp_path, monkeypatch, result):
    writer = _journal(tmp_path / "journal")
    pending = writer.begin("test_pending", state={"secret": "recovery-remains"})
    original = writer._record_path(pending.operation_id).read_bytes()
    monkeypatch.setattr(module, "_MAX_RECEIPTS_BYTES", 700)
    with pytest.raises(JournalError):
        writer.finish(pending.operation_id, result=result)
    assert writer._record_path(pending.operation_id).read_bytes() == original
    assert writer.read(pending.operation_id).status == "pending"
    assert writer.pending_refs()[0]["operation_id"] == str(pending.operation_id)


def test_missing_indexed_state_fails_closed(tmp_path):
    writer = _journal(tmp_path / "journal")
    pending = writer.begin("test_pending")
    writer._record_path(pending.operation_id).unlink()
    with pytest.raises(JournalError, match="unavailable operation state"):
        _journal(writer.paths.root).list_unfinished()


def test_crash_leftover_image_temp_is_removed_only_after_authoritative_state_is_authenticated(history):
    reader, writer, records = history
    temporary = writer.paths.operations_dir / f".{records[-1].operation_id}.enc.crash123.tmp"
    image = crypto.encrypt_blob(b'{"old_secret":"SYNTHETIC-RECOVERY-CANARY"}', password="synthetic-test-password")
    module._atomic_write_bytes(temporary, image)
    unknown = writer.paths.operations_dir / "operator-notes.tmp"
    module._atomic_write_bytes(unknown, b"keep-unrelated-user-file")
    assert reader.list_unfinished() == []
    assert not temporary.exists()
    assert unknown.read_bytes() == b"keep-unrelated-user-file"


def test_missing_recovery_state_retains_crash_temp_for_explicit_repair(tmp_path):
    writer = _journal(tmp_path / "journal")
    pending = writer.begin("test_pending")
    path = writer._record_path(pending.operation_id)
    temporary = path.parent / f".{path.name}.crash123.tmp"
    path.rename(temporary)
    with pytest.raises(JournalError, match="unavailable operation state"):
        _journal(writer.paths.root).list_unfinished()
    assert temporary.exists()
