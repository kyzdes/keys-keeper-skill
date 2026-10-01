from __future__ import annotations

import errno
import os
import pickle
import stat
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from keys_keeper import operation_journal as journal_module
from keys_keeper import crypto
from keys_keeper.operation_journal import (
    JournalError,
    OperationJournal,
    pending_operation_refs,
    read_active_generation,
    write_active_generation,
)
from keys_keeper.paths import Paths


JOURNAL_KEY = b"j" * 32


def _journal(root) -> OperationJournal:
    return OperationJournal(paths=Paths(root), password_provider=lambda: JOURNAL_KEY)


def test_secure_read_uses_binary_descriptor_for_ciphertext(tmp_path, monkeypatch):
    path = tmp_path / "ciphertext.enc"
    ciphertext = b"header\r\nbody\x1a\r\ntail"
    path.write_bytes(ciphertext)
    if os.name == "posix":
        path.chmod(0o600)
    real_open = os.open
    binary_flag = getattr(os, "O_BINARY", getattr(os, "O_NONBLOCK", 0x4))
    seen = []
    monkeypatch.setattr(journal_module.os, "O_BINARY", binary_flag, raising=False)

    def recording_open(target, flags, mode=0o777):
        seen.append(flags)
        return real_open(target, flags, mode)

    monkeypatch.setattr(journal_module.os, "open", recording_open)
    assert journal_module._secure_read(path) == ciphertext
    assert seen and seen[0] & binary_flag


def test_unsupported_directory_fsync_is_best_effort(tmp_path, monkeypatch):
    closed = []
    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", lambda *_args: 91)
    monkeypatch.setattr(
        journal_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError(errno.EINVAL, "unsupported")),
    )
    monkeypatch.setattr(journal_module.os, "close", closed.append)
    journal_module._fsync_parent(tmp_path)
    assert closed == [91]


def test_directory_fsync_propagates_real_io_failure(tmp_path, monkeypatch):
    closed = []
    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", lambda *_args: 92)
    monkeypatch.setattr(
        journal_module.os,
        "fsync",
        lambda _fd: (_ for _ in ()).throw(OSError(errno.EIO, "durability failed")),
    )
    monkeypatch.setattr(journal_module.os, "close", closed.append)
    with pytest.raises(OSError) as caught:
        journal_module._fsync_parent(tmp_path)
    assert caught.value.errno == errno.EIO
    assert closed == [92]


def test_begin_stage_finish_survive_new_process_instance(tmp_path):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("replica_install", state={"generation": "g1", "secret": "hidden"})
    journal.stage(record.operation_id, "verified", state={"generation": "g1"})

    replay = _journal(tmp_path / "profile").read(record.operation_id)
    assert replay.stage == "verified"
    assert replay.status == "pending"
    assert replay.state == {"generation": "g1"}

    finished = _journal(tmp_path / "profile").finish(
        record.operation_id, result={"generation": "g1"}
    )
    assert finished.finished
    assert _journal(tmp_path / "profile").list_unfinished() == []


def test_locked_session_is_reentrant_for_same_journal(tmp_path):
    journal = _journal(tmp_path / "profile")
    with journal.locked():
        record = journal.begin("master_import")
        journal.stage(record.operation_id, "backend_written")
        assert journal.read(record.operation_id).stage == "backend_written"


def test_pending_index_survives_stages_and_clears_only_after_terminal_record(tmp_path):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_mutation", state={"private": "encrypted"})
    assert pending_operation_refs(journal.paths, kind="master_mutation") == ({
        "operation_id": str(record.operation_id),
        "kind": "master_mutation",
    },)
    journal.stage(record.operation_id, "backend_applied")
    assert journal.pending_refs(kind="master_mutation")
    index = journal.paths.operations_dir / "pending-index.json"
    assert b"encrypted" not in index.read_bytes()
    journal.finish(record.operation_id)
    assert pending_operation_refs(journal.paths, kind="master_mutation") == ()


def test_record_state_is_encrypted_and_repr_safe(tmp_path):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_import", state={"value": "plain-secret-marker"})
    ciphertext = (journal.paths.operations_dir / f"{record.operation_id}.enc").read_bytes()
    assert b"plain-secret-marker" not in ciphertext
    assert "plain-secret-marker" not in repr(record)
    if os.name == "posix":
        assert stat.S_IMODE(
            (journal.paths.operations_dir / f"{record.operation_id}.enc").stat().st_mode
        ) == 0o600


def test_real_subprocess_exit_leaves_replayable_operation(tmp_path):
    root = tmp_path / "profile"
    operation_id = UUID("33333333-3333-4333-8333-333333333333")
    script = """
import os
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
j = OperationJournal(
    paths=Paths(os.environ['JOURNAL_ROOT']),
    password_provider=lambda: bytes.fromhex(os.environ['JOURNAL_KEY']),
)
j.begin('replica_install', operation_id=os.environ['OPERATION_ID'], state={'generation': 'new'})
os._exit(71)
"""
    env = os.environ.copy()
    env.update(
        JOURNAL_ROOT=str(root),
        JOURNAL_KEY=JOURNAL_KEY.hex(),
        OPERATION_ID=str(operation_id),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
    )
    result = subprocess.run([sys.executable, "-c", script], env=env, check=False)
    assert result.returncode == 71
    replay = _journal(root).read(operation_id)
    assert replay.status == "pending"
    assert replay.state == {"generation": "new"}


def test_recovery_completes_or_closes_failed_handlers(tmp_path):
    journal = _journal(tmp_path / "profile")
    good = journal.begin("good_replay", state={"request": "one"})
    bad = journal.begin("bad_replay", state={"request": "two"})

    recovered = journal.recover(
        {
            "good_replay": lambda record: {"request": record.state["request"]},
            "bad_replay": lambda _record: (_ for _ in ()).throw(RuntimeError("secret text")),
        }
    )
    assert {record.operation_id for record in recovered} == {
        good.operation_id,
        bad.operation_id,
    }
    assert journal.read(good.operation_id).status == "completed"
    failed = journal.read(bad.operation_id)
    assert failed.status == "failed"
    assert failed.error_code == "recovery_error"
    assert "secret text" not in repr(failed)


def test_profiles_with_same_operation_id_are_isolated(tmp_path):
    operation_id = uuid4()
    left = _journal(tmp_path / "left")
    right = _journal(tmp_path / "right")
    left.begin("master_import", operation_id=operation_id, state={"side": "left"})
    right.begin("master_import", operation_id=operation_id, state={"side": "right"})
    assert left.read(operation_id).state == {"side": "left"}
    assert right.read(operation_id).state == {"side": "right"}


def test_active_generation_atomic_failure_keeps_old_pointer(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "profile")
    write_active_generation(paths, "generation-1")

    def fail_replace(_source, _target):
        raise OSError("injected disk failure")

    monkeypatch.setattr("keys_keeper.operation_journal.os.replace", fail_replace)
    with pytest.raises(OSError, match="injected disk failure"):
        write_active_generation(paths, "generation-2")
    assert paths.active_generation.read_text(encoding="ascii") == "generation-1\n"


def test_active_generation_rejects_traversal(tmp_path):
    paths = Paths(tmp_path / "profile")
    with pytest.raises(ValueError, match="safe opaque"):
        write_active_generation(paths, "../other")
    assert read_active_generation(paths) is None


def test_wrong_journal_key_fails_without_state_in_error(tmp_path):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_import", state={"secret": "error-marker"})
    wrong = OperationJournal(
        paths=journal.paths, password_provider=lambda: b"wrong-key-material"
    )
    with pytest.raises(JournalError) as exc:
        wrong.read(record.operation_id)
    assert "error-marker" not in str(exc.value)


def _count_derivations(monkeypatch):
    derived_salts = []
    real_derive = crypto._derive_key

    def counted_derive(password, salt):
        derived_salts.append(salt)
        return real_derive(password, salt)

    monkeypatch.setattr(crypto, "_derive_key", counted_derive)
    return derived_salts


def test_repeated_reads_derive_once_but_reload_ciphertext_each_time(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "profile")
    record = writer.begin("master_import", state={"generation": "one"})
    reader = _journal(writer.paths.root)
    derived_salts = _count_derivations(monkeypatch)
    reads = []
    real_read = journal_module._secure_read

    def counted_read(path, **kwargs):
        reads.append(path)
        return real_read(path, **kwargs)

    monkeypatch.setattr(journal_module, "_secure_read", counted_read)
    for _ in range(3):
        assert reader.read(record.operation_id).state == {"generation": "one"}
    assert len(derived_salts) == 1
    assert reads == [writer._record_path(record.operation_id)] * 3


def test_external_rewrite_replaces_cached_salt_and_reads_current_state(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "profile")
    record = writer.begin("master_import", state={"generation": "one"})
    reader = _journal(writer.paths.root)
    reader.read(record.operation_id)
    writer.stage(record.operation_id, "verified", state={"generation": "two"})
    derived_salts = _count_derivations(monkeypatch)

    assert reader.read(record.operation_id).state == {"generation": "two"}
    assert reader.read(record.operation_id).stage == "verified"
    assert len(derived_salts) == 1


def test_local_rewrite_derives_new_key_once_and_reuses_it(tmp_path, monkeypatch):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_import", state={"generation": "one"})
    old_blob = journal._record_path(record.operation_id).read_bytes()
    derived_salts = _count_derivations(monkeypatch)

    journal.stage(record.operation_id, "verified", state={"generation": "two"})
    new_blob = journal._record_path(record.operation_id).read_bytes()
    assert old_blob[4:20] != new_blob[4:20]
    assert journal.read(record.operation_id).state == {"generation": "two"}
    assert journal.read(record.operation_id).stage == "verified"
    assert derived_salts == [new_blob[4:20]]
    # The normal public decrypt API can still read the unchanged blob format.
    assert b'"generation":"two"' in crypto.decrypt_blob(
        new_blob, password="key-bytes:" + JOURNAL_KEY.hex()
    )


def test_failed_local_write_keeps_previous_cache_and_durable_record(tmp_path, monkeypatch):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_import", state={"generation": "one"})
    derived_salts = _count_derivations(monkeypatch)

    def fail_write(_path, _blob):
        raise OSError("injected disk failure")

    monkeypatch.setattr(journal_module, "_atomic_write_bytes", fail_write)
    with pytest.raises(OSError, match="injected disk failure"):
        journal.stage(record.operation_id, "verified", state={"generation": "two"})
    assert journal.read(record.operation_id).state == {"generation": "one"}
    assert len(derived_salts) == 1  # Only the failed write's fresh encryption.


def test_new_instances_do_not_share_derived_keys(tmp_path, monkeypatch):
    writer = _journal(tmp_path / "profile")
    record = writer.begin("master_import")
    derived_salts = _count_derivations(monkeypatch)
    for _ in range(2):
        _journal(writer.paths.root).read(record.operation_id)
    assert len(derived_salts) == 2
    assert derived_salts[0] == derived_salts[1]


def test_cached_key_cannot_cross_profiles_or_bypass_wrong_password(tmp_path, monkeypatch):
    left = _journal(tmp_path / "left")
    record = left.begin("master_import", state={"generation": "left"})
    right = OperationJournal(
        paths=Paths(tmp_path / "right"), password_provider=lambda: b"different-key"
    )
    right.begin("master_import", operation_id=record.operation_id)
    # Even identical blob bytes/salt in another profile need that instance's key.
    right._record_path(record.operation_id).write_bytes(
        left._record_path(record.operation_id).read_bytes()
    )
    derived_salts = _count_derivations(monkeypatch)
    assert left.read(record.operation_id).state == {"generation": "left"}
    with pytest.raises(JournalError, match="cannot decrypt"):
        right.read(record.operation_id)
    assert len(derived_salts) == 1


def test_cached_key_still_authenticates_each_ciphertext_read(tmp_path, monkeypatch):
    journal = _journal(tmp_path / "profile")
    record = journal.begin("master_import")
    path = journal._record_path(record.operation_id)
    good_blob = path.read_bytes()
    corrupt_blob = good_blob[:-1] + bytes([good_blob[-1] ^ 1])
    path.write_bytes(corrupt_blob)
    derived_salts = _count_derivations(monkeypatch)
    with pytest.raises(JournalError, match="cannot decrypt"):
        journal.read(record.operation_id)
    assert derived_salts == []  # Same salt; GCM must still reject tampering.
    path.write_bytes(good_blob)
    journal.read(record.operation_id)
    assert len(derived_salts) == 1  # Authentication failure clears the cache.


def test_journal_process_cache_is_not_serializable(tmp_path):
    journal = _journal(tmp_path / "profile")
    journal.begin("master_import")
    with pytest.raises(TypeError, match="process-local unlocking material"):
        pickle.dumps(journal)
