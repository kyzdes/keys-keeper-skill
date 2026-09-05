from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path
from uuid import UUID, uuid4

import pytest

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
