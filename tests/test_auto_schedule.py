"""Automatic claims use bounded metadata locks and never unlock a vault."""
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import time

import pytest

from keys_keeper import auto_schedule
from keys_keeper.operation_journal import JournalError, profile_lock
from keys_keeper.paths import Paths


def test_busy_claim_is_bounded_preserves_marker_and_reads_no_state(tmp_path, monkeypatch):
    schedule = Paths(tmp_path / "schedule")
    auto_schedule.claim_auto_sync(schedule, 1000)
    marker = schedule.root / "last-attempt.json"
    before = marker.read_bytes()
    entered, release = threading.Event(), threading.Event()
    def holder():
        with profile_lock(schedule):
            entered.set()
            assert release.wait(5)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(holder)
        assert entered.wait(2)
        original = auto_schedule._secure_read
        monkeypatch.setattr(auto_schedule, "_secure_read", lambda *_a, **_kw: pytest.fail("busy claim read metadata/state"))
        started = time.monotonic()
        try:
            with pytest.raises(TimeoutError, match="busy"):
                auto_schedule.claim_auto_sync(schedule, 87400, force=True)
            assert time.monotonic() - started < 2
            assert marker.read_bytes() == before
        finally:
            release.set()
        future.result(timeout=2)
        monkeypatch.setattr(auto_schedule, "_secure_read", original)
    assert auto_schedule.claim_auto_sync(schedule, 1001) == (False, 87400)


def test_regular_storage_lock_default_still_waits_for_holder(tmp_path):
    paths = Paths(tmp_path)
    entered, acquired = threading.Event(), threading.Event()
    def waiting():
        entered.set()
        with profile_lock(paths):
            acquired.set()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with profile_lock(paths):
            future = pool.submit(waiting)
            assert entered.wait(2)
            assert not acquired.wait(.05)
        future.result(timeout=2)
    assert acquired.is_set()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink ownership check")
def test_unsafe_claim_lock_does_not_touch_external_target(tmp_path):
    schedule = Paths(tmp_path / "schedule")
    schedule.locks_dir.mkdir(parents=True, mode=0o700)
    target = tmp_path / "outside"
    target.write_text("unchanged")
    target.chmod(0o644)
    (schedule.locks_dir / "profile.lock").symlink_to(target)
    with pytest.raises(JournalError):
        auto_schedule.claim_auto_sync(schedule, 1000)
    assert target.read_text() == "unchanged"
    assert target.stat().st_mode & 0o777 == 0o644
    assert not (schedule.root / "last-attempt.json").exists()
