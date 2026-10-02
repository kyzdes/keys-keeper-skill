"""A damaged local anti-rollback sidecar must never become an empty anchor."""
import os

import pytest

from keys_keeper import sync
from keys_keeper.sync_remote import TransportError
from _sync_fakes import FakeRemote, make_device


@pytest.mark.parametrize("raw", [b"{bad", b"[]", b'{"highest_version":1,"highest_version":0}',
                                    b'{"highest_version":true}', b'{"highest_version":-1}',
                                    b'{"highest_version":"2"}'])
def test_corrupt_sync_state_cannot_disable_rollback_guard(tmp_path, raw):
    device = make_device(FakeRemote(), tmp_path, "synthetic")
    path = device.engine.paths.sync_state_json
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o600)
    with pytest.raises(TransportError, match="local sync state invalid"):
        device.engine._watermark()
    assert path.read_bytes() == raw


@pytest.mark.parametrize("kind", ["oversized", "symlink", "fifo"])
def test_unsafe_sync_state_rejected_before_read(tmp_path, monkeypatch, kind):
    device = make_device(FakeRemote(), tmp_path, "synthetic")
    path = device.engine.paths.sync_state_json
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("FIFO unavailable")
        os.mkfifo(path, 0o600)
    elif kind == "symlink":
        target = tmp_path / "unrelated"
        target.write_bytes(b'{"highest_version":2}')
        try:
            path.symlink_to(target)
        except OSError:
            pytest.skip("symlinks unavailable")
    else:
        path.write_bytes(b"x" * 129)
        path.chmod(0o600)
        monkeypatch.setattr(sync, "_MAX_SYNC_STATE_BYTES", 128)
    monkeypatch.setattr(os, "read", lambda *args: pytest.fail("unsafe sidecar was read"))
    with pytest.raises(TransportError, match="unavailable"):
        device.engine._watermark()


def test_failed_sidecar_persistence_is_reported_and_preserves_anchor(tmp_path, monkeypatch):
    device = make_device(FakeRemote(), tmp_path, "synthetic")
    device.engine._write_state(version=3)
    path = device.engine.paths.sync_state_json
    original = path.read_bytes()
    monkeypatch.setattr(sync, "_atomic_write_bytes", lambda *args: (_ for _ in ()).throw(OSError("synthetic I/O")))
    with pytest.raises(TransportError, match="cannot persist"):
        device.engine._write_state(version=4)
    assert path.read_bytes() == original
    assert device.engine._watermark() == 3
