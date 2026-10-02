import os
from pathlib import Path

import pytest

from keys_keeper.secure_io import (
    SecureFileCommitError,
    SecureFileError,
    read_secure_text,
    replace_secure_text,
)


def test_replace_rejects_target_changed_after_read(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("OLD=1\n")
    state = read_secure_text(target, missing_ok=False)

    replacement = tmp_path / "replacement"
    replacement.write_text("ATTACKER=1\n")
    os.replace(replacement, target)

    with pytest.raises(SecureFileError, match="changed"):
        replace_secure_text(state, "SECRET=must-not-land\n")
    assert target.read_text() == "ATTACKER=1\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_replace_preserves_stricter_owner_mode(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("OLD=1\n")
    target.chmod(0o400)
    state = read_secure_text(target, missing_ok=False)
    replace_secure_text(state, "NEW=1\n")
    assert target.read_text() == "NEW=1\n"
    assert target.stat().st_mode & 0o777 == 0o400


def test_replace_rejects_same_inode_content_change_even_if_mtime_restored(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("OLD=original\n")
    original = target.stat()
    state = read_secure_text(target, missing_ok=False)
    target.write_text("EDIT=concurrent\n")
    os.utime(target, ns=(original.st_atime_ns, original.st_mtime_ns))
    assert target.stat().st_ino == original.st_ino
    with pytest.raises(SecureFileError, match="changed"):
        replace_secure_text(state, "SECRET=must-not-land\n")
    assert target.read_text() == "EDIT=concurrent\n"
    assert list(tmp_path.iterdir()) == [target]


def test_missing_target_uses_create_only_publication_under_race(tmp_path, monkeypatch):
    target = tmp_path / "secret.env"
    state = read_secure_text(target, missing_ok=True)
    real_link = os.link

    def competitor_wins(source, destination):
        target.write_text("CONCURRENT=keep\n")
        return real_link(source, destination)

    monkeypatch.setattr(os, "link", competitor_wins)
    with pytest.raises(SecureFileError):
        replace_secure_text(state, "SECRET=must-not-land\n")
    assert target.read_text() == "CONCURRENT=keep\n"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO unavailable")
def test_fifo_swap_before_open_is_nonblocking_and_rejected(tmp_path, monkeypatch):
    from keys_keeper import private_files
    target = tmp_path / "secret.env"
    target.write_text("OLD=1\n")
    real_open = private_files._open_read

    def replace_before_open(path, flags):
        # Assert before actually opening, so a future regression cannot hang CI.
        assert flags & os.O_NONBLOCK
        target.unlink()
        os.mkfifo(target, 0o600)
        return real_open(path, flags)

    monkeypatch.setattr(private_files, "_open_read", replace_before_open)
    with pytest.raises(SecureFileError, match="regular"):
        read_secure_text(target, missing_ok=False)


@pytest.mark.parametrize("kind", ["directory", "symlink", "device"])
def test_plaintext_reader_rejects_nonregular_targets(tmp_path, kind):
    target = tmp_path / "target"
    if kind == "directory":
        target.mkdir()
    elif kind == "symlink":
        outside = tmp_path / "outside"
        outside.write_text("SYNTHETIC-SECRET-CANARY")
        try:
            target.symlink_to(outside)
        except OSError:
            pytest.skip("symlink creation unavailable")
    else:
        if os.name != "posix":
            pytest.skip("POSIX device fixture")
        target = Path("/dev/null")
    with pytest.raises(SecureFileError, match="regular"):
        read_secure_text(target, missing_ok=False)


def test_plaintext_input_and_output_are_bounded_without_modifying_target(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("a" * 129)
    with pytest.raises(SecureFileError, match="size limit"):
        read_secure_text(target, missing_ok=False, max_bytes=128)
    target.write_text("OLD=1\n")
    state = read_secure_text(target, missing_ok=False, max_bytes=128)
    with pytest.raises(SecureFileError, match="size limit"):
        replace_secure_text(state, "a" * 129)
    assert target.read_text() == "OLD=1\n"
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode assertion")
def test_plaintext_sink_does_not_change_user_directory_permissions(tmp_path):
    tmp_path.chmod(0o755)
    target = tmp_path / "secret.env"
    state = read_secure_text(target, missing_ok=True)
    replace_secure_text(state, "SECRET=synthetic\n")
    assert tmp_path.stat().st_mode & 0o777 == 0o755
    assert target.stat().st_mode & 0o777 == 0o600


def test_secret_snapshot_repr_is_redacted(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("SYNTHETIC-SECRET-CANARY")
    state = read_secure_text(target, missing_ok=False)
    assert "SYNTHETIC" not in repr(state)
    assert "SYNTHETIC" not in repr(state._bytes_state)


def test_create_only_postlink_cleanup_failure_keeps_committed_marker_and_target(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-state"
    state = read_secure_text(target, missing_ok=True)
    unlink = os.unlink
    def fail_temp_cleanup(path, *args, **kwargs):
        if str(path).endswith(".tmp"):
            raise OSError("synthetic postpublication cleanup failure")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(os, "unlink", fail_temp_cleanup)
        with pytest.raises(SecureFileCommitError) as caught:
            replace_secure_text(state, "synthetic-published-state")
    assert caught.value.committed is True
    assert isinstance(caught.value, SecureFileError)
    assert target.read_text() == "synthetic-published-state"
    for temporary in tmp_path.glob("*.tmp"):
        unlink(temporary)


@pytest.mark.skipif(os.name != "posix", reason="POSIX parent durability callback")
def test_replace_postpublication_durability_failure_keeps_committed_marker(tmp_path, monkeypatch):
    import stat
    from keys_keeper import private_files, secure_io
    target = tmp_path / "synthetic-state"
    target.write_text("old-public-state")
    state = read_secure_text(target, missing_ok=False)
    fsync = os.fsync
    def fail_directory_sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("synthetic postpublication fsync failure")
        return fsync(fd)
    # Default secret sinks use best-effort parent sync. Exercise a strict
    # callback's real post-rename error without changing that existing policy.
    monkeypatch.setattr(secure_io, "_fsync_parent_best_effort", private_files.fsync_parent)
    monkeypatch.setattr(os, "fsync", fail_directory_sync)
    with pytest.raises(SecureFileCommitError) as caught:
        replace_secure_text(state, "new-published-state")
    assert caught.value.committed is True
    assert target.read_text() == "new-published-state"
    assert list(tmp_path.iterdir()) == [target]


def test_prepublication_file_sync_failure_has_no_committed_marker(tmp_path, monkeypatch):
    target = tmp_path / "synthetic-state"
    target.write_text("previous-state")
    state = read_secure_text(target, missing_ok=False)
    def fail_sync(_fd):
        raise OSError("synthetic prepublication file fsync failure")
    monkeypatch.setattr(os, "fsync", fail_sync)
    with pytest.raises(SecureFileError) as caught:
        replace_secure_text(state, "must-not-publish")
    assert getattr(caught.value, "committed", False) is False
    assert target.read_text() == "previous-state"
    assert list(tmp_path.iterdir()) == [target]
