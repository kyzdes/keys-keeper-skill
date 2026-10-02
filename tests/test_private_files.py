"""Descriptor authority, growth bounds and first-backup publication contracts."""
import os
import stat
from types import SimpleNamespace

import pytest

from keys_keeper import private_files as files


@pytest.mark.parametrize("change", ["regular", "owner", "inode"])
def test_opened_descriptor_is_checked_before_read_and_always_closed(tmp_path, monkeypatch, change):
    if change == "owner" and os.name != "posix":
        pytest.skip("POSIX ownership contract")
    path = tmp_path / "synthetic-state"
    path.write_bytes(b"synthetic")
    path.chmod(0o600)
    real_open, real_fstat = os.open, os.fstat
    descriptors = []

    def opened(target, flags):
        fd = real_open(target, flags)
        descriptors.append(fd)
        return fd

    def altered(fd):
        info = real_fstat(fd)
        values = {key: getattr(info, key) for key in ("st_dev", "st_ino", "st_mode", "st_uid", "st_size")}
        if change == "regular":
            values["st_mode"] = stat.S_IFIFO | 0o600
        elif change == "owner":
            values["st_uid"] += 1
        else:
            values["st_ino"] += 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(files.os, "open", opened)
    monkeypatch.setattr(files.os, "fstat", altered)
    monkeypatch.setattr(files.os, "read", lambda *args: pytest.fail("untrusted descriptor read"))
    with pytest.raises(files.PrivateFileError):
        files.secure_read(path, max_bytes=128)
    assert len(descriptors) == 1
    with pytest.raises(OSError):
        real_fstat(descriptors[0])


@pytest.mark.skipif(os.name != "posix", reason="POSIX private-mode contract")
def test_permissions_changed_between_lstat_and_open_reject_before_read(tmp_path, monkeypatch):
    path = tmp_path / "synthetic-state"
    path.write_bytes(b"synthetic")
    path.chmod(0o600)
    real_open = os.open

    def opened(target, flags):
        fd = real_open(target, flags)
        path.chmod(0o644)
        return fd

    monkeypatch.setattr(files.os, "open", opened)
    monkeypatch.setattr(files.os, "read", lambda *args: pytest.fail("new public-mode descriptor read"))
    with pytest.raises(files.PrivateFileError, match="unsafe ownership or permissions"):
        files.secure_read(path, max_bytes=128)


def test_legacy_public_metadata_mode_remains_readable_only_when_explicitly_allowed(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_bytes(b"legacy exact bytes")
    path.chmod(0o644)
    assert files.secure_read(path, max_bytes=128, require_private=False) == b"legacy exact bytes"


@pytest.mark.parametrize("replacement", ["symlink", "fifo"])
def test_path_replaced_at_open_never_reads_symlink_target_or_special_file(tmp_path, monkeypatch, replacement):
    if replacement == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    path = tmp_path / "synthetic-state"
    path.write_bytes(b"synthetic")
    path.chmod(0o600)
    external = tmp_path / "protected-target"
    external.write_bytes(b"protected external bytes")
    external.chmod(0o600)
    if replacement == "symlink":
        probe = tmp_path / "link-probe"
        try:
            probe.symlink_to(external)
        except OSError:
            pytest.skip("symlinks unavailable")
        probe.unlink()
    real_open = os.open

    def replaced_before_open(target, flags):
        path.unlink()
        if replacement == "symlink":
            path.symlink_to(external)
        else:
            os.mkfifo(path, 0o600)
        return real_open(target, flags)

    monkeypatch.setattr(files.os, "open", replaced_before_open)
    monkeypatch.setattr(files.os, "read", lambda *args: pytest.fail("replacement file read"))
    with pytest.raises(files.PrivateFileError):
        files.secure_read(path, max_bytes=128)
    assert external.read_bytes() == b"protected external bytes"


def test_file_growth_after_fstat_is_bounded_to_limit_plus_one(tmp_path, monkeypatch):
    path = tmp_path / "growing-state"
    path.write_bytes(b"a")
    path.chmod(0o600)
    real_fstat, real_read = os.fstat, os.read
    reads = []

    def grows_after_size_check(fd):
        original = real_fstat(fd)
        with path.open("ab") as stream:
            stream.write(b"x" * 128)
        return original

    def bounded_read(fd, size):
        reads.append(size)
        return real_read(fd, size)

    monkeypatch.setattr(files.os, "fstat", grows_after_size_check)
    monkeypatch.setattr(files.os, "read", bounded_read)
    with pytest.raises(files.PrivateFileError, match="exceeds size limit"):
        files.secure_read(path, max_bytes=128)
    assert reads == [129]


def test_create_if_absent_publication_cannot_replace_concurrently_created_backup(tmp_path, monkeypatch):
    destination = tmp_path / "first-backup"
    real_link = os.link
    publications = []

    def another_writer_wins(source, target):
        assert source != target
        assert type(target) is type(destination)
        assert files.secure_read(type(destination)(source), max_bytes=128) == b"second-backup"
        destination.write_bytes(b"first-backup-exact-bytes")
        publications.append(True)
        return real_link(source, target)

    monkeypatch.setattr(files.os, "link", another_writer_wins)
    with pytest.raises(FileExistsError):
        files.atomic_write_bytes(destination, b"second-backup", replace_existing=False)
    assert publications == [True]
    assert destination.read_bytes() == b"first-backup-exact-bytes"
    assert list(tmp_path.iterdir()) == [destination]
