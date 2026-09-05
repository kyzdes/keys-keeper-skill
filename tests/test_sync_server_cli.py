"""Synthetic offline backup/restore checks; never opens a user relay database."""
from pathlib import Path
import os
import sqlite3
import stat

import pytest

from keys_keeper import sync_server_cli as cli
from keys_keeper.sync_server import SyncServerApp


@pytest.fixture
def database(tmp_path):
    source = tmp_path / "source.sqlite3"
    SyncServerApp(source, "synthetic-admin-token-for-backup")
    connection = sqlite3.connect(source)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE backup_fixture(revision INTEGER, ciphertext BLOB)")
    connection.execute("INSERT INTO backup_fixture VALUES(1, ?)", (b"synthetic-encrypted-record",))
    connection.commit()
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    yield source, connection, directory
    connection.close()


def test_backup_includes_live_wal_excludes_uncommitted_and_restores(database):
    source, writer, directory = database
    assert Path(str(source) + "-wal").stat().st_size > 0
    writer.execute("INSERT INTO backup_fixture VALUES(2, ?)", (b"not-committed",))
    destination = directory / "copy.sqlite3"
    cli.backup_database(source, destination)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert list(directory.iterdir()) == [destination]
    with sqlite3.connect(destination) as restored:
        assert restored.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert restored.execute("SELECT revision,ciphertext FROM backup_fixture").fetchall() == [(1, b"synthetic-encrypted-record")]
    assert writer.execute("SELECT COUNT(*) FROM backup_fixture").fetchone() == (2,)
    writer.rollback()
    # Restore through the same safe backup path into a distinct isolated DB.
    isolated = directory / "isolated.sqlite3"
    cli.backup_database(destination, isolated)
    app = SyncServerApp(isolated, "isolated-synthetic-admin-token")
    assert app.health() == {"status": "ok"}
    with sqlite3.connect(isolated) as restored:
        assert restored.execute("SELECT revision FROM backup_fixture").fetchall() == [(1,)]
        assert restored.execute("SELECT COUNT(*) FROM kk3_scopes").fetchone() == (0,)


@pytest.mark.parametrize("symlink", [False, True])
def test_existing_destination_never_overwritten(database, symlink):
    source, _, directory = database
    existing = directory / "existing"
    existing.write_bytes(b"preserve-existing")
    destination = directory / "copy.sqlite3" if symlink else existing
    if symlink:
        destination.symlink_to(existing)
    with pytest.raises(cli.BackupError, match="already exists"):
        cli.backup_database(source, destination)
    assert existing.read_bytes() == b"preserve-existing"


def test_atomic_destination_race_preserves_other_process_file(database, monkeypatch):
    source, _, directory = database
    destination = directory / "copy.sqlite3"
    real_link = os.link
    def racing_link(*args, **kwargs):
        destination.write_bytes(b"racing-existing")
        return real_link(*args, **kwargs)
    monkeypatch.setattr(cli.os, "link", racing_link)
    with pytest.raises(cli.BackupError, match="already exists"):
        cli.backup_database(source, destination)
    assert destination.read_bytes() == b"racing-existing"
    assert list(directory.iterdir()) == [destination]


@pytest.mark.parametrize("mode", [0o755, 0o770, 0o777])
def test_backup_rejects_nonprivate_directory(database, mode):
    source, _, directory = database
    directory.chmod(mode)
    with pytest.raises(cli.BackupError, match="mode 0700"):
        cli.backup_database(source, directory / "copy.sqlite3")
    assert not list(directory.iterdir())


def test_backup_rejects_symlink_directory_and_missing_source(database):
    source, _, directory = database
    link = directory.parent / "alias"
    link.symlink_to(directory, target_is_directory=True)
    with pytest.raises(cli.BackupError):
        cli.backup_database(source, link / "copy.sqlite3")
    missing = directory / "missing.sqlite3"
    with pytest.raises(cli.BackupError):
        cli.backup_database(missing, directory / "copy.sqlite3")
    assert not list(directory.iterdir())


def test_backup_timeout_cleans_unpublished_temporary_files(database, monkeypatch):
    source, _, directory = database
    ticks = iter([0, 2])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks, 2))
    with pytest.raises(cli.BackupError, match="timed out"):
        cli.backup_database(source, directory / "copy.sqlite3", timeout=1)
    assert not list(directory.iterdir())


@pytest.mark.parametrize("global_database", [False, True])
def test_backup_cli_requires_no_admin_token_and_accepts_both_database_positions(database, monkeypatch, capsys, global_database):
    source, _, directory = database
    monkeypatch.delenv("KEYS_KEEPER_SYNC_ADMIN_TOKEN", raising=False)
    args = ["backup", str(directory / "copy.sqlite3")]
    args = ["--database", str(source), *args] if global_database else [*args, "--database", str(source)]
    assert cli.main(args) == 0
    output = capsys.readouterr()
    assert output.out == "relay backup completed\n"
    assert output.err == ""
    assert cli.build_parser().parse_args(["--database", str(source), "--port", "9000"]).command is None


def test_invalid_database_error_does_not_echo_contents_or_create_destination(tmp_path, capsys):
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    source = tmp_path / "bad.sqlite3"
    source.write_text("SYNTHETIC-SECRET-CANARY")
    assert cli.main(["backup", str(directory / "copy.sqlite3"), "--database", str(source)]) == 1
    output = capsys.readouterr()
    assert "SYNTHETIC" not in output.err + output.out
    assert not list(directory.iterdir())
