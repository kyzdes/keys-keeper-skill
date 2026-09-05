"""Process entrypoint for the zero-knowledge Keys Keeper VPS relay."""
from __future__ import annotations

import argparse
import os
import signal
import sqlite3
import stat
import tempfile
import sys
import time
from pathlib import Path

from keys_keeper.sync_server import SyncServerApp, create_http_server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keys-keeper-syncd")
    parser.add_argument(
        "--database",
        default="/var/lib/keys-keeper-syncd/syncd.sqlite3",
        help="SQLite database path (default: /var/lib/keys-keeper-syncd/syncd.sqlite3)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--allow-non-loopback",
        action="store_true",
        help="allow a public bind; TLS must then be provided by a trusted reverse proxy",
    )
    commands = parser.add_subparsers(dest="command")
    backup = commands.add_parser("backup", help="make a consistent private SQLite backup")
    backup.add_argument("destination", help="new backup file in an existing owner-only directory")
    backup.add_argument("--database", default=argparse.SUPPRESS, help="source SQLite database path")
    backup.add_argument("--timeout", type=int, default=60, help="maximum backup duration in seconds (default: 60)")
    return parser


class BackupError(RuntimeError):
    """Metadata-only backup failure; never includes database contents."""


def backup_database(database: Path, destination: Path, *, timeout: int = 60) -> None:
    """Atomically publish a consistent SQLite backup without replacing any file.

    The source is opened read-only with WAL awareness. Temporary database and
    SQLite sidecars stay in a private directory and disappear on failure.
    """
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise BackupError("backup timeout must be between 1 and 3600 seconds")
    database = database.expanduser().absolute()
    destination = destination.expanduser().absolute()
    parent = destination.parent
    directory_fd = None
    try:
        if not stat.S_ISREG(database.lstat().st_mode):
            raise BackupError("backup source must be a regular database file")
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory = os.fstat(directory_fd)
        if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) & 0o077:
            raise BackupError("backup directory must be owned by this user with mode 0700")
        try:
            os.stat(destination.name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BackupError("backup destination already exists")
        deadline = time.monotonic() + timeout
        def progress(_status, _remaining, _total):
            if time.monotonic() >= deadline:
                raise BackupError("backup timed out")
        # Opening the source in mode=ro never creates a missing source and
        # intentionally does not use immutable=1, which would ignore live WAL.
        with tempfile.TemporaryDirectory(prefix=".relay-backup-", dir=parent) as temporary:
            candidate = Path(temporary) / "snapshot.sqlite3"
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            source = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=min(timeout, 1))
            try:
                target = sqlite3.connect(candidate, timeout=min(timeout, 1))
                try:
                    target.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
                    source.backup(target, pages=128, progress=progress, sleep=0.05)
                    # Publish one self-contained main file, never live sidecars.
                    target.execute("PRAGMA journal_mode=DELETE")
                    if target.execute("PRAGMA quick_check").fetchall() != [("ok",)]:
                        raise BackupError("backup integrity check failed")
                finally:
                    target.close()
            finally:
                source.close()
            progress(0, 0, 0)
            with candidate.open("rb") as handle:
                os.fsync(handle.fileno())
            try:
                # link() is atomic and fails if the name already exists, even
                # if another process created it after our initial inspection.
                os.link(candidate, destination.name, dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                raise BackupError("backup destination already exists") from None
            os.fsync(directory_fd)
    except BackupError:
        raise
    except (OSError, sqlite3.Error):
        raise BackupError("cannot create consistent relay backup") from None
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "backup":
        try:
            backup_database(Path(args.database), Path(args.destination), timeout=args.timeout)
        except BackupError as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1
        print("relay backup completed")
        return 0
    if not 0 <= args.port <= 65535:
        sys.stderr.write("error: --port must be between 0 and 65535\n")
        return 2
    token = os.environ.get("KEYS_KEEPER_SYNC_ADMIN_TOKEN")
    if not token:
        sys.stderr.write("error: KEYS_KEEPER_SYNC_ADMIN_TOKEN is required\n")
        return 2
    database = Path(args.database).expanduser()
    try:
        app = SyncServerApp(database, token)
        server = create_http_server(
            app,
            args.host,
            args.port,
            allow_non_loopback=args.allow_non_loopback,
        )
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"error: cannot start syncd: {exc}\n")
        return 1

    def stop(_signum, _frame) -> None:
        # shutdown() cannot safely be called from the serve_forever thread.
        # Raising KeyboardInterrupt reaches the common close path immediately.
        raise KeyboardInterrupt

    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, stop)
    host, port = server.server_address[:2]
    print(f"keys-keeper-syncd listening on {host}:{port}; database={database}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())
