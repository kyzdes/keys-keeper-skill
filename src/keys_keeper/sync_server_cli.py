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


def _windows_private_acl(path: Path, *, restrict: bool = False) -> None:
    """Validate a protected DACL using the process token, never environment names.

    Only the invoking user and the privileged SYSTEM/Administrators principals
    may receive access. `restrict` is only used for newly-created private temp
    objects, never to silently change an operator's existing backup directory.
    """
    import ctypes
    from ctypes import wintypes as w
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.c_void_p
    def bind(library, name, args, result):
        function = getattr(library, name)
        function.argtypes, function.restype = args, result
        return function
    process = bind(kernel, "GetCurrentProcess", [], w.HANDLE)
    close = bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
    free = bind(kernel, "LocalFree", [pointer], pointer)
    open_token = bind(api, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
    token_info = bind(api, "GetTokenInformation", [w.HANDLE, ctypes.c_int, pointer, w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
    sid_text = bind(api, "ConvertSidToStringSidW", [pointer, ctypes.POINTER(w.LPWSTR)], w.BOOL)
    get_security = bind(api, "GetNamedSecurityInfoW", [w.LPWSTR, ctypes.c_int, w.DWORD, ctypes.POINTER(pointer), pointer,
                        ctypes.POINTER(pointer), pointer, ctypes.POINTER(pointer)], w.DWORD)
    get_control = bind(api, "GetSecurityDescriptorControl", [pointer, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL)
    get_ace = bind(api, "GetAce", [pointer, w.DWORD, ctypes.POINTER(pointer)], w.BOOL)
    def checked(result):
        if not result:
            raise BackupError("cannot verify private Windows backup permissions")
    def sid_string(sid):
        text = w.LPWSTR()
        checked(sid_text(sid, ctypes.byref(text)))
        try:
            return text.value
        finally:
            free(ctypes.cast(text, pointer))
    token = w.HANDLE()
    checked(open_token(process(), 0x0008, ctypes.byref(token)))  # TOKEN_QUERY
    try:
        required = w.DWORD()
        token_info(token, 1, None, 0, ctypes.byref(required))  # TokenUser
        checked(0 < required.value <= 65536)
        data = ctypes.create_string_buffer(required.value)
        checked(token_info(token, 1, data, len(data), ctypes.byref(required)))
        user = sid_string(pointer.from_buffer(data).value)
    finally:
        close(token)
    allowed = {user, "S-1-5-18", "S-1-5-32-544"}
    if restrict:
        convert = bind(api, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                       [w.LPCWSTR, w.DWORD, ctypes.POINTER(pointer), pointer], w.BOOL)
        get_dacl = bind(api, "GetSecurityDescriptorDacl", [pointer, ctypes.POINTER(w.BOOL), ctypes.POINTER(pointer), ctypes.POINTER(w.BOOL)], w.BOOL)
        set_security = bind(api, "SetNamedSecurityInfoW", [w.LPWSTR, ctypes.c_int, w.DWORD, pointer, pointer, pointer, pointer], w.DWORD)
        descriptor, dacl = pointer(), pointer()
        checked(convert(f"D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(descriptor), None))
        try:
            present, defaulted = w.BOOL(), w.BOOL()
            checked(get_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
            checked(set_security(str(path), 1, 0x80000004, None, None, dacl, None) == 0)
        finally:
            free(descriptor)
    owner, dacl, descriptor = pointer(), pointer(), pointer()
    checked(get_security(str(path), 1, 0x00000005, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
    try:
        control, revision = w.WORD(), w.DWORD()
        checked(get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)))
        if not dacl.value or not control.value & 0x1000 or sid_string(owner) not in allowed:
            raise BackupError("backup directory requires a protected private Windows DACL")
        # ACL header: BYTE revision, BYTE reserved, WORD size, WORD AceCount.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = pointer()
            checked(get_ace(dacl, index, ctypes.byref(ace)))
            kind = ctypes.c_ubyte.from_address(ace.value).value
            if kind == 1:  # ACCESS_DENIED_ACE cannot grant access
                continue
            if kind != 0 or sid_string(ace.value + 8) not in allowed:
                raise BackupError("backup directory grants access to another Windows principal")
    finally:
        free(descriptor)


def _backup_path_identity(path: Path, *, directory: bool = False) -> tuple[int, int]:
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise BackupError("backup path must be regular and not a reparse point")
    return info.st_dev, info.st_ino


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
        _backup_path_identity(database)
        parent_identity = _backup_path_identity(parent, directory=True)
        if os.name == "nt":
            _windows_private_acl(parent)
        else:
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            directory = os.fstat(directory_fd)
            if (directory.st_dev, directory.st_ino) != parent_identity:
                raise BackupError("backup directory changed")
            if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) & 0o077:
                raise BackupError("backup directory must be owned by this user with mode 0700")
        try:
            destination.lstat() if directory_fd is None else os.stat(destination.name, dir_fd=directory_fd, follow_symlinks=False)
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
            if os.name == "nt":
                _windows_private_acl(Path(temporary), restrict=True)
            candidate = Path(temporary) / "snapshot.sqlite3"
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0), 0o600)
            try:
                if os.name == "posix":
                    os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            if os.name == "nt":
                _windows_private_acl(candidate, restrict=True)
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
            with candidate.open("r+b") as handle:
                os.fsync(handle.fileno())
            try:
                # link() is atomic and fails if the name already exists, even
                # if another process created it after our initial inspection.
                if os.name == "nt":
                    if _backup_path_identity(parent, directory=True) != parent_identity:
                        raise BackupError("backup directory changed")
                    _windows_private_acl(parent)
                    os.link(candidate, destination)
                else:
                    os.link(candidate, destination.name, dst_dir_fd=directory_fd, follow_symlinks=False)
            except FileExistsError:
                raise BackupError("backup destination already exists") from None
            if directory_fd is not None:
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
