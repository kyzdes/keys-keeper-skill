"""keys ssh — resolve server + ssh_key, write tempfile, exec ssh."""
from __future__ import annotations
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from keys_keeper.backend import KeychainBackend
from keys_keeper.models import EntryType, validate_ssh_target
from keys_keeper.refs import resolve_chain, RefMissingError
from keys_keeper.store import MetadataStore


class SSHRunnerError(ValueError):
    """SSH execution cannot proceed without exposing key material."""


def _validated_executable(path: str, label: str) -> str:
    try:
        resolved = Path(path).resolve(strict=True)
        metadata = resolved.stat()
    except OSError as ex:
        raise SSHRunnerError(f"{label} executable is unavailable") from ex
    if not stat.S_ISREG(metadata.st_mode) or not os.access(resolved, os.X_OK):
        raise SSHRunnerError(f"{label} executable is not a runnable regular file")
    if os.name == "posix":
        if metadata.st_uid not in (0, os.geteuid()):
            raise SSHRunnerError(f"{label} executable has an unexpected owner")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SSHRunnerError(f"{label} executable is group/world writable")
    return str(resolved)


def _windows_system_directory() -> Path:
    import ctypes

    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    if length <= 0 or length >= len(buffer):
        raise SSHRunnerError("cannot resolve the Windows system directory")
    return Path(buffer.value)


def _resolve_ssh_executable() -> str:
    if sys.platform == "win32":
        system_ssh = _windows_system_directory() / "OpenSSH" / "ssh.exe"
        if system_ssh.is_file():
            return _validated_executable(str(system_ssh), "ssh")
        discovered = shutil.which("ssh.exe")
    elif sys.platform == "darwin":
        return _validated_executable("/usr/bin/ssh", "ssh")
    else:
        for candidate in ("/usr/bin/ssh", "/bin/ssh"):
            if Path(candidate).is_file():
                return _validated_executable(candidate, "ssh")
        discovered = shutil.which("ssh")
    if not discovered:
        raise SSHRunnerError("ssh executable is unavailable")
    return _validated_executable(discovered, "ssh")


def _lock_down_key_file(path: str) -> None:
    """Restrict a tempfile holding an SSH private key to the current user only.

    POSIX: chmod 0600. Windows: use icacls to strip inheritance and grant
    read access to the current user only — modern OpenSSH on Windows
    refuses keys with looser ACLs.
    """
    if sys.platform == "win32":
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
        if not user:
            raise SSHRunnerError("cannot determine the current Windows user")
        icacls = _validated_executable(
            str(_windows_system_directory() / "icacls.exe"),
            "icacls",
        )
        result = subprocess.run(
            [icacls, path, "/inheritance:r", "/grant:r", f"{user}:(R)"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise SSHRunnerError("failed to restrict the SSH key tempfile ACL")
    else:
        os.chmod(path, 0o600)


def _ssh_tempdir() -> str | None:
    """Prefer ~/.ssh if it exists, else let tempfile pick the system tempdir."""
    candidate = Path.home() / ".ssh"
    return str(candidate) if candidate.exists() else None


def run_ssh(
    *,
    store: MetadataStore,
    backend: KeychainBackend,
    server_name: str,
    extra_cmd: str | None = None,
) -> int:
    server = store.get_by_name(server_name)
    if server is None or server.type != EntryType.SERVER:
        raise ValueError(f"{server_name!r} is not a server entry")
    host, user, port = validate_ssh_target(
        host=server.fields["host"],
        user=server.fields.get("user", "root"),
        port=server.fields.get("port", 22),
    )
    auth = server.fields.get("auth", "ssh_key")
    ssh_executable = _resolve_ssh_executable()

    if auth == "ssh_key":
        try:
            ssh_entry = resolve_chain(store.list(), server_name, "ssh_key")
        except RefMissingError as e:
            raise ValueError(f"server {server_name} requires ssh_key ref: {e}")
        # ACL-restricted tempfile sink (controlled, not transcript-visible).
        private_key = backend.get(ssh_entry.id).unseal()
        tmp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".key", delete=False, dir=_ssh_tempdir(),
            ) as tmp:
                tmp_path = tmp.name
                tmp.write(private_key)
                if not private_key.endswith("\n"):
                    tmp.write("\n")
            _lock_down_key_file(tmp_path)
            cmd = [
                ssh_executable,
                "-i",
                tmp_path,
                "-p",
                str(port),
                f"{user}@{host}",
            ]
            if extra_cmd:
                cmd.append(extra_cmd)
            result = subprocess.run(cmd)
            return result.returncode
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except FileNotFoundError:
                    pass
    elif auth == "password":
        cmd = [ssh_executable, "-p", str(port), f"{user}@{host}"]
        if extra_cmd:
            cmd.append(extra_cmd)
        return subprocess.run(cmd).returncode
    else:
        cmd = [ssh_executable, "-p", str(port), f"{user}@{host}"]
        if extra_cmd:
            cmd.append(extra_cmd)
        return subprocess.run(cmd).returncode
