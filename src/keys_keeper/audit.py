"""Append-only audit log (JSONL) with monthly rotation."""
from __future__ import annotations
import gzip
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator
from keys_keeper.paths import Paths, ensure_private_dir


def _private_opener(path: str, flags: int) -> int:
    """``open()`` opener that creates new files mode 0600 on POSIX.

    The mode passed to ``os.open`` only applies when the file is *created*
    and is masked by the umask, so we also chmod after open on POSIX to
    guarantee 0600 even if the file already existed with looser bits.
    On Windows the mode arg is ignored; we skip the chmod so the platform
    isn't broken. Mirrors how store.py opens the lock file / data.json.
    """
    fd = os.open(path, flags, 0o600)
    if os.name == "posix":
        os.fchmod(fd, 0o600)
    return fd


@dataclass
class AuditEvent:
    ts: str
    op: str
    name: str
    id: str
    caller_pid: int
    caller_path: str
    file_target: str | None
    success: bool
    error: str | None

    def to_json(self) -> str:
        return json.dumps(self.__dict__, separators=(",", ":"))


_UNTRUSTED_FIELD_MAX_LEN = 256


def _sanitize_untrusted(s: str | None) -> str | None:
    """Strip control chars and cap length on values that originate from the
    OS (parent executable identity) or from raw CLI flags. The audit JSONL is read
    back by the admin UI; defense-in-depth against future code paths that
    might render these fields without escaping (the current renderer uses
    textContent, but we keep this guard so a regression there can't immediately
    become a stored XSS)."""
    if s is None:
        return None
    cleaned = "".join(ch for ch in s if ch == " " or (ch.isprintable() and ch not in "\r\n\t"))
    if len(cleaned) > _UNTRUSTED_FIELD_MAX_LEN:
        cleaned = cleaned[:_UNTRUSTED_FIELD_MAX_LEN] + "…"
    return cleaned


def _resolve_caller_path(pid: int) -> str:
    """Best-effort lookup of the parent process for the audit record.

    Record only the executable identity, never its argument vector: wrappers
    frequently contain credentials in argv. Linux exposes the executable via
    /proc; macOS uses the absolute /bin/ps with ``comm=``; Windows queries the
    process image path through kernel32.
    """
    try:
        if sys.platform == "win32":
            return _sanitize_untrusted(_resolve_caller_path_win(pid)) or "?"
        if sys.platform.startswith("linux"):
            out = os.readlink(f"/proc/{pid}/exe")
            return _sanitize_untrusted(out) or "?"
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "comm="],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
            env={"PATH": "/usr/bin:/bin"},
        )
        out = result.stdout.strip() if result.returncode == 0 else ""
        return _sanitize_untrusted(out) or "?"
    except Exception:
        return "?"


def _resolve_caller_path_win(pid: int) -> str:
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    OpenProcess = kernel32.OpenProcess
    OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    OpenProcess.restype = wintypes.HANDLE

    QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
    QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE, wintypes.DWORD,
        wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    ]
    QueryFullProcessImageNameW.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if not QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return ""
        return buf.value
    finally:
        CloseHandle(h)


class AuditLog:
    def __init__(self, paths: Paths):
        self.paths = paths

    def record(
        self,
        *,
        op: str,
        name: str,
        id_: str,
        file_target: str | None = None,
        success: bool = True,
        error: str | None = None,
    ) -> None:
        ensure_private_dir(self.paths.root)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # parent pid is the caller (CLI was invoked by zsh / claude / etc)
        ppid = os.getppid()
        event = AuditEvent(
            ts=now,
            op=_sanitize_untrusted(op) or "?",
            name=_sanitize_untrusted(name) or "?",
            id=_sanitize_untrusted(id_) or "?",
            caller_pid=ppid,
            caller_path=_resolve_caller_path(ppid),
            file_target=_sanitize_untrusted(file_target),
            success=success,
            # Exception text is not durable audit metadata: an upstream tool or
            # backend can embed a credential in it. Keep only the fact of an
            # error; the interactive caller already receives the live message.
            error="operation failed" if error else None,
        )
        with open(self.paths.audit_jsonl, "a", opener=_private_opener) as f:
            f.write(event.to_json() + "\n")

    def tail(self, n: int = 50) -> Iterator[dict]:
        if not self.paths.audit_jsonl.exists():
            return
        lines = self.paths.audit_jsonl.read_text().splitlines()
        for line in lines[-n:]:
            if line.strip():
                yield json.loads(line)

    def search(
        self,
        *,
        op: str | None = None,
        name: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
    ) -> Iterator[dict]:
        if not self.paths.audit_jsonl.exists():
            return
        for line in self.paths.audit_jsonl.read_text().splitlines():
            if not line.strip():
                continue
            ev = json.loads(line)
            if op and ev["op"] != op:
                continue
            if name and ev["name"] != name:
                continue
            if since and ev["ts"] < since.strftime("%Y-%m-%dT%H:%M:%SZ"):
                continue
            yield ev
            limit -= 1
            if limit <= 0:
                break

    def rotate_if_needed(self, now: datetime | None = None) -> None:
        """If audit.jsonl contains events from a previous month, archive them."""
        if not self.paths.audit_jsonl.exists():
            return
        now = now or datetime.now(timezone.utc)
        cur_ym = now.strftime("%Y-%m")
        # peek at the first event's month
        with open(self.paths.audit_jsonl) as f:
            first = f.readline().strip()
        if not first:
            return
        first_ev = json.loads(first)
        first_ym = first_ev["ts"][:7]
        if first_ym == cur_ym:
            return
        # archive the entire current file. The rotated .gz holds the same
        # sensitive metadata as the live log, so it must be 0600 too — open it
        # through the private opener (gzip.open would inherit the umask, e.g.
        # 0644) and wrap a GzipFile around the resulting 0600 handle.
        archive = self.paths.audit_archive(first_ym)
        with open(archive, "wb", opener=_private_opener) as raw, \
                gzip.GzipFile(fileobj=raw, mode="wb") as dst, \
                open(self.paths.audit_jsonl, "rb") as src:
            shutil.copyfileobj(src, dst)
        os.unlink(self.paths.audit_jsonl)
