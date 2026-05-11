"""Append-only audit log (JSONL) with monthly rotation."""
from __future__ import annotations
import gzip
import json
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator
from keys_keeper.paths import Paths


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
    OS (parent argv via `ps`) or from raw CLI flags. The audit JSONL is read
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

    On macOS we read argv via `ps`. On Windows we use ctypes against
    kernel32 to get the image path — Windows command-line lookup requires
    either WMI (slow, ~200-500ms per audit event) or undocumented PEB
    parsing (fragile across WoW64), and the image path alone already
    captures 95% of the useful signal (which shell / IDE / agent invoked
    us). Document this asymmetry: macOS caller_path is a command line,
    Windows caller_path is an exe path.
    """
    try:
        if sys.platform == "win32":
            return _sanitize_untrusted(_resolve_caller_path_win(pid)) or "?"
        out = os.popen(f"ps -p {pid} -o command=").read().strip()
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
        self.paths.root.mkdir(parents=True, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # parent pid is the caller (CLI was invoked by zsh / claude / etc)
        ppid = os.getppid()
        event = AuditEvent(
            ts=now,
            op=op,
            name=name,
            id=id_,
            caller_pid=ppid,
            caller_path=_resolve_caller_path(ppid),
            file_target=_sanitize_untrusted(file_target),
            success=success,
            error=error,
        )
        with open(self.paths.audit_jsonl, "a") as f:
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
        # archive the entire current file
        archive = self.paths.audit_archive(first_ym)
        with open(self.paths.audit_jsonl, "rb") as src, gzip.open(archive, "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.unlink(self.paths.audit_jsonl)
