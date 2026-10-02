"""Append-only audit log (JSONL) with monthly rotation."""
from __future__ import annotations
import gzip
import errno
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterator
from keys_keeper.paths import Paths, ensure_private_dir
from keys_keeper.private_files import open_private_file


MAX_AUDIT_RESULTS = 10_000
_MAX_LINE_BYTES = 1024 * 1024
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_FORWARD_NEWLINE = re.compile(b"\r\n|[\r\n]")
_BACKWARD_NEWLINE = re.compile(b"\n\r|[\r\n]")


class AuditReadLimit(ValueError):
    """The audit file cannot be safely read within the resource limits."""

    def __init__(self):
        super().__init__("audit log read limit exceeded")


def _validate_limit(limit: int) -> None:
    if type(limit) is not int or not 0 <= limit <= MAX_AUDIT_RESULTS:
        raise ValueError(f"audit limit must be an integer from 0 to {MAX_AUDIT_RESULTS}")


@contextmanager
def _open_audit(path):
    """Reject pipes/devices before reading, including a replacement at open."""
    try:
        if not stat.S_ISREG(os.lstat(path).st_mode):
            raise AuditReadLimit()
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
    except FileNotFoundError:
        yield None
        return
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise AuditReadLimit() from None
        raise
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise AuditReadLimit()
        # Unbuffered reads keep the scan cap and newest-first short circuit exact.
        with os.fdopen(fd, "rb", buffering=0, closefd=False) as stream:
            yield stream
    finally:
        os.close(fd)


def _audit_lines(stream, *, newest_first: bool = False) -> Iterator[bytes]:
    """Read bounded logical lines without loading the rest of the audit file.

    Reversing individual chunks permits one bounded line splitter in both
    directions. UTF-8 is decoded only after the complete line is reassembled.
    CRLF is a single delimiter even when it crosses a read boundary.
    """
    size = os.fstat(stream.fileno()).st_size
    position = size if newest_first else 0
    scanned = 0
    pending = b""
    first_segment = True
    newline = _BACKWARD_NEWLINE if newest_first else _FORWARD_NEWLINE
    defer = b"\n" if newest_first else b"\r"
    while position > 0 if newest_first else position < size:
        available = position if newest_first else size - position
        amount = min(_READ_CHUNK_BYTES, available, _MAX_SCAN_BYTES - scanned)
        if amount <= 0:
            raise AuditReadLimit()
        if newest_first:
            position -= amount
            stream.seek(position)
        chunk = stream.read(amount)
        scanned += len(chunk)
        if not chunk:
            break
        if newest_first:
            chunk = chunk[::-1]
        else:
            position += len(chunk)
        pending += chunk
        at_end = position == 0 if newest_first else position >= size
        split_end = len(pending)
        if not at_end and pending.endswith(defer):
            split_end -= 1
        start = 0
        for match in newline.finditer(pending, 0, split_end):
            line = pending[start:match.start()]
            if len(line) > _MAX_LINE_BYTES:
                raise AuditReadLimit()
            if not (newest_first and first_segment and not line):
                yield line[::-1] if newest_first else line
            first_segment = False
            start = match.end()
        pending = pending[start:]
        # One deferred byte can belong to a CRLF delimiter, not the line.
        line_size = len(pending) - (1 if pending.endswith(defer) else 0)
        if line_size > _MAX_LINE_BYTES:
            raise AuditReadLimit()
    if pending or (newest_first and size and not first_segment):
        if len(pending) > _MAX_LINE_BYTES:
            raise AuditReadLimit()
        yield pending[::-1] if newest_first else pending


def _private_opener(path: str, flags: int) -> int:
    """Use the same validated, private creation contract as other vault files."""
    return open_private_file(Path(path), flags)


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
    caller_kind: str = "unknown"
    caller_agent: str | None = None
    affected_entry_ids: list[str] | None = None
    committed: bool | None = None
    outcome: str | None = None
    audit_status: str | None = None

    def to_json(self) -> str:
        data = dict(self.__dict__)
        if self.affected_entry_ids is None:
            data.pop("affected_entry_ids")
        if self.outcome is None:
            for field in ("committed", "outcome", "audit_status"):
                data.pop(field)
        return json.dumps(data, separators=(",", ":"))


def normalize_outcome(*, committed: bool | None = None,
                      audit_status: str = "unknown", error: Exception | None = None) -> dict:
    """Value-free receipt for publication, rejection or an uncertain operation.

    A later error cannot erase a known publication. Unclassified errors never
    imply either rollback or success; callers must inspect state before retrying.
    """
    if getattr(error, "committed", None) is True:
        committed = True
    elif committed is None and getattr(error, "committed", None) is False:
        committed = False
    if committed is not True and committed is not False:
        committed = None
    audit_status = getattr(error, "audit_status", audit_status)
    if type(audit_status) is not str or audit_status not in {"recorded", "unavailable", "unknown"}:
        audit_status = "unknown"
    return {"committed": committed,
            "outcome": "published" if committed is True else "failed" if committed is False else "unconfirmed",
            "audit_status": audit_status}


def record_outcome(audit, *, op: str, name: str, id_: str,
                   file_target: str | None = None, success: bool = True,
                   error: str | None = None,
                   affected_entry_ids: list[str] | None = None,
                   committed=...) -> str:
    """Record metadata without turning an audit failure into an operation retry.

    The caller decides whether the operation committed. This helper reports
    only whether its receipt was persisted, never exception text or values.
    Failed operations use a fixed error marker even for third-party audit sinks.
    """
    receipt = normalize_outcome(committed=success if committed is ... else committed,
                                audit_status="recorded")
    event = {"op": op, "name": name, "id_": id_,
             "success": receipt["committed"] is True, **receipt}
    if file_target is not None:
        event["file_target"] = file_target
    if error or not success:
        event["error"] = "operation failed"
    if affected_entry_ids is not None:
        event["affected_entry_ids"] = list(dict.fromkeys(affected_entry_ids))
    try:
        audit.record(**event)
    except Exception:
        return "unavailable"
    return "recorded"


_UNTRUSTED_FIELD_MAX_LEN = 256


def caller_identity(caller_path: str, environ=None) -> tuple[str, str | None]:
    """Best-effort display attribution, never an authorization decision.

    Persist only a fixed agent name, not environment values, session IDs,
    process arguments, or working directories. A shell alone proves nothing.
    Desktop requests must not inherit the agent that launched the UI.
    """
    env = os.environ if environ is None else environ
    if env.get("KEYS_KEEPER_CALLER") == "desktop":
        return "desktop", None
    if env.get("CODEX_THREAD_ID") or env.get("CODEX_SESSION_ID"):
        return "agent", "codex"
    if env.get("CLAUDECODE") == "1":
        return "agent", "claude"
    executable = caller_path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    known = {"codex": "codex", "claude": "claude", "opencode": "opencode",
             "codex.exe": "codex", "claude.exe": "claude", "opencode.exe": "opencode"}
    if executable in known:
        return "agent", known[executable]
    return "unknown", None


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
        affected_entry_ids: list[str] | None = None,
        committed=...,
        outcome: str | None = None,
        audit_status: str | None = None,
    ) -> None:
        receipt = None
        if committed is not ... or outcome is not None or audit_status is not None:
            receipt = normalize_outcome(committed=None if committed is ... else committed,
                                        audit_status=audit_status or "recorded")
            if outcome is not None and outcome != receipt["outcome"]:
                raise ValueError("inconsistent audit outcome")
            success = receipt["committed"] is True
        ensure_private_dir(self.paths.root)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        # parent pid is the caller (CLI was invoked by zsh / claude / etc)
        ppid = os.getppid()
        caller_path = _resolve_caller_path(ppid)
        caller_kind, caller_agent = caller_identity(caller_path)
        event = AuditEvent(
            ts=now,
            op=_sanitize_untrusted(op) or "?",
            name=_sanitize_untrusted(name) or "?",
            id=_sanitize_untrusted(id_) or "?",
            caller_pid=ppid,
            caller_path=caller_path,
            file_target=_sanitize_untrusted(file_target),
            success=success,
            # Exception text is not durable audit metadata: an upstream tool or
            # backend can embed a credential in it. Keep only the fact of an
            # error; the interactive caller already receives the live message.
            error="operation failed" if error else None,
            caller_kind=caller_kind,
            caller_agent=caller_agent,
            affected_entry_ids=(list(dict.fromkeys(
                _sanitize_untrusted(value) or "?" for value in affected_entry_ids
            )) if affected_entry_ids is not None else None),
            **(receipt or {}),
        )
        with open(self.paths.audit_jsonl, "a", opener=_private_opener) as f:
            f.write(event.to_json() + "\n")

    def tail(self, n: int = 50) -> Iterator[dict]:
        _validate_limit(n)
        if n == 0:
            return
        with _open_audit(self.paths.audit_jsonl) as stream:
            if stream is None:
                return
            lines = []
            for line in _audit_lines(stream, newest_first=True):
                lines.append(line)
                if len(lines) == n:
                    break
            for line in reversed(lines):
                if line.strip():
                    yield json.loads(line.decode("utf-8"))

    def search(
        self,
        *,
        op: str | None = None,
        name: str | None = None,
        entry_id: str | None = None,
        since: datetime | None = None,
        limit: int = 1000,
        newest_first: bool = False,
    ) -> Iterator[dict]:
        _validate_limit(limit)
        if limit == 0:
            return
        since_ts = since.strftime("%Y-%m-%dT%H:%M:%SZ") if since else None
        with _open_audit(self.paths.audit_jsonl) as stream:
            if stream is None:
                return
            for line in _audit_lines(stream, newest_first=newest_first):
                if not line.strip():
                    continue
                ev = json.loads(line.decode("utf-8"))
                if op and ev["op"] != op:
                    continue
                if name and ev["name"] != name:
                    continue
                if entry_id and entry_id != ev.get("id") and entry_id not in (ev.get("affected_entry_ids") or []):
                    continue
                if since_ts and ev["ts"] < since_ts:
                    continue
                yield ev
                limit -= 1
                if limit == 0:
                    break

    def rotate_if_needed(self, now: datetime | None = None) -> None:
        """If audit.jsonl contains events from a previous month, archive them."""
        now = now or datetime.now(timezone.utc)
        cur_ym = now.strftime("%Y-%m")
        # peek at the first event's month
        with _open_audit(self.paths.audit_jsonl) as stream:
            if stream is None:
                return
            first = next(_audit_lines(stream), b"").strip()
        if not first:
            return
        first_ev = json.loads(first.decode("utf-8"))
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
