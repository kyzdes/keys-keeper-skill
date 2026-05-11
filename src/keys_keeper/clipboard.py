"""Cross-platform clipboard primitives.

Clipboard is a controlled sink — not a transcript-visible surface — so it
fits keys-keeper's "values go to a target, not to stdout" pattern.

- macOS uses `pbcopy` / `pbpaste` via subprocess (matches the rest of the
  codebase's shell-out-to-native style).
- Windows uses ctypes against user32.dll + kernel32.dll directly. We
  deliberately avoid `clip.exe` (UTF-8 vs OEM codepage issues) and
  PowerShell `Get-Clipboard -Raw` (adds trailing CRLF via stdout writer).
"""
from __future__ import annotations
import subprocess
import sys
import time

__all__ = ["read", "write", "clear", "spawn_clear_after"]


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    _user32 = ctypes.WinDLL("user32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _OpenClipboard = _user32.OpenClipboard
    _OpenClipboard.argtypes = [wintypes.HWND]
    _OpenClipboard.restype = wintypes.BOOL

    _CloseClipboard = _user32.CloseClipboard
    _CloseClipboard.argtypes = []
    _CloseClipboard.restype = wintypes.BOOL

    _EmptyClipboard = _user32.EmptyClipboard
    _EmptyClipboard.argtypes = []
    _EmptyClipboard.restype = wintypes.BOOL

    _GetClipboardData = _user32.GetClipboardData
    _GetClipboardData.argtypes = [wintypes.UINT]
    _GetClipboardData.restype = wintypes.HANDLE

    _SetClipboardData = _user32.SetClipboardData
    _SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _SetClipboardData.restype = wintypes.HANDLE

    _IsClipboardFormatAvailable = _user32.IsClipboardFormatAvailable
    _IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    _IsClipboardFormatAvailable.restype = wintypes.BOOL

    _GlobalAlloc = _kernel32.GlobalAlloc
    _GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _GlobalAlloc.restype = wintypes.HGLOBAL

    _GlobalLock = _kernel32.GlobalLock
    _GlobalLock.argtypes = [wintypes.HGLOBAL]
    _GlobalLock.restype = ctypes.c_void_p

    _GlobalUnlock = _kernel32.GlobalUnlock
    _GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    _GlobalUnlock.restype = wintypes.BOOL

    _GlobalFree = _kernel32.GlobalFree
    _GlobalFree.argtypes = [wintypes.HGLOBAL]
    _GlobalFree.restype = wintypes.HGLOBAL

    _CF_UNICODETEXT = 13
    _GMEM_MOVEABLE = 0x0002

    def _open_with_retry(attempts: int = 10, delay: float = 0.05) -> bool:
        for _ in range(attempts):
            if _OpenClipboard(0):
                return True
            time.sleep(delay)
        return False

    def read() -> str:
        if not _open_with_retry():
            return ""
        try:
            if not _IsClipboardFormatAvailable(_CF_UNICODETEXT):
                return ""
            h = _GetClipboardData(_CF_UNICODETEXT)
            if not h:
                return ""
            ptr = _GlobalLock(h)
            if not ptr:
                return ""
            try:
                return ctypes.wstring_at(ptr)
            finally:
                _GlobalUnlock(h)
        finally:
            _CloseClipboard()

    def write(value: str) -> bool:
        if not _open_with_retry():
            return False
        try:
            _EmptyClipboard()
            # +1 for the trailing UTF-16 NUL. Each wchar on Windows = 2 bytes.
            buf = (value + "\x00").encode("utf-16-le")
            h = _GlobalAlloc(_GMEM_MOVEABLE, len(buf))
            if not h:
                return False
            ptr = _GlobalLock(h)
            if not ptr:
                _GlobalFree(h)
                return False
            try:
                ctypes.memmove(ptr, buf, len(buf))
            finally:
                _GlobalUnlock(h)
            if not _SetClipboardData(_CF_UNICODETEXT, h):
                _GlobalFree(h)
                return False
            # Ownership of `h` is now the OS clipboard — do NOT free.
            return True
        finally:
            _CloseClipboard()

    def clear() -> None:
        if not _open_with_retry():
            return
        try:
            _EmptyClipboard()
        finally:
            _CloseClipboard()

elif sys.platform == "darwin":

    def read() -> str:
        result = subprocess.run(["pbpaste"], capture_output=True, text=True)
        return result.stdout

    def write(value: str) -> bool:
        proc = subprocess.run(["pbcopy"], input=value, text=True)
        return proc.returncode == 0

    def clear() -> None:
        subprocess.run(["pbcopy"], input="", text=True)

else:
    def read() -> str:
        raise NotImplementedError(f"clipboard.read not supported on {sys.platform}")

    def write(value: str) -> bool:
        raise NotImplementedError(f"clipboard.write not supported on {sys.platform}")

    def clear() -> None:
        raise NotImplementedError(f"clipboard.clear not supported on {sys.platform}")


def spawn_clear_after(value_hash: str, delay_sec: int) -> None:
    """Spawn a detached process that clears the clipboard after `delay_sec`
    if its SHA-256 still matches `value_hash` (i.e. the user hasn't copied
    something else in the meantime).

    Detached so the CLI exits immediately after `keys copy`. The hash is
    safe to pass via argv — it's a hash, not plaintext.
    """
    args = [sys.executable, "-m", "keys_keeper._clipboard_clear_daemon",
            value_hash, str(delay_sec)]
    kwargs: dict = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if sys.platform == "win32":
        kwargs["creationflags"] = (
            subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP
            | 0x08000000  # CREATE_NO_WINDOW
        )
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen(args, **kwargs)
