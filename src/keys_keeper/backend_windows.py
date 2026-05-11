"""Windows Credential Manager backend.

Stores secrets via ctypes calls to advapi32.dll's Cred* APIs — no extra
runtime dependencies. Same KeychainBackend contract as the macOS backend:
get/set/delete/list_ids over a flat account-id namespace.

Storage layout
==============

Logical entries are kept under TargetName ``keys-keeper:{account}``. The
blob is one byte of format tag followed by payload:

  0x01 raw            payload = UTF-8 bytes of the secret
  0x02 chunked-header payload = UTF-8 JSON header: {"chunks": N, "version": 1}
                      The actual data lives in N separate credentials under
                      TargetName ``keys-keeper-chunk:{account}#{i}`` for
                      i in 0..N-1, each carrying a 0x01-raw blob.

The split happens at 2000 UTF-8 bytes — well below Windows' documented
CredentialBlob limit of 2560 bytes, with comfortable headroom for the
format-tag prefix and any multi-byte boundary slack.

`list_ids()` enumerates the ``keys-keeper:*`` filter only, so chunk
target-names never leak into the logical id list. The chunk prefix is a
different literal (``keys-keeper-chunk:``) — by construction, the
wildcard ``keys-keeper:*`` can't match it because byte 11 is ``-``, not
``:``.

Atomicity
=========

`set()` order:
  1. Delete any stragglers under ``keys-keeper-chunk:{account}#*``
     (cleanup from a previous larger value).
  2. Write all new chunks.
  3. Write the main credential LAST — it acts as the commit marker.

`get()` requires the main credential. If main is missing, the account
doesn't exist (independent of whether stray chunks are present), so a
crash mid-write at step 2 looks like "not yet written" to readers.
"""
from __future__ import annotations
import ctypes
import json
from ctypes import wintypes

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed


# ---------- Win32 constants ----------

_CRED_TYPE_GENERIC = 1
_CRED_PERSIST_LOCAL_MACHINE = 2
_ERROR_NOT_FOUND = 1168
_ERROR_BAD_LENGTH = 24

_CHUNK_THRESHOLD = 2000  # UTF-8 bytes
_FMT_RAW = 0x01
_FMT_CHUNKED = 0x02

_PREFIX_MAIN = "keys-keeper:"
_PREFIX_CHUNK = "keys-keeper-chunk:"


# ---------- ctypes structs ----------

class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
    _fields_ = [
        ("Keyword", wintypes.LPWSTR),
        ("Flags", wintypes.DWORD),
        ("ValueSize", wintypes.DWORD),
        ("Value", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class _CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", _FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.POINTER(_CREDENTIAL_ATTRIBUTEW)),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]


# ---------- bindings ----------

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

_CredWriteW = _advapi32.CredWriteW
_CredWriteW.argtypes = [ctypes.POINTER(_CREDENTIALW), wintypes.DWORD]
_CredWriteW.restype = wintypes.BOOL

_CredReadW = _advapi32.CredReadW
_CredReadW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))]
_CredReadW.restype = wintypes.BOOL

_CredDeleteW = _advapi32.CredDeleteW
_CredDeleteW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
_CredDeleteW.restype = wintypes.BOOL

_CredEnumerateW = _advapi32.CredEnumerateW
_CredEnumerateW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD,
                            ctypes.POINTER(wintypes.DWORD),
                            ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(_CREDENTIALW)))]
_CredEnumerateW.restype = wintypes.BOOL

_CredFree = _advapi32.CredFree
_CredFree.argtypes = [ctypes.c_void_p]
_CredFree.restype = None


# ---------- low-level helpers ----------

def _write_blob(target_name: str, blob: bytes) -> None:
    """Write a raw blob to CredMan under the given TargetName. Raises on failure."""
    buf_type = ctypes.c_ubyte * len(blob)
    buf = buf_type(*blob)
    cred = _CREDENTIALW()
    cred.Flags = 0
    cred.Type = _CRED_TYPE_GENERIC
    cred.TargetName = target_name
    cred.Comment = None
    cred.CredentialBlobSize = len(blob)
    cred.CredentialBlob = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
    cred.Persist = _CRED_PERSIST_LOCAL_MACHINE
    cred.AttributeCount = 0
    cred.Attributes = None
    cred.TargetAlias = None
    cred.UserName = None
    if not _CredWriteW(ctypes.byref(cred), 0):
        err = ctypes.get_last_error()
        if err == _ERROR_BAD_LENGTH:
            raise KeychainError(
                f"CredWriteW: blob too large for {target_name!r} "
                f"({len(blob)} bytes; CredMan limit ~2560)"
            )
        raise KeychainError(f"CredWriteW failed for {target_name!r}: WinError {err}")


def _read_blob(target_name: str) -> bytes:
    """Read raw blob from CredMan. Raises KeychainError on missing/failed."""
    cred_ptr = ctypes.POINTER(_CREDENTIALW)()
    if not _CredReadW(target_name, _CRED_TYPE_GENERIC, 0, ctypes.byref(cred_ptr)):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            raise KeychainError(f"keychain entry not found: {target_name}")
        raise KeychainError(f"CredReadW failed for {target_name!r}: WinError {err}")
    try:
        size = cred_ptr.contents.CredentialBlobSize
        if size == 0:
            return b""
        blob_ptr = ctypes.cast(cred_ptr.contents.CredentialBlob,
                               ctypes.POINTER(ctypes.c_ubyte * size))
        return bytes(blob_ptr.contents)
    finally:
        _CredFree(cred_ptr)


def _delete_target(target_name: str) -> None:
    """Delete a single target. Missing target is not an error."""
    if not _CredDeleteW(target_name, _CRED_TYPE_GENERIC, 0):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return
        raise KeychainError(f"CredDeleteW failed for {target_name!r}: WinError {err}")


def _enumerate_targets(filter_: str) -> list[str]:
    """Enumerate TargetNames matching the wildcard filter (e.g. 'foo:*')."""
    count = wintypes.DWORD()
    arr_ptr = ctypes.POINTER(ctypes.POINTER(_CREDENTIALW))()
    if not _CredEnumerateW(filter_, 0, ctypes.byref(count), ctypes.byref(arr_ptr)):
        err = ctypes.get_last_error()
        if err == _ERROR_NOT_FOUND:
            return []
        raise KeychainError(f"CredEnumerateW failed for {filter_!r}: WinError {err}")
    try:
        names: list[str] = []
        for i in range(count.value):
            names.append(arr_ptr[i].contents.TargetName)
        return names
    finally:
        _CredFree(arr_ptr)


# ---------- backend ----------

class WindowsCredentialBackend(KeychainBackend):
    """Windows Credential Manager backend with transparent chunking."""

    def __init__(self, *, service: str = "keys-keeper"):
        # `service` parameter is reserved for parity with MacOSKeychainBackend.
        # On Windows the prefix is hardcoded (`keys-keeper:` / `keys-keeper-chunk:`)
        # since CredMan has a global namespace per-user. Tests isolate via a
        # unique service value that we splice into the prefix.
        self.service = service
        self._prefix_main = f"{service}:" if service != "keys-keeper" else _PREFIX_MAIN
        self._prefix_chunk = (
            f"{service}-chunk:" if service != "keys-keeper" else _PREFIX_CHUNK
        )

    # ---- KeychainBackend interface ----

    def get(self, account: str) -> Sealed:
        target = self._prefix_main + account
        blob = _read_blob(target)
        if not blob:
            return Sealed("")
        fmt = blob[0]
        payload = blob[1:]
        if fmt == _FMT_RAW:
            try:
                return Sealed(payload.decode("utf-8"))
            except UnicodeDecodeError as e:
                raise KeychainError(f"failed to decode {target}: {e}")
        if fmt == _FMT_CHUNKED:
            try:
                header = json.loads(payload.decode("utf-8"))
                n = int(header["chunks"])
            except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError) as e:
                raise KeychainError(f"corrupt chunked header for {target}: {e}")
            parts: list[bytes] = []
            for i in range(n):
                chunk_target = f"{self._prefix_chunk}{account}#{i}"
                chunk_blob = _read_blob(chunk_target)
                if not chunk_blob or chunk_blob[0] != _FMT_RAW:
                    raise KeychainError(
                        f"chunk {i} missing or malformed for {target}"
                    )
                parts.append(chunk_blob[1:])
            try:
                return Sealed(b"".join(parts).decode("utf-8"))
            except UnicodeDecodeError as e:
                raise KeychainError(f"failed to decode chunks for {target}: {e}")
        raise KeychainError(f"unknown format byte {fmt:#x} for {target}")

    def set(self, account: str, value: str) -> None:
        main_target = self._prefix_main + account
        encoded = value.encode("utf-8")

        # Step 1: clean up any stragglers from a previous larger value.
        for stale in _enumerate_targets(f"{self._prefix_chunk}{account}#*"):
            _delete_target(stale)

        # Step 2 + 3: write chunks (if any), then the main commit marker.
        if len(encoded) <= _CHUNK_THRESHOLD:
            _write_blob(main_target, bytes([_FMT_RAW]) + encoded)
            return

        n = (len(encoded) + _CHUNK_THRESHOLD - 1) // _CHUNK_THRESHOLD
        for i in range(n):
            chunk = encoded[i * _CHUNK_THRESHOLD : (i + 1) * _CHUNK_THRESHOLD]
            _write_blob(f"{self._prefix_chunk}{account}#{i}",
                        bytes([_FMT_RAW]) + chunk)
        header = json.dumps({"chunks": n, "version": 1}).encode("utf-8")
        _write_blob(main_target, bytes([_FMT_CHUNKED]) + header)

    def delete(self, account: str) -> None:
        # Delete main first so readers see "not found" immediately even if
        # chunk cleanup is interrupted.
        _delete_target(self._prefix_main + account)
        for chunk_target in _enumerate_targets(f"{self._prefix_chunk}{account}#*"):
            _delete_target(chunk_target)

    def list_ids(self) -> list[str]:
        names = _enumerate_targets(f"{self._prefix_main}*")
        prefix_len = len(self._prefix_main)
        return [n[prefix_len:] for n in names]
