"""Native Windows private-file policy, without username or chmod assumptions.

New objects receive a protected DACL at creation, before any payload is written.
The process-token user, SYSTEM and Administrators are the permitted principals;
this is not isolation from a local administrator. Existing ACLs are inspected,
never silently repaired. All reads validate the opened handle, not just a path.
"""
from __future__ import annotations

import ctypes
import os
from contextlib import contextmanager
from ctypes import wintypes as w
from pathlib import Path


class WindowsFileSecurityError(OSError):
    """An object cannot satisfy the native private-file policy."""


_pointer = ctypes.c_void_p
_libraries = None
_PRIVILEGED_SIDS = {"S-1-5-18", "S-1-5-32-544"}


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", _pointer), ("inherit", w.BOOL)]


def _bindings():
    global _libraries
    if os.name != "nt":
        raise RuntimeError("Windows file security requires Windows")
    if _libraries is None:
        api = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        def bind(library, name, arguments, result):
            function = getattr(library, name)
            function.argtypes, function.restype = arguments, result
        bind(kernel, "GetCurrentProcess", [], w.HANDLE)
        bind(kernel, "CloseHandle", [w.HANDLE], w.BOOL)
        bind(kernel, "LocalFree", [_pointer], _pointer)
        bind(kernel, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, _pointer,
                                     w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
        bind(kernel, "CreateDirectoryW", [w.LPCWSTR, _pointer], w.BOOL)
        bind(kernel, "GetFileType", [w.HANDLE], w.DWORD)
        bind(kernel, "GetFileInformationByHandleEx", [w.HANDLE, ctypes.c_int,
                                                      _pointer, w.DWORD], w.BOOL)
        bind(api, "OpenProcessToken", [w.HANDLE, w.DWORD, ctypes.POINTER(w.HANDLE)], w.BOOL)
        bind(api, "GetTokenInformation", [w.HANDLE, ctypes.c_int, _pointer,
                                           w.DWORD, ctypes.POINTER(w.DWORD)], w.BOOL)
        bind(api, "ConvertSidToStringSidW", [_pointer, ctypes.POINTER(w.LPWSTR)], w.BOOL)
        bind(api, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
             [w.LPCWSTR, w.DWORD, ctypes.POINTER(_pointer), _pointer], w.BOOL)
        bind(api, "GetSecurityInfo", [w.HANDLE, ctypes.c_int, w.DWORD,
                                      ctypes.POINTER(_pointer), _pointer,
                                      ctypes.POINTER(_pointer), _pointer,
                                      ctypes.POINTER(_pointer)], w.DWORD)
        bind(api, "GetSecurityDescriptorControl",
             [_pointer, ctypes.POINTER(w.WORD), ctypes.POINTER(w.DWORD)], w.BOOL)
        bind(api, "GetSecurityDescriptorDacl",
             [_pointer, ctypes.POINTER(w.BOOL), ctypes.POINTER(_pointer),
              ctypes.POINTER(w.BOOL)], w.BOOL)
        bind(api, "GetAce", [_pointer, w.DWORD, ctypes.POINTER(_pointer)], w.BOOL)
        bind(api, "SetNamedSecurityInfoW", [w.LPWSTR, ctypes.c_int, w.DWORD,
                                           _pointer, _pointer, _pointer, _pointer], w.DWORD)
        # Publish only fully bound libraries; concurrent first calls must
        # never observe ctypes functions with their default pointer signatures.
        _libraries = (api, kernel)
    return _libraries


def _checked(value, message="cannot verify private Windows file permissions"):
    if not value:
        raise WindowsFileSecurityError(message)


def _sid_string(sid) -> str:
    api, kernel = _bindings()
    value = w.LPWSTR()
    _checked(api.ConvertSidToStringSidW(sid, ctypes.byref(value)))
    try:
        return value.value
    finally:
        kernel.LocalFree(ctypes.cast(value, _pointer))


def _current_token_sid(information_class: int) -> str:
    api, kernel = _bindings()
    token = w.HANDLE()
    _checked(api.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)))
    try:
        required = w.DWORD()
        api.GetTokenInformation(token, information_class, None, 0, ctypes.byref(required))
        _checked(0 < required.value <= 65536)
        data = ctypes.create_string_buffer(required.value)
        _checked(api.GetTokenInformation(token, information_class, data, len(data), ctypes.byref(required)))
        return _sid_string(_pointer.from_buffer(data).value)
    finally:
        kernel.CloseHandle(token)


def current_user_sid() -> str:
    """Resolve TokenUser, so localized/non-ASCII/environment names are irrelevant."""
    return _current_token_sid(1)


def current_token_owner_sid() -> str:
    """TokenOwner may be Administrators for ordinary elevated-process objects."""
    return _current_token_sid(4)


def _owner_is_current_token(owner: str, user: str, *, allow_default_owner: bool) -> bool:
    if owner == user:
        return True
    return (allow_default_owner and owner in _PRIVILEGED_SIDS
            and owner == current_token_owner_sid())


def _allow_sid_is_private(sid: str, user: str, *, owner_trusted: bool) -> bool:
    # OWNER RIGHTS resolves to this object's owner, which must be verified
    # before scanning any ACE. It never authorizes another owner or principal.
    return owner_trusted and (sid in {user, *_PRIVILEGED_SIDS} or sid == "S-1-3-4")


@contextmanager
def _attributes(*, directory: bool = False):
    api, kernel = _bindings()
    descriptor = _pointer()
    user = current_user_sid()
    inherit = "OICI" if directory else ""
    sddl = (f"O:{user}D:P(A;{inherit};FA;;;{user})"
            f"(A;{inherit};FA;;;SY)(A;{inherit};FA;;;BA)")
    _checked(api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None))
    try:
        yield _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
    finally:
        kernel.LocalFree(descriptor)


def _check_handle_type(handle, *, directory: bool):
    _, kernel = _bindings()
    attributes = (w.DWORD * 2)()  # FILE_ATTRIBUTE_TAG_INFO
    _checked(kernel.GetFileType(handle) == 1, "Windows private file must be a disk file")
    _checked(kernel.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)))
    if attributes[0] & 0x400 or bool(attributes[0] & 0x10) != directory:
        raise WindowsFileSecurityError("Windows private path must not be a reparse point or special file")


def validate_handle(handle, *, directory: bool = False, require_private: bool = True,
                    require_protected: bool = False, require_current_owner: bool = True,
                    allow_default_owner: bool = True):
    """Validate owner and effective allow ACEs on an already opened object.

    Safe inherited ACLs remain compatible with existing private directories.
    Existing ownership may match the current token's trusted default owner;
    newly created objects require TokenUser ownership and protected DACLs.
    """
    api, kernel = _bindings()
    _check_handle_type(handle, directory=directory)
    owner, dacl, descriptor = _pointer(), _pointer(), _pointer()
    _checked(api.GetSecurityInfo(handle, 1, 0x00000005, ctypes.byref(owner), None,
                                ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0)
    try:
        user = current_user_sid()
        allowed = {user, *_PRIVILEGED_SIDS}
        actual_owner = _sid_string(owner)
        owned = (_owner_is_current_token(actual_owner, user, allow_default_owner=allow_default_owner)
                 if require_current_owner else actual_owner in allowed)
        if not owned:
            raise WindowsFileSecurityError("Windows private file has an unexpected owner")
        if not require_private:
            return
        control, revision = w.WORD(), w.DWORD()
        _checked(api.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)))
        if not dacl.value or (require_protected and not control.value & 0x1000):
            raise WindowsFileSecurityError("Windows private file requires a protected private DACL")
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = _pointer()
            _checked(api.GetAce(dacl, index, ctypes.byref(ace)))
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            # INHERIT_ONLY ACEs do not grant access to this object. Deny ACEs
            # cannot expand access. Unrecognized effective grants fail closed.
            if flags & 0x08 or kind in (1, 6, 10, 12):
                continue
            if kind != 0 or not _allow_sid_is_private(
                    _sid_string(ace.value + 8), user, owner_trusted=owned):
                raise WindowsFileSecurityError("Windows private file grants access to another Windows principal")
    finally:
        kernel.LocalFree(descriptor)


def validate_fd(fd: int, *, require_private: bool = True, require_protected: bool = False):
    import msvcrt
    validate_handle(msvcrt.get_osfhandle(fd), require_private=require_private,
                    require_protected=require_protected)


def _open_handle(path: Path, *, directory=False, create=False, attributes=None):
    _, kernel = _bindings()
    access = 0x00020080 | (0xC0000000 if create else (0 if directory else 0x80000000))
    flags = 0x00200000 | (0x02000000 if directory else 0x80)
    handle = kernel.CreateFileW(str(path), access, 0x7,
                                ctypes.byref(attributes) if attributes else None,
                                1 if create else 3, flags, None)
    if handle == _pointer(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    return handle


def open_read(path: Path) -> int:
    """Open the final component itself, including reparse-point rejection."""
    import msvcrt
    _, kernel = _bindings()
    handle = _open_handle(path)
    try:
        _check_handle_type(handle, directory=False)
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    return fd  # CRT descriptor now owns the handle.


def open_private_file(path: Path, flags: int) -> int:
    """Open/create a private stream; validate before append or truncation."""
    import msvcrt
    _, kernel = _bindings()
    write = flags & (os.O_WRONLY | os.O_RDWR)
    access = 0x00020080 | (0x40000000 if write else 0)
    if not flags & os.O_WRONLY:
        access |= 0x80000000
    create = bool(flags & os.O_CREAT)
    disposition = 1 if flags & os.O_EXCL else (4 if create else 3)
    with _attributes() as attributes:
        handle = kernel.CreateFileW(str(path), access, 0x7,
                                     ctypes.byref(attributes) if create else None,
                                     disposition, 0x00200080, None)
        error = ctypes.get_last_error()
    if handle == _pointer(-1).value:
        raise ctypes.WinError(error)
    created = create and (disposition == 1 or error != 183)  # ERROR_ALREADY_EXISTS
    try:
        validate_handle(handle, require_protected=created, allow_default_owner=not created)
        fd = msvcrt.open_osfhandle(handle, (flags & (os.O_APPEND | os.O_RDONLY | os.O_WRONLY | os.O_RDWR))
                                   | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    if flags & os.O_TRUNC:
        try:
            os.ftruncate(fd, 0)
        except BaseException:
            os.close(fd)
            raise
    return fd


def create_private_file(path: Path) -> int:
    return open_private_file(path, os.O_RDWR | os.O_CREAT | os.O_EXCL)


def create_private_directory(path: Path) -> None:
    _, kernel = _bindings()
    with _attributes(directory=True) as attributes:
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    validate_path(path, directory=True, require_protected=True, allow_default_owner=False)


def validate_path(path: Path, *, directory=False, require_protected=False,
                  require_current_owner=True, require_private=True, allow_default_owner=True) -> None:
    _, kernel = _bindings()
    handle = _open_handle(path, directory=directory)
    try:
        validate_handle(handle, directory=directory, require_protected=require_protected,
                        require_current_owner=require_current_owner, require_private=require_private,
                        allow_default_owner=allow_default_owner)
    finally:
        kernel.CloseHandle(handle)


def restrict_new_object(path: Path) -> None:
    """Compatibility for relay-created empty objects inside a private directory.

    Never call this to repair an existing user-selected object. General secret
    files use create_private_file, which sets the descriptor before creation.
    """
    api, _ = _bindings()
    with _attributes(directory=path.is_dir()) as attributes:
        present, defaulted, dacl = w.BOOL(), w.BOOL(), _pointer()
        _checked(api.GetSecurityDescriptorDacl(attributes.descriptor, ctypes.byref(present),
                                              ctypes.byref(dacl), ctypes.byref(defaulted)))
        _checked(api.SetNamedSecurityInfoW(str(path), 1, 0x80000004,
                                          None, None, dacl, None) == 0)
