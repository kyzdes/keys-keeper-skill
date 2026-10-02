"""Real isolated Windows DACL checks, collected by the existing OS CI matrix."""
from __future__ import annotations

import ctypes
import os
from ctypes import wintypes as w

import pytest

from keys_keeper import private_files, windows_file_security as security
from keys_keeper.paths import ensure_private_dir
from keys_keeper.secure_io import read_secure_text, replace_secure_text

pytestmark = pytest.mark.windows


def _set_dacl(path, sddl):
    api, kernel = security._bindings()
    descriptor, dacl = ctypes.c_void_p(), ctypes.c_void_p()
    assert api.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None)
    try:
        present, defaulted = w.BOOL(), w.BOOL()
        assert api.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted))
        assert api.SetNamedSecurityInfoW(str(path), 1, 0x80000004, None, None, dacl, None) == 0
    finally:
        kernel.LocalFree(descriptor)


def _security_snapshot(path):
    api, kernel = security._bindings()
    handle = security._open_handle(path, directory=path.is_dir())
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    convert = api.ConvertSecurityDescriptorToStringSecurityDescriptorW
    convert.argtypes = [ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.POINTER(w.LPWSTR), ctypes.c_void_p]
    convert.restype = w.BOOL
    text = w.LPWSTR()
    try:
        assert api.GetSecurityInfo(handle, 1, 0x5, ctypes.byref(owner), None,
                                    ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0
        assert convert(descriptor, 1, 0x5, ctypes.byref(text), None)
        return security._sid_string(owner), text.value
    finally:
        if text:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
        kernel.LocalFree(descriptor)
        kernel.CloseHandle(handle)


def _dacl_snapshot(path):
    return _security_snapshot(path)[1]


@pytest.fixture
def broad_parent(tmp_path):
    directory = tmp_path / "широкий-каталог"
    directory.mkdir()
    user = security.current_user_sid()
    _set_dacl(directory, f"D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GR;;;WD)")
    return directory


def test_windows_private_creation_is_protected_before_payload_in_broad_parent(broad_parent, monkeypatch):
    monkeypatch.setenv("USERNAME", "не-доверять-имени")
    monkeypatch.setenv("USER", "different-user")
    before = _dacl_snapshot(broad_parent)
    fd, path = private_files.create_private_temp(broad_parent, prefix="ключ-", suffix=".key")
    try:
        assert path.stat().st_size == 0
        # This verifies the current process-token owner, protected control flag,
        # and every effective grant while the file is still empty.
        security.validate_fd(fd, require_protected=True)
        assert "D:P" in _dacl_snapshot(path)
        # SDDL may serialize the same SID as a well-known alias (e.g. LA).
        assert _security_snapshot(path)[0] == security.current_user_sid()
        os.write(fd, b"SYNTHETIC-SECRET-CANARY")
    finally:
        os.close(fd)
    assert private_files.secure_read(path, max_bytes=128) == b"SYNTHETIC-SECRET-CANARY"
    assert _dacl_snapshot(broad_parent) == before


def test_windows_existing_unsafe_file_and_directory_are_rejected_without_acl_repair(broad_parent):
    path = broad_parent / "unsafe-state"
    path.write_bytes(b"synthetic")
    directory_acl, file_acl = _dacl_snapshot(broad_parent), _dacl_snapshot(path)
    with pytest.raises(OSError, match="another Windows principal"):
        ensure_private_dir(broad_parent)
    with pytest.raises(private_files.PrivateFileError):
        private_files.secure_read(path, max_bytes=128)
    # Public ciphertext import may intentionally waive read privacy, still
    # checking the process-token owner and regular opened object.
    assert private_files.secure_read(path, max_bytes=128, require_private=False) == b"synthetic"
    assert _dacl_snapshot(broad_parent) == directory_acl
    assert _dacl_snapshot(path) == file_acl


def test_windows_plaintext_sink_replacement_gets_private_protected_dacl(broad_parent):
    path = broad_parent / "секрет.env"
    path.write_text("KEY=template\n", encoding="utf-8")
    before = _dacl_snapshot(broad_parent)
    state = read_secure_text(path, missing_ok=False)
    replace_secure_text(state, "KEY=synthetic\n")
    security.validate_path(path, require_protected=True)
    assert private_files.secure_read(path, max_bytes=128) == b"KEY=synthetic\n"
    assert _dacl_snapshot(broad_parent) == before


def test_windows_new_nested_state_and_unlock_file_share_private_policy(broad_parent):
    root = broad_parent / "private-state" / "profiles" / "synthetic-profile"
    ensure_private_dir(root)
    security.validate_path(root, directory=True, require_protected=True)
    security.validate_path(root.parent, directory=True, require_protected=True)
    password = root / "service-keys" / "file-backend-password"
    private_files.atomic_write_bytes(password, b"synthetic-unlock-source")
    security.validate_path(password, require_protected=True)
    assert private_files.secure_read(password, max_bytes=128) == b"synthetic-unlock-source"


def test_windows_existing_safe_inherited_directory_is_not_rewritten(tmp_path, monkeypatch):
    directory = tmp_path / "protected-parent"
    ensure_private_dir(directory)
    inherited = directory / "inherited-child"
    inherited.mkdir()
    before = _dacl_snapshot(inherited)
    assert _security_snapshot(inherited)[0] == security.current_token_owner_sid()
    assert "D:P" not in before
    ensure_private_dir(inherited)
    assert _dacl_snapshot(inherited) == before
    # Read the same real descriptor under a simulated foreign policy context.
    # An untrusted token default never makes someone else's object acceptable.
    with monkeypatch.context() as foreign:
        foreign.setattr(security, "current_user_sid", lambda: "S-1-5-21-0-0-0-1234")
        foreign.setattr(security, "current_token_owner_sid", lambda: "S-1-5-32-545")
        with pytest.raises(OSError, match="unexpected owner"):
            ensure_private_dir(inherited)
    assert _dacl_snapshot(inherited) == before


def test_windows_append_streams_are_protected_and_refuse_existing_broad_acl(broad_parent):
    path = broad_parent / "private-audit.jsonl"
    fd = private_files.open_private_file(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND)
    try:
        security.validate_fd(fd, require_protected=True)
        os.write(fd, b"synthetic-audit\n")
    finally:
        os.close(fd)
    assert private_files.secure_read(path, max_bytes=128) == b"synthetic-audit\n"
    unsafe = broad_parent / "unsafe-audit.jsonl"
    unsafe.write_bytes(b"preserve-existing")
    with pytest.raises(OSError, match="another Windows principal"):
        private_files.open_private_file(unsafe, os.O_WRONLY | os.O_TRUNC)
    assert unsafe.read_bytes() == b"preserve-existing"
