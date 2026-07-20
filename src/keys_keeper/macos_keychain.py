"""Native macOS Keychain writer that keeps secret values out of argv.

The system ``security`` tool has no non-interactive stdin option for
``add-generic-password``.  This small ctypes binding passes secret bytes
directly to Keychain Services, including for multiline values and custom
keychain files.  Newly created items explicitly trust the fixed system
``/usr/bin/security`` tool so existing read/delete behavior remains compatible
across Python and Keys Keeper upgrades without a new Keychain approval prompt.
"""
from __future__ import annotations

import ctypes
import sys
from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator


_ERR_SEC_SUCCESS = 0
_MAX_LABEL_BYTES = 4096
_MAX_SECRET_BYTES = 4 * 1024 * 1024
_CF_STRING_ENCODING_UTF8 = 0x08000100
_GENERIC_PASSWORD_ITEM_CLASS = 0x67656E70  # 'genp'
_ACCOUNT_ITEM_ATTR = 0x61636374  # 'acct'
_SERVICE_ITEM_ATTR = 0x73766365  # 'svce'


class _KeychainAttribute(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class _KeychainAttributeList(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("attr", ctypes.POINTER(_KeychainAttribute)),
    ]


class SecurityFrameworkError(RuntimeError):
    """A native Keychain Services operation failed without exposing data."""

    def __init__(self, operation: str, status: int | None = None):
        self.operation = operation
        self.status = status
        suffix = "" if status is None else f" (OSStatus {status})"
        super().__init__(f"{operation} failed{suffix}")


class _Bindings:
    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise SecurityFrameworkError("load macOS Security framework")
        try:
            self.security = ctypes.CDLL(
                "/System/Library/Frameworks/Security.framework/Security"
            )
            self.core_foundation = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
        except OSError as ex:
            raise SecurityFrameworkError("load macOS Security framework") from ex

        void_p = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        status = ctypes.c_int32

        self.security.SecKeychainOpen.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainOpen.restype = status

        self.security.SecKeychainGetUserInteractionAllowed.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        self.security.SecKeychainGetUserInteractionAllowed.restype = status

        self.security.SecKeychainSetUserInteractionAllowed.argtypes = [
            ctypes.c_ubyte,
        ]
        self.security.SecKeychainSetUserInteractionAllowed.restype = status

        self.security.SecKeychainItemCreateFromContent.argtypes = [
            uint32,
            ctypes.POINTER(_KeychainAttributeList),
            uint32,
            void_p,
            void_p,
            void_p,
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainItemCreateFromContent.restype = status

        self.security.SecTrustedApplicationCreateFromPath.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(void_p),
        ]
        self.security.SecTrustedApplicationCreateFromPath.restype = status

        self.security.SecAccessCreate.argtypes = [
            void_p,
            void_p,
            ctypes.POINTER(void_p),
        ]
        self.security.SecAccessCreate.restype = status

        self.core_foundation.CFStringCreateWithCString.argtypes = [
            void_p,
            ctypes.c_char_p,
            uint32,
        ]
        self.core_foundation.CFStringCreateWithCString.restype = void_p

        self.core_foundation.CFArrayCreate.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
            ctypes.c_long,
            void_p,
        ]
        self.core_foundation.CFArrayCreate.restype = void_p

        self.core_foundation.CFRelease.argtypes = [void_p]
        self.core_foundation.CFRelease.restype = None


@lru_cache(maxsize=1)
def _bindings() -> _Bindings:
    return _Bindings()


def _encode_label(value: str, label: str) -> bytes:
    if not isinstance(value, str) or "\x00" in value:
        raise SecurityFrameworkError(f"validate {label}")
    encoded = value.encode("utf-8")
    if not encoded or len(encoded) > _MAX_LABEL_BYTES:
        raise SecurityFrameworkError(f"validate {label}")
    return encoded


class MacOSNativeKeychain:
    """Create generic-password items through an in-process byte buffer."""

    def __init__(
        self,
        *,
        service: str,
        keychain_path: str | None = None,
        allow_interaction: bool = True,
    ):
        self.service = _encode_label(service, "keychain service")
        self.keychain_path = keychain_path
        self.allow_interaction = allow_interaction
        self.api = _bindings()

    @contextmanager
    def _interaction_policy(self) -> Iterator[None]:
        if self.allow_interaction:
            yield
            return
        previous = ctypes.c_ubyte()
        status = self.api.security.SecKeychainGetUserInteractionAllowed(
            ctypes.byref(previous)
        )
        if status != _ERR_SEC_SUCCESS:
            raise SecurityFrameworkError("read keychain interaction policy", status)
        status = self.api.security.SecKeychainSetUserInteractionAllowed(0)
        if status != _ERR_SEC_SUCCESS:
            raise SecurityFrameworkError("disable keychain interaction", status)
        try:
            yield
        finally:
            self.api.security.SecKeychainSetUserInteractionAllowed(previous.value)

    @contextmanager
    def _keychain_ref(self) -> Iterator[ctypes.c_void_p | None]:
        if self.keychain_path is None:
            yield None
            return
        path = _encode_label(self.keychain_path, "keychain path")
        keychain = ctypes.c_void_p()
        status = self.api.security.SecKeychainOpen(path, ctypes.byref(keychain))
        if status != _ERR_SEC_SUCCESS:
            raise SecurityFrameworkError("open keychain", status)
        try:
            yield keychain
        finally:
            self.api.core_foundation.CFRelease(keychain)

    @contextmanager
    def _compatible_access(self) -> Iterator[ctypes.c_void_p]:
        """Build an ACL that trusts this process and `/usr/bin/security`."""
        self_app = ctypes.c_void_p()
        security_app = ctypes.c_void_p()
        trusted_apps = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        access = ctypes.c_void_p()
        try:
            for path, target in (
                (None, self_app),
                (b"/usr/bin/security", security_app),
            ):
                status = self.api.security.SecTrustedApplicationCreateFromPath(
                    path,
                    ctypes.byref(target),
                )
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("create trusted application", status)

            values = (ctypes.c_void_p * 2)(self_app.value, security_app.value)
            trusted_apps = ctypes.c_void_p(
                self.api.core_foundation.CFArrayCreate(None, values, 2, None)
            )
            descriptor = ctypes.c_void_p(
                self.api.core_foundation.CFStringCreateWithCString(
                    None,
                    b"keys-keeper",
                    _CF_STRING_ENCODING_UTF8,
                )
            )
            if trusted_apps.value is None or descriptor.value is None:
                raise SecurityFrameworkError("create keychain access policy")
            status = self.api.security.SecAccessCreate(
                descriptor,
                trusted_apps,
                ctypes.byref(access),
            )
            if status != _ERR_SEC_SUCCESS:
                raise SecurityFrameworkError("create keychain access policy", status)
            yield access
        finally:
            for value in (access, descriptor, trusted_apps, security_app, self_app):
                if value.value is not None:
                    self.api.core_foundation.CFRelease(value)

    def add(self, account_value: str, value: str) -> None:
        account = _encode_label(account_value, "keychain account")
        raw = value.encode("utf-8")
        if len(raw) > _MAX_SECRET_BYTES:
            raise SecurityFrameworkError("validate keychain value")
        secret = ctypes.create_string_buffer(raw, max(1, len(raw)))
        service = ctypes.create_string_buffer(self.service, len(self.service))
        account_buffer = ctypes.create_string_buffer(account, len(account))
        attributes = (_KeychainAttribute * 2)(
            _KeychainAttribute(
                _SERVICE_ITEM_ATTR,
                len(self.service),
                ctypes.cast(service, ctypes.c_void_p),
            ),
            _KeychainAttribute(
                _ACCOUNT_ITEM_ATTR,
                len(account),
                ctypes.cast(account_buffer, ctypes.c_void_p),
            ),
        )
        attribute_list = _KeychainAttributeList(2, attributes)
        item = ctypes.c_void_p()
        try:
            with (
                self._interaction_policy(),
                self._compatible_access() as access,
                self._keychain_ref() as keychain,
            ):
                status = self.api.security.SecKeychainItemCreateFromContent(
                    _GENERIC_PASSWORD_ITEM_CLASS,
                    ctypes.byref(attribute_list),
                    len(raw),
                    secret,
                    keychain,
                    access,
                    ctypes.byref(item),
                )
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("write keychain item", status)
        finally:
            if item.value is not None:
                self.api.core_foundation.CFRelease(item)
            ctypes.memset(secret, 0, len(secret))
