"""Native macOS Keychain operations that keep values out of argv.

This ctypes binding reads, writes, deletes, and enumerates generic-password
items directly through Keychain Services, including multiline values and
custom keychain files. No ``/usr/bin/security`` child process is involved.
"""
from __future__ import annotations

import ctypes
import sys
import threading
from contextlib import contextmanager
from functools import lru_cache
from typing import Iterator


_ERR_SEC_SUCCESS = 0
_ERR_SEC_ITEM_NOT_FOUND = -25300
_MAX_LABEL_BYTES = 4096
_MAX_SECRET_BYTES = 4 * 1024 * 1024
_CF_STRING_ENCODING_UTF8 = 0x08000100
_GENERIC_PASSWORD_ITEM_CLASS = 0x67656E70  # 'genp'
_ACCOUNT_ITEM_ATTR = 0x61636374  # 'acct'
_SERVICE_ITEM_ATTR = 0x73766365  # 'svce'
_INTERACTION_LOCK = threading.RLock()


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

        self.security.SecKeychainFindGenericPassword.argtypes = [
            void_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainFindGenericPassword.restype = status

        self.security.SecKeychainItemFreeContent.argtypes = [
            ctypes.POINTER(_KeychainAttributeList),
            void_p,
        ]
        self.security.SecKeychainItemFreeContent.restype = status

        self.security.SecKeychainItemDelete.argtypes = [void_p]
        self.security.SecKeychainItemDelete.restype = status

        self.security.SecKeychainSearchCreateFromAttributes.argtypes = [
            void_p,
            uint32,
            ctypes.POINTER(_KeychainAttributeList),
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainSearchCreateFromAttributes.restype = status

        self.security.SecKeychainSearchCopyNext.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainSearchCopyNext.restype = status

        self.security.SecKeychainItemCopyContent.argtypes = [
            void_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(_KeychainAttributeList),
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_p),
        ]
        self.security.SecKeychainItemCopyContent.restype = status

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
    """Operate on generic-password items entirely inside the current process."""

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
        # The Security.framework interaction flag is process-global. Serialize
        # policy changes so concurrent admin requests cannot restore it early.
        with _INTERACTION_LOCK:
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
    def _self_access(self) -> Iterator[ctypes.c_void_p]:
        """Build an ACL that trusts only the current Keys Keeper process."""
        self_app = ctypes.c_void_p()
        trusted_apps = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        access = ctypes.c_void_p()
        try:
            status = self.api.security.SecTrustedApplicationCreateFromPath(
                None,
                ctypes.byref(self_app),
            )
            if status != _ERR_SEC_SUCCESS:
                raise SecurityFrameworkError("create trusted application", status)

            values = (ctypes.c_void_p * 1)(self_app.value)
            trusted_apps = ctypes.c_void_p(
                self.api.core_foundation.CFArrayCreate(None, values, 1, None)
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
            for value in (access, descriptor, trusted_apps, self_app):
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
                self._self_access() as access,
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

    def get(self, account_value: str) -> str:
        """Read one value natively; the framework-owned buffer is zeroed/freed."""
        account = _encode_label(account_value, "keychain account")
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        with self._interaction_policy(), self._keychain_ref() as keychain:
            status = self.api.security.SecKeychainFindGenericPassword(
                keychain,
                len(self.service),
                self.service,
                len(account),
                account,
                ctypes.byref(length),
                ctypes.byref(data),
                None,
            )
        if status != _ERR_SEC_SUCCESS:
            raise SecurityFrameworkError("read keychain item", status)
        try:
            raw = ctypes.string_at(data, length.value)
            return raw.decode("utf-8")
        except UnicodeDecodeError as ex:
            raise SecurityFrameworkError("decode keychain item") from ex
        finally:
            if data.value is not None:
                ctypes.memset(data, 0, length.value)
                self.api.security.SecKeychainItemFreeContent(None, data)

    def delete(self, account_value: str) -> bool:
        """Delete one item natively; return False when it did not exist."""
        account = _encode_label(account_value, "keychain account")
        item = ctypes.c_void_p()
        try:
            with self._interaction_policy(), self._keychain_ref() as keychain:
                status = self.api.security.SecKeychainFindGenericPassword(
                    keychain,
                    len(self.service),
                    self.service,
                    len(account),
                    account,
                    None,
                    None,
                    ctypes.byref(item),
                )
                if status == _ERR_SEC_ITEM_NOT_FOUND:
                    return False
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("find keychain item for deletion", status)
                status = self.api.security.SecKeychainItemDelete(item)
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("delete keychain item", status)
            return True
        finally:
            if item.value is not None:
                self.api.core_foundation.CFRelease(item)

    def list_accounts(self) -> list[str]:
        """Enumerate accounts for this service without requesting secret data."""
        service_buffer = ctypes.create_string_buffer(self.service, len(self.service))
        search_attributes = (_KeychainAttribute * 1)(
            _KeychainAttribute(
                _SERVICE_ITEM_ATTR,
                len(self.service),
                ctypes.cast(service_buffer, ctypes.c_void_p),
            )
        )
        search_attribute_list = _KeychainAttributeList(1, search_attributes)
        search = ctypes.c_void_p()
        accounts: list[str] = []
        try:
            with self._interaction_policy(), self._keychain_ref() as keychain:
                status = self.api.security.SecKeychainSearchCreateFromAttributes(
                    keychain,
                    _GENERIC_PASSWORD_ITEM_CLASS,
                    ctypes.byref(search_attribute_list),
                    ctypes.byref(search),
                )
                if status == _ERR_SEC_ITEM_NOT_FOUND:
                    return []
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("search keychain items", status)
                while True:
                    item = ctypes.c_void_p()
                    status = self.api.security.SecKeychainSearchCopyNext(
                        search,
                        ctypes.byref(item),
                    )
                    if status == _ERR_SEC_ITEM_NOT_FOUND:
                        break
                    if status != _ERR_SEC_SUCCESS:
                        raise SecurityFrameworkError("enumerate keychain items", status)
                    try:
                        account_attributes = (_KeychainAttribute * 1)(
                            _KeychainAttribute(_ACCOUNT_ITEM_ATTR, 0, None)
                        )
                        account_attribute_list = _KeychainAttributeList(1, account_attributes)
                        status = self.api.security.SecKeychainItemCopyContent(
                            item,
                            None,
                            ctypes.byref(account_attribute_list),
                            None,
                            None,
                        )
                        if status != _ERR_SEC_SUCCESS:
                            raise SecurityFrameworkError("read keychain account attribute", status)
                        try:
                            raw = ctypes.string_at(
                                account_attributes[0].data,
                                account_attributes[0].length,
                            )
                            accounts.append(raw.decode("utf-8"))
                        except UnicodeDecodeError as ex:
                            raise SecurityFrameworkError("decode keychain account") from ex
                        finally:
                            self.api.security.SecKeychainItemFreeContent(
                                ctypes.byref(account_attribute_list),
                                None,
                            )
                    finally:
                        if item.value is not None:
                            self.api.core_foundation.CFRelease(item)
        finally:
            if search.value is not None:
                self.api.core_foundation.CFRelease(search)
        return accounts
