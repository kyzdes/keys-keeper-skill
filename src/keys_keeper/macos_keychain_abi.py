"""Private ctypes ABI declarations for macOS Security.framework.

This module contains no Keychain policy or secret-handling logic. Keeping the
raw C signatures here makes :mod:`keys_keeper.macos_keychain` responsible only
for operation ordering, interaction policy, and resource ownership.
"""

from __future__ import annotations

import ctypes
import sys

ERR_SEC_SUCCESS = 0
ERR_SEC_ITEM_NOT_FOUND = -25300
MAX_LABEL_BYTES = 4096
MAX_SECRET_BYTES = 4 * 1024 * 1024
CF_STRING_ENCODING_UTF8 = 0x08000100
GENERIC_PASSWORD_ITEM_CLASS = 0x67656E70  # 'genp'
ACCOUNT_ITEM_ATTR = 0x61636374  # 'acct'
SERVICE_ITEM_ATTR = 0x73766365  # 'svce'
UNLOCKED_STATUS = 1
SYSTEM_SECURITY_PATH = b"/usr/bin/security"


class KeychainAttribute(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_uint32),
        ("length", ctypes.c_uint32),
        ("data", ctypes.c_void_p),
    ]


class KeychainAttributeList(ctypes.Structure):
    _fields_ = [
        ("count", ctypes.c_uint32),
        ("attr", ctypes.POINTER(KeychainAttribute)),
    ]


class FrameworkUnavailableError(RuntimeError):
    """The macOS framework cannot be loaded on this runtime."""


class FrameworkBindings:
    """Loaded framework handles with explicit ctypes signatures."""

    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise FrameworkUnavailableError("macOS Security framework is unavailable")
        self.security = ctypes.CDLL(
            "/System/Library/Frameworks/Security.framework/Security"
        )
        self.core_foundation = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self._declare_security()
        self._declare_core_foundation()

    def _declare_security(self) -> None:
        void_p = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        status = ctypes.c_int32
        security = self.security

        security.SecKeychainOpen.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainOpen.restype = status

        security.SecKeychainGetUserInteractionAllowed.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte),
        ]
        security.SecKeychainGetUserInteractionAllowed.restype = status

        security.SecKeychainSetUserInteractionAllowed.argtypes = [
            ctypes.c_ubyte,
        ]
        security.SecKeychainSetUserInteractionAllowed.restype = status

        security.SecKeychainGetStatus.argtypes = [
            void_p,
            ctypes.POINTER(uint32),
        ]
        security.SecKeychainGetStatus.restype = status

        security.SecKeychainCopyDefault.argtypes = [ctypes.POINTER(void_p)]
        security.SecKeychainCopyDefault.restype = status

        security.SecKeychainItemCreateFromContent.argtypes = [
            uint32,
            ctypes.POINTER(KeychainAttributeList),
            uint32,
            void_p,
            void_p,
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainItemCreateFromContent.restype = status

        security.SecKeychainFindGenericPassword.argtypes = [
            void_p,
            uint32,
            ctypes.c_char_p,
            uint32,
            ctypes.c_char_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainFindGenericPassword.restype = status

        security.SecKeychainItemFreeContent.argtypes = [
            ctypes.POINTER(KeychainAttributeList),
            void_p,
        ]
        security.SecKeychainItemFreeContent.restype = status

        security.SecKeychainItemDelete.argtypes = [void_p]
        security.SecKeychainItemDelete.restype = status

        security.SecKeychainItemModifyContent.argtypes = [
            void_p,
            ctypes.POINTER(KeychainAttributeList),
            uint32,
            void_p,
        ]
        security.SecKeychainItemModifyContent.restype = status

        security.SecKeychainSearchCreateFromAttributes.argtypes = [
            void_p,
            uint32,
            ctypes.POINTER(KeychainAttributeList),
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainSearchCreateFromAttributes.restype = status

        security.SecKeychainSearchCopyNext.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainSearchCopyNext.restype = status

        security.SecKeychainItemCopyContent.argtypes = [
            void_p,
            ctypes.POINTER(uint32),
            ctypes.POINTER(KeychainAttributeList),
            ctypes.POINTER(uint32),
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainItemCopyContent.restype = status

        security.SecTrustedApplicationCreateFromPath.argtypes = [
            ctypes.c_char_p,
            ctypes.POINTER(void_p),
        ]
        security.SecTrustedApplicationCreateFromPath.restype = status

        security.SecAccessCreate.argtypes = [
            void_p,
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecAccessCreate.restype = status

        security.SecKeychainItemCopyAccess.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecKeychainItemCopyAccess.restype = status

        security.SecKeychainItemSetAccess.argtypes = [void_p, void_p]
        security.SecKeychainItemSetAccess.restype = status

        security.SecAccessCopyACLList.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecAccessCopyACLList.restype = status

        security.SecACLCopyAuthorizations.argtypes = [void_p]
        security.SecACLCopyAuthorizations.restype = void_p

        security.SecACLCopyContents.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
            ctypes.POINTER(void_p),
            ctypes.POINTER(uint32),
        ]
        security.SecACLCopyContents.restype = status

        security.SecACLSetContents.argtypes = [
            void_p,
            void_p,
            void_p,
            uint32,
        ]
        security.SecACLSetContents.restype = status

        security.SecTrustedApplicationCopyData.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
        ]
        security.SecTrustedApplicationCopyData.restype = status

    def _declare_core_foundation(self) -> None:
        void_p = ctypes.c_void_p
        uint32 = ctypes.c_uint32
        core_foundation = self.core_foundation

        core_foundation.CFStringCreateWithCString.argtypes = [
            void_p,
            ctypes.c_char_p,
            uint32,
        ]
        core_foundation.CFStringCreateWithCString.restype = void_p

        core_foundation.CFArrayCreate.argtypes = [
            void_p,
            ctypes.POINTER(void_p),
            ctypes.c_long,
            void_p,
        ]
        core_foundation.CFArrayCreate.restype = void_p

        core_foundation.CFArrayCreateMutableCopy.argtypes = [
            void_p,
            ctypes.c_long,
            void_p,
        ]
        core_foundation.CFArrayCreateMutableCopy.restype = void_p

        core_foundation.CFArrayAppendValue.argtypes = [void_p, void_p]
        core_foundation.CFArrayAppendValue.restype = None

        core_foundation.CFArrayGetCount.argtypes = [void_p]
        core_foundation.CFArrayGetCount.restype = ctypes.c_long

        core_foundation.CFArrayGetValueAtIndex.argtypes = [
            void_p,
            ctypes.c_long,
        ]
        core_foundation.CFArrayGetValueAtIndex.restype = void_p

        core_foundation.CFDataGetLength.argtypes = [void_p]
        core_foundation.CFDataGetLength.restype = ctypes.c_long

        core_foundation.CFDataGetBytePtr.argtypes = [void_p]
        core_foundation.CFDataGetBytePtr.restype = ctypes.POINTER(ctypes.c_ubyte)

        core_foundation.CFEqual.argtypes = [void_p, void_p]
        core_foundation.CFEqual.restype = ctypes.c_ubyte

        core_foundation.CFRelease.argtypes = [void_p]
        core_foundation.CFRelease.restype = None
