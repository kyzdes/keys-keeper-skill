"""Native macOS Keychain operations that keep values out of argv.

This ctypes binding reads, writes, deletes, and enumerates generic-password
items directly through Keychain Services, including multiline values and
custom keychain files. No ``/usr/bin/security`` child process is involved.
"""

from __future__ import annotations

import ctypes
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from keys_keeper.macos_keychain_abi import (
    ACCOUNT_ITEM_ATTR as _ACCOUNT_ITEM_ATTR,
)
from keys_keeper.macos_keychain_abi import (
    CF_STRING_ENCODING_UTF8 as _CF_STRING_ENCODING_UTF8,
)
from keys_keeper.macos_keychain_abi import (
    ERR_SEC_ITEM_NOT_FOUND as _ERR_SEC_ITEM_NOT_FOUND,
)
from keys_keeper.macos_keychain_abi import (
    ERR_SEC_SUCCESS as _ERR_SEC_SUCCESS,
)
from keys_keeper.macos_keychain_abi import (
    GENERIC_PASSWORD_ITEM_CLASS as _GENERIC_PASSWORD_ITEM_CLASS,
)
from keys_keeper.macos_keychain_abi import (
    MAX_LABEL_BYTES as _MAX_LABEL_BYTES,
)
from keys_keeper.macos_keychain_abi import (
    MAX_SECRET_BYTES as _MAX_SECRET_BYTES,
)
from keys_keeper.macos_keychain_abi import (
    SERVICE_ITEM_ATTR as _SERVICE_ITEM_ATTR,
)
from keys_keeper.macos_keychain_abi import (
    SYSTEM_SECURITY_PATH as _SYSTEM_SECURITY_PATH,
)
from keys_keeper.macos_keychain_abi import (
    UNLOCKED_STATUS as _UNLOCKED_STATUS,
)
from keys_keeper.macos_keychain_abi import (
    FrameworkBindings as _Bindings,
)
from keys_keeper.macos_keychain_abi import (
    FrameworkUnavailableError as _FrameworkUnavailableError,
)
from keys_keeper.macos_keychain_abi import (
    KeychainAttribute as _KeychainAttribute,
)
from keys_keeper.macos_keychain_abi import (
    KeychainAttributeList as _KeychainAttributeList,
)
from keys_keeper.macos_keychain_cf import release_cf_refs

_INTERACTION_LOCK = threading.RLock()


class SecurityFrameworkError(RuntimeError):
    """A native Keychain Services operation failed without exposing data."""

    def __init__(self, operation: str, status: int | None = None):
        self.operation = operation
        self.status = status
        suffix = "" if status is None else f" (OSStatus {status})"
        super().__init__(f"{operation} failed{suffix}")


@lru_cache(maxsize=1)
def _bindings() -> _Bindings:
    try:
        return _Bindings()
    except (_FrameworkUnavailableError, OSError) as ex:
        raise SecurityFrameworkError("load macOS Security framework") from ex


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
            release_cf_refs(self.api.core_foundation, keychain)

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
            release_cf_refs(
                self.api.core_foundation,
                access,
                descriptor,
                trusted_apps,
                self_app,
            )

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
            release_cf_refs(self.api.core_foundation, item)
            ctypes.memset(secret, 0, len(secret))

    def set(self, account_value: str, value: str) -> None:
        """Create or update one item without a destructive delete window.

        Updating uses SecKeychainItemModifyContent on the existing native item.
        Its ACL and identity remain intact, and a failed update leaves the old
        value in place. The lookup requests only the item reference, not data.
        """
        account = _encode_label(account_value, "keychain account")
        raw = value.encode("utf-8")
        if len(raw) > _MAX_SECRET_BYTES:
            raise SecurityFrameworkError("validate keychain value")
        secret = ctypes.create_string_buffer(raw, max(1, len(raw)))
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
                    # add() re-enters the process-wide interaction lock safely.
                    self.add(account_value, value)
                    return
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError(
                        "find keychain item for update", status
                    )
                status = self.api.security.SecKeychainItemModifyContent(
                    item,
                    None,
                    len(raw),
                    secret,
                )
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("update keychain item", status)
        finally:
            release_cf_refs(self.api.core_foundation, item)
            ctypes.memset(secret, 0, len(secret))

    @contextmanager
    def _readiness_keychain_ref(self) -> Iterator[ctypes.c_void_p]:
        """Resolve a concrete Keychain ref for metadata-only status calls."""
        if self.keychain_path is not None:
            with self._keychain_ref() as keychain:
                assert keychain is not None
                yield keychain
            return
        keychain = ctypes.c_void_p()
        status = self.api.security.SecKeychainCopyDefault(ctypes.byref(keychain))
        if status != _ERR_SEC_SUCCESS or keychain.value is None:
            raise SecurityFrameworkError("open default keychain", status)
        try:
            yield keychain
        finally:
            release_cf_refs(self.api.core_foundation, keychain)

    def is_unlocked(self) -> bool:
        """Return lock state without reading any item or secret value."""
        with self._interaction_policy(), self._readiness_keychain_ref() as keychain:
            keychain_status = ctypes.c_uint32()
            status = self.api.security.SecKeychainGetStatus(
                keychain,
                ctypes.byref(keychain_status),
            )
            if status != _ERR_SEC_SUCCESS:
                raise SecurityFrameworkError("read keychain status", status)
            return bool(keychain_status.value & _UNLOCKED_STATUS)

    @contextmanager
    def _self_trusted_application(self) -> Iterator[ctypes.c_void_p]:
        """Return Security.framework's identity for this executable, not a label."""
        application = ctypes.c_void_p()
        status = self.api.security.SecTrustedApplicationCreateFromPath(
            None,
            ctypes.byref(application),
        )
        if status != _ERR_SEC_SUCCESS or application.value is None:
            raise SecurityFrameworkError("create current runtime identity", status)
        try:
            yield application
        finally:
            release_cf_refs(self.api.core_foundation, application)

    @contextmanager
    def _item_access(
        self, account_value: str
    ) -> Iterator[tuple[ctypes.c_void_p, ctypes.c_void_p]]:
        """Copy one item's ACL metadata without requesting its secret data."""
        account = _encode_label(account_value, "keychain account")
        item = ctypes.c_void_p()
        access = ctypes.c_void_p()
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
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError(
                        "find keychain item for access preparation", status
                    )
                status = self.api.security.SecKeychainItemCopyAccess(
                    item,
                    ctypes.byref(access),
                )
                if status != _ERR_SEC_SUCCESS or access.value is None:
                    raise SecurityFrameworkError("copy keychain item access", status)
                yield item, access
        finally:
            release_cf_refs(self.api.core_foundation, access, item)

    def native_access_prepared(self, account_value: str) -> bool:
        """Return whether this exact runtime is trusted for decrypt.

        The query copies only item and ACL metadata. It never asks Keychain for
        the password bytes and is therefore safe to use for a no-UI preflight.
        """
        return self.native_access_state(account_value) == "prepared"

    def native_access_state(self, account_value: str) -> str:
        """Classify metadata for bounded preparation without reading data."""
        with (
            self._item_access(account_value) as (_, access),
            self._self_trusted_application() as application,
        ):
            if self._access_has_authorization(
                access, "kSecACLAuthorizationPartitionID"
            ):
                # Partition-list requirements are code-signature policy. This
                # compatibility path must not weaken or guess them for a Python
                # runtime; the future signed broker owns that migration.
                return "partitioned"
            if self._access_trusts_application(access, application):
                return "prepared"
            return "needs-preparation"

    def prepare_native_access(self, account_value: str) -> bool:
        """Add this exact runtime to one original item's decrypt ACL.

        Returns True when the original ACL was changed and False when it was
        already sufficient. No password value is read, copied, or rewritten.
        The caller controls whether macOS interaction is allowed; production
        code enables it only for an explicit single-item setup command.
        """
        with (
            self._item_access(account_value) as (item, access),
            self._self_trusted_application() as application,
        ):
            if self._access_has_authorization(
                access, "kSecACLAuthorizationPartitionID"
            ):
                raise SecurityFrameworkError(
                    "prepare partitioned keychain item access (signed broker required)"
                )
            if self._access_trusts_application(access, application):
                return False
            if not self._append_application_to_decrypt_acls(access, application):
                raise SecurityFrameworkError(
                    "prepare keychain item access (no decrypt ACL)"
                )
            status = self.api.security.SecKeychainItemSetAccess(item, access)
            if status != _ERR_SEC_SUCCESS:
                raise SecurityFrameworkError("set keychain item access", status)
        if not self.native_access_prepared(account_value):
            raise SecurityFrameworkError("verify keychain item access")
        return True

    def _access_trusts_application(
        self,
        access: ctypes.c_void_p,
        application: ctypes.c_void_p,
    ) -> bool:
        acl_list = ctypes.c_void_p()
        try:
            status = self.api.security.SecAccessCopyACLList(
                access,
                ctypes.byref(acl_list),
            )
            if status != _ERR_SEC_SUCCESS or acl_list.value is None:
                raise SecurityFrameworkError("copy keychain ACL list", status)
            for index in range(self.api.core_foundation.CFArrayGetCount(acl_list)):
                acl = self.api.core_foundation.CFArrayGetValueAtIndex(
                    acl_list,
                    index,
                )
                if not self._acl_allows_decrypt(acl):
                    continue
                applications = ctypes.c_void_p()
                descriptor = ctypes.c_void_p()
                prompt_selector = ctypes.c_uint32()
                try:
                    status = self.api.security.SecACLCopyContents(
                        acl,
                        ctypes.byref(applications),
                        ctypes.byref(descriptor),
                        ctypes.byref(prompt_selector),
                    )
                    if status != _ERR_SEC_SUCCESS:
                        raise SecurityFrameworkError("copy decrypt ACL", status)
                    # Apple defines a NULL application list as unrestricted.
                    if applications.value is None:
                        return True
                    for app_index in range(
                        self.api.core_foundation.CFArrayGetCount(applications)
                    ):
                        candidate = self.api.core_foundation.CFArrayGetValueAtIndex(
                            applications,
                            app_index,
                        )
                        if self._trusted_applications_equal(candidate, application):
                            return True
                finally:
                    release_cf_refs(
                        self.api.core_foundation,
                        descriptor,
                        applications,
                    )
            return False
        finally:
            release_cf_refs(self.api.core_foundation, acl_list)

    def _append_application_to_decrypt_acls(
        self,
        access: ctypes.c_void_p,
        application: ctypes.c_void_p,
    ) -> bool:
        acl_list = ctypes.c_void_p()
        changed = False
        try:
            status = self.api.security.SecAccessCopyACLList(
                access,
                ctypes.byref(acl_list),
            )
            if status != _ERR_SEC_SUCCESS or acl_list.value is None:
                raise SecurityFrameworkError("copy keychain ACL list", status)
            for index in range(self.api.core_foundation.CFArrayGetCount(acl_list)):
                acl = self.api.core_foundation.CFArrayGetValueAtIndex(
                    acl_list,
                    index,
                )
                if not self._acl_allows_decrypt(acl):
                    continue
                applications = ctypes.c_void_p()
                descriptor = ctypes.c_void_p()
                prompt_selector = ctypes.c_uint32()
                replacement = ctypes.c_void_p()
                try:
                    status = self.api.security.SecACLCopyContents(
                        acl,
                        ctypes.byref(applications),
                        ctypes.byref(descriptor),
                        ctypes.byref(prompt_selector),
                    )
                    if status != _ERR_SEC_SUCCESS:
                        raise SecurityFrameworkError("copy decrypt ACL", status)
                    # NULL means every app is already trusted; do not narrow it
                    # implicitly during a compatibility preparation command.
                    if applications.value is None:
                        continue
                    if descriptor.value is None:
                        raise SecurityFrameworkError("preserve decrypt ACL descriptor")
                    count = self.api.core_foundation.CFArrayGetCount(applications)
                    replacement = ctypes.c_void_p(
                        self.api.core_foundation.CFArrayCreateMutableCopy(
                            None,
                            count + 1,
                            applications,
                        )
                    )
                    if replacement.value is None:
                        raise SecurityFrameworkError(
                            "create prepared decrypt ACL application list"
                        )
                    self.api.core_foundation.CFArrayAppendValue(
                        replacement,
                        application,
                    )
                    status = self.api.security.SecACLSetContents(
                        acl,
                        replacement,
                        descriptor,
                        prompt_selector.value,
                    )
                    if status != _ERR_SEC_SUCCESS:
                        raise SecurityFrameworkError("update decrypt ACL", status)
                    changed = True
                finally:
                    release_cf_refs(
                        self.api.core_foundation,
                        replacement,
                        descriptor,
                        applications,
                    )
            return changed
        finally:
            release_cf_refs(self.api.core_foundation, acl_list)

    def _acl_allows_decrypt(self, acl: ctypes.c_void_p) -> bool:
        return self._acl_has_authorization(acl, "kSecACLAuthorizationDecrypt")

    def _access_has_authorization(
        self,
        access: ctypes.c_void_p,
        symbol: str,
    ) -> bool:
        acl_list = ctypes.c_void_p()
        try:
            status = self.api.security.SecAccessCopyACLList(
                access,
                ctypes.byref(acl_list),
            )
            if status != _ERR_SEC_SUCCESS or acl_list.value is None:
                raise SecurityFrameworkError("copy keychain ACL list", status)
            return any(
                self._acl_has_authorization(
                    self.api.core_foundation.CFArrayGetValueAtIndex(acl_list, index),
                    symbol,
                )
                for index in range(self.api.core_foundation.CFArrayGetCount(acl_list))
            )
        finally:
            release_cf_refs(self.api.core_foundation, acl_list)

    def _acl_has_authorization(
        self,
        acl: ctypes.c_void_p,
        symbol: str,
    ) -> bool:
        authorizations = ctypes.c_void_p(
            self.api.security.SecACLCopyAuthorizations(acl)
        )
        if authorizations.value is None:
            return False
        try:
            authorization = ctypes.c_void_p.in_dll(
                self.api.security,
                symbol,
            ).value
            return any(
                self.api.core_foundation.CFEqual(
                    self.api.core_foundation.CFArrayGetValueAtIndex(
                        authorizations, index
                    ),
                    authorization,
                )
                for index in range(
                    self.api.core_foundation.CFArrayGetCount(authorizations)
                )
            )
        finally:
            release_cf_refs(self.api.core_foundation, authorizations)

    def _trusted_applications_equal(
        self,
        left: ctypes.c_void_p,
        right: ctypes.c_void_p,
    ) -> bool:
        left_data = ctypes.c_void_p()
        right_data = ctypes.c_void_p()
        try:
            left_status = self.api.security.SecTrustedApplicationCopyData(
                left,
                ctypes.byref(left_data),
            )
            right_status = self.api.security.SecTrustedApplicationCopyData(
                right,
                ctypes.byref(right_data),
            )
            if (
                left_status != _ERR_SEC_SUCCESS
                or right_status != _ERR_SEC_SUCCESS
                or left_data.value is None
                or right_data.value is None
            ):
                return False
            return bool(self.api.core_foundation.CFEqual(left_data, right_data))
        finally:
            release_cf_refs(self.api.core_foundation, right_data, left_data)

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

    def legacy_security_read_allowed(self, account_value: str) -> bool:
        """Return whether an unlocked legacy item explicitly trusts ``security``.

        Some records created before the native writer trust only Apple's fixed
        ``/usr/bin/security`` executable for the decrypt authorization. Bypass
        may use that already-authorized executable as a narrow compatibility
        bridge, but only after this metadata-only ACL check proves that it will
        not need an authorization prompt. Any inspection error fails closed.
        """
        account = _encode_label(account_value, "keychain account")
        item = ctypes.c_void_p()
        access = ctypes.c_void_p()
        acl_list = ctypes.c_void_p()
        try:
            with self._interaction_policy(), self._keychain_ref() as keychain:
                keychain_status = ctypes.c_uint32()
                status = self.api.security.SecKeychainGetStatus(
                    keychain,
                    ctypes.byref(keychain_status),
                )
                if status != _ERR_SEC_SUCCESS or not (
                    keychain_status.value & _UNLOCKED_STATUS
                ):
                    return False
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
                if status != _ERR_SEC_SUCCESS:
                    return False
                status = self.api.security.SecKeychainItemCopyAccess(
                    item,
                    ctypes.byref(access),
                )
                if status != _ERR_SEC_SUCCESS:
                    return False
                status = self.api.security.SecAccessCopyACLList(
                    access,
                    ctypes.byref(acl_list),
                )
                if status != _ERR_SEC_SUCCESS or acl_list.value is None:
                    return False
            decrypt = ctypes.c_void_p.in_dll(
                self.api.security,
                "kSecACLAuthorizationDecrypt",
            ).value
            for index in range(self.api.core_foundation.CFArrayGetCount(acl_list)):
                acl = self.api.core_foundation.CFArrayGetValueAtIndex(
                    acl_list,
                    index,
                )
                authorizations = ctypes.c_void_p(
                    self.api.security.SecACLCopyAuthorizations(acl)
                )
                if authorizations.value is None:
                    continue
                try:
                    is_decrypt_acl = any(
                        self.api.core_foundation.CFEqual(
                            self.api.core_foundation.CFArrayGetValueAtIndex(
                                authorizations,
                                auth_index,
                            ),
                            decrypt,
                        )
                        for auth_index in range(
                            self.api.core_foundation.CFArrayGetCount(authorizations)
                        )
                    )
                finally:
                    release_cf_refs(self.api.core_foundation, authorizations)
                if is_decrypt_acl and self._acl_trusts_system_security(acl):
                    return True
            return False
        except (
            OSError,
            ValueError,
            TypeError,
            ctypes.ArgumentError,
            SecurityFrameworkError,
        ):
            return False
        finally:
            release_cf_refs(self.api.core_foundation, acl_list, access, item)

    def _acl_trusts_system_security(self, acl: ctypes.c_void_p) -> bool:
        applications = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        prompt_selector = ctypes.c_uint32()
        try:
            status = self.api.security.SecACLCopyContents(
                acl,
                ctypes.byref(applications),
                ctypes.byref(descriptor),
                ctypes.byref(prompt_selector),
            )
            if status != _ERR_SEC_SUCCESS or applications.value is None:
                return False
            for index in range(self.api.core_foundation.CFArrayGetCount(applications)):
                application = self.api.core_foundation.CFArrayGetValueAtIndex(
                    applications,
                    index,
                )
                data = ctypes.c_void_p()
                try:
                    status = self.api.security.SecTrustedApplicationCopyData(
                        application,
                        ctypes.byref(data),
                    )
                    if status != _ERR_SEC_SUCCESS or data.value is None:
                        continue
                    length = self.api.core_foundation.CFDataGetLength(data)
                    raw = bytes(
                        self.api.core_foundation.CFDataGetBytePtr(data)[:length]
                    ).rstrip(b"\0")
                    if raw == _SYSTEM_SECURITY_PATH:
                        return True
                finally:
                    release_cf_refs(self.api.core_foundation, data)
            return False
        finally:
            release_cf_refs(self.api.core_foundation, descriptor, applications)

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
                    raise SecurityFrameworkError(
                        "find keychain item for deletion", status
                    )
                status = self.api.security.SecKeychainItemDelete(item)
                if status != _ERR_SEC_SUCCESS:
                    raise SecurityFrameworkError("delete keychain item", status)
            return True
        finally:
            release_cf_refs(self.api.core_foundation, item)

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
                        account_attribute_list = _KeychainAttributeList(
                            1, account_attributes
                        )
                        status = self.api.security.SecKeychainItemCopyContent(
                            item,
                            None,
                            ctypes.byref(account_attribute_list),
                            None,
                            None,
                        )
                        if status != _ERR_SEC_SUCCESS:
                            raise SecurityFrameworkError(
                                "read keychain account attribute", status
                            )
                        try:
                            raw = ctypes.string_at(
                                account_attributes[0].data,
                                account_attributes[0].length,
                            )
                            accounts.append(raw.decode("utf-8"))
                        except UnicodeDecodeError as ex:
                            raise SecurityFrameworkError(
                                "decode keychain account"
                            ) from ex
                        finally:
                            self.api.security.SecKeychainItemFreeContent(
                                ctypes.byref(account_attribute_list),
                                None,
                            )
                    finally:
                        release_cf_refs(self.api.core_foundation, item)
        finally:
            release_cf_refs(self.api.core_foundation, search)
        return accounts
