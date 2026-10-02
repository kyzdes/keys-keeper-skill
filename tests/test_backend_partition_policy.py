"""Synthetic ACL metadata contracts; never load or read a user Keychain."""
import ctypes
from collections import Counter
from contextlib import nullcontext
import plistlib
import subprocess
from types import SimpleNamespace

import pytest

from keys_keeper import macos_keychain
from keys_keeper.backend import KeychainError, MacOSKeychainBackend
from keys_keeper.macos_keychain import MacOSNativeKeychain, SecurityFrameworkError
from keys_keeper.macos_keychain_abi import FrameworkBindings


DECRYPT, PARTITION = 801, 802


def policy_description(value, *, fmt=plistlib.FMT_XML):
    return plistlib.dumps(value, fmt=fmt).hex().encode("ascii")


def partition_acl(partitions, **extra):
    return {"authorizations": [PARTITION], "description": policy_description({"Partitions": partitions}), **extra}


def decrypt_acl(path=b"/usr/bin/security\x00", **extra):
    return {"authorizations": [DECRYPT], "path": path, **extra}


@pytest.mark.parametrize(("partitions", "allowed"), [
    (["apple-tool:"], True), (["apple-tool:", "apple:", "teamid:SYNTHETIC1"], True),
    (["apple:"], False), (["teamid:SYNTHETIC1"], False), ([], False),
    (["apple-tool:extra"], False), (["prefix-apple-tool:"], False), (["Apple-tool:"], False),
    (["apple-tool:", 1], False), (["apple-tool:", ["other"]], False),
    (["apple-tool:", ""], False), (["apple-tool:", "α"], False),
])
def test_partition_policy_requires_exact_typed_security_partition(partitions, allowed):
    assert macos_keychain._partition_description_allows_security(policy_description({"Partitions": partitions})) is allowed


@pytest.mark.parametrize("value", [[], {}, {"partitions": ["apple-tool:"]},
                                        {"Partitions": "apple-tool:"}, {"Partitions": ["apple-tool:"], "Unknown": True}])
def test_unknown_partition_policy_schema_fails_closed(value):
    assert macos_keychain._partition_description_allows_security(policy_description(value)) is False


@pytest.mark.parametrize("description", [b"", b"0", b"GG", b"aa bb", b"<plist/>",
    b"00" * (macos_keychain._MAX_PARTITION_DESCRIPTION_BYTES // 2 + 1),
    policy_description({"Partitions": ["apple-tool:"]}, fmt=plistlib.FMT_BINARY),
    b"not XML".hex().encode("ascii"),
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string></array>'
    b'<key>Partitions</key><array><string>apple:</string></array></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple:</string></array>'
    b'<key>Partitions</key><array><string>apple-tool:</string></array></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string></array>'
    b'<key>Partitions</key><array><string>apple-tool:</string></array></dict></plist>',
])
def test_malformed_oversized_duplicate_or_unsupported_descriptor_fails_closed(description):
    # Duplicate keys include last-wins cases that would grant access if the
    # uniqueness check were removed from the policy parser.
    if description.startswith(b"<plist version="):
        description = description.hex().encode("ascii")
    assert macos_keychain._partition_description_allows_security(description) is False


@pytest.mark.parametrize("partitions", [
    ["apple-tool:"] * (macos_keychain._MAX_PARTITIONS + 1),
    ["apple-tool:", "x" * (macos_keychain._MAX_PARTITION_ID_BYTES + 1)],
])
def test_partition_count_and_id_length_are_bounded(partitions):
    assert macos_keychain._partition_description_allows_security(policy_description({"Partitions": partitions})) is False


@pytest.mark.parametrize("xml", [
    b'<!DOCTYPE plist [<!ENTITY grant "apple-tool:">]><plist version="1.0"><dict><key>Partitions</key>'
    b'<array><string>&grant;</string></array></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string>'
    b'<unknown/></array></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string></array>'
    b'<unknown/></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string ignored="true">apple-tool:</string>'
    b'</array></dict></plist>',
    b'<plist version="1.0"><dict><key>Partitions</key><array><string>apple-tool:</string></array></dict>'
    b'<dict><key>Partitions</key><array><string>apple-tool:</string></array></dict></plist>',
    b'<plist version="1.0"><dict>ignored<key>Partitions</key><array><string>apple-tool:</string></array></dict></plist>',
])
def test_entities_and_unknown_xml_grammar_cannot_grant_legacy_access(xml):
    assert macos_keychain._partition_description_allows_security(xml.hex().encode("ascii")) is False


def synthetic_legacy_backend(monkeypatch, acls):
    """Run the real preflight over fake owned CF references and no value IO."""
    arrays, descriptors, path_buffers = {}, {}, {}
    allocated, released, events = [], [], []
    acl_by_ref = {100 + index: acl for index, acl in enumerate(acls)}
    arrays[3] = list(acl_by_ref)

    def ref(reference):
        return reference.value if isinstance(reference, ctypes.c_void_p) else reference

    def own(reference, output):
        output._obj.value = reference
        if reference is not None:
            allocated.append(reference)

    class Security:
        @staticmethod
        def SecKeychainGetStatus(_keychain, output):
            output._obj.value = 1
            return 0

        @staticmethod
        def SecKeychainFindGenericPassword(_keychain, _service_length, _service, _account_length, _account,
                                          length, data, item):
            assert length is None and data is None, "preflight may request metadata only"
            own(1, item)
            return 0

        @staticmethod
        def SecKeychainItemCopyAccess(_item, access):
            own(2, access)
            return 0

        @staticmethod
        def SecAccessCopyACLList(_access, output):
            own(3, output)
            return 0

        @staticmethod
        def SecACLCopyAuthorizations(acl):
            row = acl_by_ref[ref(acl)]
            if row["authorizations"] is None:
                return None
            authorization_ref = 200 + ref(acl)
            arrays[authorization_ref] = row["authorizations"]
            allocated.append(authorization_ref)
            return authorization_ref

        @staticmethod
        def SecACLCopyContents(acl, applications, descriptor, selector):
            acl_ref = ref(acl)
            row = acl_by_ref[acl_ref]
            events.append(("contents", acl_ref))
            selector._obj.value = row.get("prompt_flags", 0)
            if PARTITION in row["authorizations"]:
                if row.get("unexpected_applications"):
                    own(400 + acl_ref, applications)
                description = row.get("description")
                if description is not None:
                    own(500 + acl_ref, descriptor)
                    descriptors[500 + acl_ref] = row
            else:
                if row.get("path") is not None:
                    own(400 + acl_ref, applications)
                    arrays[400 + acl_ref] = [600 + acl_ref] * row.get("app_count", 1)
                    path_buffers[600 + acl_ref] = ctypes.create_string_buffer(row["path"])
            return row.get("contents_status", 0)

        @staticmethod
        def SecTrustedApplicationCopyData(application, output):
            own(ref(application), output)
            return 0

        @staticmethod
        def SecTrustedApplicationValidateWithPath(application, path):
            assert path == b"/usr/bin/security"
            events.append(("validate", ref(application)))
            return acl_by_ref[ref(application) - 600].get("validation_status", 0)

    class CoreFoundation:
        @staticmethod
        def CFArrayGetCount(array):
            return len(arrays[ref(array)])

        @staticmethod
        def CFArrayGetValueAtIndex(array, index):
            return arrays[ref(array)][index]

        @staticmethod
        def CFEqual(left, right):
            return ref(left) == ref(right)

        @staticmethod
        def CFGetTypeID(description):
            return descriptors[ref(description)].get("type_id", 11)

        @staticmethod
        def CFStringGetTypeID():
            return 11

        @staticmethod
        def CFStringGetLength(description):
            row = descriptors[ref(description)]
            return row.get("reported_length", len(row["description"]))

        @staticmethod
        def CFStringGetCString(description, buffer, size, _encoding):
            events.append(("string_copy", ref(description)))
            row = descriptors[ref(description)]
            if not row.get("copy_ok", True):
                return False
            raw = row["description"]
            assert len(raw) + 1 == size
            ctypes.memmove(buffer, raw + b"\x00", size)
            return True

        @staticmethod
        def CFDataGetLength(data):
            row = acl_by_ref[ref(data) - 600]
            return row.get("path_length", len(row["path"]))

        @staticmethod
        def CFDataGetBytePtr(data):
            return ctypes.cast(path_buffers[ref(data)], ctypes.POINTER(ctypes.c_ubyte))

        @staticmethod
        def CFRelease(reference):
            released.append(ref(reference))

    native = object.__new__(MacOSNativeKeychain)
    native.service = b"synthetic-partition-test"
    native.allow_interaction = False
    native.api = SimpleNamespace(security=Security(), core_foundation=CoreFoundation())
    monkeypatch.setattr(native, "_interaction_policy", lambda: nullcontext())
    monkeypatch.setattr(native, "_keychain_ref", lambda: nullcontext())
    symbols = {"kSecACLAuthorizationDecrypt": DECRYPT, "kSecACLAuthorizationPartitionID": PARTITION}
    monkeypatch.setattr(ctypes.c_void_p, "in_dll", staticmethod(lambda _library, symbol: ctypes.c_void_p(symbols[symbol])))

    def denied(_account):
        raise SecurityFrameworkError("read keychain item", -25308)

    monkeypatch.setattr(native, "get", denied)
    backend = object.__new__(MacOSKeychainBackend)
    backend.service = "synthetic-partition-test"
    backend.keychain_path = "/synthetic/not-a-user-keychain"
    backend.allow_legacy_bridge = True
    backend._native = native
    return backend, allocated, released, events


@pytest.mark.parametrize(("acls", "allowed"), [
    ([decrypt_acl(), partition_acl(["apple-tool:"])], True),
    ([partition_acl(["apple-tool:"]), decrypt_acl()], True),
    ([decrypt_acl()], True),
    ([decrypt_acl(), partition_acl(["apple:"])], False),
    ([partition_acl(["apple:"]), decrypt_acl()], False),
    ([decrypt_acl(), partition_acl(["teamid:SYNTHETIC1"])], False),
    ([decrypt_acl(), partition_acl(["apple-tool:extra"])], False),
    ([decrypt_acl(), {"authorizations": [PARTITION], "description": b"not-hex"}], False),
    ([decrypt_acl(), {"authorizations": None}], False),
    ([decrypt_acl(), partition_acl(["apple-tool:"]), {"authorizations": None}], False),
    ([decrypt_acl(), partition_acl(["apple-tool:"]), partition_acl(["apple-tool:"])], False),
    ([partition_acl(["apple-tool:"]), decrypt_acl(), partition_acl(["apple:"])], False),
    ([partition_acl(["apple-tool:"])], False),
    ([decrypt_acl(b"/tmp/security\x00"), partition_acl(["apple-tool:"])], False),
    ([decrypt_acl(None), partition_acl(["apple-tool:"])], False),
    ([decrypt_acl(validation_status=-1), partition_acl(["apple-tool:"])], False),
    ([decrypt_acl(validation_status=-1)], False),
    ([decrypt_acl(prompt_flags=1), partition_acl(["apple-tool:"])], False),
    ([decrypt_acl(prompt_flags=0x80)], False),
    ([decrypt_acl(app_count=macos_keychain._MAX_LEGACY_APPLICATIONS + 1)], False),
    ([decrypt_acl(path_length=-1)], False),
    ([decrypt_acl(path_length=macos_keychain._MAX_LABEL_BYTES + 1)], False),
    ([{**partition_acl(["apple-tool:"]), "authorizations": [PARTITION, DECRYPT]}], False),
    ([], False), ([decrypt_acl()] * (macos_keychain._MAX_LEGACY_ACLS + 1), False),
    ([decrypt_acl(), {"authorizations": []}], False),
    ([decrypt_acl(), {"authorizations": [None]}], False),
    ([decrypt_acl(), {"authorizations": [PARTITION] * (macos_keychain._MAX_ACL_AUTHORIZATIONS + 1)}], False),
])
def test_all_partition_metadata_is_checked_before_one_legacy_helper(monkeypatch, acls, allowed):
    backend, allocated, released, events = synthetic_legacy_backend(monkeypatch, acls)
    helpers = []

    def run(command, **kwargs):
        assert any(kind == "validate" for kind, _ in events), "signature must pass before helper starts"
        helpers.append(command)
        return subprocess.CompletedProcess(command, 0, b"metadata", b'password: "synthetic"\n')

    monkeypatch.setattr(subprocess, "run", run)
    if allowed:
        assert backend.get("kk:synthetic-partition").unseal() == "synthetic"
        assert len(helpers) == 1
        assert "-g" in helpers[0]
        if len(acls) > 1 and DECRYPT in acls[0]["authorizations"]:
            assert events.index(("contents", 101)) < events.index(("contents", 100))
    else:
        with pytest.raises(KeychainError, match="Keychain UI is disabled"):
            backend.get("kk:synthetic-partition")
        assert helpers == []
    assert Counter(allocated) == Counter(released), "every copied metadata reference must be released"


@pytest.mark.parametrize("override", [
    {"description": None}, {"contents_status": -1}, {"copy_ok": False}, {"type_id": 99},
    {"reported_length": -1}, {"reported_length": macos_keychain._MAX_PARTITION_DESCRIPTION_BYTES + 1},
    {"unexpected_applications": True}, {"prompt_flags": 1},
])
def test_unreadable_or_nonstandard_partition_descriptor_denies_before_helper(monkeypatch, override):
    backend, allocated, released, events = synthetic_legacy_backend(
        monkeypatch, [decrypt_acl(), partition_acl(["apple-tool:"], **override)]
    )
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: pytest.fail("denied policy must not spawn security"))
    assert backend._native.legacy_security_read_allowed("kk:synthetic-partition") is False
    if "reported_length" in override or "type_id" in override:
        assert not any(kind == "string_copy" for kind, _ in events)
    assert Counter(allocated) == Counter(released)


@pytest.mark.parametrize("operation", ["SecKeychainFindGenericPassword", "SecKeychainItemCopyAccess", "SecAccessCopyACLList"])
def test_success_status_without_owned_metadata_reference_is_not_authorization(monkeypatch, operation):
    backend, allocated, released, _events = synthetic_legacy_backend(monkeypatch, [decrypt_acl()])

    def missing_reference(*arguments):
        arguments[-1]._obj.value = None
        return 0

    monkeypatch.setattr(backend._native.api.security, operation, missing_reference)
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: pytest.fail("unknown metadata must not spawn helper"))
    assert backend._native.legacy_security_read_allowed("kk:synthetic-partition") is False
    assert Counter(allocated) == Counter(released)


def test_core_foundation_string_abi_uses_pointer_sized_lengths_and_type_ids():
    class Function:
        pass

    class Library:
        def __getattr__(self, name):
            function = Function()
            setattr(self, name, function)
            return function

    bindings = object.__new__(FrameworkBindings)
    bindings.core_foundation = Library()
    bindings.security = Library()
    bindings._declare_core_foundation()
    bindings._declare_security()
    cf = bindings.core_foundation
    assert cf.CFGetTypeID.argtypes == [ctypes.c_void_p]
    assert cf.CFGetTypeID.restype is ctypes.c_ulong
    assert cf.CFStringGetTypeID.argtypes == []
    assert cf.CFStringGetTypeID.restype is ctypes.c_ulong
    assert cf.CFStringGetLength.restype is ctypes.c_long
    assert cf.CFStringGetCString.argtypes == [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long, ctypes.c_uint32]
    assert cf.CFStringGetCString.restype is ctypes.c_ubyte
    assert bindings.security.SecTrustedApplicationValidateWithPath.argtypes == [ctypes.c_void_p, ctypes.c_char_p]
    assert bindings.security.SecTrustedApplicationValidateWithPath.restype is ctypes.c_int32
