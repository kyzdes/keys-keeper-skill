"""Cross-platform secret-storage abstraction."""
from __future__ import annotations
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from keys_keeper.macos_keychain import MacOSNativeKeychain, SecurityFrameworkError


class KeychainError(RuntimeError):
    """An operation failed; an unclassified failure must never mean absent."""


class SecretNotFound(KeychainError):
    """The provider positively identified an absent account."""


class SecretAccessDenied(KeychainError):
    """The provider refused access, including a cancelled authorization."""


class SecretUnavailable(KeychainError):
    """The provider is unavailable or cannot safely return the stored value."""


class Sealed:
    """A plaintext secret that refuses to render itself.

    This is defense-in-depth against accidental rendering, not an
    authorization boundary. The keychain backend returns Sealed instead of a
    bare str so an accidental f-string, print, log line, or repr in a debug
    session prints "<sealed>" instead of the value. Any caller that can import
    this package can deliberately call `.unseal()`; high-assurance isolation
    therefore requires a separate broker/security principal.
    """

    __slots__ = ("_v",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("secret value must be a string")
        self._v = value

    def unseal(self) -> str:
        return self._v

    def __repr__(self) -> str:
        return "<sealed>"

    def __str__(self) -> str:
        return "<sealed>"

    def __len__(self) -> int:
        return len(self._v)

    def __bool__(self) -> bool:
        return bool(self._v)

    def __eq__(self, other: object) -> bool:
        # comparing two Sealed values is fine for tests; comparing against
        # a bare string is a code smell and returns False to make it visible.
        return isinstance(other, Sealed) and self._v == other._v

    def __hash__(self) -> int:
        return hash(("Sealed", self._v))


class KeychainBackend(ABC):
    """Storage interface for secret blobs."""

    @abstractmethod
    def get(self, account: str) -> Sealed: ...

    @abstractmethod
    def set(self, account: str, value: str) -> None: ...

    @abstractmethod
    def delete(self, account: str) -> None: ...

    @abstractmethod
    def list_ids(self) -> list[str]: ...


@dataclass(frozen=True)
class MacOSKeychainReadiness:
    """Metadata-only state; obtaining it never reads a secret value."""

    state: str
    interaction_allowed: bool
    legacy_bridge_allowed: bool


def _decode_legacy_security_password(output: bytes) -> str | None:
    """Decode Apple's tagged ``print_buffer`` output, never guess raw hex.

    ``security -g`` writes exactly one password record to stderr. Printable
    bytes are enclosed in literal quotes (interior quotes are not escaped).
    Other bytes use an authoritative hex field and, when printable bytes are
    present, an octal-escaped preview. Validate that preview too so malformed
    or unexpected output cannot silently become a different credential.

    A failure sentinel keeps secret-bearing decoding exceptions out of the
    caller's error chain. Empty passwords are distinct from failures.
    """
    prefix = b"password: "
    if not isinstance(output, bytes) or not output.startswith(prefix) or not output.endswith(b"\n"):
        return None
    payload = output[len(prefix):-1]
    if not payload:
        raw = b""
    elif payload.startswith(b'"') and payload.endswith(b'"'):
        raw = payload[1:-1]
        if not raw or any(byte < 32 or byte > 126 or byte == 92 for byte in raw):
            return None
    elif payload.startswith(b"0x"):
        end = payload.find(b" ", 2)
        hexadecimal = payload[2:end] if end != -1 else b""
        if not hexadecimal or len(hexadecimal) % 2 or any(byte not in b"0123456789ABCDEF" for byte in hexadecimal):
            return None
        raw = bytes.fromhex(hexadecimal.decode("ascii"))
        printable = [32 <= byte <= 126 and byte != 92 for byte in raw]
        if all(printable):
            return None
        expected = b"0x" + hexadecimal
        if any(printable):
            preview = b"".join(
                bytes((byte,)) if is_printable else f"\\{byte:03o}".encode("ascii")
                for byte, is_printable in zip(raw, printable)
            )
            expected += b'  "' + preview + b'"'
        else:
            expected += b" "
        if payload != expected:
            return None
    else:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


class MacOSKeychainBackend(KeychainBackend):
    """macOS Keychain backend with native secret-value operations.

    All entries belong to one fixed `service` (default: "keys-keeper").
    The `account` is the entry's UUID id (e.g. "kk:abc..." or "kk:abc:passphrase").
    Use a custom `keychain_path` in tests to avoid touching the user's login keychain.

    Ordinary operations use Keychain Services in-process. In bypass mode user
    interaction is disabled. A legacy read may use ``/usr/bin/security`` only
    when native ACL inspection first proves that the unlocked original item
    explicitly trusts that binary for decrypt; every other untrusted item fails
    closed instead of opening a system authorization dialog.
    """

    def __init__(
        self,
        *,
        service: str = "keys-keeper",
        keychain_path: str | None = None,
        allow_interaction: bool = True,
        allow_legacy_bridge: bool = True,
    ):
        self.service = service
        self.keychain_path = keychain_path
        self.allow_legacy_bridge = allow_legacy_bridge
        self._native = MacOSNativeKeychain(
            service=service,
            keychain_path=keychain_path,
            allow_interaction=allow_interaction,
        )

    def get(self, account: str) -> Sealed:
        try:
            return Sealed(self._native.get(account))
        except SecurityFrameworkError as ex:
            if ex.status == -25300:
                raise SecretNotFound(f"keychain entry not found: {account}") from None
            if not self._native.allow_interaction and ex.status in (-25293, -25308):
                try:
                    legacy_allowed = self.allow_legacy_bridge and self._native.legacy_security_read_allowed(account)
                except SecurityFrameworkError:
                    raise SecretUnavailable("Keychain access metadata is unavailable") from None
                if legacy_allowed:
                    return self._read_legacy_security_bridge(account)
                raise SecretAccessDenied(
                    f"keychain entry {account} does not trust this Keys Keeper runtime; "
                    "Keychain UI is disabled for this operation. Use "
                    "`keys keychain prompt` only for an explicit interactive command "
                    "where you want macOS to ask once."
                ) from None
            if ex.status in (-128, -25293, -25308):
                raise SecretAccessDenied("Keychain secret access denied") from None
            raise SecretUnavailable("Keychain secret read failed") from None

    def _read_legacy_security_bridge(self, account: str) -> Sealed:
        """Read one security-CLI-only legacy item without changing the item.

        The caller has already verified, from native ACL metadata, that the
        unlocked item explicitly grants decrypt access to Apple's fixed
        ``/usr/bin/security`` binary. That makes this a compatibility path for
        original Keychain records, not a general CLI fallback: unknown ACLs
        still fail closed before any child process can request authorization.
        """
        command = [
            "/usr/bin/security",
            "find-generic-password",
            "-s",
            self.service,
            "-a",
            account,
            "-g",
        ]
        if self.keychain_path:
            command.append(self.keychain_path)
        result = None
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            # TimeoutExpired can retain captured secret bytes. Raise only after
            # leaving the handler, without retaining it as cause or context.
            pass
        if result is None or result.returncode != 0:
            result = None
            raise SecretUnavailable(
                f"trusted legacy Keychain bridge failed for {account}"
            )
        value = _decode_legacy_security_password(result.stderr)
        result = None
        if value is None:
            raise SecretUnavailable(
                f"failed to decode keychain entry {account}"
            )
        return Sealed(value)

    def set(self, account: str, value: str) -> None:
        try:
            self._native.set(account, value)
        except (SecurityFrameworkError, UnicodeEncodeError) as ex:
            raise KeychainError(f"failed to set keychain entry {account}") from ex

    def readiness(self) -> MacOSKeychainReadiness:
        """Probe lock/readiness metadata without requesting secret data."""
        try:
            unlocked = self._native.is_unlocked()
        except SecurityFrameworkError as ex:
            raise KeychainError(f"failed to inspect Keychain readiness: {ex}") from ex
        return MacOSKeychainReadiness(
            state="ready" if unlocked else "locked",
            interaction_allowed=self._native.allow_interaction,
            legacy_bridge_allowed=self.allow_legacy_bridge,
        )

    def native_access_prepared(self, account: str) -> bool:
        """Check the current runtime's decrypt ACL without reading the value."""
        try:
            return self._native.native_access_prepared(account)
        except SecurityFrameworkError as ex:
            if ex.status == -25300:
                raise KeychainError(f"keychain entry not found: {account}") from ex
            raise KeychainError(
                f"failed to inspect native access for {account}: {ex}"
            ) from ex

    def native_access_state(self, account: str) -> str:
        """Return prepared/needs-preparation/partitioned from ACL metadata."""
        try:
            return self._native.native_access_state(account)
        except SecurityFrameworkError as ex:
            if ex.status == -25300:
                raise KeychainError(f"keychain entry not found: {account}") from ex
            raise KeychainError(
                f"failed to inspect native access for {account}: {ex}"
            ) from ex

    def prepare_native_access(self, account: str) -> bool:
        """Prepare one original item for this runtime without copying its value."""
        try:
            return self._native.prepare_native_access(account)
        except SecurityFrameworkError as ex:
            if ex.status == -25300:
                raise KeychainError(f"keychain entry not found: {account}") from ex
            raise KeychainError(
                f"failed to prepare native access for {account}: {ex}"
            ) from ex

    def delete(self, account: str) -> None:
        try:
            self._native.delete(account)
        except SecurityFrameworkError as ex:
            raise KeychainError(f"failed to delete keychain entry {account}: {ex}") from ex

    def list_ids(self) -> list[str]:
        try:
            return self._native.list_accounts()
        except SecurityFrameworkError as ex:
            raise KeychainError(f"failed to list keychain entries: {ex}") from ex
