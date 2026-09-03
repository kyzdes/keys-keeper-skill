"""Cross-platform secret-storage abstraction."""
from __future__ import annotations
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass

from keys_keeper.macos_keychain import MacOSNativeKeychain, SecurityFrameworkError


class KeychainError(RuntimeError):
    """Raised when keychain ops fail (not found, access denied, etc)."""


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
                raise KeychainError(f"keychain entry not found: {account}") from ex
            if not self._native.allow_interaction and ex.status in (-25293, -25308):
                if (
                    self.allow_legacy_bridge
                    and self._native.legacy_security_read_allowed(account)
                ):
                    return self._read_legacy_security_bridge(account)
                raise KeychainError(
                    f"keychain entry {account} does not trust this Keys Keeper runtime; "
                    "Keychain UI is disabled for this operation. Use "
                    "`keys keychain prompt` only for an explicit interactive command "
                    "where you want macOS to ask once."
                ) from ex
            raise KeychainError(f"failed to read keychain entry {account}: {ex}") from ex

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
            "-w",
        ]
        if self.keychain_path:
            command.append(self.keychain_path)
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired) as ex:
            raise KeychainError(
                f"trusted legacy Keychain bridge failed for {account}"
            ) from ex
        if result.returncode != 0:
            raise KeychainError(
                f"trusted legacy Keychain bridge failed for {account}"
            )
        raw = result.stdout[:-1] if result.stdout.endswith(b"\n") else result.stdout
        try:
            return Sealed(raw.decode("utf-8"))
        except UnicodeDecodeError as ex:
            raise KeychainError(
                f"failed to decode keychain entry {account}"
            ) from ex

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
