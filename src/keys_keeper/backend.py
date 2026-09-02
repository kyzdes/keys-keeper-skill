"""Cross-platform secret-storage abstraction."""
from __future__ import annotations
from abc import ABC, abstractmethod

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


class MacOSKeychainBackend(KeychainBackend):
    """macOS Keychain backend with native secret-value operations.

    All entries belong to one fixed `service` (default: "keys-keeper").
    The `account` is the entry's UUID id (e.g. "kk:abc..." or "kk:abc:passphrase").
    Use a custom `keychain_path` in tests to avoid touching the user's login keychain.

    Every operation uses Keychain Services in-process. In bypass mode user
    interaction is disabled, so an untrusted item returns a clean error instead
    of opening a system authorization dialog.
    """

    def __init__(
        self,
        *,
        service: str = "keys-keeper",
        keychain_path: str | None = None,
        allow_interaction: bool = True,
    ):
        self.service = service
        self.keychain_path = keychain_path
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
                raise KeychainError(
                    f"keychain entry {account} does not trust this Keys Keeper runtime; "
                    "bypass blocked the authorization dialog. Use `keys keychain prompt` "
                    "only if you want macOS to ask once."
                ) from ex
            raise KeychainError(f"failed to read keychain entry {account}: {ex}") from ex

    def set(self, account: str, value: str) -> None:
        self.delete(account)
        try:
            self._native.add(account, value)
        except (SecurityFrameworkError, UnicodeEncodeError) as ex:
            raise KeychainError(f"failed to set keychain entry {account}") from ex

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
