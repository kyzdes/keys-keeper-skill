"""Keychain abstraction. v1 = macOS via `security` CLI."""
from __future__ import annotations
import subprocess
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

    Writes use Keychain Services directly, keeping values out of process argv.
    Reads and deletes retain the fixed system ``security`` executable so legacy
    items keep their existing ACL behavior. Native writes explicitly trust that
    executable; no per-upgrade Keychain approval is required.
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

    def _kc_args(self) -> list[str]:
        return [self.keychain_path] if self.keychain_path else []

    def get(self, account: str) -> Sealed:
        # `-g` emits non-printable/multiline values as an exact hex encoding;
        # `-w` provides an unambiguous printable value. Both outputs are private
        # pipes, never argv or inherited terminal streams.
        result = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                self.service,
                "-a",
                account,
                "-g",
                *self._kc_args(),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"keychain entry not found: {account}")
        first_line = result.stderr.splitlines()[0] if result.stderr else ""
        if first_line.startswith("password: 0x"):
            hex_part = first_line[len("password: 0x"):]
            hex_string = hex_part.split(" ", 1)[0]
            try:
                return Sealed(bytes.fromhex(hex_string).decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as ex:
                raise KeychainError(
                    f"failed to decode keychain entry {account}"
                ) from ex
        plain = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-s",
                self.service,
                "-a",
                account,
                "-w",
                *self._kc_args(),
            ],
            capture_output=True,
            text=True,
        )
        if plain.returncode != 0:
            raise KeychainError(f"keychain entry not found: {account}")
        return Sealed(plain.stdout.rstrip("\n"))

    def set(self, account: str, value: str) -> None:
        # The system CLI can delete legacy items under their existing ACL. The
        # replacement value is then created natively, never through `-w VALUE`.
        self.delete(account)
        try:
            self._native.add(account, value)
        except (SecurityFrameworkError, UnicodeEncodeError) as ex:
            raise KeychainError(f"failed to set keychain entry {account}") from ex

    def delete(self, account: str) -> None:
        result = subprocess.run(
            [
                "/usr/bin/security",
                "delete-generic-password",
                "-s",
                self.service,
                "-a",
                account,
                *self._kc_args(),
            ],
            capture_output=True,
            text=True,
        )
        # macOS maps errSecItemNotFound (-25300) to process status 44. Missing
        # entries are an intentional no-op; any other failure must stop a
        # metadata deletion or replacement instead of leaving an orphan.
        if result.returncode not in (0, 44):
            raise KeychainError(f"failed to delete keychain entry {account}")

    def list_ids(self) -> list[str]:
        # `security dump-keychain` is heavy + verbose; we use a more targeted approach
        # by parsing `security find-generic-password` repeatedly is impractical too.
        # Instead, dump all generic passwords for our service via dump-keychain.
        result = subprocess.run(
            ["/usr/bin/security", "dump-keychain", *self._kc_args()],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return []
        ids: list[str] = []
        current_service = None
        current_account = None
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith('"svce"<blob>='):
                current_service = _extract_attr(line)
            elif line.startswith('"acct"<blob>='):
                current_account = _extract_attr(line)
            elif line.startswith("class:"):
                # next entry starts; flush the previous one
                if current_service == self.service and current_account:
                    ids.append(current_account)
                current_service = None
                current_account = None
        # flush final
        if current_service == self.service and current_account:
            ids.append(current_account)
        return ids


def _extract_attr(line: str) -> str | None:
    # line looks like: "svce"<blob>="keys-keeper-test"
    if '="' in line and line.endswith('"'):
        return line.split('="', 1)[1][:-1]
    return None
