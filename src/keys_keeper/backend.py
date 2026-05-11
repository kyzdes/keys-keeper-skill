"""Keychain abstraction. v1 = macOS via `security` CLI."""
from __future__ import annotations
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path


class KeychainError(RuntimeError):
    """Raised when keychain ops fail (not found, access denied, etc)."""


class Sealed:
    """A plaintext secret that refuses to render itself.

    The product's central guarantee is that AI agents cannot leak secret
    values into their transcripts. The keychain backend returns Sealed
    instead of bare str so an accidental f-string, print, log line, or
    repr in a debug session prints "<sealed>" instead of the value.
    Plaintext is only produced via the explicit `.unseal()` call —
    grep -rn "\\.unseal()" enumerates every site where a secret leaves
    its envelope.
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
    """Wraps the macOS `security` CLI.

    All entries belong to one fixed `service` (default: "keys-keeper").
    The `account` is the entry's UUID id (e.g. "kk:abc..." or "kk:abc:passphrase").
    Use a custom `keychain_path` in tests to avoid touching the user's login keychain.
    """

    def __init__(self, *, service: str = "keys-keeper", keychain_path: str | None = None):
        self.service = service
        self.keychain_path = keychain_path

    def _kc_args(self) -> list[str]:
        return [self.keychain_path] if self.keychain_path else []

    def get(self, account: str) -> Sealed:
        # Use `-g` so we can detect non-printable / multi-line values via the
        # `password: 0x<HEX>  "<octal>"` form on stderr. Plain printable values
        # come back via `-w` on stdout verbatim; hex-encoded ones (anything
        # containing a newline or other non-printable byte) we decode from the
        # `0x` prefix on stderr.
        result = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", self.service, "-a", account,
                "-g",
                *self._kc_args(),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"keychain entry not found: {account}")
        # stderr starts with either `password: "literal"\n` or
        # `password: 0xHEX  "octal-form"\n`. Prefer the hex form when present.
        first_line = result.stderr.splitlines()[0] if result.stderr else ""
        if first_line.startswith("password: 0x"):
            hex_part = first_line[len("password: 0x"):]
            # hex runs until a space (the tail is `  "octal"` for display)
            hex_str = hex_part.split(" ", 1)[0]
            try:
                return Sealed(bytes.fromhex(hex_str).decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as e:
                raise KeychainError(
                    f"failed to decode keychain entry {account}: {e}"
                )
        # Plain printable value — read from `-w` for an unambiguous string.
        plain = subprocess.run(
            [
                "security", "find-generic-password",
                "-s", self.service, "-a", account,
                "-w",
                *self._kc_args(),
            ],
            capture_output=True, text=True,
        )
        if plain.returncode != 0:
            raise KeychainError(f"keychain entry not found: {account}")
        return Sealed(plain.stdout.rstrip("\n"))

    def set(self, account: str, value: str) -> None:
        # delete first to avoid duplicate entries
        self.delete(account)
        result = subprocess.run(
            [
                "security", "add-generic-password",
                "-s", self.service, "-a", account, "-w", value,
                "-U",  # update if exists (belt-and-suspenders)
                *self._kc_args(),
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"failed to set keychain entry {account}: {result.stderr.strip()}")

    def delete(self, account: str) -> None:
        subprocess.run(
            ["security", "delete-generic-password", "-s", self.service, "-a", account, *self._kc_args()],
            capture_output=True, text=True,
        )
        # ignore returncode — missing entry is fine

    def list_ids(self) -> list[str]:
        # `security dump-keychain` is heavy + verbose; we use a more targeted approach
        # by parsing `security find-generic-password` repeatedly is impractical too.
        # Instead, dump all generic passwords for our service via dump-keychain.
        result = subprocess.run(
            ["security", "dump-keychain", *self._kc_args()],
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
