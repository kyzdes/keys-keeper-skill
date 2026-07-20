"""Keychain abstraction. v1 = macOS via `security` CLI."""
from __future__ import annotations
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path


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
        # KNOWN LIMITATION (H3 — argv exposure): the secret is passed as the
        # `-w <value>` argument below, so for the brief lifetime of this child
        # process the plaintext is visible in its argv to other local users via
        # `ps -axww`. The Linux backend avoids this by writing the secret to the
        # `security`-equivalent over stdin; the macOS `security` tool has no
        # stdin-password mode, and the only argv-free alternative — `-w` with no
        # value, which makes `security` prompt on the controlling terminal —
        # was evaluated and rejected because it cannot satisfy this backend's
        # contract:
        #   1. The interactive prompt reads a SINGLE line (tty line discipline),
        #      so it truncates any multi-line secret at the first newline. PEM /
        #      OpenSSH private keys and other multi-line values (see
        #      test_set_multiline_value) would be silently corrupted.
        #   2. Prompt mode requires `-w` to be the literal last argv token, which
        #      is mutually exclusive with passing a `[keychain]` path. That would
        #      force every write onto the user's default login keychain and break
        #      test isolation (and the custom-keychain feature) entirely.
        # A pty-driven prompt was prototyped and confirmed to corrupt multi-line
        # values and ignore the keychain path, so it is NOT shipped: a keychain
        # write that can truncate or mis-target a secret is worse than the argv
        # window. The exposure is bounded to a sub-second child on a machine
        # where a local attacker would, in most threat models, already have the
        # access needed to read the keychain anyway. Revisit if Apple adds a
        # stdin/file password input to `security` (none exists as of macOS 15).
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
