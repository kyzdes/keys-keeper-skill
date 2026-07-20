"""Linux Secret Service keychain backend via the `secret-tool` CLI.

Mirrors `MacOSKeychainBackend`'s shell-out style: instead of Apple's `security`
we drive `secret-tool` (from libsecret-tools), which talks to the desktop's
Secret Service (GNOME Keyring / KWallet) over D-Bus. No new Python dependency —
`secret-tool` is a system package, exactly like `security` on macOS (D-014).

Every entry uses a fixed two-attribute schema:
    service=<service>   account=<entry-id>
so `secret-tool search --all service <service>` enumerates exactly our entries.

The secret value is passed to `secret-tool store` via **stdin**, never argv, so
it is not visible in `ps`/`/proc/<pid>/cmdline` to other local processes.
"""
from __future__ import annotations

import os
import shutil
import subprocess

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed

_SECRET_TOOL = "secret-tool"
_PROBE_ACCOUNT = "kk:__keys-keeper-availability-probe__"


def _secret_tool_path() -> str | None:
    resolved = shutil.which(_SECRET_TOOL)
    return os.path.abspath(resolved) if resolved else None


def secret_service_available(service: str = "keys-keeper") -> bool:
    """True if `secret-tool` is on PATH and a Secret Service daemon answers.

    Used by the composition root to auto-select between this backend and the
    encrypted-file fallback. A missing daemon (headless server) makes
    `secret-tool` exit with a D-Bus error and a non-trivial returncode; an
    empty-but-present keyring returns 0 (or 1 for "no results") quickly.
    """
    executable = _secret_tool_path()
    if executable is None:
        return False
    try:
        result = subprocess.run(
            [
                executable,
                "search",
                "--all",
                "service",
                service,
                "account",
                _PROBE_ACCOUNT,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    # rc 0 = matches found, rc 1 = none found — both mean the daemon answered.
    # Any other rc (e.g. D-Bus "Cannot autolaunch") means no service.
    return result.returncode in (0, 1)


def _parse_accounts(output: str) -> list[str]:
    """Extract entry ids from `secret-tool search --all` output.

    Each match prints a block including a line `attribute.account = <id>`.
    We read only those lines and ignore everything else (notably `secret = ...`).

    NOTE: `secret-tool search` writes the human-readable item dump (labels,
    attributes, created/modified) to **stderr**; stdout carries secret values
    and is deliberately redirected to DEVNULL by callers.
    """
    ids: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("attribute.account = "):
            acct = line[len("attribute.account = "):]
            if acct not in seen:
                seen.add(acct)
                ids.append(acct)
    return ids


class SecretToolBackend(KeychainBackend):
    """Secret Service backend driving the `secret-tool` CLI."""

    def __init__(self, *, service: str = "keys-keeper"):
        self.service = service
        self.executable = _secret_tool_path()
        if self.executable is None:
            raise KeychainError("secret-tool executable not found")

    def _attrs(self, account: str) -> list[str]:
        return ["service", self.service, "account", account]

    def get(self, account: str) -> Sealed:
        result = subprocess.run(
            [self.executable, "lookup", *self._attrs(account)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(f"secret not found: {account}")
        # `secret-tool lookup` prints the value with no trailing newline.
        return Sealed(result.stdout)

    def set(self, account: str, value: str) -> None:
        label = f"keys-keeper: {account}"
        result = subprocess.run(
            [
                self.executable,
                "store",
                "--label",
                label,
                *self._attrs(account),
            ],
            input=value, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise KeychainError(
                f"failed to store secret {account}: {result.stderr.strip()}"
            )

    def delete(self, account: str) -> None:
        # `secret-tool clear` removes all items matching the attributes; a
        # missing entry is a no-op with rc 0, so we don't inspect returncode.
        subprocess.run(
            [self.executable, "clear", *self._attrs(account)],
            capture_output=True, text=True,
        )

    def list_ids(self) -> list[str]:
        result = subprocess.run(
            [self.executable, "search", "--all", "service", self.service],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode not in (0, 1):
            raise KeychainError(
                f"secret-tool search failed: {result.stderr.strip()}"
            )
        # `secret-tool search` prints attributes to stderr. stdout contains
        # secret material and was never captured by this process.
        return _parse_accounts(result.stderr)
