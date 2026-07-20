"""Detached daemon that clears the clipboard if its contents still match.

Spawned by `keys copy` (CLI) via `clipboard.spawn_clear_after`. It reads the
expected SHA-256 digest from a private stdin pipe before sleeping, then hashes
the current clipboard and only clears if the digest still matches. This avoids
wiping content the user copied in the meantime.

The digest can act as an offline verifier for a weak clipboard value, so it is
never placed in argv. Plaintext only lives in the OS clipboard.
"""
from __future__ import annotations
import hashlib
import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        return 2
    try:
        delay = int(argv[1])
    except ValueError:
        return 2
    if delay < 0:
        return 2
    expected_hash = sys.stdin.readline(66).strip()
    if len(expected_hash) != 64 or any(
        ch not in "0123456789abcdef" for ch in expected_hash
    ):
        return 2
    if delay > 0:
        time.sleep(delay)
    from keys_keeper import clipboard
    current = clipboard.read()
    current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
    if current_hash == expected_hash:
        clipboard.clear()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
