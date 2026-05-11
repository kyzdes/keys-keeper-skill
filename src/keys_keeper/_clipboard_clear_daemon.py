"""Detached daemon that clears the clipboard if its contents still match
a SHA-256 hash provided at spawn time.

Spawned by `keys copy` (CLI) via `clipboard.spawn_clear_after`. Sleeps for
the requested duration, then reads the current clipboard, hashes it, and
only clears if the hash still matches — so we never wipe content the user
copied in the meantime.

The hash on argv is safe (it's a hash, not plaintext); plaintext only
lives in the OS clipboard, never crosses this process's stdin/stdout/argv.
"""
from __future__ import annotations
import hashlib
import sys
import time


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    expected_hash = argv[1]
    try:
        delay = int(argv[2])
    except ValueError:
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
