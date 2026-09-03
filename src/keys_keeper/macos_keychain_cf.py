"""Private CoreFoundation ownership helpers for macOS Keychain bindings."""

from __future__ import annotations

import ctypes
from typing import Protocol


class _CoreFoundationReleaser(Protocol):
    def CFRelease(self, value: ctypes.c_void_p) -> None: ...


def release_cf_refs(
    core_foundation: _CoreFoundationReleaser,
    *references: ctypes.c_void_p,
) -> None:
    """Release populated owned CF references, ignoring NULL outputs.

    Callers pass references in the same order in which their existing cleanup
    ran. Errors are intentionally not swallowed: hiding an ownership bug would
    make native failure paths less observable.
    """
    for reference in references:
        if reference.value is not None:
            core_foundation.CFRelease(reference)
