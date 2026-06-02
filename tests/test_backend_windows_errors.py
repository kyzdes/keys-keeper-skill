"""Cross-platform unit tests for the Windows backend's error mapping.

These don't touch CredMan — they exercise the pure `_credwrite_error` helper,
so they run on every platform (the module imports off-Windows because the
advapi32 bindings are guarded behind `sys.platform == "win32"`).
"""
from keys_keeper.backend import KeychainError
from keys_keeper.backend_windows import (
    _credwrite_error,
    _ERROR_BAD_LENGTH,
    _ERROR_NOT_ENOUGH_MEMORY,
)


def test_error_8_explains_per_app_credential_limit():
    err = _credwrite_error(_ERROR_NOT_ENOUGH_MEMORY, "keys-keeper:kk:abc", 64)
    assert isinstance(err, KeychainError)
    msg = str(err)
    # The actionable bits: it's the per-app cap, not size, and how to lift it.
    assert "20-credentials-per-app" in msg
    assert "MaxPerAppCredentialNumber" in msg
    assert "credential-limit-per-app" in msg  # docs link
    # Must NOT mislead the user into thinking a 64-byte value was too big.
    assert "too large" not in msg


def test_error_24_reports_blob_too_large():
    err = _credwrite_error(_ERROR_BAD_LENGTH, "keys-keeper:kk:big", 9000)
    msg = str(err)
    assert "too large" in msg
    assert "9000" in msg


def test_unknown_error_falls_through_to_raw_winerror():
    err = _credwrite_error(1312, "keys-keeper:kk:x", 10)
    assert "WinError 1312" in str(err)
