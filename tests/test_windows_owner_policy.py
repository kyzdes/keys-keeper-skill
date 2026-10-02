"""Platform-independent checks of the native Windows owner boundary."""
import pytest

from keys_keeper import windows_file_security as security


_USER = "S-1-5-21-0-0-0-1234"
_ADMIN = "S-1-5-32-544"
_SYSTEM = "S-1-5-18"
_UNTRUSTED = "S-1-5-32-545"


@pytest.mark.parametrize("owner,default,allow_default,expected", [
    (_USER, _ADMIN, False, True),
    (_ADMIN, _ADMIN, True, True),
    (_SYSTEM, _SYSTEM, True, True),
    (_ADMIN, _ADMIN, False, False),
    (_ADMIN, _USER, True, False),
    (_SYSTEM, _ADMIN, True, False),
    (_UNTRUSTED, _UNTRUSTED, True, False),
    ("S-1-3-4", "S-1-3-4", True, False),
])
def test_only_user_or_trusted_matching_token_default_owner_is_accepted(
    monkeypatch, owner, default, allow_default, expected,
):
    monkeypatch.setattr(security, "current_token_owner_sid", lambda: default)
    assert security._owner_is_current_token(owner, _USER,
                                           allow_default_owner=allow_default) is expected


@pytest.mark.parametrize("sid,trusted,expected", [
    ("S-1-3-4", True, True),
    ("S-1-3-4", False, False),
    (_USER, True, True),
    (_USER, False, False),
    (_SYSTEM, True, True),
    (_ADMIN, True, True),
    ("S-1-1-0", True, False),
    (_UNTRUSTED, True, False),
    ("S-1-3-0", True, False),
    ("S-1-3-44", True, False),
])
def test_only_verified_owner_rights_and_explicit_private_principals_are_allowed(
    sid, trusted, expected,
):
    assert security._allow_sid_is_private(sid, _USER, owner_trusted=trusted) is expected
