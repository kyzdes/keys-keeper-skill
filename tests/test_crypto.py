import pytest
from keys_keeper.crypto import encrypt_blob, decrypt_blob, BadPassword


def test_round_trip():
    data = b"hello world"
    sealed = encrypt_blob(data, password="pwd123")
    out = decrypt_blob(sealed, password="pwd123")
    assert out == data


def test_wrong_password_fails():
    sealed = encrypt_blob(b"x", password="right")
    with pytest.raises(BadPassword):
        decrypt_blob(sealed, password="wrong")


def test_format_includes_version_byte():
    sealed = encrypt_blob(b"x", password="p")
    assert sealed[:4] == b"KK1\x00"  # magic + version
