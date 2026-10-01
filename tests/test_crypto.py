import pytest
from keys_keeper.crypto import encrypt_blob, decrypt_blob, BadPassword
from keys_keeper import crypto


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


@pytest.mark.parametrize("blob", [b"", b"KK1\x00", b"KK1\x00" + b"x" * 43])
def test_malformed_header_fails_before_derivation(blob, monkeypatch):
    def unexpected_derive(*_args):
        pytest.fail("malformed encrypted blob must not invoke PBKDF2")

    monkeypatch.setattr(crypto, "_derive_key", unexpected_derive)
    with pytest.raises(BadPassword):
        decrypt_blob(blob, password="unused")
