"""Sealed wrapper — the structural guard behind 'AI agents cannot leak'.

These tests pin the rendering invariants. If any of them break, an
accidental f-string or print of a Sealed value would leak plaintext
into a transcript. That is the whole reason this class exists.
"""
from keys_keeper.backend import Sealed


def test_repr_does_not_leak():
    s = Sealed("sk-very-secret-key")
    assert repr(s) == "<sealed>"
    assert "sk-very-secret-key" not in repr(s)


def test_str_does_not_leak():
    s = Sealed("sk-very-secret-key")
    assert str(s) == "<sealed>"
    assert "sk-very-secret-key" not in str(s)


def test_fstring_does_not_leak():
    s = Sealed("sk-very-secret-key")
    rendered = f"value is {s}"
    assert "sk-very-secret-key" not in rendered
    assert "<sealed>" in rendered


def test_format_does_not_leak():
    s = Sealed("sk-very-secret-key")
    assert "sk-very-secret-key" not in "{}".format(s)
    assert "sk-very-secret-key" not in "{!r}".format(s)
    assert "sk-very-secret-key" not in "{!s}".format(s)


def test_unseal_returns_plaintext():
    s = Sealed("sk-very-secret-key")
    assert s.unseal() == "sk-very-secret-key"


def test_len_works_without_unseal():
    # Truthy/length checks shouldn't require an unseal — useful for "is this
    # secret empty?" without producing the value.
    s = Sealed("hello")
    assert len(s) == 5
    assert bool(s) is True
    assert bool(Sealed("")) is False


def test_eq_compares_sealed_to_sealed():
    a = Sealed("x")
    b = Sealed("x")
    c = Sealed("y")
    assert a == b
    assert a != c


def test_eq_to_bare_string_is_false():
    # Comparing a Sealed to a raw str is a code smell — typically means the
    # caller forgot to .unseal(). Returning False makes that visible in tests.
    s = Sealed("x")
    assert s != "x"
    assert "x" != s
