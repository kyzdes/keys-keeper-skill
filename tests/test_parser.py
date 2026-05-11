import pytest
from keys_keeper.parser import parse_bulk, ParsedEntry, ParseError


def test_parse_simple_equals():
    src = "openrouter-cline = sk-or-v1-abc"
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert rows[0].name == "openrouter-cline"
    assert rows[0].value == "sk-or-v1-abc"
    assert rows[0].type == "api_key"
    assert rows[0].tags == []
    assert rows[0].error is None


def test_parse_colon_separator():
    rows = parse_bulk("foo: bar")
    assert rows[0].value == "bar"


def test_parse_with_inline_tags():
    rows = parse_bulk("k1 = v1 [llm,personal]")
    assert rows[0].tags == ["llm", "personal"]


def test_parse_with_explicit_type():
    rows = parse_bulk("my-key (ssh_key) = something")
    assert rows[0].type == "ssh_key"


def test_parse_skips_comments_and_blanks():
    src = "# comment\n\nfoo = bar\n# another\n"
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert rows[0].name == "foo"


def test_parse_multiline_triple_quote():
    src = '''my-pem (ssh_key) = """
-----BEGIN PRIVATE KEY-----
linetwo
-----END-----
"""'''
    rows = parse_bulk(src)
    assert len(rows) == 1
    assert "BEGIN PRIVATE KEY" in rows[0].value
    assert "linetwo" in rows[0].value
    assert rows[0].type == "ssh_key"


def test_parse_unclosed_multiline_is_error():
    src = 'my-pem = """\nline1\n'
    rows = parse_bulk(src)
    assert rows[0].error is not None
    assert "unclosed" in rows[0].error.lower() or "multiline" in rows[0].error.lower()


def test_parse_invalid_name_recorded_as_error():
    rows = parse_bulk("Bad Name = v")
    assert rows[0].error is not None


def test_parse_returns_line_numbers():
    src = "a = 1\nb = 2\n"
    rows = parse_bulk(src)
    assert rows[0].line == 1
    assert rows[1].line == 2
