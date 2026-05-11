import pytest
from datetime import datetime, timezone
from keys_keeper.models import Entry, EntryType, ValidationError, validate_name


def test_validate_name_accepts_valid_slug():
    validate_name("openrouter-cline")
    validate_name("do-prod-droplet")
    validate_name("mysite.com")
    validate_name("stripe_test")


def test_validate_name_rejects_invalid():
    with pytest.raises(ValidationError, match="length"):
        validate_name("a")
    with pytest.raises(ValidationError, match="length"):
        validate_name("x" * 65)
    with pytest.raises(ValidationError, match="characters"):
        validate_name("Has Space")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("UPPER")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("-leading-dash")
    with pytest.raises(ValidationError, match="characters"):
        validate_name("trailing-dash-")


def test_entry_type_enum():
    assert EntryType.API_KEY.value == "api_key"
    assert EntryType.SSH_KEY.value == "ssh_key"
    assert EntryType.SERVER.value == "server"
    assert EntryType.DOMAIN.value == "domain"
    assert EntryType.NOTE.value == "note"


def test_entry_minimal_construction():
    e = Entry(
        id="kk:abc",
        name="openrouter-cline",
        type=EntryType.API_KEY,
        fields={"service": "openrouter"},
        tags=["llm"],
        note="",
        refs=[],
        created_at="2026-05-04T10:00:00Z",
        updated_at="2026-05-04T10:00:00Z",
    )
    assert e.name == "openrouter-cline"
    assert e.type is EntryType.API_KEY


def test_entry_to_dict_round_trip():
    e = Entry(
        id="kk:abc",
        name="do-prod",
        type=EntryType.SERVER,
        fields={"host": "1.2.3.4", "port": 22, "user": "root", "auth": "ssh_key"},
        tags=["prod"],
        note="main",
        refs=[{"role": "ssh_key", "name": "my-do-key"}],
        created_at="2026-05-04T10:00:00Z",
        updated_at="2026-05-04T10:00:00Z",
    )
    d = e.to_dict()
    assert d["type"] == "server"
    assert d["refs"][0]["role"] == "ssh_key"
    e2 = Entry.from_dict(d)
    assert e2 == e


def test_entry_validates_fields_for_type():
    # api_key: service is optional, no other required fields
    Entry.new(name="x-test", type=EntryType.API_KEY, fields={})
    # server: requires host, user, auth
    with pytest.raises(ValidationError, match="host"):
        Entry.new(name="bad-server", type=EntryType.SERVER, fields={})
    # ssh_key: requires public_key
    with pytest.raises(ValidationError, match="public_key"):
        Entry.new(name="bad-ssh", type=EntryType.SSH_KEY, fields={})
    # domain: requires host
    with pytest.raises(ValidationError, match="host"):
        Entry.new(name="bad-dom", type=EntryType.DOMAIN, fields={})
    # note: requires secret_body flag
    Entry.new(name="ok-note", type=EntryType.NOTE, fields={"secret_body": False, "body": "hi"})


def test_entry_new_assigns_uuid_and_timestamps():
    e = Entry.new(name="test-key", type=EntryType.API_KEY, fields={})
    assert e.id.startswith("kk:")
    assert len(e.id) > 10
    assert e.created_at == e.updated_at
