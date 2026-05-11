import pytest
from keys_keeper.models import Entry, EntryType
from keys_keeper.refs import (
    detect_cycles,
    reverse_refs,
    resolve_chain,
    RefCycleError,
    RefMissingError,
)


def _e(name, refs=None, type_=EntryType.SERVER, fields=None):
    return Entry.new(
        name=name,
        type=type_,
        fields=fields or {"host": "x", "user": "y", "auth": "ssh_key"} if type_ == EntryType.SERVER else (
            {"public_key": "ssh-..."} if type_ == EntryType.SSH_KEY else {}
        ),
        refs=refs or [],
    )


def test_detect_cycles_returns_none_for_dag():
    a = _e("aa", refs=[{"role": "ssh_key", "name": "bb"}])
    b = _e("bb", type_=EntryType.SSH_KEY)
    detect_cycles([a, b])  # no error


def test_detect_cycles_raises_on_self_ref():
    a = _e("aa", refs=[{"role": "ssh_key", "name": "aa"}])
    with pytest.raises(RefCycleError):
        detect_cycles([a])


def test_detect_cycles_raises_on_two_node_cycle():
    a = _e("aa", refs=[{"role": "ssh_key", "name": "bb"}])
    b = _e("bb", refs=[{"role": "ssh_key", "name": "aa"}])
    with pytest.raises(RefCycleError):
        detect_cycles([a, b])


def test_reverse_refs_lists_dependents():
    a = _e("aa", refs=[{"role": "ssh_key", "name": "shared-key"}])
    b = _e("bb", refs=[{"role": "ssh_key", "name": "shared-key"}])
    shared = _e("shared-key", type_=EntryType.SSH_KEY)
    rev = reverse_refs([a, b, shared])
    assert set(rev["shared-key"]) == {"aa", "bb"}


def test_resolve_chain_finds_target():
    a = _e("server-a", refs=[{"role": "ssh_key", "name": "k1"}])
    k1 = _e("k1", type_=EntryType.SSH_KEY)
    target = resolve_chain([a, k1], "server-a", "ssh_key")
    assert target.name == "k1"


def test_resolve_chain_missing_raises():
    a = _e("server-a", refs=[{"role": "ssh_key", "name": "missing"}])
    with pytest.raises(RefMissingError):
        resolve_chain([a], "server-a", "ssh_key")
