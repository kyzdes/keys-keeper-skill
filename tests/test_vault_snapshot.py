"""Shared snapshot and deterministic merge contracts, independent of a transport."""
from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from _vault_fakes import FakeBackend, add_entry
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.vault_snapshot import (
    build_snapshot_payload, content_hash, decrypt_snapshot, encrypt_snapshot,
    merge, prepare_snapshot_payload,
)


def test_merge_tombstone_vs_resurrect_unit():
    e = Entry.new(name="xx", type=EntryType.API_KEY)
    older = "2026-06-01T00:00:00Z"
    newer = "2026-06-02T00:00:00Z"
    live = Entry.from_dict({**e.to_dict(), "updated_at": newer})
    # tombstone older than a live edit -> resurrected
    res = merge([live], [], [], [{"id": e.id, "name": "xx", "deleted_at": older}])
    assert [x.id for x in res.entries] == [e.id]
    # tombstone newer than (or equal to) the live edit -> stays deleted
    res2 = merge([live], [], [], [{"id": e.id, "name": "xx", "deleted_at": newer}])
    assert res2.entries == []
    assert any(t["id"] == e.id for t in res2.tombstones)



def test_merge_remote_delete_vs_local_update_timestamp_boundaries():
    entry = Entry.new(name="remote-delete", type=EntryType.API_KEY)
    older = "2026-06-01T00:00:00Z"
    equal = "2026-06-02T00:00:00Z"
    local = Entry.from_dict({**entry.to_dict(), "updated_at": equal})

    older_delete = {"id": entry.id, "name": entry.name, "deleted_at": older}
    live_result = merge([local], [], [], [older_delete])
    assert [item.id for item in live_result.entries] == [entry.id]
    assert live_result.tombstones == []
    assert live_result.remote_win_ids == set()
    assert live_result.secret_delete_ids == set()
    assert live_result.changed is False

    equal_delete = {"id": entry.id, "name": entry.name, "deleted_at": equal}
    deleted_result = merge([local], [], [], [equal_delete])
    assert deleted_result.entries == []
    assert deleted_result.tombstones == [equal_delete]
    assert deleted_result.remote_win_ids == set()
    assert deleted_result.secret_delete_ids == {entry.id}
    assert deleted_result.changed is True



def test_merge_local_delete_vs_remote_update_timestamp_boundaries():
    entry = Entry.new(name="local-delete", type=EntryType.API_KEY)
    delete_ts = "2026-06-02T00:00:00Z"
    newer = "2026-06-03T00:00:00Z"
    local_delete = {
        "id": entry.id,
        "name": entry.name,
        "deleted_at": delete_ts,
    }

    remote_newer = Entry.from_dict({**entry.to_dict(), "updated_at": newer})
    live_result = merge([], [local_delete], [remote_newer], [])
    assert [item.id for item in live_result.entries] == [entry.id]
    assert live_result.tombstones == []
    assert live_result.remote_win_ids == {entry.id}
    assert live_result.secret_delete_ids == set()
    assert live_result.changed is True

    remote_equal = Entry.from_dict({**entry.to_dict(), "updated_at": delete_ts})
    deleted_result = merge([], [local_delete], [remote_equal], [])
    assert deleted_result.entries == []
    assert deleted_result.tombstones == [local_delete]
    assert deleted_result.remote_win_ids == set()
    assert deleted_result.secret_delete_ids == set()
    assert deleted_result.changed is False



def test_merge_latest_tombstone_prefers_local_on_equal_timestamp():
    entry = Entry.new(name="tombstone-order", type=EntryType.API_KEY)
    equal = "2026-06-02T00:00:00Z"
    newer = "2026-06-03T00:00:00Z"
    local = {"id": entry.id, "name": "local-name", "deleted_at": equal}
    remote_equal = {"id": entry.id, "name": "remote-name", "deleted_at": equal}
    remote_newer = {"id": entry.id, "name": "remote-name", "deleted_at": newer}

    equal_result = merge([], [local], [], [remote_equal])
    assert equal_result.tombstones == [local]

    newer_result = merge([], [local], [], [remote_newer])
    assert newer_result.tombstones == [remote_newer]



def test_merge_disjoint_entries_has_deterministic_id_order():
    ids = [
        "kk:00000000-0000-4000-8000-000000000001",
        "kk:00000000-0000-4000-8000-000000000002",
        "kk:00000000-0000-4000-8000-000000000003",
        "kk:00000000-0000-4000-8000-000000000004",
    ]
    entries = [
        Entry.new(name=f"order-{index}", type=EntryType.API_KEY)
        for index in range(4)
    ]
    for entry, id_ in zip(entries, ids, strict=True):
        entry.id = id_

    result = merge([entries[2], entries[0]], [], [entries[3], entries[1]], [])
    reversed_result = merge(
        [entries[0], entries[2]],
        [],
        [entries[1], entries[3]],
        [],
    )

    assert [entry.id for entry in result.entries] == ids
    assert [entry.to_dict() for entry in reversed_result.entries] == [
        entry.to_dict() for entry in result.entries
    ]
    assert result.remote_win_ids == reversed_result.remote_win_ids == {
        ids[1],
        ids[3],
    }
    assert result.tombstones == reversed_result.tombstones == []
    assert result.changed is True



def test_lww_newer_updated_at_wins():
    e = Entry.new(name="xx", type=EntryType.API_KEY)
    local = Entry.from_dict({**e.to_dict(), "updated_at": "2026-06-01T00:00:00Z", "note": "L"})
    remote = Entry.from_dict({**e.to_dict(), "updated_at": "2026-06-02T00:00:00Z", "note": "R"})
    res = merge([local], [], [remote], [])
    assert res.entries[0].note == "R"
    assert e.id in res.remote_win_ids



def test_tiebreak_is_commutative_for_same_second_edits():
    e = Entry.new(name="xx", type=EntryType.API_KEY)
    ts = "2026-06-02T00:00:00Z"
    a = Entry.from_dict({**e.to_dict(), "updated_at": ts, "note": "aaa"})
    b = Entry.from_dict({**e.to_dict(), "updated_at": ts, "note": "bbb"})
    r1 = merge([a], [], [b], [])
    r2 = merge([b], [], [a], [])
    assert r1.entries[0].note == r2.entries[0].note  # same winner regardless of order



def test_name_collision_keeps_both(tmp_path):
    # two DISTINCT ids with the same name must both survive, disambiguated
    e1 = Entry.new(name="dup", type=EntryType.API_KEY)
    e2 = Entry.new(name="dup", type=EntryType.API_KEY)
    res = merge([e1], [], [e2], [])
    assert len(res.entries) == 2
    assert len({x.name for x in res.entries}) == 2   # names disambiguated
    assert {x.id for x in res.entries} == {e1.id, e2.id}



def test_content_hash_distinguishes_missing_and_empty_secret_components():
    entry = Entry.new(name="hash-contract", type=EntryType.API_KEY).to_dict()
    payload = {"entries": [entry], "tombstones": []}
    pairs = [(None, None), ("", None), (None, ""), ("", ""),
             ("synthetic-secret", None), ("synthetic-secret", "")]
    digests = []
    for primary, optional in pairs:
        candidate = copy.deepcopy(payload)
        candidate["entries"][0].update(_secret=primary, _secret_passphrase=optional)
        digests.append(content_hash(candidate))
    assert len(set(digests)) == len(pairs)
    assert all(len(digest) == 64 for digest in digests)


def test_snapshot_preparation_reads_each_account_once_and_captures_exact_revision(tmp_path, monkeypatch):
    class TrackedBackend(FakeBackend):
        def __init__(self):
            super().__init__()
            self.reads = []
            self.enumerations = 0

        def list_ids(self):
            self.enumerations += 1
            return super().list_ids()

        def get(self, account):
            self.reads.append(account)
            return super().get(account)

    store = MetadataStore(Paths(tmp_path / "synthetic"))
    backend = TrackedBackend()
    device = SimpleNamespace(store=store, backend=backend)
    key = add_entry(device, "key", "")
    ssh = Entry.new(name="ssh", type=EntryType.SSH_KEY,
                    fields={"public_key": "ssh-ed25519 synthetic"})
    store.add(ssh)
    backend.set(ssh.id, "synthetic-private-key")
    backend.set(ssh.id + ":passphrase", "")
    domain = Entry.new(name="domain", type=EntryType.DOMAIN, fields={"host": "example.test"})
    store.add(domain)
    backend.set("kk:project-runtime-key", "synthetic-reserved-value")
    expected_revision = store.snapshot().revision
    snapshots = []
    original_snapshot = store.snapshot

    def tracked_snapshot():
        snapshot = original_snapshot()
        snapshots.append(snapshot)
        return snapshot

    monkeypatch.setattr(store, "snapshot", tracked_snapshot)
    payload, revision = prepare_snapshot_payload(store, backend)

    assert len(snapshots) == 1
    assert revision == snapshots[0].revision == expected_revision
    assert backend.enumerations == 1
    assert backend.reads == [key.id, ssh.id, ssh.id + ":passphrase"]
    records = {entry["id"]: entry for entry in payload["entries"]}
    assert records[key.id]["_secret"] == ""
    assert records[ssh.id]["_secret_passphrase"] == ""
    assert records[domain.id]["_secret"] is None
    assert "kk:project-runtime-key" not in records


def test_shared_snapshot_codec_keeps_kk1_export_compatible(tmp_path):
    store, backend = MetadataStore(Paths(tmp_path / "synthetic")), FakeBackend()
    entry = add_entry(SimpleNamespace(store=store, backend=backend), "key", "synthetic-value")
    payload = build_snapshot_payload(store, backend)
    blob = encrypt_snapshot(payload, passphrase="synthetic-password")
    assert blob.startswith(b"KK1\x00")
    assert b"synthetic-value" not in blob
    restored = decrypt_snapshot(blob, passphrase="synthetic-password")
    assert restored == payload
    assert restored["entries"][0]["id"] == entry.id


def test_merge_reserves_preexisting_generated_suffix_and_renames_only_loser():
    older = Entry.new(name="same", type=EntryType.API_KEY)
    older.id = "kk:12345600-0000-4000-8000-000000000001"
    older.updated_at = "2026-01-01T00:00:00Z"
    newer = Entry.new(name="same", type=EntryType.API_KEY)
    newer.updated_at = "2026-01-02T00:00:00Z"
    occupied = Entry.new(name="same-123456", type=EntryType.API_KEY)

    result = merge([older], [], [newer, occupied], [])
    names = {entry.id: entry.name for entry in result.entries}

    assert len(set(names.values())) == 3
    assert names[newer.id] == newer.name
    assert names[occupied.id] == occupied.name
    assert names[older.id] not in {newer.name, occupied.name}
    assert {entry.id for entry in result.entries} == {older.id, newer.id, occupied.id}


def test_merge_duplicate_id_prefixes_and_long_names_are_deterministic_under_permutations():
    from itertools import permutations
    from keys_keeper.models import validate_name

    prefix = "long" * 14
    local, remote = [], []
    for index, ending in enumerate(("alpha", "beta"), start=1):
        older = Entry.new(name=prefix + ending, type=EntryType.API_KEY)
        older.id = f"kk:12345600-0000-4000-8000-{index:012d}"
        older.updated_at = "2026-01-01T00:00:00Z"
        newer = Entry.from_dict({**older.to_dict(),
                                "id": f"kk:65432100-0000-4000-8000-{index:012d}",
                                "updated_at": "2026-01-02T00:00:00Z"})
        local.append(older)
        remote.append(newer)
    occupied = Entry.new(name=prefix + "-123456", type=EntryType.API_KEY)
    local.append(occupied)
    baseline = merge(local, [], remote, [])
    expected = [entry.to_dict() for entry in baseline.entries]

    assert len({entry.name for entry in baseline.entries}) == len(local) + len(remote)
    by_id = {entry.id: entry.name for entry in baseline.entries}
    assert by_id[occupied.id] == occupied.name
    assert all(by_id[entry.id] == entry.name for entry in remote)
    for entry in baseline.entries:
        assert len(entry.name) <= 64
        validate_name(entry.name)
    for local_order in permutations(local):
        for remote_order in permutations(remote):
            result = merge(list(local_order), [], list(remote_order), [])
            assert [entry.to_dict() for entry in result.entries] == expected
            assert result.remote_win_ids == baseline.remote_win_ids
            assert result.tombstones == []


def _referenced_collision():
    target = Entry.new(name="shared-key", type=EntryType.SSH_KEY,
                       fields={"public_key": "ssh-ed25519 synthetic-local"})
    target.updated_at = "2026-01-01T00:00:00Z"
    dependent = Entry.new(name="server", type=EntryType.SERVER,
                          fields={"host": "host.example.test", "user": "synthetic", "auth": "ssh_key"},
                          refs=[{"name": target.name, "role": "ssh_key"}])
    newer = Entry.new(name=target.name, type=EntryType.SSH_KEY,
                      fields={"public_key": "ssh-ed25519 synthetic-other"})
    newer.updated_at = "2026-01-02T00:00:00Z"
    return target, dependent, newer


def test_merge_rejects_source_reference_substitution_after_local_or_remote_collision_rename():
    from keys_keeper.vault_snapshot import MergeReferenceConflict

    target, dependent, newer = _referenced_collision()
    bound = [target, dependent]
    other = [newer]
    original = [entry.to_dict() for entry in bound + other]
    for local, remote in ((bound, other), (other, bound)):
        with pytest.raises(MergeReferenceConflict) as failure:
            merge(local, [], remote, [])
        assert str(failure.value) == (
            "vault merge would redirect an existing credential reference; "
            "resolve conflicting names before syncing"
        )
    assert [entry.to_dict() for entry in bound + other] == original


def test_merge_preserves_reference_already_bound_to_name_winner():
    from keys_keeper.refs import resolve_chain

    target, dependent, newer = _referenced_collision()
    result = merge([target], [], [newer, dependent], [])
    assert resolve_chain(result.entries, dependent.name, "ssh_key").id == newer.id
    assert len({entry.name for entry in result.entries}) == 3


def test_merge_rejects_tombstone_recreation_substitution_but_preserves_dangling_reference_contract():
    from keys_keeper.vault_snapshot import MergeReferenceConflict

    target, dependent, newer = _referenced_collision()
    tombstone = {"id": target.id, "name": target.name, "deleted_at": "2026-01-03T00:00:00Z"}
    with pytest.raises(MergeReferenceConflict):
        merge([target, dependent], [], [newer], [tombstone])
    result = merge([target, dependent], [], [], [tombstone])
    assert [entry.id for entry in result.entries] == [dependent.id]
    assert result.entries[0].refs == dependent.refs
    assert result.tombstones == [tombstone]
