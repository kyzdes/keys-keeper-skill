"""Sync engine — offline, FakeRemote + FakeBackend. The correctness core."""
import json

import pytest
from _sync_fakes import (
    FakeBackend,
    FakeRemote,
    NonCasRemote,
    RaceOnceRemote,
    add_entry,
    live_ids,
    make_device,
    names,
)

from keys_keeper.backend import KeychainError
from keys_keeper.models import Entry, EntryType
from keys_keeper.service import VaultService
from keys_keeper.sync import (
    SnapshotValidationError,
    content_hash,
    encrypt_snapshot,
    merge,
    vkey,
)
from keys_keeper.sync_remote import TransportError

PW = "correct horse battery staple"


# ---------- push / pull basics ----------

def test_push_creates_version_snapshot_and_head(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "api-one", "sk-AAA")
    pushed = a.engine.push(PW)
    assert pushed == 1
    assert vkey(1) in r.objs
    assert any(k.startswith("snapshots/000001-A") for k in r.objs)
    assert json.loads(r.objs["HEAD"])["version"] == 1


def test_pull_is_idempotent_no_duplicates(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "api-one", "sk-AAA")
    a.engine.push(PW)
    b = make_device(r, tmp_path, "B")
    assert b.engine.pull(PW) == 1
    before = b.paths.data_json.read_text()
    assert b.engine.pull(PW) == 0           # no change on re-pull
    assert b.paths.data_json.read_text() == before
    assert names(b) == ["api-one"]          # exactly one, no duplicate
    assert b.backend.d  # secret materialised on B


def test_pull_rejects_reserved_account_before_local_mutation(tmp_path):
    remote = FakeRemote()
    source = make_device(remote, tmp_path, "source")
    add_entry(source, "safe-entry", "sk-safe")
    source.engine.push(PW)

    commit = json.loads(remote.objs[vkey(1)])
    malicious = {
        "schema_version": 2,
        "entries": [{
            "id": "kk:sync-passphrase",
            "name": "attacker-entry",
            "type": "api_key",
            "fields": {},
            "tags": [],
            "note": "",
            "refs": [],
            "created_at": "2026-07-20T00:00:00Z",
            "updated_at": "2026-07-20T00:00:00Z",
            "_secret": "overwrite-attempt",
            "_secret_passphrase": None,
        }],
        "tombstones": [],
    }
    remote.objs[commit["snapshot"]] = encrypt_snapshot(malicious, passphrase=PW)
    commit["entries_hash"] = content_hash(malicious)
    remote.objs[vkey(1)] = json.dumps(commit).encode()

    target = make_device(remote, tmp_path, "target")
    with pytest.raises(SnapshotValidationError, match="reserved"):
        target.engine.pull(PW)
    assert target.store.list() == []
    assert target.backend.d == {}


def test_no_empty_commit(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "api-one", "sk-AAA")
    a.engine.push(PW)
    assert a.engine.push(PW) == 0           # nothing changed
    assert vkey(2) not in r.objs            # F42: no empty version


# ---------- convergence / concurrency ----------

def test_two_device_convergence_no_lost_entries(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    b = make_device(r, tmp_path, "B")
    ea = add_entry(a, "from-a", "sk-A")
    eb = add_entry(b, "from-b", "sk-B")
    a.engine.push(PW)            # v1: {ea}
    b.engine.push(PW)            # pulls ea, then v2: {ea, eb}
    a.engine.pull(PW)           # gets eb
    assert live_ids(a) == live_ids(b) == {ea.id, eb.id}
    assert a.backend.d[eb.id] == "sk-B"      # A materialised B's secret
    assert b.backend.d[ea.id] == "sk-A"


def test_concurrent_cas_retry_survives_race(tmp_path):
    r = RaceOnceRemote()
    a = make_device(r, tmp_path, "A")
    b = make_device(r, tmp_path, "B")
    ea = add_entry(a, "from-a", "sk-A")
    eb = add_entry(b, "from-b", "sk-B")
    # When A first tries to commit v1, B wins the race by committing v1 first.
    r.on_first_commit = lambda: b.engine.push(PW)
    a.engine.push(PW)            # 412 -> re-pull B's v1, merge, commit v2
    assert r._fired is True
    a.engine.pull(PW)
    # No lost entries: both survive across the race.
    assert live_ids(a) == {ea.id, eb.id}
    assert a.engine._current_tip().version == 2


# ---------- deletes / tombstones ----------

def test_delete_propagates_and_does_not_resurrect(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    e = add_entry(a, "doomed", "sk-AAA")
    a.engine.push(PW)                 # v1 has the entry
    b = make_device(r, tmp_path, "B")
    b.engine.pull(PW)
    assert names(b) == ["doomed"]
    # A deletes, pushes v2 (carries the tombstone)
    a.store.delete_by_name("doomed")
    a.backend.delete(e.id)
    a.engine.push(PW)
    # B pulls -> entry gone, secret purged, tombstone present
    b.engine.pull(PW)
    assert names(b) == []
    assert e.id not in b.backend.d
    assert any(t["id"] == e.id for t in b.store.tombstones())
    # re-pull never resurrects
    b.engine.pull(PW)
    assert names(b) == []


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


# ---------- LWW + tiebreak ----------

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


# ---------- rollback / gc ----------

def test_rollback_restores_prior_snapshot(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                       # v1 = {first}
    add_entry(a, "second", "sk-2")
    a.engine.push(PW)                       # v2 = {first, second}
    assert sorted(names(a)) == ["first", "second"]
    a.engine.rollback(1, PW)                # back to {first}, published as v3
    assert names(a) == ["first"]
    assert a.engine._current_tip().version == 3


def test_gc_keeps_newest_and_preserves_head(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A", retain=3)
    for i in range(5):
        add_entry(a, f"k{i}", f"sk-{i}")
        a.engine.push(PW)
    # gc runs inside push; after 5 commits with retain=3, 2 oldest are gone
    remaining = sorted(int(k.split("/")[1][:6]) for k in r.objs if k.startswith("versions/"))
    assert remaining == [3, 4, 5]
    assert json.loads(r.objs["HEAD"])["version"] == 5
    tip = a.engine._current_tip()           # HEAD lineage intact
    assert tip.version == 5


# ---------- security invariants ----------

def test_commit_object_has_no_entry_fields(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "secret-name", "sk-SENSITIVE")
    a.engine.push(PW)
    commit = json.loads(r.objs[vkey(1)])
    assert set(commit) <= {"version", "parent", "device", "ts", "snapshot", "entries_hash"}
    raw = json.dumps(commit)
    assert "secret-name" not in raw and "sk-SENSITIVE" not in raw


def test_every_snapshot_upload_is_encrypted(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "key", "sk-PLAINTEXT")
    a.engine.push(PW)
    for key, body in r.objs.items():
        if key.startswith("snapshots/"):
            assert body[:4] == b"KK1\x00"           # S1
            assert b"sk-PLAINTEXT" not in body       # encrypted, not plaintext
            assert b"secret-name" not in body


def test_merge_keychain_failure_leaves_metadata_untouched(tmp_path):
    # source device with two secrets
    r = FakeRemote()
    src = make_device(r, tmp_path, "SRC")
    add_entry(src, "one", "sk-1")
    add_entry(src, "two", "sk-2")
    src.engine.push(PW)
    # victim pulls with a backend that fails on the 2nd secret write
    victim = make_device(r, tmp_path, "V", backend=FakeBackend(fail_after=1))
    with pytest.raises(KeychainError):
        victim.engine.pull(PW)
    # F21: metadata was NOT applied (no partial state)
    assert victim.store.list() == []


# ---------- review-driven regression tests ----------

def test_owns_commit_detects_foreign_winner(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "k1", "s1")
    a.engine.push(PW)
    import json as _json
    commit = _json.loads(r.objs[vkey(1)])
    assert a.engine._owns_commit(1, commit) is True
    foreign = dict(commit, device="OTHER", ts="2099-01-01T00:00:00Z")
    assert a.engine._owns_commit(1, foreign) is False


def test_noncas_provider_two_device_convergence(tmp_path):
    # Provider ignores If-None-Match; sequential pushes still converge via the
    # read-back path, with no lost entries.
    r = NonCasRemote()
    a = make_device(r, tmp_path, "A", cas=False)
    b = make_device(r, tmp_path, "B", cas=False)
    ea = add_entry(a, "from-a", "sk-A")
    eb = add_entry(b, "from-b", "sk-B")
    a.engine.push(PW)
    b.engine.push(PW)
    a.engine.pull(PW)
    assert live_ids(a) == live_ids(b) == {ea.id, eb.id}


def test_dangling_head_self_heals(tmp_path):
    # HEAD points at a version whose commit object is gone; engine recovers by
    # listing the real versions (KI #4).
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "k1", "s1")
    a.engine.push(PW)                # v1
    import json as _json
    r.objs["HEAD"] = _json.dumps({"version": 99, "snapshot": "snapshots/gone.kk"}).encode()
    tip = a.engine._current_tip()    # must not raise; falls back to v1
    assert tip is not None and tip.version == 1


def test_empty_first_push_creates_no_version(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    assert a.engine.push(PW) == 0    # empty vault, no remote tip
    assert all(not k.startswith("versions/") for k in r.objs)   # F42


def test_keychain_failure_leaves_no_orphan_secrets(tmp_path):
    # On a mid-merge KeychainError, secrets written this attempt are rolled back
    # so none are orphaned (KI #8).
    r = FakeRemote()
    src = make_device(r, tmp_path, "SRC")
    add_entry(src, "one", "sk-1")
    add_entry(src, "two", "sk-2")
    src.engine.push(PW)
    victim = make_device(r, tmp_path, "V", backend=FakeBackend(fail_after=1))
    with pytest.raises(KeychainError):
        victim.engine.pull(PW)
    assert victim.store.list() == []
    assert victim.backend.d == {}    # no orphan secret left behind


def test_pull_retries_when_local_metadata_changes_before_apply(tmp_path, monkeypatch):
    remote = FakeRemote()
    source = make_device(remote, tmp_path, "SRC")
    add_entry(source, "remote-entry", "sentinel-remote")
    source.engine.push(PW)
    victim = make_device(remote, tmp_path, "V")
    original_apply = VaultService.apply_snapshot
    raced = False
    concurrent = Entry.new(name="local-concurrent", type=EntryType.API_KEY)

    def racing_apply(service, *args, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            service.store.add(concurrent)
            service.backend.set(concurrent.id, "sentinel-local")
        return original_apply(service, *args, **kwargs)

    monkeypatch.setattr(VaultService, "apply_snapshot", racing_apply)
    assert victim.engine.pull(PW) == 1

    assert raced is True
    assert names(victim) == ["local-concurrent", "remote-entry"]
    assert victim.backend.d[concurrent.id] == "sentinel-local"


def test_rollback_refuses_local_metadata_race_without_loss(tmp_path, monkeypatch):
    remote = FakeRemote()
    device = make_device(remote, tmp_path, "A")
    add_entry(device, "first", "sentinel-first")
    device.engine.push(PW)
    add_entry(device, "second", "sentinel-second")
    device.engine.push(PW)
    original_apply = VaultService.apply_snapshot
    raced = False
    concurrent = Entry.new(name="rollback-concurrent", type=EntryType.API_KEY)

    def racing_apply(service, *args, **kwargs):
        nonlocal raced
        if not raced:
            raced = True
            service.store.add(concurrent)
            service.backend.set(concurrent.id, "sentinel-concurrent")
        return original_apply(service, *args, **kwargs)

    monkeypatch.setattr(VaultService, "apply_snapshot", racing_apply)
    with pytest.raises(TransportError, match="local vault changed during rollback"):
        device.engine.rollback(1, PW)

    assert names(device) == ["first", "rollback-concurrent", "second"]
    assert device.backend.d[concurrent.id] == "sentinel-concurrent"
    assert device.engine._current_tip().version == 2


def test_rollback_delete_propagates_to_peer(tmp_path):
    # Two-device rollback: peer that already pulled the newer entry must lose it
    # after the rollback propagates (KI #6).
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                # v1 = {first}
    e2 = add_entry(a, "second", "sk-2")
    a.engine.push(PW)                # v2 = {first, second}
    b = make_device(r, tmp_path, "B")
    b.engine.pull(PW)
    assert sorted(names(b)) == ["first", "second"]
    a.engine.rollback(1, PW)         # restore {first}, publish v3
    b.engine.pull(PW)
    assert names(b) == ["first"]
    assert e2.id not in b.backend.d  # peer purged the rolled-away secret
