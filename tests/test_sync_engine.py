"""Sync engine — offline, FakeRemote + FakeBackend. The correctness core."""
import json
import pytest

from keys_keeper.models import Entry, EntryType, now_iso
from keys_keeper.backend import KeychainError
from keys_keeper.sync import merge, vkey, content_hash, build_snapshot_payload
from _sync_fakes import (
    FakeRemote, RaceOnceRemote, NonCasRemote, FakeBackend, make_device, add_entry,
    live_ids, names,
)

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
