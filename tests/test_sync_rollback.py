"""Anti-rollback / replay hardening for the S3 sync engine + passphrase floor.

These cover client-side defences against a malicious/MITM bucket that can only
*replay* authentic data (it cannot forge AEAD ciphertext):

  (a) repointing HEAD to an older authentic commit is rejected on a normal pull,
      but the explicit `sync rollback` path is still allowed;
  (b) a commit pointing at a snapshot whose decrypted content hash != the
      commit's recorded entries_hash is rejected (swapped pointer);
  (c) `sync setup` / `web_setup` enforce a 12-char minimum passphrase.

No on-disk crypto format changes: the watermark lives in the 0600 sync-state
sidecar, and the integrity check recomputes the SAME client-side content hash.
"""
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from keys_keeper.paths import Paths
from keys_keeper.sync import (
    HEAD_KEY, vkey, encrypt_snapshot, content_hash,
    RollbackDetected, SnapshotIntegrityError,
)
from _sync_fakes import FakeRemote, make_device, add_entry, names, live_ids

PW = "correct horse battery staple"


# ---------- (a) version watermark: silent rollback rejected ----------

def _repoint_head(remote, version):
    """Simulate a hostile bucket repointing HEAD at an OLDER authentic commit."""
    commit = json.loads(remote.objs[vkey(version)])
    remote.objs[HEAD_KEY] = json.dumps(
        {"version": version, "snapshot": commit["snapshot"]}
    ).encode()


def test_silent_rollback_to_older_version_is_rejected_on_pull(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                          # v1
    e2 = add_entry(a, "second", "sk-2")
    a.engine.push(PW)                          # v2  -> watermark now 2
    assert a.engine._watermark() == 2

    # Attacker repoints HEAD back to the (authentic) v1 to resurrect the state
    # before `second` existed. A normal pull must refuse it.
    _repoint_head(r, 1)
    with pytest.raises(RollbackDetected):
        a.engine.pull(PW)
    # Local vault untouched by the rejected pull.
    assert sorted(names(a)) == ["first", "second"]
    assert e2.id in live_ids(a)


def test_silent_rollback_is_rejected_on_push_too(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                          # v1
    add_entry(a, "second", "sk-2")
    a.engine.push(PW)                          # v2 -> watermark 2
    _repoint_head(r, 1)
    add_entry(a, "third", "sk-3")              # local change wants to push
    with pytest.raises(RollbackDetected):
        a.engine.push(PW)


def test_first_pull_with_no_watermark_is_allowed(tmp_path):
    # Empty local + no watermark must NOT be treated as a rollback.
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "shared", "sk-1")
    a.engine.push(PW)                          # v1
    b = make_device(r, tmp_path, "B")          # fresh device, no state file
    assert b.engine._watermark() is None
    assert b.engine.pull(PW) == 1              # first pull allowed
    assert names(b) == ["shared"]
    assert b.engine._watermark() == 1


def test_explicit_rollback_is_allowed_and_resets_watermark(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                          # v1
    add_entry(a, "second", "sk-2")
    a.engine.push(PW)                          # v2 -> watermark 2
    assert a.engine._watermark() == 2

    # The sanctioned path may move backwards: restore v1, published as v3.
    new_v = a.engine.rollback(1, PW)
    assert new_v == 3
    assert names(a) == ["first"]
    # Watermark re-anchored to the freshly published version; a subsequent pull
    # of v3 is fine and is NOT seen as a rollback.
    assert a.engine._watermark() == 3
    assert a.engine.pull(PW) == 0


def test_rollback_then_pull_does_not_resurrect_via_watermark(tmp_path):
    # After a real rollback (v3 restoring v1), a peer that still sits on v2 must
    # accept v3 (3 > its watermark 2) — i.e. the watermark never blocks genuine
    # forward progress published by the rollback.
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)
    add_entry(a, "second", "sk-2")
    a.engine.push(PW)                          # v2
    b = make_device(r, tmp_path, "B")
    b.engine.pull(PW)                          # B watermark = 2
    assert b.engine._watermark() == 2
    a.engine.rollback(1, PW)                   # publish v3 = {first}
    assert b.engine.pull(PW) == 1              # 3 > 2 -> accepted
    assert names(b) == ["first"]


# ---------- (b) snapshot/commit hash binding ----------

def test_snapshot_pointer_swap_is_rejected(tmp_path):
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "real", "sk-real")
    a.engine.push(PW)                          # v1, authentic
    commit = json.loads(r.objs[vkey(1)])
    snap_key = commit["snapshot"]

    # Forge a DIFFERENT but validly-encrypted (same passphrase) snapshot and
    # swap it under the commit's pointer. AEAD still decrypts it cleanly, but its
    # content hash no longer matches the commit's recorded entries_hash.
    forged_payload = {
        "schema_version": 1,
        "entries": [{
            "id": "kk:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "name": "attacker", "type": "api_key", "fields": {},
            "tags": [], "note": "", "refs": [],
            "created_at": "2099-01-01T00:00:00Z",
            "updated_at": "2099-01-01T00:00:00Z",
            "_secret": "sk-evil", "_secret_passphrase": None,
        }],
        "tombstones": [],
    }
    assert content_hash(forged_payload) != commit["entries_hash"]
    r.objs[snap_key] = encrypt_snapshot(forged_payload, passphrase=PW)

    b = make_device(r, tmp_path, "B")
    with pytest.raises(SnapshotIntegrityError):
        b.engine.pull(PW)
    # Nothing from the forged snapshot leaked into B's vault.
    assert names(b) == []
    assert b.backend.d == {}


def test_intact_snapshot_passes_integrity_check(tmp_path):
    # Control: an untampered snapshot pulls cleanly (the check is not a false alarm).
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "ok", "sk-ok")
    a.engine.push(PW)
    b = make_device(r, tmp_path, "B")
    assert b.engine.pull(PW) == 1
    assert names(b) == ["ok"]


def test_rollback_to_swapped_snapshot_is_rejected(tmp_path):
    # The explicit rollback path skips the watermark guard but STILL enforces the
    # content-hash binding, so a swapped target snapshot is refused.
    r = FakeRemote()
    a = make_device(r, tmp_path, "A")
    add_entry(a, "first", "sk-1")
    a.engine.push(PW)                          # v1
    add_entry(a, "second", "sk-2")
    a.engine.push(PW)                          # v2
    commit = json.loads(r.objs[vkey(1)])
    forged = {"schema_version": 1,
              "entries": [{"id": "kk:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                           "name": "attacker", "type": "api_key", "fields": {},
                           "tags": [], "note": "", "refs": [],
                           "created_at": "2099-01-01T00:00:00Z",
                           "updated_at": "2099-01-01T00:00:00Z",
                           "_secret": "x", "_secret_passphrase": None}],
              "tombstones": []}
    r.objs[commit["snapshot"]] = encrypt_snapshot(forged, passphrase=PW)
    with pytest.raises(SnapshotIntegrityError):
        a.engine.rollback(1, PW)


# ---------- (c) passphrase strength floor ----------

@pytest.fixture
def sync_cli(kk_home, monkeypatch):
    from _sync_fakes import FakeBackend
    backend = FakeBackend()
    remote = FakeRemote()
    monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
    monkeypatch.setattr(
        "keys_keeper.cli_sync.build_backend", lambda **_kwargs: backend
    )
    monkeypatch.setattr("keys_keeper.cli_sync._build_remote", lambda cfg, b: remote)
    return SimpleNamespace(backend=backend, remote=remote)


def _run_setup(passphrase):
    from keys_keeper import cli
    args = ["sync", "setup", "--endpoint", "https://s3.example.com",
            "--bucket", "b", "--access-key-id", "AKID"]
    with patch("getpass.getpass", side_effect=["s3secret", passphrase, passphrase]):
        return cli.main(args)


def test_cli_setup_rejects_short_passphrase(sync_cli, capsys):
    from keys_keeper.cli_sync import SYNC_PASS
    assert _run_setup("8charpwd") == 1                  # 8 chars -> rejected
    err = capsys.readouterr().err
    assert "12" in err and "passphrase" in err.lower()
    # nothing persisted from a failed setup
    import pytest as _pytest
    from keys_keeper.backend import KeychainError
    with _pytest.raises(KeychainError):
        sync_cli.backend.get(SYNC_PASS)


def test_cli_setup_accepts_strong_passphrase(sync_cli):
    from keys_keeper.cli_sync import SYNC_PASS
    assert _run_setup("correct horse battery staple") == 0   # 28 chars
    assert sync_cli.backend.get(SYNC_PASS).unseal() == "correct horse battery staple"


def test_cli_setup_rejects_low_entropy_passphrase(sync_cli):
    # 12 chars but only one distinct character -> rejected by the entropy floor.
    assert _run_setup("aaaaaaaaaaaa") == 1


def test_web_setup_rejects_short_passphrase(kk_home):
    from keys_keeper.cli_sync import web_setup
    from keys_keeper.config import SyncConfigError
    data = {"endpoint": "https://s3.example.com", "bucket": "b",
            "access_key_id": "AKID", "secret_key": "s3secret",
            "passphrase": "short", "region": "auto", "prefix": "kk"}
    with pytest.raises(SyncConfigError):
        web_setup(Paths(), data)


def test_web_setup_accepts_strong_passphrase(monkeypatch, kk_home):
    from _sync_fakes import FakeBackend
    from keys_keeper.cli_sync import web_setup, SYNC_PASS
    backend = FakeBackend()
    remote = FakeRemote()
    monkeypatch.setattr(
        "keys_keeper.cli_sync.build_backend", lambda **_kwargs: backend
    )
    monkeypatch.setattr("keys_keeper.cli_sync._build_remote", lambda cfg, b: remote)
    data = {"endpoint": "https://s3.example.com", "bucket": "b",
            "access_key_id": "AKID", "secret_key": "s3secret",
            "passphrase": "a-strong-enough-passphrase", "region": "auto",
            "prefix": "kk"}
    out = web_setup(Paths(), data)
    assert out["ok"] is True
    assert backend.get(SYNC_PASS).unseal() == "a-strong-enough-passphrase"
