"""Synthetic KK2 resource bounds and authenticated history/merge regressions."""
from __future__ import annotations

import copy
import hashlib
import json
import tracemalloc
from collections import Counter
from dataclasses import replace
from types import SimpleNamespace

import pytest

from _vault_fakes import add_entry
from test_sync_vps import b64, two_devices
from keys_keeper.backend import SecretAccessDenied
from keys_keeper.models import Entry, EntryType
from keys_keeper.sync_protocol_v2 import build_signed_commit, canonical_json_bytes, seal_snapshot
from keys_keeper.sync_vps import (
    VpsSyncCommitError, VpsSyncError, VpsTrustError, make_revocation_statement, sign_revocation,
)
from keys_keeper.sync_vps_client import VpsAuthenticationError, VpsBadRequestError
from keys_keeper.vault_snapshot import MergeReferenceConflict, SnapshotReadError, build_snapshot_payload


def populated(tmp_path, *, commits=3, secret_bytes=2048):
    remote, root, peer = two_devices(tmp_path)
    eng, _paths, store, backend = root
    entry = add_entry(SimpleNamespace(store=store, backend=backend), "synthetic-key", "s" * secret_bytes)
    payload = build_snapshot_payload(store, backend)
    snapshot = seal_snapshot(canonical_json_bytes(payload), vault_key=eng.vault_key,
                             vault_id=eng.config.vault_id)
    parent_id = parent_hash = None
    for sequence in range(1, commits + 1):
        blob = build_signed_commit(
            snapshot, vault_id=eng.config.vault_id, sequence=sequence,
            parent_commit_id=parent_id, parent_manifest_hash=parent_hash,
            author_device_id=eng.config.device_id, signing_private_key=eng.signing_private_key,
        )
        receipt = remote.append_commit(eng.config.vault_id, commit_blob=blob,
                                       snapshot_ciphertext=snapshot, expected_parent=parent_id)
        parent_id = receipt["commit_id"]
        parent_hash = remote.commits[parent_id]["manifest_hash"]
    return remote, root, peer, entry


def count_transport(monkeypatch, remote):
    counters = Counter()
    for method in ("get_head", "list_devices", "get_commit", "list_commits"):
        original = getattr(remote, method)
        def measured(*args, _method=method, _original=original, **kwargs):
            result = _original(*args, **kwargs)
            counters[_method] += 1
            counters["response_bytes"] += len(json.dumps(result, separators=(",", ":")).encode("utf-8"))
            counters["snapshot_responses"] += int("snapshot_ciphertext" in result)
            return result
        monkeypatch.setattr(remote, method, measured)
    return counters


def test_cold_and_pinned_history_use_one_ciphertext_and_paged_envelopes(tmp_path, monkeypatch):
    remote, root, peer, _entry = populated(tmp_path, commits=205)
    counters = count_transport(monkeypatch, remote)
    peer_engine = peer[0]
    verified = peer_engine.verified_head()
    assert verified.sequence == 205
    cold = dict(counters)
    assert cold["get_head"] == cold["list_devices"] == cold["get_commit"] == 1
    assert cold["list_commits"] == 3
    assert cold["snapshot_responses"] == 1
    peer_engine._write_state(verified)
    counters.clear()
    assert peer_engine.verified_head().commit_id == verified.commit_id
    assert dict(counters) == cold
    # Baseline 36df576 downloaded every encrypted historical snapshot.
    old_body_bytes = sum(len(json.dumps(item, separators=(",", ":")).encode("utf-8"))
                         for item in remote.commits.values())
    old_body_bytes += len(json.dumps(remote.get_head(remote.vault_id), separators=(",", ":")).encode("utf-8"))
    old_body_bytes += len(json.dumps(remote.list_devices(remote.vault_id), separators=(",", ":")).encode("utf-8"))
    assert cold["response_bytes"] < old_body_bytes / 3


def test_history_ciphertext_memory_does_not_grow_per_commit(tmp_path):
    remote, _root, peer, _entry = populated(tmp_path, commits=80, secret_bytes=128 * 1024)
    # The synthetic relay data already exists before tracing client work.
    tracemalloc.start()
    try:
        assert peer[0].verified_head().sequence == 80
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    history_cipher_bytes = sum(len(item["snapshot_ciphertext"]) * 3 // 4 for item in remote.commits.values())
    assert peak < history_cipher_bytes / 2


@pytest.mark.parametrize("defect", ["gap", "duplicate", "reordered", "metadata", "blob", "empty", "head_fields"])
def test_malformed_history_never_reaches_local_apply(tmp_path, monkeypatch, defect):
    remote, _root, peer, _entry = populated(tmp_path)
    engine, _paths, store, backend = peer
    original = remote.list_commits
    def corrupt(*args, **kwargs):
        page = copy.deepcopy(original(*args, **kwargs))
        records = page["commits"]
        if defect == "gap":
            del records[0]
        elif defect == "duplicate":
            records[1]["commit_id"] = records[0]["commit_id"]
        elif defect == "reordered":
            records.reverse()
        elif defect == "metadata":
            records[0]["author_device_id"] = "peer-device"
        elif defect == "blob":
            records[0]["commit_blob"] = records[1]["commit_blob"]
        elif defect == "empty":
            records.clear()
        return page
    monkeypatch.setattr(remote, "list_commits", corrupt)
    if defect == "head_fields":
        original_head = remote.get_head
        monkeypatch.setattr(remote, "get_head", lambda *_: {**original_head(remote.vault_id), "sequence": True})
    with pytest.raises(VpsTrustError):
        engine.pull()
    assert store.list() == []
    assert backend.d == {}


def test_head_drift_retries_one_complete_proof_without_merging_stale_payload(tmp_path, monkeypatch):
    remote, _root, peer, _entry = populated(tmp_path)
    original = remote.list_commits
    calls = 0
    def drifting(*args, **kwargs):
        nonlocal calls
        calls += 1
        page = original(*args, **kwargs)
        if calls == 1:
            page["head_commit_id"] = "a" * 64
        return page
    monkeypatch.setattr(remote, "list_commits", drifting)
    assert peer[0].pull() == 1
    assert calls == 2


def test_new_signed_membership_after_captured_head_causes_complete_proof_retry(tmp_path, monkeypatch):
    from keys_keeper.sync_vps import make_membership_statement, sign_membership
    remote, root, peer, _entry = populated(tmp_path, commits=1)
    engine = peer[0]
    original = remote.list_devices
    refreshed = False
    def enroll_after_head(*args):
        nonlocal refreshed
        if not refreshed:
            refreshed = True
            parent = remote.commits[remote.head]
            payload = canonical_json_bytes(build_snapshot_payload(root[2], root[3]))
            snapshot = seal_snapshot(payload, vault_key=root[0].vault_key, vault_id=remote.vault_id)
            commit = build_signed_commit(
                snapshot, vault_id=remote.vault_id, sequence=2, parent_commit_id=remote.head,
                parent_manifest_hash=parent["manifest_hash"], author_device_id=root[0].config.device_id,
                signing_private_key=root[0].signing_private_key,
            )
            remote.append_commit(remote.vault_id, commit_blob=commit, snapshot_ciphertext=snapshot,
                                 expected_parent=remote.head)
            head = remote.commits[remote.head]
            statement = make_membership_statement(
                vault_id=remote.vault_id, device_id=engine.config.device_id,
                sign_public_key=engine.config.sign_public_key, wrap_public_key=engine.config.wrap_public_key,
                approved_by_device_id=root[0].config.device_id, checkpoint_commit_id=remote.head,
                checkpoint_manifest_hash=head["manifest_hash"], checkpoint_sequence=2,
            )
            remote.devices[1].update(membership_statement=statement,
                                     membership_signature=sign_membership(statement, root[0].signing_private_key))
        return original(*args)
    calls = []
    original_head = remote.get_head
    monkeypatch.setattr(remote, "get_head", lambda *args: (calls.append(True), original_head(*args))[1])
    monkeypatch.setattr(remote, "list_devices", enroll_after_head)
    assert engine.verified_head().sequence == 2
    assert len(calls) == 2


def test_old_query_fallback_is_once_per_verification_and_auth_errors_do_not_fallback(tmp_path, monkeypatch):
    remote, _root, peer, _entry = populated(tmp_path, commits=101)
    original = remote.list_commits
    hints = []
    def old_list(*args, include_commit=False, **kwargs):
        hints.append(include_commit)
        if include_commit:
            raise VpsBadRequestError("HTTP 400 [invalid_request]")
        return original(*args, **kwargs)
    monkeypatch.setattr(remote, "list_commits", old_list)
    assert peer[0].verified_head().sequence == 101
    assert hints == [True, False, False]
    hints.clear()
    def denied(*args, **kwargs):
        hints.append(kwargs["include_commit"])
        raise VpsAuthenticationError("HTTP 403")
    monkeypatch.setattr(remote, "list_commits", denied)
    with pytest.raises(VpsAuthenticationError):
        peer[0].verified_head()
    assert hints == [True]


def test_both_unsupported_query_hints_have_one_bounded_fallback(tmp_path, monkeypatch):
    remote, _root, peer, _entry = populated(tmp_path)
    original_list, original_get = remote.list_commits, remote.get_commit
    hints = []
    monkeypatch.setattr(remote, "list_commits", lambda *a, **k: original_list(*a, **{**k, "include_commit": False}))
    def old_get(*args, include_snapshot=True, **kwargs):
        hints.append(include_snapshot)
        if not include_snapshot:
            raise VpsBadRequestError("HTTP 400 [invalid_request]")
        return original_get(*args, **kwargs)
    monkeypatch.setattr(remote, "get_commit", old_get)
    assert peer[0].verified_head().sequence == 3
    assert hints == [True, False, True, True]


def test_unchanged_head_still_checks_new_membership_and_revocation_evidence(tmp_path):
    remote, root, peer, _entry = populated(tmp_path)
    root_engine = root[0]
    head = root_engine.verified_head()
    root_engine._write_state(head)
    statement = make_revocation_statement(
        vault_id=remote.vault_id, device_id="peer-device", revoked_by_device_id="root-device",
        checkpoint_commit_id=head.commit_id, checkpoint_manifest_hash=head.manifest_hash,
        checkpoint_sequence=head.sequence,
    )
    remote.devices[1].update(status="revoked", revoked_by_device_id="root-device",
                             revocation_statement=canonical_json_bytes(statement).decode("utf-8"),
                             revocation_signature=sign_revocation(statement, root_engine.signing_private_key))
    assert root_engine.push() == 0
    state = json.loads((root[1].root / "vps-sync-state.json").read_text(encoding="utf-8"))
    assert "peer-device" in state["revocations"]
    remote.devices[1]["status"] = "active"
    with pytest.raises(VpsTrustError, match="previously trusted revocation"):
        root_engine.status()


@pytest.mark.parametrize("operation", ["push", "pull", "status"])
def test_denied_present_secret_aborts_without_state_or_backend_mutation(tmp_path, monkeypatch, operation):
    remote, root, _peer, entry = populated(tmp_path)
    engine, paths, store, backend = root
    before = store.snapshot().revision
    def denied(_account):
        raise SecretAccessDenied("synthetic-provider-secret-detail")
    monkeypatch.setattr(backend, "get", denied)
    with pytest.raises(SnapshotReadError) as raised:
        getattr(engine, operation)()
    assert "synthetic-provider-secret-detail" not in str(raised.value)
    assert store.snapshot().revision == before
    assert backend.d == {entry.id: "s" * 2048}
    assert not (paths.root / "vps-sync-state.json").exists()


def test_idle_push_reads_each_entry_once_and_does_not_rewrite_state(tmp_path, monkeypatch):
    _remote, root, _peer, entry = populated(tmp_path)
    engine, paths, _store, backend = root
    assert engine.push() == 0
    target = paths.root / "vps-sync-state.json"
    before = target.read_bytes(), target.stat().st_mtime_ns
    original_get, original_list = backend.get, backend.list_ids
    reads, inventories = [], []
    monkeypatch.setattr(backend, "get", lambda account: (reads.append(account), original_get(account))[1])
    monkeypatch.setattr(backend, "list_ids", lambda: (inventories.append(True), original_list())[1])
    for _ in range(3):
        assert engine.push() == 0
        assert (target.read_bytes(), target.stat().st_mtime_ns) == before
    assert reads == [entry.id] * 3
    assert len(inventories) == 3
    assert engine.status().dirty is False
    assert (target.read_bytes(), target.stat().st_mtime_ns) == before


def test_remote_winner_removes_old_optional_passphrase_and_preserves_empty_secret(tmp_path):
    remote, root, peer, entry = populated(tmp_path, commits=1)
    assert peer[0].pull() == 1
    peer[3].set(entry.id + ":passphrase", "stale-passphrase")
    changed = replace(root[2].get_by_id(entry.id), updated_at="2030-01-01T00:00:00Z")
    root[2].update(changed)
    root[3].set(entry.id, "")
    assert root[0].push() == 1
    assert peer[0].pull() == 1
    assert peer[3].get(entry.id).unseal() == ""
    assert entry.id + ":passphrase" not in peer[3].d


def test_secret_tie_does_not_conflate_absent_and_empty_passphrase(tmp_path):
    _remote, root, peer, entry = populated(tmp_path, commits=1)
    peer[0].pull()
    peer[3].set(entry.id + ":passphrase", "")
    peer[0].push()
    root[0].pull()
    first = build_snapshot_payload(root[2], root[3])
    second = build_snapshot_payload(peer[2], peer[3])
    assert first == second
    pair_none, pair_empty = ["s" * 2048, None], ["s" * 2048, ""]
    expected = max((pair_none, pair_empty), key=lambda pair: hashlib.sha256(canonical_json_bytes(pair)).digest())
    assert first["entries"][0]["_secret_passphrase"] == expected[1]


def test_confirmed_remote_append_failure_is_committed_and_not_replayed(tmp_path, monkeypatch):
    remote, root, _peer = two_devices(tmp_path)
    entry = add_entry(SimpleNamespace(store=root[2], backend=root[3]), "test-api", "synthetic")
    monkeypatch.setattr(root[0], "_write_state", lambda *_: (_ for _ in ()).throw(OSError("synthetic-secret-detail")))
    with pytest.raises(VpsSyncCommitError) as raised:
        root[0].push()
    assert raised.value.committed is True
    assert "synthetic-secret-detail" not in str(raised.value)
    assert len(remote.commits) == 1
    assert root[3].get(entry.id).unseal() == "synthetic"


def test_applied_pull_failure_reports_local_commit(tmp_path, monkeypatch):
    _remote, _root, peer, entry = populated(tmp_path)
    monkeypatch.setattr(peer[0], "_write_state", lambda *_: (_ for _ in ()).throw(OSError("detail")))
    with pytest.raises(VpsSyncCommitError):
        peer[0].pull()
    assert peer[2].get_by_id(entry.id) is not None
    assert peer[3].get(entry.id).unseal() == "s" * 2048


@pytest.mark.parametrize("checkpoint", [(-1, None, None), (True, None, None), (0, "x", None), (1, None, None)])
def test_invalid_checkpoint_rejected_before_network(tmp_path, monkeypatch, checkpoint):
    remote, root, _peer = two_devices(tmp_path)
    monkeypatch.setattr(remote, "get_head", lambda *_: pytest.fail("invalid checkpoint reached network"))
    with pytest.raises(VpsTrustError):
        root[0].require_checkpoint(*checkpoint)


def test_history_deadline_checked_before_network(tmp_path, monkeypatch):
    import keys_keeper.sync_vps as module
    remote, root, _peer = two_devices(tmp_path)
    times = iter([0.0, 61.0])
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(times)))
    monkeypatch.setattr(remote, "get_head", lambda *_: pytest.fail("expired proof reached network"))
    with pytest.raises(VpsSyncError, match="timed out"):
        root[0].verified_head()


def test_large_supported_snapshot_does_not_use_local_api_eight_mib_limit(tmp_path):
    remote, root, peer, _entry = populated(tmp_path, commits=1, secret_bytes=1024 * 1024)
    for index in range(8):
        add_entry(SimpleNamespace(store=root[2], backend=root[3]), f"large-{index}", "s" * (1024 * 1024))
    payload = canonical_json_bytes(build_snapshot_payload(root[2], root[3]))
    assert len(payload) > 8 * 1024 * 1024
    snapshot = seal_snapshot(payload, vault_key=root[0].vault_key, vault_id=remote.vault_id)
    parent = remote.commits[remote.head]
    commit = build_signed_commit(
        snapshot, vault_id=remote.vault_id, sequence=2, parent_commit_id=remote.head,
        parent_manifest_hash=parent["manifest_hash"], author_device_id=root[0].config.device_id,
        signing_private_key=root[0].signing_private_key,
    )
    remote.append_commit(remote.vault_id, commit_blob=commit, snapshot_ciphertext=snapshot, expected_parent=remote.head)
    assert peer[0].verified_head().sequence == 2


@pytest.mark.parametrize("operation", ["push", "pull"])
def test_reference_name_collision_aborts_without_local_or_remote_mutation(tmp_path, monkeypatch, operation):
    remote, root, peer = two_devices(tmp_path)
    remote_key = Entry.new(name="shared-key", type=EntryType.SSH_KEY,
                           fields={"public_key": "ssh-ed25519 synthetic-remote"})
    root[2].add(replace(remote_key, updated_at="2030-01-01T00:00:00Z"))
    root[3].set(remote_key.id, "remote-key")
    assert root[0].push() == 1
    local_key = Entry.new(name="shared-key", type=EntryType.SSH_KEY,
                          fields={"public_key": "ssh-ed25519 synthetic-local"})
    peer[2].add(local_key)
    peer[3].set(local_key.id, "local-key")
    server = Entry.new(name="server", type=EntryType.SERVER,
                       fields={"host": "synthetic.example.test", "user": "synthetic", "auth": "ssh_key"},
                       refs=[{"name": local_key.name, "role": "ssh_key"}])
    peer[2].add(server)
    before = peer[2].snapshot().revision, dict(peer[3].d), remote.head, len(remote.commits)
    monkeypatch.setattr(peer[3], "set", lambda *_: pytest.fail("rejected reference changed credentials"))
    monkeypatch.setattr(peer[3], "delete", lambda *_: pytest.fail("rejected reference deleted credentials"))
    remote.before_append = lambda: pytest.fail("rejected reference published a commit")
    with pytest.raises(MergeReferenceConflict):
        getattr(peer[0], operation)()
    assert (peer[2].snapshot().revision, dict(peer[3].d), remote.head, len(remote.commits)) == before
    assert not (peer[1].root / "vps-sync-state.json").exists()
