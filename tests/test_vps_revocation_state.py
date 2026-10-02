"""Durable KK2 revocation, uncertain HTTP outcomes and shared operation locks.

Every vault, signing key, transport and backend in these tests is synthetic.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import multiprocessing
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from test_sync_vps import two_devices
from test_vps_resource_contracts import populated
from keys_keeper import private_files
from keys_keeper.sync_protocol_v2 import build_signed_commit, canonical_json_bytes, seal_snapshot
from keys_keeper.sync_vps import (
    VpsSyncEngine, VpsSyncError, VpsSyncCommitError, VpsTrustError,
    VpsRevokePreparationError, _VpsOperationLock, make_revocation_statement, sign_revocation,
)
from keys_keeper.sync_vps_client import VpsConflictError, VpsTransportError
from keys_keeper.vault_snapshot import build_snapshot_payload


def clone(engine, **kwargs):
    return VpsSyncEngine(client=engine.client, config=engine.config, store=engine.store,
                         backend=engine.backend, vault_key=engine.vault_key,
                         signing_private_key=engine.signing_private_key, paths=engine.paths,
                         **kwargs)


def state(engine):
    path = engine.paths.root / 'vps-sync-state.json'
    return {} if not path.exists() else json.loads(path.read_text())


def publish(remote, engine):
    parent = None if remote.head is None else remote.commits[remote.head]
    snapshot = seal_snapshot(canonical_json_bytes(build_snapshot_payload(engine.store, engine.backend)),
                             vault_key=engine.vault_key, vault_id=remote.vault_id)
    blob = build_signed_commit(snapshot, vault_id=remote.vault_id,
        sequence=1 if parent is None else parent['sequence'] + 1,
        parent_commit_id=remote.head, parent_manifest_hash=None if parent is None else parent['manifest_hash'],
        author_device_id=engine.config.device_id, signing_private_key=engine.signing_private_key)
    remote.append_commit(remote.vault_id, commit_blob=blob, snapshot_ciphertext=snapshot,
                         expected_parent=remote.head)


def install_revoke(monkeypatch, remote, engine, *, mode='normal', before=None):
    calls = []

    def revoke(vault, target, **kwargs):
        calls.append(dict(kwargs))
        pending = state(engine)['pending_revoke']
        assert pending['device_id'] == target
        assert pending['statement'] == kwargs['revocation_statement']
        assert pending['signature'] == kwargs['revocation_signature']
        if before is not None:
            before(len(calls))
        if mode == 'offline':
            raise VpsTransportError('synthetic timeout')
        if kwargs['expected_head'] != remote.head:
            raise VpsConflictError('cas_conflict')
        if mode == 'omit':
            return {'device_id': target, 'status': 'revoked'}
        record = next(item for item in remote.devices if item['device_id'] == target)
        if record['status'] == 'revoked':
            raise VpsConflictError('already_revoked')
        record.update(status='revoked', revoked_by_device_id=engine.config.root_device_id,
                      revocation_statement=pending['statement'], revocation_signature=pending['signature'])
        if mode == 'lost_ack':
            raise VpsTransportError('synthetic lost response')
        return {'device_id': target, 'status': 'revoked'}

    monkeypatch.setattr(remote, 'revoke_device', revoke, raising=False)
    return calls


def remote_revocation(remote, engine, head):
    statement = make_revocation_statement(vault_id=remote.vault_id, device_id='peer-device',
        revoked_by_device_id=engine.config.root_device_id,
        checkpoint_commit_id=None if head is None else head.commit_id,
        checkpoint_manifest_hash=None if head is None else head.manifest_hash,
        checkpoint_sequence=0 if head is None else head.sequence)
    remote.devices[1].update(status='revoked', revoked_by_device_id=engine.config.root_device_id,
        revocation_statement=canonical_json_bytes(statement).decode(),
        revocation_signature=sign_revocation(statement, engine.signing_private_key))


def test_false_ack_keeps_pending_without_claiming_confirmed_revocation(tmp_path, monkeypatch):
    remote, root, peer, _ = populated(tmp_path)
    engine = root[0]
    install_revoke(monkeypatch, remote, engine, mode='omit')
    with pytest.raises(VpsSyncError) as failure:
        engine.revoke_device('peer-device')
    assert getattr(failure.value, 'committed', None) is None
    saved = state(engine)
    assert saved['revocations'] == {}
    assert saved['pending_revoke']['device_id'] == 'peer-device'
    publish(remote, peer[0])
    with pytest.raises(VpsSyncError, match='recovery_required'):
        clone(engine).revoke_device('peer-device')
    assert state(engine) == saved
    assert engine.store.get_by_name('post-revocation') is None


@pytest.mark.parametrize('operation', ['push', 'pull', 'status', 'verified_head', 'refresh_trust_anchor', 'require_checkpoint'])
def test_every_normal_proof_entrypoint_blocks_pending_before_network(tmp_path, monkeypatch, operation):
    remote, root, _peer = two_devices(tmp_path)
    engine = root[0]
    install_revoke(monkeypatch, remote, engine, mode='offline')
    with pytest.raises(VpsSyncError):
        engine.revoke_device('peer-device')
    monkeypatch.setattr(remote, 'get_head', lambda *_: pytest.fail('pending reached network'))
    args = (0, None, None) if operation == 'require_checkpoint' else ()
    with pytest.raises(VpsSyncError, match='recovery_required'):
        getattr(engine, operation)(*args)


@pytest.mark.parametrize('operation', ['pull', 'push', 'refresh_trust_anchor'])
def test_empty_head_revocation_is_durable_and_noop_does_not_rewrite(tmp_path, operation):
    remote, root, peer = two_devices(tmp_path)
    engine = root[0]
    remote_revocation(remote, engine, None)
    getattr(engine, operation)()
    saved = state(engine)
    assert 'peer-device' in saved['revocations']
    assert not {'commit_id', 'manifest_hash', 'sequence', 'manifest'} & saved.keys()
    path = engine.paths.root / 'vps-sync-state.json'
    before = path.read_bytes(), path.stat().st_mtime_ns
    getattr(engine, operation)()
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    remote.devices[1]['status'] = 'active'
    publish(remote, peer[0])
    with pytest.raises(VpsTrustError, match='previously trusted revocation'):
        engine.pull()


def test_same_head_stale_writer_preserves_concurrently_added_revocation(tmp_path):
    remote, root, _peer, _ = populated(tmp_path)
    a, b = root[0], clone(root[0])
    old_head = a.verified_head()
    remote_revocation(remote, a, old_head)
    b.refresh_trust_anchor()
    before = state(a)
    a._write_state(old_head)
    assert state(a) == before
    remote.devices[1]['status'] = 'active'
    with pytest.raises(VpsTrustError, match='previously trusted revocation'):
        a.pull()


def test_newer_stale_proof_cannot_merge_cutoff_over_target_authored_commit(tmp_path):
    remote, root, peer, _ = populated(tmp_path)
    a, b = root[0], clone(root[0])
    checkpoint = a.verified_head()
    publish(remote, peer[0])
    newer = a.verified_head()
    remote.head = checkpoint.commit_id
    later = remote.commits.pop(newer.commit_id)
    remote_revocation(remote, b, checkpoint)
    b.refresh_trust_anchor()
    remote.commits[newer.commit_id] = later
    remote.head = newer.commit_id
    before = state(a)
    with pytest.raises(VpsTrustError, match='after a trusted revocation'):
        a._write_state(newer)
    assert state(a) == before


@pytest.mark.parametrize('missing', ['commit_id', 'manifest_hash', 'sequence', 'manifest'])
def test_partial_legacy_anchor_fails_before_network(tmp_path, monkeypatch, missing):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    engine.refresh_trust_anchor()
    malformed = state(engine)
    del malformed[missing]
    (engine.paths.root / 'vps-sync-state.json').write_text(json.dumps(malformed))
    monkeypatch.setattr(remote, 'get_head', lambda *_: pytest.fail('malformed state reached network'))
    with pytest.raises(VpsTrustError, match='incomplete'):
        engine.status()


def test_legacy_anchor_without_revocation_fields_and_root_genesis_after_empty_revocation(tmp_path):
    remote, root, _peer = two_devices(tmp_path)
    engine = root[0]
    remote_revocation(remote, engine, None)
    engine.refresh_trust_anchor()
    publish(remote, engine)
    engine.refresh_trust_anchor()
    assert state(engine)['sequence'] == 1
    old = state(engine)
    del old['revocations']
    (engine.paths.root / 'vps-sync-state.json').write_text(json.dumps(old))
    assert engine.verified_head().sequence == 1


@pytest.mark.parametrize('boundary', ['before_post', 'after_ack'])
def test_process_exit_preserves_intent_and_resume_reuses_exact_signature(tmp_path, monkeypatch, boundary):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine)
    if boundary == 'before_post':
        original = remote.revoke_device
        monkeypatch.setattr(remote, 'revoke_device', lambda *_a, **_k: (_ for _ in ()).throw(SystemExit()))
    else:
        original_proof = engine._verified_head
        def crash_after_ack(*args, **kwargs):
            if calls:
                raise SystemExit()
            return original_proof(*args, **kwargs)
        monkeypatch.setattr(engine, '_verified_head', crash_after_ack)
    with pytest.raises(SystemExit):
        engine.revoke_device('peer-device')
    pending = state(engine)['pending_revoke']
    if boundary == 'before_post':
        monkeypatch.setattr(remote, 'revoke_device', original)
    else:
        monkeypatch.setattr(remote, 'revoke_device', lambda *_a, **_k: pytest.fail('confirmed evidence reposted'))
    resumed = clone(engine)
    resumed.revoke_device('peer-device')
    assert 'pending_revoke' not in state(resumed)
    assert state(resumed)['revocations']['peer-device'] == {k: pending[k] for k in ('statement', 'signature')}
    assert len(calls) == 1


def test_lost_ack_stays_unknown_then_exact_remote_evidence_confirms_without_post(tmp_path, monkeypatch):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine, mode='lost_ack')
    with pytest.raises(VpsSyncError) as failure:
        engine.revoke_device('peer-device')
    assert getattr(failure.value, 'committed', None) is None
    assert 'pending_revoke' in state(engine)
    monkeypatch.setattr(remote, 'revoke_device', lambda *_a, **_k: pytest.fail('lost ACK caused repost'))
    clone(engine).revoke_device('peer-device')
    assert len(calls) == 1
    assert 'pending_revoke' not in state(engine)


@pytest.mark.parametrize('target_writes', [False, True])
def test_resume_after_head_drift_keeps_cutoff_and_checks_target_authors(tmp_path, monkeypatch, target_writes):
    remote, root, peer, _ = populated(tmp_path)
    engine = root[0]
    install_revoke(monkeypatch, remote, engine, mode='offline')
    with pytest.raises(VpsSyncError):
        engine.revoke_device('peer-device')
    pending = state(engine)['pending_revoke']
    publish(remote, peer[0] if target_writes else engine)
    calls = install_revoke(monkeypatch, remote, engine)
    if target_writes:
        with pytest.raises(VpsSyncError, match='recovery_required'):
            clone(engine).revoke_device('peer-device')
        assert calls == []
        assert state(engine)['pending_revoke'] == pending
    else:
        clone(engine).revoke_device('peer-device')
        assert calls[0]['expected_head'] == remote.head
        assert calls[0]['revocation_statement'] == pending['statement']
        assert calls[0]['revocation_signature'] == pending['signature']
        assert json.loads(pending['statement'])['checkpoint_sequence'] == 3


def test_cas_retry_reverifies_ancestry_and_keeps_signed_cutoff(tmp_path, monkeypatch):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine,
                           before=lambda number: publish(remote, engine) if number == 1 else None)
    engine.revoke_device('peer-device')
    assert len(calls) == 2
    assert calls[0]['expected_head'] != calls[1]['expected_head']
    assert calls[0]['revocation_statement'] == calls[1]['revocation_statement']
    assert calls[0]['revocation_signature'] == calls[1]['revocation_signature']


def test_conflicting_signed_evidence_does_not_clear_pending(tmp_path, monkeypatch):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    install_revoke(monkeypatch, remote, engine, mode='offline')
    with pytest.raises(VpsSyncError):
        engine.revoke_device('peer-device')
    before = state(engine)
    remote_revocation(remote, engine, None)
    with pytest.raises(VpsSyncError, match='recovery_required'):
        clone(engine).revoke_device('peer-device')
    assert state(engine) == before


@pytest.mark.parametrize('phase', ['prepare', 'confirm'])
def test_fsync_failure_preserves_publication_and_truthful_outcome(tmp_path, monkeypatch, phase):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine)
    original = private_files.fsync_parent
    def fail(directory):
        current = state(engine)
        trigger = ((phase == 'prepare' and 'pending_revoke' in current and not calls)
                   or (phase == 'confirm' and calls and 'pending_revoke' not in current))
        if Path(directory) == engine.paths.root and trigger:
            raise OSError('synthetic directory durability failure')
        return original(directory)
    monkeypatch.setattr(private_files, 'fsync_parent', fail)
    with pytest.raises(VpsSyncError) as failure:
        engine.revoke_device('peer-device')
    assert failure.value.committed is (phase != 'prepare')
    assert bool(calls) is (phase != 'prepare')
    assert state(engine).get('pending_revoke') or state(engine).get('revocations')
    monkeypatch.setattr(private_files, 'fsync_parent', original)
    clone(engine).revoke_device('peer-device')
    assert 'pending_revoke' not in state(engine)


def test_confirmed_retry_does_not_resign_repost_or_rewrite(tmp_path, monkeypatch):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine)
    engine.revoke_device('peer-device')
    path = engine.paths.root / 'vps-sync-state.json'
    before = path.read_bytes(), path.stat().st_mtime_ns
    monkeypatch.setattr('keys_keeper.sync_vps.sign_revocation', lambda *_: pytest.fail('retry resigned'))
    clone(engine).revoke_device('peer-device')
    assert len(calls) == 1
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


@pytest.mark.parametrize('same_engine', [False, True])
def test_parallel_status_cannot_replace_inflight_pull_proof(tmp_path, monkeypatch, same_engine):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    other = engine if same_engine else clone(engine)
    other.lock_timeout = .05
    entered, release = threading.Event(), threading.Event()
    original = engine._apply_payload
    def held_apply(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)
    monkeypatch.setattr(engine, '_apply_payload', held_apply)
    with ThreadPoolExecutor(max_workers=2) as workers:
        active = workers.submit(engine.pull)
        try:
            assert entered.wait(5)
            with pytest.raises(VpsSyncError, match='busy'):
                workers.submit(other.status).result(timeout=2)
        finally:
            release.set()
        active.result(timeout=5)
    assert other.status().remote_sequence == 3


def _hold_process_lock(root, entered, release):
    with _VpsOperationLock(Path(root)).locked(2):
        entered.set()
        release.wait(10)


def test_independent_process_lock_has_bounded_wait_before_network(tmp_path, monkeypatch):
    remote, root, _peer = two_devices(tmp_path)
    engine = root[0]
    engine.lock_timeout = .05
    context = multiprocessing.get_context('spawn')
    entered, release = context.Event(), context.Event()
    process = context.Process(target=_hold_process_lock, args=(str(engine.paths.root), entered, release))
    process.start()
    try:
        assert entered.wait(5)
        monkeypatch.setattr(remote, 'get_head', lambda *_: pytest.fail('busy operation reached network'))
        with pytest.raises(VpsSyncError, match='busy'):
            engine.status()
    finally:
        release.set()
        process.join(5)
        if process.is_alive():
            process.terminate()
            process.join(5)
    assert process.exitcode == 0


def test_network_holds_no_journal_profile_lock_and_reentrant_calls_finish(tmp_path, monkeypatch):
    from keys_keeper.operation_journal import profile_lock
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    original = remote.get_head
    def inspect(*args):
        with profile_lock(engine.paths, timeout=0):
            return original(*args)
    monkeypatch.setattr(remote, 'get_head', inspect)
    head = engine.verified_head()
    assert engine.require_checkpoint(head.sequence, head.commit_id, head.manifest_hash) == head
    assert engine.pull() == 0


@pytest.mark.parametrize('operation', ['status', 'verified_head', 'require_checkpoint'])
@pytest.mark.parametrize('commits', [0, 3])
def test_successful_proof_inspection_remembers_new_revocations(tmp_path, operation, commits):
    if commits:
        remote, root, peer, _ = populated(tmp_path, commits=commits)
    else:
        remote, root, peer = two_devices(tmp_path)
    engine = root[0]
    remote_revocation(remote, engine, engine.verified_head())
    args = (0, None, None) if operation == 'require_checkpoint' else ()
    getattr(engine, operation)(*args)
    assert 'peer-device' in state(engine)['revocations']
    path = engine.paths.root / 'vps-sync-state.json'
    before = path.read_bytes(), path.stat().st_mtime_ns
    getattr(engine, operation)(*args)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before
    remote.devices[1]['status'] = 'active'
    publish(remote, peer[0])
    with pytest.raises(VpsTrustError, match='previously trusted revocation'):
        engine.pull()


def test_pin_failure_before_publication_keeps_pending_after_ack(tmp_path, monkeypatch):
    remote, root, _peer, _ = populated(tmp_path)
    engine = root[0]
    calls = install_revoke(monkeypatch, remote, engine)
    original = private_files.atomic_write_bytes
    def fail(path, blob, **kwargs):
        if Path(path).name == 'vps-sync-state.json' and calls:
            raise OSError('synthetic unpublished pin')
        return original(path, blob, **kwargs)
    monkeypatch.setattr(private_files, 'atomic_write_bytes', fail)
    with pytest.raises(VpsSyncCommitError):
        engine.revoke_device('peer-device')
    assert state(engine)['pending_revoke']['device_id'] == 'peer-device'
    assert state(engine)['revocations'] == {}
    monkeypatch.setattr(private_files, 'atomic_write_bytes', original)
    clone(engine).revoke_device('peer-device')
    assert len(calls) == 1
    assert 'pending_revoke' not in state(engine)


def _try_inherited_lock(lock, output):
    try:
        with lock.locked(.05):
            output.put('unexpectedly acquired')
    except VpsSyncError:
        output.put('busy')


@pytest.mark.skipif('fork' not in multiprocessing.get_all_start_methods(), reason='POSIX fork ownership')
def test_fork_does_not_inherit_reentrant_operation_ownership(tmp_path):
    _remote, root, _peer = two_devices(tmp_path)
    lock = root[0]._operation_lock
    context = multiprocessing.get_context('fork')
    output = context.Queue()
    with lock.locked(1):
        process = context.Process(target=_try_inherited_lock, args=(lock, output))
        process.start()
        try:
            assert output.get(timeout=5) == 'busy'
        finally:
            process.join(5)
            if process.is_alive():
                process.terminate()
                process.join(5)
    assert process.exitcode == 0
    output.close()
    output.join_thread()


@pytest.mark.parametrize('mode,committed,outcome', [('omit', None, 'unconfirmed'), ('prepare_failure', False, 'failed')])
def test_revoke_cli_and_audit_agree_on_unconfirmed_and_unpublished(tmp_path, monkeypatch, capsys, mode, committed, outcome):
    from keys_keeper import cli_sync_vps
    remote, root, _peer, _ = populated(tmp_path)
    engine, paths, _store, backend = root
    calls = install_revoke(monkeypatch, remote, engine, mode='omit')
    monkeypatch.setattr(cli_sync_vps, 'Paths', lambda: paths)
    monkeypatch.setattr(cli_sync_vps, '_engine', lambda *_: (engine, engine.config, backend))
    if mode == 'prepare_failure':
        monkeypatch.setattr(engine, '_write_state', lambda *_a, **_k: (_ for _ in ()).throw(OSError('synthetic-private-detail')))
    assert cli_sync_vps.cmd_vps_revoke(SimpleNamespace(device_id='peer-device')) == 1
    captured = capsys.readouterr()
    receipt = json.loads([line for line in captured.err.splitlines() if line.startswith('{')][-1])
    event = json.loads(paths.audit_jsonl.read_text().splitlines()[-1])
    assert receipt['committed'] is event['committed'] is committed
    assert receipt['outcome'] == event['outcome'] == outcome
    assert event['success'] is False
    assert 'synthetic-private-detail' not in captured.out + captured.err
    assert len(calls) == (0 if mode == 'prepare_failure' else 1)


def _exit_during_revoke(root, boundary, connection):
    """An actual process death: no Python finally or context manager unwinds."""
    from dataclasses import asdict
    import os
    remote, root_device, _peer = two_devices(Path(root))
    engine = root_device[0]
    posted = False
    original_head = remote.get_head
    def die():
        connection.send(dict(config=asdict(engine.config), signing_key=engine.signing_private_key,
                             vault_key=engine.vault_key, devices=remote.devices, commits=remote.commits,
                             head=remote.head))
        os._exit(73)
    def post(vault, target, **kwargs):
        nonlocal posted
        if boundary == 'before_post':
            die()
        remote.devices[1].update(status='revoked', revoked_by_device_id=engine.config.root_device_id,
            revocation_statement=kwargs['revocation_statement'], revocation_signature=kwargs['revocation_signature'])
        posted = True
        return {'device_id': target, 'status': 'revoked'}
    def get_head(*args):
        if posted:
            # The engine has received ACK and is about to confirm it.
            die()
        return original_head(*args)
    remote.revoke_device, remote.get_head = post, get_head
    engine.revoke_device('peer-device')
    raise AssertionError('crash boundary was not reached')


@pytest.mark.parametrize('boundary', ['before_post', 'after_ack'])
def test_real_process_death_keeps_pending_and_releases_lock_for_resume(tmp_path, monkeypatch, boundary):
    from _vault_fakes import FakeBackend
    from test_sync_vps import FakeVps
    from keys_keeper.paths import Paths
    from keys_keeper.store import MetadataStore
    from keys_keeper.sync_vps import VpsSyncConfig
    context = multiprocessing.get_context('spawn')
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_exit_during_revoke, args=(str(tmp_path), boundary, sender))
    process.start()
    sender.close()
    try:
        assert receiver.poll(10), 'crash worker did not reach its durable boundary'
        material = receiver.recv()
        process.join(5)
        assert process.exitcode == 73
    finally:
        receiver.close()
        if process.is_alive():
            process.terminate()
            process.join(5)
    cfg = VpsSyncConfig(**material['config'])
    remote = FakeVps(cfg.vault_id, material['devices'])
    remote.commits, remote.head = material['commits'], material['head']
    paths = Paths(tmp_path / 'root')
    resumed = VpsSyncEngine(client=remote, config=cfg, store=MetadataStore(paths), backend=FakeBackend(),
        vault_key=material['vault_key'], signing_private_key=material['signing_key'], paths=paths, lock_timeout=.5)
    before = state(resumed)
    assert before['pending_revoke']['device_id'] == 'peer-device'
    assert before['revocations'] == {}
    calls = install_revoke(monkeypatch, remote, resumed)
    resumed.revoke_device('peer-device')
    after = state(resumed)
    assert 'pending_revoke' not in after
    assert after['revocations']['peer-device'] == {key: before['pending_revoke'][key]
                                                  for key in ('statement', 'signature')}
    assert len(calls) == (1 if boundary == 'before_post' else 0)
