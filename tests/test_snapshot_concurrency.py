"""Multi-operation snapshot regressions use only synthetic in-memory credentials."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from types import SimpleNamespace

import pytest

from keys_keeper import api, cli
from keys_keeper.models import Entry, EntryType
from keys_keeper.refs import resolve_chain
from keys_keeper.service import ConcurrentMutation, SecretInput, VaultService
from keys_keeper.sync_protocol_v2 import canonical_json_bytes
from keys_keeper.vault_snapshot import (
    MergeReferenceConflict, encrypt_snapshot, merge, prepare_snapshot_payload,
)
from test_cli_secret_contracts import MemoryAudit
from test_sync_vps import two_devices


def test_same_second_api_rotation_survives_stale_sync_apply(tmp_path, monkeypatch):
    _remote, (engine, paths, store, backend), _peer = two_devices(tmp_path)
    service = VaultService(store, backend)
    old, remote_value, fresh = sorted(
        [f"synthetic-{i}" for i in range(3)],
        key=lambda value: hashlib.sha256(canonical_json_bytes([value, None])).digest(),
    )
    fixed_time = "2026-10-02T00:00:00Z"
    entry = Entry.new(name="rotation", type=EntryType.API_KEY)
    entry.created_at = entry.updated_at = fixed_time
    service.create_entry(entry, secrets=SecretInput(value=old))
    prepared = prepare_snapshot_payload(store, backend)
    remote_payload = deepcopy(prepared[0])
    remote_payload["entries"][0]["_secret"] = remote_value
    responses = []
    context = SimpleNamespace(paths=paths, store=store, backend=backend,
                              audit=MemoryAudit(), kind="master", service=service)
    handler = SimpleNamespace(_kk_context=context,
                              _send_json=lambda code, body: responses.append((code, body)))
    monkeypatch.setattr(api, "now_iso", lambda: fixed_time)
    api._replace_secret(handler, paths, entry.id, json.dumps({"value": fresh}).encode())
    assert responses[0][0] == 200 and responses[0][1]["committed"] is True
    assert store.snapshot().revision == prepared[1]

    original_apply = VaultService.apply_snapshot
    retries = []

    def observe_retry(self, *args, **kwargs):
        try:
            return original_apply(self, *args, **kwargs)
        except ConcurrentMutation:
            retries.append(True)
            raise

    monkeypatch.setattr(VaultService, "apply_snapshot", observe_retry)
    assert engine._apply_payload(remote_payload, prepared=prepared) == 0
    assert retries == [True]
    assert backend.get(entry.id).unseal() == fresh


def _key(name="prod-key"):
    entry = Entry.new(name=name, type=EntryType.SSH_KEY,
                      fields={"public_key": "ssh-ed25519 synthetic"})
    entry.created_at = entry.updated_at = "2026-10-01T00:00:00Z"
    return entry


def _dependent():
    entry = Entry.new(name="prod-host", type=EntryType.SERVER,
                      fields={"host": "example.test", "user": "root", "auth": "ssh_key"},
                      refs=[{"role": "ssh_key", "name": "prod-key"}])
    entry.created_at = entry.updated_at = "2026-10-01T00:00:00Z"
    return entry


def test_two_sync_name_reuse_requires_explicit_reference_removal_and_relink(tmp_path, monkeypatch):
    _remote, (ae, _ap, ast, ab), (be, _bp, bst, bb) = two_devices(tmp_path)
    sa, sb = VaultService(ast, ab), VaultService(bst, bb)
    original = _key()
    sa.create_entry(original, secrets=SecretInput(value="original-key"))
    ae.push()
    be.pull()
    dependent = _dependent()
    sa.create_entry(dependent)
    monkeypatch.setattr("keys_keeper.store.now_iso", lambda: "2026-10-03T00:00:00Z")
    sb.delete_entry(original.id)
    be.push()
    with pytest.raises(MergeReferenceConflict, match="to missing"):
        ae.pull()
    assert resolve_chain(ast.list(), dependent.name, "ssh_key").id == original.id
    assert ab.get(original.id).unseal() == "original-key"

    replacement = _key()
    sb.create_entry(replacement, secrets=SecretInput(value="replacement-key"))
    be.push()
    with pytest.raises(MergeReferenceConflict, match="would change reference"):
        ae.pull()
    assert resolve_chain(ast.list(), dependent.name, "ssh_key").id == original.id
    # Explicit resolution: publish the removed reference before introducing a
    # fresh one. No hidden cascade or name-based identity migration is needed.
    edited = ast.get_by_id(dependent.id)
    edited.refs = []
    edited.updated_at = "2026-10-04T00:00:00Z"
    sa.update_entry(edited)
    ae.push()
    be.pull()
    assert ast.get_by_id(original.id) is None
    assert ast.get_by_id(dependent.id).refs == bst.get_by_id(dependent.id).refs == []
    edited = ast.get_by_id(dependent.id)
    edited.refs = dependent.refs
    edited.updated_at = "2026-10-05T00:00:00Z"
    sa.update_entry(edited)
    ae.push()
    be.pull()
    assert resolve_chain(ast.list(), dependent.name, "ssh_key").id == replacement.id
    assert resolve_chain(bst.list(), dependent.name, "ssh_key").id == replacement.id


@pytest.mark.parametrize("reverse", [False, True])
def test_surviving_reference_checked_against_both_histories_despite_metadata_winner(reverse):
    original, replacement, dependent = _key(), _key(), _dependent()
    newer = deepcopy(dependent)
    newer.updated_at = "2026-10-04T00:00:00Z"
    newer.note = "unrelated metadata edit is not consent to change the credential"
    left, right = [original, dependent], [replacement, newer]
    if reverse:
        left, right = right, left
    with pytest.raises(MergeReferenceConflict):
        merge(left, [], right, [])


@pytest.mark.parametrize("reverse", [False, True])
def test_existing_dangling_reference_cannot_acquire_new_target(reverse):
    dependent, new_key = _dependent(), _key()
    left, right = [dependent], [new_key]
    if reverse:
        left, right = right, left
    with pytest.raises(MergeReferenceConflict, match="from missing"):
        merge(left, [], right, [])
    # Existing damage may remain visible, but a sync must not silently bind it.
    assert merge([dependent], [], [], []).entries[0].refs == dependent.refs


def test_import_replace_deletes_passphrase_absent_from_backup(tmp_path, monkeypatch, capsys):
    _remote, (_engine, paths, store, backend), _peer = two_devices(tmp_path)
    service = VaultService(store, backend)
    entry = _key()
    service.create_entry(entry, secrets=SecretInput(value="old-key", passphrase="obsolete-passphrase"))
    record = entry.to_dict()
    record.update(_secret="restored-key", _secret_passphrase=None)
    payload = {"schema_version": 2, "entries": [record], "tombstones": []}
    backup = tmp_path / "synthetic.kk"
    backup.write_bytes(encrypt_snapshot(payload, passphrase="synthetic-password"))
    context = SimpleNamespace(paths=paths, store=store, backend=backend,
                              audit=MemoryAudit(), kind="master", service=service)
    monkeypatch.setattr(cli, "_context_or_error", lambda *_a, **_kw: context)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_a: "synthetic-password")
    assert cli.main(["import", str(backup), "--replace"]) == 0
    restored, _revision = prepare_snapshot_payload(store, backend)
    assert restored["entries"][0]["_secret"] == "restored-key"
    assert restored["entries"][0]["_secret_passphrase"] is None
    assert entry.id + ":passphrase" not in backend.list_ids()
    captured = capsys.readouterr()
    assert "imported 1 entries" in captured.out
    assert "obsolete-passphrase" not in captured.out + captured.err
