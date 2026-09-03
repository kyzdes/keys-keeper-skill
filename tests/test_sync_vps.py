"""KK2 VPS coordinator tests: real crypto, in-memory zero-knowledge relay."""
from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest
from _sync_fakes import FakeBackend, add_entry

from keys_keeper.models import EntryType
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.sync_protocol_v2 import (
    canonical_json_bytes,
    generate_device_identity,
    generate_vault_key,
)
from keys_keeper.sync_vps import (
    VpsSyncConfig,
    VpsSyncEngine,
    VpsTrustError,
    make_membership_statement,
    make_revocation_statement,
    save_vps_config,
    sign_membership,
    sign_revocation,
)
from keys_keeper.sync_vps_client import VpsConflictError


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class FakeVps:
    def __init__(self, vault_id: str, devices: list[dict]):
        self.vault_id = vault_id
        self.devices = devices
        self.commits: dict[str, dict] = {}
        self.head: str | None = None
        self.before_append = None

    def list_devices(self, vault_id):
        assert vault_id == self.vault_id
        return {"devices": self.devices}

    def get_head(self, vault_id):
        assert vault_id == self.vault_id
        if self.head is None:
            return {"head_commit_id": None, "sequence": None, "manifest_hash": None}
        item = self.commits[self.head]
        return {
            "head_commit_id": self.head,
            "sequence": item["sequence"],
            "manifest_hash": item["manifest_hash"],
        }

    def get_commit(self, vault_id, commit_id):
        assert vault_id == self.vault_id
        return self.commits[commit_id]

    def append_commit(
        self, vault_id, *, commit_blob, snapshot_ciphertext, expected_parent
    ):
        assert vault_id == self.vault_id
        callback, self.before_append = self.before_append, None
        if callback is not None:
            callback()
        if self.head != expected_parent:
            raise VpsConflictError("lost CAS")
        parsed = json.loads(commit_blob)
        commit_id = parsed["commit_id"]
        manifest = parsed["manifest"]
        from keys_keeper.sync_protocol_v2 import compute_manifest_hash

        self.commits[commit_id] = {
            "commit_id": commit_id,
            "sequence": manifest["sequence"],
            "parent_commit_id": manifest["parent_commit_id"],
            "manifest_hash": compute_manifest_hash(manifest),
            "author_device_id": manifest["author_device_id"],
            "commit_blob": b64(commit_blob),
            "snapshot_ciphertext": b64(snapshot_ciphertext),
        }
        self.head = commit_id
        return {"commit_id": commit_id}


def device_record(identity, *, device_id, membership=None, signature=None):
    return {
        "device_id": device_id,
        "sign_public_key": b64(identity.signing_public_bytes),
        "wrap_public_key": b64(identity.agreement_public_bytes),
        "status": "active",
        "membership_statement": membership,
        "membership_signature": signature,
    }


def config(vault_id, root, identity, device_id):
    return VpsSyncConfig(
        endpoint="http://127.0.0.1:9419",
        vault_id=vault_id,
        device_id=device_id,
        root_device_id="root-device",
        root_sign_public_key=b64(root.signing_public_bytes),
        sign_public_key=b64(identity.signing_public_bytes),
        wrap_public_key=b64(identity.agreement_public_bytes),
    )


def engine(tmp_path, name, *, remote, cfg, identity, vault_key):
    paths = Paths(root=tmp_path / name)
    paths.ensure()
    backend = FakeBackend()
    store = MetadataStore(paths)
    return VpsSyncEngine(
        client=remote,
        config=cfg,
        store=store,
        backend=backend,
        vault_key=vault_key,
        signing_private_key=identity.signing_private_bytes,
        paths=paths,
    ), paths, store, backend


def two_devices(tmp_path):
    vault_id = "vault-test"
    root = generate_device_identity("root-device")
    peer = generate_device_identity("peer-device")
    membership = make_membership_statement(
        vault_id=vault_id,
        device_id="peer-device",
        sign_public_key=b64(peer.signing_public_bytes),
        wrap_public_key=b64(peer.agreement_public_bytes),
        approved_by_device_id="root-device",
        checkpoint_commit_id=None,
        checkpoint_manifest_hash=None,
        checkpoint_sequence=0,
        issued_at="2026-09-04T00:00:00Z",
    )
    remote = FakeVps(
        vault_id,
        [
            device_record(root, device_id="root-device"),
            device_record(
                peer,
                device_id="peer-device",
                membership=membership,
                signature=sign_membership(membership, root.signing_private_bytes),
            ),
        ],
    )
    vault_key = generate_vault_key()
    root_dev = engine(
        tmp_path,
        "root",
        remote=remote,
        cfg=config(vault_id, root, root, "root-device"),
        identity=root,
        vault_key=vault_key,
    )
    peer_dev = engine(
        tmp_path,
        "peer",
        remote=remote,
        cfg=config(vault_id, root, peer, "peer-device"),
        identity=peer,
        vault_key=vault_key,
    )
    return remote, root_dev, peer_dev


def test_two_devices_exchange_secret_without_relay_plaintext(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (
        peer_engine,
        _pp,
        peer_store,
        peer_backend,
    ) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    entry = add_entry(holder, "shared-api", "super-secret", type=EntryType.API_KEY)

    assert root_engine.push() == 1
    assert peer_engine.pull() == 1
    assert peer_store.get_by_name("shared-api").id == entry.id
    assert peer_backend.get(entry.id).unseal() == "super-secret"

    server_dump = json.dumps(remote.commits, sort_keys=True)
    assert "super-secret" not in server_dump
    assert "shared-api" not in server_dump


def test_secret_only_same_metadata_conflict_converges_deterministically(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (
        peer_engine,
        _pp,
        _peer_store,
        peer_backend,
    ) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    entry = add_entry(holder, "rotated-api", "initial", type=EntryType.API_KEY)
    root_engine.push()
    peer_engine.pull()

    # Simulate two secret rotations within the same metadata timestamp.
    root_backend.set(entry.id, "root-rotation")
    peer_backend.set(entry.id, "peer-rotation")
    root_engine.push()
    peer_engine.push()
    root_engine.pull()

    assert root_backend.get(entry.id) == peer_backend.get(entry.id)
    stable_head = remote.head
    assert root_engine.push() == 0
    assert peer_engine.push() == 0
    assert remote.head == stable_head


def test_relay_cannot_swap_ciphertext_under_signed_manifest(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (peer_engine, *_rest) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "shared-api", "super-secret")
    root_engine.push()
    remote.commits[remote.head]["snapshot_ciphertext"] = b64(b"forged")

    with pytest.raises(VpsTrustError):
        peer_engine.pull()


def test_relay_cannot_hide_a_previously_trusted_head(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (peer_engine, *_rest) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "shared-api", "super-secret")
    root_engine.push()
    peer_engine.pull()
    remote.head = None

    with pytest.raises(VpsTrustError, match="omitted"):
        peer_engine.pull()


def test_unsigned_device_membership_is_not_trusted(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (peer_engine, *_rest) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "shared-api", "super-secret")
    root_engine.push()
    remote.devices[1]["membership_signature"] = b64(b"0" * 64)

    with pytest.raises(VpsTrustError, match="membership signature"):
        peer_engine.status()


def test_new_device_requires_signed_onboarding_checkpoint_in_chain(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (peer_engine, *_rest) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "shared-api", "super-secret")
    root_engine.push()
    peer_engine.config = replace(
        peer_engine.config,
        trusted_checkpoint_commit_id="a" * 64,
        trusted_checkpoint_manifest_hash="b" * 64,
        trusted_checkpoint_sequence=1,
    )

    with pytest.raises(VpsTrustError, match="onboarding checkpoint"):
        peer_engine.pull()


def test_vps_config_contains_only_public_material(tmp_path):
    root = generate_device_identity("root-device")
    cfg = config("vault-test", root, root, "root-device")
    paths = Paths(root=tmp_path / "config")
    save_vps_config(cfg, paths)
    raw = (paths.root / "vps-sync.json").read_text()

    assert cfg.root_sign_public_key in raw
    assert b64(root.signing_private_bytes) not in raw
    assert "device-token" not in raw


def test_push_retries_and_merges_head_that_won_cas_race(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (
        peer_engine, _pp, peer_store, peer_backend,
    ) = two_devices(tmp_path)
    root_holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    peer_holder = type("Holder", (), {"store": peer_store, "backend": peer_backend})()
    add_entry(root_holder, "base-api", "base")
    root_engine.push()
    peer_engine.pull()
    add_entry(root_holder, "root-only", "root")
    add_entry(peer_holder, "peer-only", "peer")
    remote.before_append = peer_engine.push

    root_engine.push()

    assert {entry.name for entry in root_store.list()} == {"base-api", "root-only", "peer-only"}
    assert remote.commits[remote.head]["sequence"] == 3


def test_corrupt_local_anchor_fails_closed(tmp_path):
    _remote, (root_engine, root_paths, root_store, root_backend), _peer = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "base-api", "base")
    root_engine.push()
    (root_paths.root / "vps-sync-state.json").write_text("not-json")

    with pytest.raises(VpsTrustError, match="unreadable or malformed"):
        root_engine.pull()


def test_signed_revocation_blocks_device_from_publishing(tmp_path):
    remote, (root_engine, _rp, root_store, root_backend), (
        peer_engine, _pp, peer_store, peer_backend,
    ) = two_devices(tmp_path)
    holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
    add_entry(holder, "base-api", "base")
    root_engine.push()
    peer_engine.pull()
    root_head = root_engine.verified_head()
    root_identity_private = root_engine.signing_private_key
    revocation = make_revocation_statement(
        vault_id="vault-test",
        device_id="peer-device",
        revoked_by_device_id="root-device",
        checkpoint_commit_id=root_head.commit_id,
        checkpoint_manifest_hash=root_head.manifest_hash,
        checkpoint_sequence=root_head.sequence,
        issued_at="2026-09-04T00:01:00Z",
    )
    peer_record = remote.devices[1]
    peer_record.update(
        {
            "status": "revoked",
            "revoked_by_device_id": "root-device",
            "revocation_statement": canonical_json_bytes(revocation).decode(),
            "revocation_signature": sign_revocation(revocation, root_identity_private),
        }
    )
    peer_holder = type("Holder", (), {"store": peer_store, "backend": peer_backend})()
    add_entry(peer_holder, "peer-only", "peer")

    with pytest.raises(VpsTrustError, match="has been revoked"):
        peer_engine.push()
