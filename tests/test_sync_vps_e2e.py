"""Real HTTP + SQLite + KK2 two-device integration test."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from unittest.mock import patch

from _sync_fakes import FakeBackend, add_entry
from keys_keeper.backend import Sealed
from keys_keeper import cli
from keys_keeper.cli_sync_vps import _invite_trust_fingerprint
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore
from keys_keeper.sync_protocol_v2 import (
    canonical_json_bytes,
    generate_device_identity,
    generate_vault_key,
    unwrap_vault_key_for_recipient,
    wrap_vault_key_for_recipient,
)
from keys_keeper.sync_server import SyncServerApp, create_http_server
from keys_keeper.sync_vps import (
    VpsSyncConfig,
    VpsSyncEngine,
    invite_secret,
    invite_secret_hash,
    make_membership_statement,
    sign_membership,
    verify_membership,
    load_vps_config,
)
from keys_keeper.sync_vps_client import VpsSyncClient, VpsTransportError


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@contextmanager
def running_syncd(tmp_path):
    app = SyncServerApp(tmp_path / "syncd.sqlite3", "admin-token-for-e2e")
    server = create_http_server(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}", tmp_path / "syncd.sqlite3"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def make_engine(tmp_path, name, client, config, identity, vault_key):
    paths = Paths(root=tmp_path / name)
    paths.ensure()
    store = MetadataStore(paths)
    backend = FakeBackend()
    engine = VpsSyncEngine(
        client=client,
        config=config,
        store=store,
        backend=backend,
        vault_key=vault_key,
        signing_private_key=identity.signing_private_bytes,
        paths=paths,
    )
    return engine, store, backend


def test_real_syncd_pairing_and_encrypted_exchange(tmp_path):
    with running_syncd(tmp_path) as (endpoint, database):
        root_identity = generate_device_identity()
        root_token = "root-device-token-with-at-least-32-bytes"
        created = VpsSyncClient(
            base_url=endpoint, token=Sealed("admin-token-for-e2e")
        ).create_vault(
            device_token=Sealed(root_token),
            sign_public_key=b64(root_identity.signing_public_bytes),
            wrap_public_key=b64(root_identity.agreement_public_bytes),
        )
        vault_id, root_id = created["vault_id"], created["device_id"]
        root_client = VpsSyncClient(
            base_url=endpoint, token=Sealed(root_token), device_id=root_id
        )
        root_config = VpsSyncConfig(
            endpoint=endpoint,
            vault_id=vault_id,
            device_id=root_id,
            root_device_id=root_id,
            root_sign_public_key=b64(root_identity.signing_public_bytes),
            sign_public_key=b64(root_identity.signing_public_bytes),
            wrap_public_key=b64(root_identity.agreement_public_bytes),
        )
        vault_key = generate_vault_key()
        root_engine, root_store, root_backend = make_engine(
            tmp_path, "root", root_client, root_config, root_identity, vault_key
        )
        root_holder = type("Holder", (), {"store": root_store, "backend": root_backend})()
        entry = add_entry(root_holder, "production-api", "secret-never-on-vps")
        assert root_engine.push() == 1

        secret = invite_secret()
        invitation = root_client.create_invite(
            vault_id, secret_hash=invite_secret_hash(secret), expires_in_seconds=900
        )
        peer_identity = generate_device_identity()
        peer_token = "peer-device-token-with-at-least-32-bytes"
        claim = VpsSyncClient(base_url=endpoint).claim_invite(
            invitation["invite_id"],
            secret=Sealed(secret),
            device_id=peer_identity.device_id,
            device_token=Sealed(peer_token),
            sign_public_key=b64(peer_identity.signing_public_bytes),
            wrap_public_key=b64(peer_identity.agreement_public_bytes),
        )
        peer_id = claim["device_id"]
        head = root_client.get_head(vault_id)
        statement = make_membership_statement(
            vault_id=vault_id,
            device_id=peer_id,
            sign_public_key=b64(peer_identity.signing_public_bytes),
            wrap_public_key=b64(peer_identity.agreement_public_bytes),
            approved_by_device_id=root_id,
            checkpoint_commit_id=head["head_commit_id"],
            checkpoint_manifest_hash=head["manifest_hash"],
            checkpoint_sequence=head["sequence"],
            issued_at="2026-09-04T00:00:00Z",
        )
        wrapped = wrap_vault_key_for_recipient(
            vault_key,
            recipient_public_key=peer_identity.agreement_public_bytes,
            vault_id=vault_id,
            recipient_device_id=peer_id,
            context=canonical_json_bytes(statement),
        )
        root_client.approve_invite(
            vault_id,
            invitation["invite_id"],
            wrapped_vault_key=wrapped.decode(),
            membership_statement=canonical_json_bytes(statement).decode(),
            membership_signature=sign_membership(statement, root_identity.signing_private_bytes),
        )

        peer_client = VpsSyncClient(
            base_url=endpoint, token=Sealed(peer_token), device_id=peer_id
        )
        approved = peer_client.invite_status(invitation["invite_id"])
        received_statement = json.loads(approved["membership_statement"])
        verify_membership(
            received_statement,
            approved["membership_signature"],
            root_identity.signing_public_bytes,
        )
        peer_vault_key = unwrap_vault_key_for_recipient(
            approved["wrapped_vault_key"].encode(),
            recipient_private_key=peer_identity.agreement_private_bytes,
            expected_vault_id=vault_id,
            expected_recipient_device_id=peer_id,
            context=canonical_json_bytes(received_statement),
        )
        assert peer_vault_key == vault_key

        peer_config = VpsSyncConfig(
            endpoint=endpoint,
            vault_id=vault_id,
            device_id=peer_id,
            root_device_id=root_id,
            root_sign_public_key=b64(root_identity.signing_public_bytes),
            sign_public_key=b64(peer_identity.signing_public_bytes),
            wrap_public_key=b64(peer_identity.agreement_public_bytes),
        )
        peer_engine, peer_store, peer_backend = make_engine(
            tmp_path, "peer", peer_client, peer_config, peer_identity, peer_vault_key
        )
        assert peer_engine.pull() == 1
        assert peer_store.get_by_name("production-api").id == entry.id
        assert peer_backend.get(entry.id).unseal() == "secret-never-on-vps"

        raw_database = b"".join(
            path.read_bytes()
            for path in (database, database.with_name(database.name + "-wal"))
            if path.exists()
        )
        assert b"secret-never-on-vps" not in raw_database
        assert b"production-api" not in raw_database
        # The server retains only a SHA-256 digest of bearer credentials.
        assert root_token.encode() not in raw_database
        if os.name == "posix":
            assert database.stat().st_mode & 0o777 == 0o600
            assert database.parent.stat().st_mode & 0o777 == 0o700
        with sqlite3.connect(database) as connection:
            stored_hash = connection.execute(
                "SELECT token_hash FROM devices WHERE device_id = ?", (root_id,)
            ).fetchone()[0]
        assert stored_hash == hashlib.sha256(root_token.encode()).digest()


def test_cli_init_and_push_against_real_syncd(tmp_path, monkeypatch, capsys):
    with running_syncd(tmp_path) as (endpoint, database):
        home = tmp_path / "cli-home"
        home.mkdir()
        recovery = tmp_path / "offline-recovery.json"
        backend = FakeBackend()
        monkeypatch.setenv("KEYS_KEEPER_HOME", str(home))
        monkeypatch.setattr("keys_keeper.cli_sync_vps.build_backend", lambda: backend)
        monkeypatch.setattr("keys_keeper.cli.build_backend", lambda: backend)
        with patch("getpass.getpass", return_value="admin-token-for-e2e"):
            assert cli.main(
                [
                    "sync", "vps", "init", "--endpoint", endpoint,
                    "--recovery-file", str(recovery),
                ]
            ) == 0
        with patch("sys.stdin", __import__("io").StringIO("cli-secret\n")):
            assert cli.main(["add", "cli-api", "--type", "api_key", "--stdin"]) == 0
        assert cli.main(["sync", "vps", "push"]) == 0

        output = capsys.readouterr().out + capsys.readouterr().err
        assert "admin-token-for-e2e" not in output
        assert "cli-secret" not in output
        assert recovery.exists()
        if os.name == "posix":
            assert oct(recovery.stat().st_mode & 0o777) == "0o600"
        assert "recovery_secret" in recovery.read_text()
        assert "cli-secret" not in database.read_bytes().decode("latin-1")


def test_complete_cli_device_enrollment(tmp_path, monkeypatch, capsys):
    with running_syncd(tmp_path) as (endpoint, _database):
        root_home = tmp_path / "root-home"
        peer_home = tmp_path / "peer-home"
        root_home.mkdir()
        peer_home.mkdir()
        root_backend = FakeBackend()
        peer_backend = FakeBackend()
        backends = {str(root_home): root_backend, str(peer_home): peer_backend}

        def current_backend():
            return backends[os.environ["KEYS_KEEPER_HOME"]]

        monkeypatch.setattr("keys_keeper.cli_sync_vps.build_backend", current_backend)
        monkeypatch.setattr("keys_keeper.cli.build_backend", current_backend)
        monkeypatch.setenv("KEYS_KEEPER_HOME", str(root_home))
        recovery = tmp_path / "root-recovery.json"
        with patch("getpass.getpass", return_value="admin-token-for-e2e"):
            assert cli.main(
                ["sync", "vps", "init", "--endpoint", endpoint, "--recovery-file", str(recovery)]
            ) == 0
        with patch("sys.stdin", __import__("io").StringIO("shared-via-cli\n")):
            assert cli.main(["add", "paired-api", "--type", "api_key", "--stdin"]) == 0
        assert cli.main(["sync", "vps", "push"]) == 0
        invitation_path = tmp_path / "device-invite.json"
        assert cli.main(["sync", "vps", "invite", "--out", str(invitation_path)]) == 0
        invitation = json.loads(invitation_path.read_text())

        monkeypatch.setenv("KEYS_KEEPER_HOME", str(peer_home))
        assert cli.main(
            [
                "sync", "vps", "join", "--invite", str(invitation_path),
                "--trust-fingerprint", _invite_trust_fingerprint(invitation),
            ]
        ) == 0
        pending = load_vps_config(Paths())
        fingerprint_hash = hashlib.sha256(
            base64.urlsafe_b64decode(pending.sign_public_key + "==")
            + base64.urlsafe_b64decode(pending.wrap_public_key + "==")
        ).hexdigest()[:24]
        fingerprint = "-".join(
            fingerprint_hash[index:index + 4] for index in range(0, 24, 4)
        )

        monkeypatch.setenv("KEYS_KEEPER_HOME", str(root_home))
        assert cli.main(
            [
                "sync", "vps", "approve", invitation["invite_id"],
                "--invite", str(invitation_path),
                "--fingerprint", fingerprint,
            ]
        ) == 0

        monkeypatch.setenv("KEYS_KEEPER_HOME", str(peer_home))
        assert cli.main(["sync", "vps", "finish", "--invite", str(invitation_path)]) == 0
        assert cli.main(["sync", "vps", "pull"]) == 0
        assert MetadataStore(Paths()).get_by_name("paired-api") is not None
        entry = MetadataStore(Paths()).get_by_name("paired-api")
        assert peer_backend.get(entry.id).unseal() == "shared-via-cli"

        captured = capsys.readouterr()
        output = captured.out + captured.err
        assert "shared-via-cli" not in output
        assert invitation["invite_secret"] not in output


def test_cli_join_retries_same_claim_after_lost_response(tmp_path, monkeypatch):
    with running_syncd(tmp_path) as (endpoint, database):
        root_home = tmp_path / "retry-root"
        peer_home = tmp_path / "retry-peer"
        root_home.mkdir()
        peer_home.mkdir()
        root_backend = FakeBackend()
        peer_backend = FakeBackend()
        backends = {str(root_home): root_backend, str(peer_home): peer_backend}

        def current_backend():
            return backends[os.environ["KEYS_KEEPER_HOME"]]

        monkeypatch.setattr("keys_keeper.cli_sync_vps.build_backend", current_backend)
        monkeypatch.setenv("KEYS_KEEPER_HOME", str(root_home))
        with patch("getpass.getpass", return_value="admin-token-for-e2e"):
            assert cli.main(
                [
                    "sync", "vps", "init", "--endpoint", endpoint,
                    "--recovery-file", str(tmp_path / "retry-recovery.json"),
                ]
            ) == 0
        invitation_path = tmp_path / "retry-device-invite.json"
        assert cli.main(["sync", "vps", "invite", "--out", str(invitation_path)]) == 0
        invitation = json.loads(invitation_path.read_text())

        original_claim = VpsSyncClient.claim_invite
        lose_once = True

        def claim_then_lose(self, *args, **kwargs):
            nonlocal lose_once
            result = original_claim(self, *args, **kwargs)
            if lose_once:
                lose_once = False
                raise VpsTransportError("simulated lost response")
            return result

        monkeypatch.setattr(VpsSyncClient, "claim_invite", claim_then_lose)
        monkeypatch.setenv("KEYS_KEEPER_HOME", str(peer_home))
        join_args = [
            "sync", "vps", "join", "--invite", str(invitation_path),
            "--trust-fingerprint", _invite_trust_fingerprint(invitation),
        ]
        assert cli.main(join_args) == 1
        first_device_id = load_vps_config(Paths()).device_id
        assert cli.main(join_args) == 0
        assert load_vps_config(Paths()).device_id == first_device_id
        with sqlite3.connect(database) as connection:
            device_count = connection.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
        assert device_count == 2
