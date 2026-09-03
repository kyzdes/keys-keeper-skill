"""Security and concurrency tests for the zero-knowledge VPS sync service."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from keys_keeper.sync_protocol_v2 import (
    build_signed_commit,
    canonical_json_bytes,
    generate_device_identity,
    generate_vault_key,
    seal_snapshot,
    verify_commit_signature,
)
from keys_keeper.sync_server import MAX_REQUEST_BODY, SyncServerApp, create_http_server


ADMIN_TOKEN = "admin-token-for-tests"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class Clock:
    def __init__(self, value: int = 1_800_000_000):
        self.value = value

    def __call__(self) -> int:
        return self.value


@contextmanager
def _running(app: SyncServerApp) -> Iterator[tuple[str, int]]:
    server = create_http_server(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _request(
    address: tuple[str, int],
    method: str,
    path: str,
    *,
    body: dict[str, Any] | bytes | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    request_headers = dict(headers or {})
    if isinstance(body, dict):
        data = json.dumps(body, separators=(",", ":")).encode()
        request_headers.setdefault("Content-Type", "application/json")
    else:
        data = body
    connection = http.client.HTTPConnection(*address, timeout=5)
    try:
        connection.request(method, path, body=data, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        return response.status, json.loads(response_body)
    finally:
        connection.close()


def _identity_payload(identity: Any, token: str) -> dict[str, str]:
    return {
        "device_token": token,
        "sign_public_key": _b64(identity.signing_public_bytes),
        "wrap_public_key": _b64(identity.agreement_public_bytes),
    }


def _create_vault(
    address: tuple[str, int], token: str | None = None
) -> tuple[dict[str, Any], Any, str]:
    identity = generate_device_identity()
    device_token = token or secrets.token_urlsafe(32)
    status, created = _request(
        address,
        "POST",
        "/v1/vaults",
        body=_identity_payload(identity, device_token),
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert status == 201
    return created, identity, device_token


def _auth(device_id: str, token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "X-Device-ID": device_id,
    }


def _commit_payload(
    *,
    vault_id: str,
    device_id: str,
    identity: Any,
    vault_key: bytes,
    plaintext: bytes,
    sequence: int = 1,
    parent_commit_id: str | None = None,
    parent_manifest_hash: str | None = None,
    timestamp: str = "2027-01-15T08:00:00Z",
) -> tuple[dict[str, Any], bytes, bytes]:
    snapshot = seal_snapshot(plaintext, vault_key=vault_key, vault_id=vault_id)
    commit = build_signed_commit(
        snapshot,
        vault_id=vault_id,
        sequence=sequence,
        parent_commit_id=parent_commit_id,
        parent_manifest_hash=parent_manifest_hash,
        author_device_id=device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=timestamp,
    )
    return (
        {
            "expected_parent_commit_id": parent_commit_id,
            "commit_blob": _b64(commit),
            "snapshot_ciphertext": _b64(snapshot),
        },
        commit,
        snapshot,
    )


@pytest.fixture
def app(tmp_path: Path) -> SyncServerApp:
    return SyncServerApp(tmp_path / "sync.sqlite3", ADMIN_TOKEN)


def test_create_vault_requires_bootstrap_and_hashes_device_token(app: SyncServerApp) -> None:
    with _running(app) as address:
        status, health = _request(address, "GET", "/healthz")
        assert status == 200
        assert health == {"status": "ok"}
        identity = generate_device_identity()
        token = secrets.token_urlsafe(32)
        payload = _identity_payload(identity, token)
        status, error = _request(address, "POST", "/v1/vaults", body=payload)
        assert status == 401
        assert error["error"]["code"] == "unauthorized"

        status, created = _request(
            address,
            "POST",
            "/v1/vaults",
            body=payload,
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert status == 201
        assert created["head_commit_id"] is None

    with sqlite3.connect(app.database) as connection:
        stored_hash, = connection.execute(
            "SELECT token_hash FROM devices WHERE device_id = ?", (created["device_id"],)
        ).fetchone()
    assert bytes(stored_hash) == hashlib.sha256(token.encode()).digest()
    assert token.encode() not in Path(app.database).read_bytes()


def test_device_auth_head_commit_and_persistence(tmp_path: Path) -> None:
    database = tmp_path / "persistent.sqlite3"
    app = SyncServerApp(database, ADMIN_TOKEN)
    with _running(app) as address:
        created, identity, token = _create_vault(address)
        vault_id, device_id = created["vault_id"], created["device_id"]
        headers = _auth(device_id, token)

        status, head = _request(address, "GET", f"/v1/vaults/{vault_id}/head", headers=headers)
        assert status == 200
        assert head == {"head_commit_id": None, "manifest_hash": None, "sequence": None}

        payload, commit, snapshot = _commit_payload(
            vault_id=vault_id,
            device_id=device_id,
            identity=identity,
            vault_key=generate_vault_key(),
            plaintext=b"ciphertext-only server",
        )
        status, appended = _request(
            address, "POST", f"/v1/vaults/{vault_id}/commits", body=payload, headers=headers
        )
        assert status == 201
        verified = verify_commit_signature(
            commit,
            signing_public_key=identity.signing_public_bytes,
            snapshot_ciphertext=snapshot,
        )
        assert appended["commit_id"] == verified.commit_id

    restarted = SyncServerApp(database, "a-new-in-memory-admin-token")
    with _running(restarted) as address:
        status, fetched = _request(
            address,
            "GET",
            f"/v1/vaults/{vault_id}/commits/{verified.commit_id}",
            headers=headers,
        )
        assert status == 200
        assert fetched["commit_blob"] == _b64(commit)
        assert fetched["snapshot_ciphertext"] == _b64(snapshot)
        status, listed = _request(
            address,
            "GET",
            f"/v1/vaults/{vault_id}/commits?after_sequence=0&limit=10",
            headers=headers,
        )
        assert status == 200
        assert [item["commit_id"] for item in listed["commits"]] == [verified.commit_id]


def test_wrong_token_wrong_vault_and_revoked_device_are_denied(app: SyncServerApp) -> None:
    with _running(app) as address:
        first, _, first_token = _create_vault(address)
        second, _, second_token = _create_vault(address)
        status, _ = _request(
            address,
            "GET",
            f"/v1/vaults/{first['vault_id']}/head",
            headers=_auth(first["device_id"], "x" * 32),
        )
        assert status == 401
        status, _ = _request(
            address,
            "GET",
            f"/v1/vaults/{first['vault_id']}/head",
            headers=_auth(second["device_id"], second_token),
        )
        assert status == 403

        peer_identity = generate_device_identity("dev-peer-00000001")
        peer_token = "peer-token-for-tests-000000000000"
        with sqlite3.connect(app.database) as connection:
            connection.execute(
                """INSERT INTO devices(
                       device_id, vault_id, sign_public_key, wrap_public_key,
                       token_hash, status, approved_by_device_id, created_at, approved_at
                   ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?)""",
                (
                    peer_identity.device_id,
                    first["vault_id"],
                    _b64(peer_identity.signing_public_bytes),
                    _b64(peer_identity.agreement_public_bytes),
                    hashlib.sha256(peer_token.encode()).digest(),
                    first["device_id"],
                    1_800_000_000,
                    1_800_000_000,
                ),
            )
        status, denied = _request(
            address,
            "POST",
            f"/v1/vaults/{first['vault_id']}/devices/{first['device_id']}/revoke",
            body={
                "expected_head_commit_id": None,
                "revocation_statement": "opaque-revocation",
                "revocation_signature": "signed",
            },
            headers=_auth(first["device_id"], first_token),
        )
        assert status == 409
        assert denied["error"]["code"] == "root_revoke_forbidden"

        status, denied = _request(
            address,
            "POST",
            f"/v1/vaults/{first['vault_id']}/devices/{peer_identity.device_id}/revoke",
            body={
                "expected_head_commit_id": "a" * 64,
                "revocation_statement": "opaque-revocation",
                "revocation_signature": "signed",
            },
            headers=_auth(first["device_id"], first_token),
        )
        assert status == 409
        assert denied["error"]["code"] == "cas_conflict"

        status, revoked = _request(
            address,
            "POST",
            f"/v1/vaults/{first['vault_id']}/devices/{peer_identity.device_id}/revoke",
            body={
                "expected_head_commit_id": None,
                "revocation_statement": "opaque-revocation",
                "revocation_signature": "signed",
            },
            headers=_auth(first["device_id"], first_token),
        )
        assert status == 200
        assert revoked["status"] == "revoked"
        status, _ = _request(
            address,
            "GET",
            f"/v1/vaults/{first['vault_id']}/head",
            headers=_auth(peer_identity.device_id, peer_token),
        )
        assert status == 403


def test_tampered_commit_or_ciphertext_is_rejected(app: SyncServerApp) -> None:
    with _running(app) as address:
        created, identity, token = _create_vault(address)
        vault_id, device_id = created["vault_id"], created["device_id"]
        headers = _auth(device_id, token)
        payload, commit, snapshot = _commit_payload(
            vault_id=vault_id,
            device_id=device_id,
            identity=identity,
            vault_key=generate_vault_key(),
            plaintext=b"secret snapshot",
        )

        parsed = json.loads(commit)
        parsed["signature"] = ("A" if parsed["signature"][0] != "A" else "B") + parsed[
            "signature"
        ][1:]
        tampered = dict(payload, commit_blob=_b64(canonical_json_bytes(parsed)))
        status, error = _request(
            address, "POST", f"/v1/vaults/{vault_id}/commits", body=tampered, headers=headers
        )
        assert status == 422
        assert error["error"]["code"] == "invalid_commit"

        corrupted_snapshot = bytearray(snapshot)
        corrupted_snapshot[-2] ^= 1
        tampered = dict(payload, snapshot_ciphertext=_b64(bytes(corrupted_snapshot)))
        status, _ = _request(
            address, "POST", f"/v1/vaults/{vault_id}/commits", body=tampered, headers=headers
        )
        assert status == 422

        status, head = _request(address, "GET", f"/v1/vaults/{vault_id}/head", headers=headers)
        assert status == 200
        assert head["head_commit_id"] is None


def test_atomic_compare_and_swap_allows_only_one_concurrent_append(app: SyncServerApp) -> None:
    with _running(app) as address:
        created, identity, token = _create_vault(address)
        vault_id, device_id = created["vault_id"], created["device_id"]
        headers = _auth(device_id, token)
        vault_key = generate_vault_key()
        payloads = [
            _commit_payload(
                vault_id=vault_id,
                device_id=device_id,
                identity=identity,
                vault_key=vault_key,
                plaintext=f"candidate-{number}".encode(),
                timestamp=f"2027-01-15T08:00:0{number}Z",
            )[0]
            for number in (1, 2)
        ]
        barrier = threading.Barrier(3)
        results: list[int] = []

        def append(payload: dict[str, Any]) -> None:
            barrier.wait()
            status, _ = _request(
                address,
                "POST",
                f"/v1/vaults/{vault_id}/commits",
                body=payload,
                headers=headers,
            )
            results.append(status)

        threads = [threading.Thread(target=append, args=(payload,)) for payload in payloads]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=5)

        assert sorted(results) == [201, 409]
        status, listed = _request(
            address, "GET", f"/v1/vaults/{vault_id}/commits", headers=headers
        )
        assert status == 200
        assert len(listed["commits"]) == 1
        assert "snapshot_ciphertext" not in listed["commits"][0]
        assert "commit_blob" not in listed["commits"][0]


def test_signed_parent_manifest_hash_must_extend_current_head(app: SyncServerApp) -> None:
    with _running(app) as address:
        created, identity, token = _create_vault(address)
        vault_id, device_id = created["vault_id"], created["device_id"]
        headers = _auth(device_id, token)
        vault_key = generate_vault_key()
        root_payload, root_blob, root_snapshot = _commit_payload(
            vault_id=vault_id,
            device_id=device_id,
            identity=identity,
            vault_key=vault_key,
            plaintext=b"root",
        )
        status, _ = _request(
            address,
            "POST",
            f"/v1/vaults/{vault_id}/commits",
            body=root_payload,
            headers=headers,
        )
        assert status == 201
        root = verify_commit_signature(
            root_blob,
            signing_public_key=identity.signing_public_bytes,
            snapshot_ciphertext=root_snapshot,
        )

        bad_child, _, _ = _commit_payload(
            vault_id=vault_id,
            device_id=device_id,
            identity=identity,
            vault_key=vault_key,
            plaintext=b"child",
            sequence=2,
            parent_commit_id=root.commit_id,
            parent_manifest_hash="0" * 64,
            timestamp="2027-01-15T08:00:03Z",
        )
        status, error = _request(
            address,
            "POST",
            f"/v1/vaults/{vault_id}/commits",
            body=bad_child,
            headers=headers,
        )
        assert status == 422
        assert error["error"]["code"] == "invalid_commit"

        good_child, _, _ = _commit_payload(
            vault_id=vault_id,
            device_id=device_id,
            identity=identity,
            vault_key=vault_key,
            plaintext=b"child",
            sequence=2,
            parent_commit_id=root.commit_id,
            parent_manifest_hash=root.manifest_hash,
            timestamp="2027-01-15T08:00:04Z",
        )
        status, child = _request(
            address,
            "POST",
            f"/v1/vaults/{vault_id}/commits",
            body=good_child,
            headers=headers,
        )
        assert status == 201
        assert child["sequence"] == 2


def test_invite_claim_approve_is_one_time_and_returns_wrapped_key(app: SyncServerApp) -> None:
    with _running(app) as address:
        root, _, root_token = _create_vault(address)
        root_headers = _auth(root["device_id"], root_token)
        secret = secrets.token_urlsafe(32)
        status, invite = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/invites",
            body={"secret_hash": hashlib.sha256(secret.encode()).hexdigest()},
            headers=root_headers,
        )
        assert status == 201

        claimant = generate_device_identity()
        claimant_token = secrets.token_urlsafe(32)
        claim_payload = dict(
            _identity_payload(claimant, claimant_token),
            secret=secret,
            device_id=claimant.device_id,
        )
        status, claim = _request(
            address,
            "POST",
            f"/v1/invites/{invite['invite_id']}/claim",
            body=claim_payload,
        )
        assert status == 201
        pending_headers = _auth(claim["device_id"], claimant_token)
        status, pending = _request(
            address,
            "GET",
            f"/v1/invites/{invite['invite_id']}/status",
            headers=pending_headers,
        )
        assert status == 200
        assert pending["status"] == "claimed"

        status, repeated = _request(
            address,
            "POST",
            f"/v1/invites/{invite['invite_id']}/claim",
            body=claim_payload,
        )
        assert status == 201
        assert repeated["device_id"] == claim["device_id"]

        other = generate_device_identity()
        other_claim = dict(
            _identity_payload(other, secrets.token_urlsafe(32)),
            secret=secret,
            device_id=other.device_id,
        )
        status, _ = _request(
            address,
            "POST",
            f"/v1/invites/{invite['invite_id']}/claim",
            body=other_claim,
        )
        assert status == 409

        status, inspected = _request(
            address,
            "GET",
            f"/v1/vaults/{root['vault_id']}/invites/{invite['invite_id']}",
            headers=root_headers,
        )
        assert status == 200
        assert inspected["claimant"]["wrap_public_key"] == claim_payload["wrap_public_key"]

        approval = {
            "wrapped_vault_key": "opaque-hpke-envelope",
            "membership_statement": "opaque-membership-record",
            "membership_signature": "opaque-signature",
        }
        status, approved = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/invites/{invite['invite_id']}/approve",
            body=approval,
            headers=root_headers,
        )
        assert status == 200
        assert approved["device_id"] == claim["device_id"]

        status, ready = _request(
            address,
            "GET",
            f"/v1/invites/{invite['invite_id']}/status",
            headers=pending_headers,
        )
        assert status == 200
        assert ready["wrapped_vault_key"] == approval["wrapped_vault_key"]
        assert ready["membership_statement"] == approval["membership_statement"]

        status, devices = _request(
            address,
            "GET",
            f"/v1/vaults/{root['vault_id']}/devices",
            headers=pending_headers,
        )
        assert status == 200
        new_record = next(
            item for item in devices["devices"] if item["device_id"] == claim["device_id"]
        )
        assert new_record["approved_by_device_id"] == root["device_id"]
        assert "token_hash" not in new_record
        assert "wrapped_vault_key" not in new_record

        # Ordinary active devices can publish, but administration stays with
        # the pinned root device.
        peer_headers = _auth(claim["device_id"], claimant_token)
        peer_commit, _, _ = _commit_payload(
            vault_id=root["vault_id"],
            device_id=claim["device_id"],
            identity=claimant,
            vault_key=generate_vault_key(),
            plaintext=b"peer may publish",
        )
        status, _ = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/commits",
            body=peer_commit,
            headers=peer_headers,
        )
        assert status == 201
        status, denied = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/invites",
            body={"secret_hash": "0" * 64},
            headers=peer_headers,
        )
        assert status == 403
        assert denied["error"]["code"] == "root_required"
        status, denied = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/devices/{root['device_id']}/revoke",
            body={
                "expected_head_commit_id": root.get("head_commit_id"),
                "revocation_statement": "opaque",
                "revocation_signature": "signed",
            },
            headers=peer_headers,
        )
        assert status == 403
        assert denied["error"]["code"] == "root_required"


def test_expired_or_wrong_secret_invite_cannot_be_claimed(tmp_path: Path) -> None:
    clock = Clock()
    app = SyncServerApp(tmp_path / "clock.sqlite3", ADMIN_TOKEN, clock=clock)
    with _running(app) as address:
        root, _, root_token = _create_vault(address)
        root_headers = _auth(root["device_id"], root_token)
        secret = secrets.token_urlsafe(32)
        status, invite = _request(
            address,
            "POST",
            f"/v1/vaults/{root['vault_id']}/invites",
            body={
                "secret_hash": hashlib.sha256(secret.encode()).hexdigest(),
                "expires_in_seconds": 5,
            },
            headers=root_headers,
        )
        assert status == 201
        claimant = generate_device_identity()
        claim = dict(
            _identity_payload(claimant, secrets.token_urlsafe(32)),
            secret="x" * 32,
            device_id=claimant.device_id,
        )
        status, _ = _request(
            address, "POST", f"/v1/invites/{invite['invite_id']}/claim", body=claim
        )
        assert status == 401

        clock.value += 5
        claim["secret"] = secret
        status, error = _request(
            address, "POST", f"/v1/invites/{invite['invite_id']}/claim", body=claim
        )
        assert status == 410
        assert error["error"]["code"] == "invite_expired"
        with sqlite3.connect(app.database) as connection:
            stored_status, = connection.execute(
                "SELECT status FROM invites WHERE invite_id = ?", (invite["invite_id"],)
            ).fetchone()
        assert stored_status == "expired"


def test_strict_json_size_limit_and_private_bind_default(app: SyncServerApp) -> None:
    with pytest.raises(ValueError, match="non-loopback"):
        create_http_server(app, host="0.0.0.0")

    with _running(app) as address:
        status, _ = _request(
            address,
            "POST",
            "/v1/vaults",
            body=b"{}",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "text/plain"},
        )
        assert status == 415

        status, error = _request(
            address,
            "POST",
            "/v1/vaults",
            body=b'{"device_token":"a","device_token":"b"}',
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"},
        )
        assert status == 400
        assert error["error"]["code"] == "invalid_json"

        connection = http.client.HTTPConnection(*address, timeout=5)
        try:
            connection.request(
                "POST",
                "/v1/vaults",
                body=b"{}",
                headers={
                    "Authorization": f"Bearer {ADMIN_TOKEN}",
                    "Content-Type": "application/json",
                    "Content-Length": str(MAX_REQUEST_BODY + 1),
                },
            )
            response = connection.getresponse()
            assert response.status == 413
            response.read()
        finally:
            connection.close()
