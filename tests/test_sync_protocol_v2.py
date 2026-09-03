from __future__ import annotations

import json

import pytest

from keys_keeper.sync_protocol_v2 import (
    AuthenticationError,
    ChainValidationError,
    MAX_COMMIT_SIZE,
    MAX_CONTEXT_SIZE,
    MAX_SNAPSHOT_PLAINTEXT_SIZE,
    ReplayDetected,
    SignatureVerificationError,
    ValidationError,
    build_signed_commit,
    canonical_json_bytes,
    compute_manifest_hash,
    generate_device_identity,
    generate_recovery_secret,
    generate_vault_key,
    open_snapshot,
    seal_snapshot,
    unwrap_vault_key_for_recipient,
    unwrap_vault_key_for_recovery,
    verify_commit,
    verify_commit_signature,
    wrap_vault_key_for_recipient,
    wrap_vault_key_for_recovery,
)


VAULT_ID = "vault-0123456789abcdef"
TIMESTAMP_1 = "2026-09-04T10:00:00Z"
TIMESTAMP_2 = "2026-09-04T10:01:00Z"
PAIRING_CONTEXT = b"keys-keeper/pairing/v1/session-123"


def _genesis(snapshot, identity, *, timestamp=TIMESTAMP_1):
    return build_signed_commit(
        snapshot,
        vault_id=VAULT_ID,
        sequence=1,
        parent_commit_id=None,
        parent_manifest_hash=None,
        author_device_id=identity.device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=timestamp,
    )


def _successor(snapshot, identity, parent, *, timestamp=TIMESTAMP_2):
    return build_signed_commit(
        snapshot,
        vault_id=VAULT_ID,
        sequence=parent.sequence + 1,
        parent_commit_id=parent.commit_id,
        parent_manifest_hash=parent.manifest_hash,
        author_device_id=identity.device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=timestamp,
    )


def _rewrite_commit(blob, mutator):
    value = json.loads(blob)
    mutator(value)
    return canonical_json_bytes(value)


def test_snapshot_commit_and_server_verifier_round_trip():
    vault_key = generate_vault_key()
    identity = generate_device_identity("device-a")
    plaintext = canonical_json_bytes({"entries": [{"id": "one", "secret": "s3cr3t"}]})
    snapshot = seal_snapshot(plaintext, vault_key=vault_key, vault_id=VAULT_ID)
    commit = _genesis(snapshot, identity)

    verified = verify_commit(
        commit,
        signing_public_key=identity.signing_public_key,
        snapshot_ciphertext=snapshot,
        expected_vault_id=VAULT_ID,
        expected_author_device_id="device-a",
        require_genesis=True,
    )

    assert open_snapshot(
        snapshot, vault_key=vault_key, expected_vault_id=VAULT_ID
    ) == plaintext
    assert verified.sequence == 1
    assert verified.parent_commit_id is None
    assert verified.parent_manifest_hash is None
    assert verified.manifest_hash == compute_manifest_hash(verified.manifest)
    assert len(verified.commit_id) == 64


def test_snapshot_wrong_key_and_wrong_vault_are_rejected():
    snapshot = seal_snapshot(b"secret", vault_key=generate_vault_key(), vault_id=VAULT_ID)
    with pytest.raises(AuthenticationError):
        open_snapshot(snapshot, vault_key=generate_vault_key(), expected_vault_id=VAULT_ID)
    with pytest.raises(AuthenticationError):
        open_snapshot(
            snapshot,
            vault_key=generate_vault_key(),
            expected_vault_id="different-vault",
        )


def test_commit_is_deterministic_for_identical_inputs():
    identity = generate_device_identity("device-a")
    snapshot = seal_snapshot(b"same", vault_key=generate_vault_key(), vault_id=VAULT_ID)
    one = _genesis(snapshot, identity)
    two = _genesis(snapshot, identity)
    assert one == two


def test_canonical_json_is_deterministic_and_rejects_unsupported_numbers():
    left = {"z": [3, "é"], "a": {"two": 2, "one": 1}}
    right = {"a": {"one": 1, "two": 2}, "z": [3, "é"]}
    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(left) == (
        b'{"a":{"one":1,"two":2},"z":[3,"\xc3\xa9"]}'
    )
    with pytest.raises(ValidationError):
        canonical_json_bytes({"float": 1.5})


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("protocol", "KK3"),
        ("format_profile", "kk2-commit-ed25519-sha256-v2"),
        ("vault_id", "vault-other"),
        ("sequence", 3),
        ("parent_commit_id", "a" * 64),
        ("parent_manifest_hash", "b" * 64),
        ("ciphertext_sha256", "c" * 64),
        ("author_device_id", "device-attacker"),
        ("timestamp", "2026-09-04T11:00:00Z"),
    ],
)
def test_tampering_any_manifest_binding_is_detected(field, replacement):
    key = generate_vault_key()
    identity = generate_device_identity("device-a")
    first_snapshot = seal_snapshot(b"one", vault_key=key, vault_id=VAULT_ID)
    genesis_blob = _genesis(first_snapshot, identity)
    parent = verify_commit_signature(
        genesis_blob,
        signing_public_key=identity.signing_public_key,
        snapshot_ciphertext=first_snapshot,
    )
    second_snapshot = seal_snapshot(b"two", vault_key=key, vault_id=VAULT_ID)
    commit = _successor(second_snapshot, identity, parent)
    tampered = _rewrite_commit(
        commit, lambda value: value["manifest"].__setitem__(field, replacement)
    )

    with pytest.raises((ValidationError, SignatureVerificationError)):
        verify_commit_signature(
            tampered,
            signing_public_key=identity.signing_public_key,
            snapshot_ciphertext=second_snapshot,
        )


def test_ciphertext_swap_and_wrong_signer_are_rejected_without_plaintext_access():
    key = generate_vault_key()
    author = generate_device_identity("author")
    stranger = generate_device_identity("stranger")
    snapshot = seal_snapshot(b"real", vault_key=key, vault_id=VAULT_ID)
    swapped = seal_snapshot(b"swapped", vault_key=key, vault_id=VAULT_ID)
    commit = _genesis(snapshot, author)

    with pytest.raises(SignatureVerificationError):
        verify_commit_signature(commit, signing_public_key=stranger.signing_public_key)
    with pytest.raises(SignatureVerificationError):
        verify_commit_signature(
            commit,
            signing_public_key=author.signing_public_key,
            snapshot_ciphertext=swapped,
        )


def test_parent_id_and_manifest_hash_must_match_trusted_head():
    key = generate_vault_key()
    identity = generate_device_identity("device-a")
    first_snapshot = seal_snapshot(b"one", vault_key=key, vault_id=VAULT_ID)
    first_blob = _genesis(first_snapshot, identity)
    first = verify_commit(
        first_blob,
        signing_public_key=identity.signing_public_key,
        snapshot_ciphertext=first_snapshot,
        require_genesis=True,
    )
    second_snapshot = seal_snapshot(b"two", vault_key=key, vault_id=VAULT_ID)

    wrong_parent_id_blob = build_signed_commit(
        second_snapshot,
        vault_id=VAULT_ID,
        sequence=2,
        parent_commit_id="0" * 64,
        parent_manifest_hash=first.manifest_hash,
        author_device_id=identity.device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=TIMESTAMP_2,
    )
    with pytest.raises(ChainValidationError, match="parent_commit_id"):
        verify_commit(
            wrong_parent_id_blob,
            signing_public_key=identity.signing_public_key,
            snapshot_ciphertext=second_snapshot,
            previous=first,
        )

    wrong_parent_hash_blob = build_signed_commit(
        second_snapshot,
        vault_id=VAULT_ID,
        sequence=2,
        parent_commit_id=first.commit_id,
        parent_manifest_hash="0" * 64,
        author_device_id=identity.device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=TIMESTAMP_2,
    )
    with pytest.raises(ChainValidationError, match="parent_manifest_hash"):
        verify_commit(
            wrong_parent_hash_blob,
            signing_public_key=identity.signing_public_key,
            snapshot_ciphertext=second_snapshot,
            previous=first,
        )


def test_sequence_gap_and_replay_are_rejected():
    key = generate_vault_key()
    identity = generate_device_identity("device-a")
    first_snapshot = seal_snapshot(b"one", vault_key=key, vault_id=VAULT_ID)
    first_blob = _genesis(first_snapshot, identity)
    first = verify_commit_signature(
        first_blob,
        signing_public_key=identity.signing_public_key,
        snapshot_ciphertext=first_snapshot,
    )

    with pytest.raises(ReplayDetected):
        verify_commit(
            first_blob,
            signing_public_key=identity.signing_public_key,
            minimum_sequence=1,
        )

    later_snapshot = seal_snapshot(b"later", vault_key=key, vault_id=VAULT_ID)
    gap = build_signed_commit(
        later_snapshot,
        vault_id=VAULT_ID,
        sequence=3,
        parent_commit_id=first.commit_id,
        parent_manifest_hash=first.manifest_hash,
        author_device_id=identity.device_id,
        signing_private_key=identity.signing_private_key,
        timestamp=TIMESTAMP_2,
    )
    with pytest.raises(ChainValidationError, match="next sequence"):
        verify_commit(
            gap,
            signing_public_key=identity.signing_public_key,
            snapshot_ciphertext=later_snapshot,
            previous=first,
        )


def test_device_recipient_key_wrap_round_trip_and_bindings():
    vault_key = generate_vault_key()
    recipient = generate_device_identity("device-b")
    other = generate_device_identity("device-c")
    wrapped = wrap_vault_key_for_recipient(
        vault_key,
        recipient_public_key=recipient.agreement_public_key,
        vault_id=VAULT_ID,
        recipient_device_id=recipient.device_id,
        context=PAIRING_CONTEXT,
    )

    assert unwrap_vault_key_for_recipient(
        wrapped,
        recipient_private_key=recipient.agreement_private_key,
        expected_vault_id=VAULT_ID,
        expected_recipient_device_id=recipient.device_id,
        context=PAIRING_CONTEXT,
    ) == vault_key
    with pytest.raises(AuthenticationError):
        unwrap_vault_key_for_recipient(
            wrapped,
            recipient_private_key=other.agreement_private_key,
            expected_vault_id=VAULT_ID,
            expected_recipient_device_id=recipient.device_id,
            context=PAIRING_CONTEXT,
        )
    with pytest.raises(AuthenticationError, match="context"):
        unwrap_vault_key_for_recipient(
            wrapped,
            recipient_private_key=recipient.agreement_private_key,
            expected_vault_id=VAULT_ID,
            expected_recipient_device_id=recipient.device_id,
            context=b"keys-keeper/pairing/v1/different-session",
        )
    with pytest.raises(AuthenticationError, match="recipient"):
        unwrap_vault_key_for_recipient(
            wrapped,
            recipient_private_key=recipient.agreement_private_key,
            expected_vault_id=VAULT_ID,
            expected_recipient_device_id=other.device_id,
            context=PAIRING_CONTEXT,
        )


def test_recovery_wrap_requires_random_32_byte_secret_and_round_trips():
    vault_key = generate_vault_key()
    recovery = generate_recovery_secret()
    wrapped = wrap_vault_key_for_recovery(
        vault_key, recovery_secret=recovery, vault_id=VAULT_ID
    )
    assert unwrap_vault_key_for_recovery(
        wrapped, recovery_secret=recovery, expected_vault_id=VAULT_ID
    ) == vault_key
    with pytest.raises(AuthenticationError):
        unwrap_vault_key_for_recovery(
            wrapped,
            recovery_secret=generate_recovery_secret(),
            expected_vault_id=VAULT_ID,
        )
    with pytest.raises(ValidationError, match="32 bytes"):
        wrap_vault_key_for_recovery(
            vault_key, recovery_secret=b"password", vault_id=VAULT_ID
        )


def test_malformed_noncanonical_unknown_and_duplicate_fields_are_rejected():
    identity = generate_device_identity("device-a")
    snapshot = seal_snapshot(b"x", vault_key=generate_vault_key(), vault_id=VAULT_ID)
    commit = _genesis(snapshot, identity)

    noncanonical = json.dumps(json.loads(commit), indent=2).encode()
    with pytest.raises(ValidationError, match="canonical"):
        verify_commit_signature(
            noncanonical, signing_public_key=identity.signing_public_key
        )

    unknown = _rewrite_commit(commit, lambda value: value.__setitem__("extra", 1))
    with pytest.raises(ValidationError, match="invalid fields"):
        verify_commit_signature(unknown, signing_public_key=identity.signing_public_key)

    duplicate = commit[:-1] + b',"commit_id":"' + b"0" * 64 + b'"}'
    with pytest.raises(ValidationError, match="duplicate"):
        verify_commit_signature(duplicate, signing_public_key=identity.signing_public_key)

    malformed_base64 = _rewrite_commit(
        commit, lambda value: value.__setitem__("signature", "not+urlsafe/base64==")
    )
    with pytest.raises(ValidationError, match="base64"):
        verify_commit_signature(
            malformed_base64, signing_public_key=identity.signing_public_key
        )


def test_oversize_and_invalid_lengths_are_rejected_before_crypto():
    identity = generate_device_identity("device-a")
    with pytest.raises(ValidationError, match="size limit"):
        seal_snapshot(
            b"x" * (MAX_SNAPSHOT_PLAINTEXT_SIZE + 1),
            vault_key=generate_vault_key(),
            vault_id=VAULT_ID,
        )
    with pytest.raises(ValidationError, match="size limit"):
        verify_commit_signature(
            b"{" + b" " * MAX_COMMIT_SIZE,
            signing_public_key=identity.signing_public_key,
        )
    with pytest.raises(ValidationError, match="32 bytes"):
        seal_snapshot(b"x", vault_key=b"short", vault_id=VAULT_ID)
    with pytest.raises(ValidationError, match="1024"):
        wrap_vault_key_for_recipient(
            generate_vault_key(),
            recipient_public_key=identity.agreement_public_key,
            vault_id=VAULT_ID,
            recipient_device_id=identity.device_id,
            context=b"x" * (MAX_CONTEXT_SIZE + 1),
        )


def test_snapshot_tampered_nonce_and_commit_id_are_rejected():
    key = generate_vault_key()
    identity = generate_device_identity("device-a")
    snapshot = seal_snapshot(b"x", vault_key=key, vault_id=VAULT_ID)
    snapshot_value = json.loads(snapshot)
    snapshot_value["nonce"] = "A" * 16
    tampered_snapshot = canonical_json_bytes(snapshot_value)
    with pytest.raises(AuthenticationError):
        open_snapshot(tampered_snapshot, vault_key=key, expected_vault_id=VAULT_ID)

    commit = _genesis(snapshot, identity)
    tampered_commit = _rewrite_commit(
        commit, lambda value: value.__setitem__("commit_id", "0" * 64)
    )
    with pytest.raises(SignatureVerificationError, match="commit_id"):
        verify_commit_signature(
            tampered_commit, signing_public_key=identity.signing_public_key
        )
