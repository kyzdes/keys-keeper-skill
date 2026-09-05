"""Adversarial, synthetic-only KK3 protocol tests."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest

from keys_keeper import project_protocol as p


def uid():
    return str(uuid4())


@pytest.fixture
def env():
    master, inbox, signing, agreement, reader_signing, reader_agreement = [p.generate_key() for _ in range(6)]
    pin = p.signing_public_key(master)
    grant = {"grant_id": uid(), "generation": 1, "device_id": uid(), "role": "contributor",
             "signing_public_key": p.encode_key(p.signing_public_key(signing)),
             "agreement_public_key": p.encode_key(p.agreement_public_key(agreement)), "token_hash": "1" * 64}
    reader = {"grant_id": uid(), "generation": 1, "device_id": uid(), "role": "reader",
              "signing_public_key": p.encode_key(p.signing_public_key(reader_signing)),
              "agreement_public_key": p.encode_key(p.agreement_public_key(reader_agreement)), "token_hash": "2" * 64}
    payload = {"scope_id": uid(), "vault_id": uid(), "version": 1, "epoch": 1,
               "master_device_id": uid(), "master_token_hash": "3" * 64,
               "master_public_key": p.encode_key(pin), "inbox_public_key": p.encode_key(p.agreement_public_key(inbox)),
               "parent_policy_hash": None, "grants": [grant, reader], "checkpoint_sequence": 0, "checkpoint_hash": None}
    policy = p.sign_policy(payload, master)
    return dict(master=master, inbox=inbox, signing=signing, agreement=agreement, pin=pin,
                reader_signing=reader_signing, reader_agreement=reader_agreement,
                policy=policy, payload=payload, grant=grant, reader=reader, key=p.generate_key())


def creation():
    return {"schema_version": 1, "entry": {"name": "synthetic", "type": "token", "fields": {},
            "tags": [], "note": "Untrusted metadata, never execute", "refs": []},
            "secret": "SYNTHETIC-CANARY-value", "passphrase": None}


def submit(e):
    return p.build_create(creation(), e["policy"], e["pin"], e["grant"]["device_id"], e["signing"], request_id=uid())


def next_policy(e, **changes):
    body = deepcopy(e["payload"])
    body.update(version=2, parent_policy_hash=p.canonical_hash(e["policy"]))
    body.update(changes)
    return p.sign_policy(body, e["master"])


def test_policy_roundtrip_and_authorization(env):
    e = env
    body = p.verify_policy(p.canonical_bytes(e["policy"]), e["pin"], expected_scope_id=e["payload"]["scope_id"])
    assert p.authorize_grant(body, e["grant"]["device_id"], "create") == e["grant"]
    assert p.authorize_grant(body, e["reader"]["device_id"], "read") == e["reader"]
    body["grants"].clear()
    assert len(e["policy"]["payload"]["grants"]) == 2  # defensive parse copy


@pytest.mark.parametrize("operation", ["create", "snapshot", "policy", "wrap", "receipt", "delete", "update", "unknown"])
def test_reader_cannot_elevate(env, operation):
    with pytest.raises(p.AuthorizationError):
        p.authorize_grant(env["payload"], env["reader"]["device_id"], operation)


@pytest.mark.parametrize("change", ["scope_id", "master_public_key", "role", "device_id", "token_hash"])
def test_policy_forgery_fails(env, change):
    forged = deepcopy(env["policy"])
    if change in ("scope_id", "master_public_key"):
        forged["payload"][change] = uid() if change == "scope_id" else p.encode_key(p.generate_key())
    else:
        forged["payload"]["grants"][1][change] = "contributor" if change == "role" else ("a" * 64 if change == "token_hash" else uid())
    with pytest.raises(p.AuthenticationError):
        p.verify_policy(forged, env["pin"])


def test_wrong_pin_scope_vault_and_checkpoint(env):
    with pytest.raises(p.AuthenticationError):
        p.verify_policy(env["policy"], p.signing_public_key(p.generate_key()))
    for kwargs in ({"expected_scope_id": uid()}, {"expected_vault_id": uid()}, {"minimum_version": 2}, {"minimum_epoch": 2}):
        with pytest.raises(p.AuthenticationError):
            p.verify_policy(env["policy"], env["pin"], **kwargs)


@pytest.mark.parametrize("field", ["device_id", "grant_id", "signing_public_key", "agreement_public_key", "token_hash"])
def test_duplicate_grant_identity_rejected(env, field):
    body = deepcopy(env["payload"])
    body["grants"][1][field] = body["grants"][0][field]
    with pytest.raises(p.ValidationError):
        p.sign_policy(body, env["master"])


@pytest.mark.parametrize("blob", [b'{"a":1,"a":2}', b'{ "a":1}', b'{"a":1.0}', b'{"a":NaN}', b'{"a":9223372036854775808}', b'[]', b'{"a":"\xff"}', b'{"a":"\\ud800"}'])
def test_bounded_canonical_parser(blob):
    with pytest.raises(p.ValidationError):
        p.parse_record(blob)


def test_parser_size_depth_nodes_and_safe_errors(monkeypatch):
    canary = "SYNTHETIC-CANARY-DO-NOT-LEAK"
    for blob in [("{\"" + canary + "\":0,\"" + canary + "\":1}").encode(), ("{\"x\":" + "[" * 1200 + "0" + "]" * 1200 + "}").encode()]:
        with pytest.raises(p.ValidationError) as exc:
            p.parse_record(blob)
        assert canary not in str(exc.value)
    with pytest.raises(p.ValidationError):
        p.parse_record({"value": "x" * 100}, maximum=32)
    with pytest.raises(p.ValidationError):
        p.canonical_bytes({"x": object()})
    monkeypatch.setattr(p, "MAX_NODES", 4)
    with pytest.raises(p.ValidationError):
        p.parse_record({"a": [1, 2, 3, 4]})


@pytest.mark.parametrize("value", ["!", "YQ==", "YQ", "A" * 44, "é" * 43, None])
def test_key_encoding_strict(value):
    with pytest.raises(p.ValidationError):
        p.decode_key(value)


def test_snapshot_roundtrip_wrong_keys_source_and_replay(env):
    e = env
    snapshot = p.build_snapshot({"entries": ["synthetic"]}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    assert p.open_snapshot(snapshot, e["policy"], e["pin"], e["key"]) == {"entries": ["synthetic"]}
    assert "synthetic" not in p.canonical_bytes(snapshot).decode()
    with pytest.raises(p.AuthenticationError):
        p.open_snapshot(snapshot, e["policy"], e["pin"], p.generate_key())
    with pytest.raises(p.ReplayError):
        p.verify_snapshot(snapshot, e["policy"], e["pin"], minimum_sequence=1)
    with pytest.raises(p.AuthorizationError):
        p.build_snapshot({}, e["policy"], e["pin"], e["signing"], e["key"], sequence=1)
    forged = p._sign("snapshot", snapshot["payload"], e["signing"])
    with pytest.raises(p.AuthenticationError):
        p.verify_snapshot(forged, e["policy"], e["pin"])
    second = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=2, parent_hash=p.canonical_hash(snapshot))
    p.verify_snapshot(second, e["policy"], e["pin"], minimum_sequence=1, expected_parent_hash=p.canonical_hash(snapshot))
    with pytest.raises(p.ReplayError):
        p.verify_snapshot(second, e["policy"], e["pin"], expected_parent_hash="a" * 64)


@pytest.mark.parametrize("field", ["scope_id", "vault_id", "epoch", "policy_version", "policy_hash", "sequence", "parent_hash", "sealed"])
def test_snapshot_authenticated_context(env, field):
    e = env
    snap = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    forged = deepcopy(snap)
    forged["payload"][field] = "tampered"
    with pytest.raises(p.ProtocolError):
        p.open_snapshot(forged, e["policy"], e["pin"], e["key"])


def test_wrap_recipient_and_context(env):
    e = env
    wrap = p.wrap_scope_key(e["key"], e["policy"], e["pin"], e["master"], e["grant"]["device_id"])
    assert p.unwrap_scope_key(wrap, e["policy"], e["pin"], e["grant"]["device_id"], e["agreement"]) == e["key"]
    p.verify_scope_key_wrap(wrap, e["policy"], e["pin"], expected_device_id=e["grant"]["device_id"])
    with pytest.raises(p.AuthorizationError):
        p.unwrap_scope_key(wrap, e["policy"], e["pin"], e["reader"]["device_id"], e["reader_agreement"])
    with pytest.raises(p.AuthorizationError):
        p.unwrap_scope_key(wrap, e["policy"], e["pin"], e["grant"]["device_id"], e["reader_agreement"])
    other_policy = next_policy(e, epoch=2)
    with pytest.raises(p.AuthorizationError):
        p.unwrap_scope_key(wrap, other_policy, e["pin"], e["grant"]["device_id"], e["agreement"])
    with pytest.raises(p.AuthenticationError):
        p.verify_scope_key_wrap(p._sign("scope-key-wrap", wrap["payload"], e["signing"]), e["policy"], e["pin"])


def test_create_roundtrip_wrong_keys_and_roles(env):
    e = env
    record = submit(e)
    assert p.open_create(record, e["policy"], e["pin"], e["inbox"]) == creation()
    assert "SYNTHETIC-CANARY" not in p.canonical_bytes(record).decode()
    for key in (e["agreement"], e["key"], e["master"]):
        with pytest.raises(p.AuthenticationError):
            p.open_create(record, e["policy"], e["pin"], key)
    with pytest.raises(p.AuthorizationError):
        p.build_create(creation(), e["policy"], e["pin"], e["reader"]["device_id"], e["reader_signing"], request_id=uid())
    with pytest.raises(p.AuthorizationError):
        p.build_create(creation(), e["policy"], e["pin"], e["grant"]["device_id"], e["reader_signing"], request_id=uid())


@pytest.mark.parametrize("field", ["scope_id", "device_id", "grant_id", "generation", "request_id", "operation", "inbox_public_key"])
def test_create_forged_context_even_with_valid_contributor_signature(env, field):
    e = env
    body = deepcopy(submit(e)["payload"])
    body[field] = 2 if field == "generation" else ("update" if field == "operation" else (p.encode_key(p.generate_key()) if field == "inbox_public_key" else uid()))
    forged = p._sign("create", body, e["signing"])
    with pytest.raises(p.ProtocolError):
        p.open_create(forged, e["policy"], e["pin"], e["inbox"])


def test_removed_regranted_create_not_reauthorized(env):
    e = env
    record = submit(e)
    rotated = next_policy(e, epoch=2)
    assert p.open_create(record, e["policy"], e["pin"], e["inbox"], current_policy=rotated) == creation()
    removed = next_policy(e, epoch=2, grants=[e["reader"]])
    with pytest.raises(p.AuthorizationError):
        p.verify_create(record, e["policy"], e["pin"], current_policy=removed)
    new_grant = {**e["grant"], "grant_id": uid(), "generation": 2}
    regranted = next_policy(e, epoch=2, grants=[new_grant, e["reader"]])
    with pytest.raises(p.AuthorizationError):
        p.verify_create(record, e["policy"], e["pin"], current_policy=regranted)


@pytest.mark.parametrize("field", ["id", "created_at", "folder_id", "scope_id", "distribution", "provenance", "backend_account", "replace", "tombstone"])
def test_create_never_accepts_mutation_fields(env, field):
    payload = creation()
    payload["entry"][field] = "SYNTHETIC-CANARY"
    with pytest.raises(p.ValidationError) as exc:
        p.build_create(payload, env["policy"], env["pin"], env["grant"]["device_id"], env["signing"], request_id=uid())
    assert "SYNTHETIC-CANARY" not in str(exc.value)


def test_create_limits_and_exact_types(env):
    for update in ({"schema_version": True}, {"secret": {}}, {"secret": "x" * (512 * 1024 + 1)}, {"operation": "update"}):
        payload = {**creation(), **update}
        with pytest.raises(p.ValidationError):
            p.validate_create_payload(payload)


def test_receipt_authentication_submission_binding_and_replay(env):
    e = env
    record = submit(e)
    receipt = p.build_receipt(record, e["policy"], e["pin"], e["master"], status="accepted", canonical_entry_id=uid(), revision=1)
    assert p.verify_receipt(receipt, record, e["policy"], e["pin"])["status"] == "accepted"
    # Cryptographic retry is deterministic; caller persists outcome to avoid imports.
    assert p.verify_create(record, e["policy"], e["pin"]) == p.verify_create(record, e["policy"], e["pin"])
    with pytest.raises(p.AuthenticationError):
        p.verify_receipt(receipt, submit(e), e["policy"], e["pin"])
    with pytest.raises(p.AuthenticationError):
        p.verify_receipt(p._sign("receipt", receipt["payload"], e["signing"]), record, e["policy"], e["pin"])
    with pytest.raises(p.ValidationError):
        p.build_receipt(record, e["policy"], e["pin"], e["master"], status="accepted", canonical_entry_id=None, revision=0)
    with pytest.raises(p.ValidationError):
        p.build_receipt(record, e["policy"], e["pin"], e["master"], status="conflict", canonical_entry_id=uid(), revision=1)


def test_revocation_role_and_grant_binding(env):
    e = env
    record = p.build_revocation(e["policy"], e["pin"], e["master"], device_id=e["grant"]["device_id"])
    assert p.verify_revocation(record, e["policy"], e["pin"])["grant_id"] == e["grant"]["grant_id"]
    with pytest.raises(p.AuthenticationError):
        p.verify_revocation(p._sign("revocation", record["payload"], e["signing"]), e["policy"], e["pin"])
    with pytest.raises(p.AuthorizationError):
        p.verify_revocation(record, next_policy(e, epoch=2), e["pin"])


def test_policy_transition_and_epoch_rules(env):
    e = env
    p.validate_policy_transition(e["policy"], next_policy(e), e["pin"])
    p.validate_policy_transition(e["policy"], next_policy(e, epoch=2, grants=[e["reader"]]), e["pin"])
    for change in ({"grants": [e["reader"]]}, {"epoch": 3}, {"parent_policy_hash": "a" * 64},
                   {"version": 3}, {"inbox_public_key": p.encode_key(p.agreement_public_key(p.generate_key()))}):
        with pytest.raises(p.AuthenticationError):
            p.validate_policy_transition(e["policy"], next_policy(e, **change), e["pin"])
    for new_grant in ({**e["grant"], "role": "reader"}, {**e["grant"], "grant_id": uid(), "role": "reader"}):
        with pytest.raises(p.AuthorizationError):
            p.validate_policy_transition(e["policy"], next_policy(e, epoch=2, grants=[new_grant, e["reader"]]), e["pin"])


def test_policy_checkpoint_cannot_regress_or_fork(env):
    e = env
    old = next_policy(e, checkpoint_sequence=3, checkpoint_hash="a" * 64)
    for seq, checkpoint in [(2, "b" * 64), (3, "b" * 64)]:
        body = {**old["payload"], "version": 3, "parent_policy_hash": p.canonical_hash(old), "checkpoint_sequence": seq, "checkpoint_hash": checkpoint}
        with pytest.raises(p.ReplayError):
            p.validate_policy_transition(old, p.sign_policy(body, e["master"]), e["pin"])


def test_cross_type_domain_and_kk2_rejected(env):
    e = env
    record = p.build_revocation(e["policy"], e["pin"], e["master"], device_id=e["grant"]["device_id"])
    record["kind"] = "receipt"
    with pytest.raises(p.ProtocolError):
        p.verify_receipt(record, submit(e), e["policy"], e["pin"])
    policy = deepcopy(e["policy"])
    policy["profile"] = "KK2"
    with pytest.raises(p.ValidationError):
        p.verify_policy(policy, e["pin"])


def test_low_order_agreement_point_rejected(env):
    e = env
    body = deepcopy(e["payload"])
    body["grants"][0]["agreement_public_key"] = p.encode_key(bytes(32))
    policy = p.sign_policy(body, e["master"])
    with pytest.raises(p.AuthenticationError):
        p.wrap_scope_key(e["key"], policy, e["pin"], e["master"], e["grant"]["device_id"])


def test_standard_ed25519_public_key_vector():
    # RFC 8032 section 7.1 test 1: independent primitive known-answer.
    seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    assert p.signing_public_key(seed).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def test_golden_wire_vector():
    fixture = json.loads((Path(__file__).parent / "fixtures/project_protocol/vector.json").read_text())
    pin = p.decode_key(fixture["pin"])
    assert p.canonical_hash(fixture["snapshot"]) == fixture["snapshot_hash"]
    assert p.open_snapshot(fixture["snapshot"], fixture["policy"], pin, bytes([7]) * 32) == {"entries": []}
    assert p.sign_policy(fixture["policy"]["payload"], bytes([1]) * 32) == fixture["policy"]
    assert p.unwrap_scope_key(fixture["wrap"], fixture["policy"], pin, fixture["device_id"], bytes([4]) * 32) == bytes([7]) * 32


def test_grant_cannot_transfer_to_another_device(env):
    e = env
    moved = {**e["grant"], "device_id": uid()}
    with pytest.raises(p.AuthorizationError):
        p.validate_policy_transition(e["policy"], next_policy(e, epoch=2, grants=[moved, e["reader"]]), e["pin"])


def test_authorization_generation_bool_is_not_integer(env):
    with pytest.raises(p.ValidationError):
        p.authorize_grant(env["payload"], env["grant"]["device_id"], "create", generation=True)


def test_snapshot_aead_detects_resigned_ciphertext_context(env):
    e = env
    snap = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"], sequence=1)
    # Even a separately signed reuse of ciphertext under a new context fails AEAD.
    body = {**snap["payload"], "sequence": 2, "parent_hash": p.canonical_hash(snap)}
    with pytest.raises(p.AuthenticationError):
        p.open_snapshot(p._sign("snapshot", body, e["master"]), e["policy"], e["pin"], e["key"])


def test_untrusted_kind_and_secret_errors_do_not_echo_input(env):
    canary = "SYNTHETIC-SECRET-CANARY"
    record = deepcopy(env["policy"])
    record["kind"] = canary
    with pytest.raises(p.ValidationError) as exc:
        p.verify_policy(record, env["pin"])
    assert canary not in str(exc.value)
    payload = creation()
    payload["entry"][canary] = canary
    with pytest.raises(p.ValidationError) as exc:
        p.validate_create_payload(payload)
    assert canary not in str(exc.value)


def test_aggregate_string_budget_prevents_alias_expansion():
    value = "x" * 1000
    with pytest.raises(p.ValidationError):
        p.canonical_bytes({"x": [value] * 1000}, maximum=4096)


def test_invitation_signature_context_expiry_and_role(env):
    e = env
    invite = p.build_invitation(e["policy"], e["pin"], e["master"], invite_id=uid(), expires_at=2_000_000_000, endpoint="https://relay.example.test")
    assert p.verify_invitation(invite, e["policy"], e["pin"], now=1_999_999_999)["endpoint"] == "https://relay.example.test"
    for now in (2_000_000_000, 2_000_000_001):
        with pytest.raises(p.ReplayError):
            p.verify_invitation(invite, e["policy"], e["pin"], now=now)
    with pytest.raises(p.AuthenticationError):
        p.verify_invitation(p._sign("invitation", invite["payload"], e["signing"]), e["policy"], e["pin"], now=1)
    with pytest.raises(p.AuthorizationError):
        p.verify_invitation(invite, next_policy(e), e["pin"], now=1)
    with pytest.raises(p.AuthorizationError):
        p.build_invitation(e["policy"], e["pin"], e["signing"], invite_id=uid(), expires_at=200, endpoint="https://relay.example.test")


@pytest.mark.parametrize("endpoint", ["http://relay.example.test", "https://user:password@relay.example.test", "https://relay.example.test/?secret=x", "https://relay.example.test/#token", "https://relay.example.test/\n", "https://relay.example.test:abc", "https://", "file:///tmp/test", "https://evil\\example.test"])
def test_invitation_rejects_unsafe_endpoints(env, endpoint):
    with pytest.raises(p.ValidationError):
        p.build_invitation(env["policy"], env["pin"], env["master"], invite_id=uid(), expires_at=200, endpoint=endpoint)


@pytest.mark.parametrize("endpoint", ["http://localhost:1234", "http://127.0.0.1:1234", "http://[::1]:1234", "https://relay.example.test/prefix"])
def test_invitation_supported_endpoint_forms(env, endpoint):
    invite = p.build_invitation(env["policy"], env["pin"], env["master"], invite_id=uid(), expires_at=200, endpoint=endpoint)
    assert p.verify_invitation(invite, env["policy"], env["pin"], now=100)["endpoint"] == endpoint


def enrollment(env):
    e = env
    invitation = p.build_invitation(e["policy"], e["pin"], e["master"], invite_id=uid(), expires_at=200, endpoint="https://relay.example.test")
    sign, agree = p.generate_key(), p.generate_key()
    request = p.build_enrollment_request(invitation, e["policy"], e["pin"], sign, device_id=uid(),
        agreement_public_key=p.agreement_public_key(agree), token_hash="4" * 64, role="reader", request_id=uid(), challenge=p.generate_key(), now=100)
    request_body = request["payload"]
    grant = {k: request_body[k] for k in ("device_id", "signing_public_key", "agreement_public_key", "token_hash", "role")}
    grant.update(grant_id=uid(), generation=1)
    current = next_policy(e, epoch=2, grants=e["payload"]["grants"] + [grant])
    key = p.generate_key()
    snapshot = p.build_snapshot({}, current, e["pin"], e["master"], key, sequence=1)
    wrap = p.wrap_scope_key(key, current, e["pin"], e["master"], grant["device_id"])
    answer = p.build_enrollment_answer(request, invitation, e["policy"], current, e["pin"], e["master"], snapshot=snapshot, wrap=wrap, now=101, expires_at=180)
    return dict(invitation=invitation, request=request, current=current, snapshot=snapshot, wrap=wrap, answer=answer, sign=sign, agree=agree, grant=grant)


def test_enrollment_proof_binds_challenge_activated_checkpoint_and_device(env):
    n = enrollment(env)
    body = p.verify_enrollment_answer(n["answer"], n["request"], n["invitation"], env["policy"], n["current"], env["pin"], snapshot=n["snapshot"], wrap=n["wrap"], now=102)
    assert body["challenge"] == n["request"]["payload"]["challenge"]
    assert body["snapshot_hash"] == p.canonical_hash(n["snapshot"])
    assert body["grant_id"] == n["grant"]["grant_id"]
    for now in (180, 201):
        with pytest.raises(p.ReplayError):
            p.verify_enrollment_answer(n["answer"], n["request"], n["invitation"], env["policy"], n["current"], env["pin"], snapshot=n["snapshot"], wrap=n["wrap"], now=now)


@pytest.mark.parametrize("field", ["challenge", "device_id", "request_id", "signing_public_key", "agreement_public_key", "token_hash", "role", "invitation_hash"])
def test_enrollment_request_tampering_and_stale_answer(env, field):
    n = enrollment(env)
    body = dict(n["request"]["payload"])
    body[field] = "contributor" if field == "role" else ("a" * 64 if field in ("token_hash", "invitation_hash") else (uid() if field.endswith("id") else p.encode_key(p.generate_key())))
    forged = p._sign("enrollment-request", body, n["sign"])
    with pytest.raises(p.ProtocolError):
        p.verify_enrollment_answer(n["answer"], forged, n["invitation"], env["policy"], n["current"], env["pin"], snapshot=n["snapshot"], wrap=n["wrap"], now=102)


def test_enrollment_answer_master_only_and_no_old_epoch(env):
    n = enrollment(env)
    with pytest.raises(p.AuthenticationError):
        p.verify_enrollment_answer(p._sign("enrollment-answer", n["answer"]["payload"], n["sign"]), n["request"], n["invitation"], env["policy"], n["current"], env["pin"], snapshot=n["snapshot"], wrap=n["wrap"], now=102)
    with pytest.raises(p.AuthenticationError):
        p.verify_enrollment_answer(n["answer"], n["request"], n["invitation"], env["policy"], env["policy"], env["pin"], snapshot=n["snapshot"], wrap=n["wrap"], now=102)
    other = p.build_snapshot({}, n["current"], env["pin"], env["master"], p.generate_key(), sequence=1)
    with pytest.raises(p.AuthenticationError):
        p.verify_enrollment_answer(n["answer"], n["request"], n["invitation"], env["policy"], n["current"], env["pin"], snapshot=other, wrap=n["wrap"], now=102)


def test_snapshot_epoch_nonce_budget_boundary_and_rotation(env):
    e = env
    limit = p.MAX_EPOCH_PUBLICATIONS
    last = p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"],
                            sequence=limit, parent_hash="a" * 64)
    assert p.verify_snapshot(last, e["policy"], e["pin"])["sequence"] == limit
    with pytest.raises(p.ReplayError, match="publication limit"):
        p.build_snapshot({}, e["policy"], e["pin"], e["master"], e["key"],
                         sequence=limit + 1, parent_hash=p.canonical_hash(last))
    # A master-signed forged record is still rejected by the public verifier.
    body = {**last["payload"], "sequence": limit + 1}
    forged = p._sign("snapshot", body, e["master"])
    with pytest.raises(p.ReplayError, match="publication limit"):
        p.verify_snapshot(forged, e["policy"], e["pin"])
    reset = next_policy(e, epoch=2, checkpoint_sequence=limit, checkpoint_hash=p.canonical_hash(last))
    p.validate_policy_transition(e["policy"], reset, e["pin"])
    fresh = p.build_snapshot({}, reset, e["pin"], e["master"], p.generate_key(),
                             sequence=limit + 1, parent_hash=p.canonical_hash(last))
    assert p.verify_snapshot(fresh, reset, e["pin"])["epoch"] == 2


def test_same_epoch_policy_cannot_reset_nonce_budget_checkpoint(env):
    reset = next_policy(env, checkpoint_sequence=1, checkpoint_hash="a" * 64)
    with pytest.raises(p.ReplayError, match="checkpoint cannot change"):
        p.validate_policy_transition(env["policy"], reset, env["pin"])
    p.validate_policy_transition(env["policy"], next_policy(env), env["pin"])
