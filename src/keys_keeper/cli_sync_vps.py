"""CLI workflow for a private, zero-knowledge ``keys-keeper-syncd`` VPS."""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from keys_keeper.audit import AuditLog
from keys_keeper.backend import KeychainError, Sealed
from keys_keeper.composition import build_backend
from keys_keeper.paths import Paths
from keys_keeper.secure_io import SecureFileError, read_secure_text, replace_secure_text
from keys_keeper.service import compensating_secret_update
from keys_keeper.store import MetadataStore
from keys_keeper.sync_protocol_v2 import (
    KK2Error,
    canonical_json_bytes,
    generate_device_identity,
    generate_recovery_secret,
    generate_vault_key,
    unwrap_vault_key_for_recipient,
    wrap_vault_key_for_recipient,
    wrap_vault_key_for_recovery,
)
from keys_keeper.sync_vps import (
    SYNC_VPS_SIGNING_PRIVATE,
    SYNC_VPS_TOKEN,
    SYNC_VPS_VAULT_KEY,
    SYNC_VPS_WRAPPING_PRIVATE,
    VpsSyncConfig,
    VpsSyncEngine,
    VpsSyncError,
    VpsTrustError,
    invite_secret,
    invite_secret_hash,
    load_vps_config,
    make_membership_statement,
    make_revocation_statement,
    new_device_token,
    save_vps_config,
    sign_membership,
    sign_revocation,
    verify_membership,
)
from keys_keeper.sync_vps_client import VpsClientError, VpsSyncClient


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str, *, label: str, length: int | None = None) -> bytes:
    try:
        if not isinstance(value, str) or not value or "=" in value:
            raise ValueError
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if _b64(raw) != value or (length is not None and len(raw) != length):
            raise ValueError
        return raw
    except (ValueError, TypeError):
        raise VpsTrustError(f"invalid {label}") from None


def _fingerprint(sign_public_key: str, wrap_public_key: str) -> str:
    digest = hashlib.sha256(
        _unb64(sign_public_key, label="signing public key", length=32)
        + _unb64(wrap_public_key, label="wrapping public key", length=32)
    ).hexdigest()[:24]
    return "-".join(digest[index:index + 4] for index in range(0, len(digest), 4))


def _invite_trust_fingerprint(invite: dict[str, Any]) -> str:
    binding_fields = (
        "endpoint", "vault_id", "root_device_id", "root_sign_public_key",
        "inviter_device_id", "inviter_sign_public_key", "invite_id",
        "checkpoint_commit_id", "checkpoint_manifest_hash", "checkpoint_sequence",
    )
    try:
        binding = {field: invite[field] for field in binding_fields}
    except KeyError:
        raise VpsTrustError("device invitation is missing trust-binding fields") from None
    digest = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()[:24]
    return "-".join(digest[index:index + 4] for index in range(0, len(digest), 4))


def _safe_json_file(path: str, payload: dict[str, Any]) -> None:
    target = Path(path).expanduser()
    state = read_secure_text(target, missing_ok=True)
    if state.identity is not None:
        raise SecureFileError(f"refusing to overwrite an existing secret bundle: {target}")
    replace_secure_text(state, json.dumps(payload, sort_keys=True, indent=2) + "\n")


def _require_new_secret_file(path: str) -> None:
    target = Path(path).expanduser()
    state = read_secure_text(target, missing_ok=True)
    if state.identity is not None:
        raise SecureFileError(f"refusing to overwrite an existing secret bundle: {target}")


def _require_vps_unconfigured(paths: Paths) -> None:
    state = read_secure_text(paths.root / "vps-sync.json", missing_ok=True)
    if state.identity is not None:
        raise VpsSyncError("VPS sync is already configured on this device")


def _bootstrap_admin_token(args: argparse.Namespace, paths: Paths, backend):
    """Return a sealed bootstrap token without putting it on the command line.

    Interactive prompting remains the default.  Automation may instead name an
    existing Keys Keeper entry; only the non-sensitive entry name is passed as
    an argument and the value stays sealed until the HTTP client builds the
    authenticated request.
    """
    entry_name = getattr(args, "admin_token_entry", None)
    if entry_name:
        store = MetadataStore(paths)
        entry = store.get_by_id(entry_name) or store.get_by_name(entry_name)
        if entry is None:
            raise VpsSyncError(f"bootstrap admin token entry not found: {entry_name}")
        return backend.get(entry.id), entry

    admin_token = getpass.getpass("syncd bootstrap admin token: ")
    if not admin_token:
        raise VpsSyncError("bootstrap admin token is empty")
    return Sealed(admin_token), None


def _read_json_file(path: str, *, expected_type: str) -> dict[str, Any]:
    try:
        payload = json.loads(read_secure_text(Path(path).expanduser(), missing_ok=False).text)
    except (ValueError, OSError, SecureFileError) as exc:
        raise VpsSyncError(f"cannot read a valid {expected_type} file") from exc
    if not isinstance(payload, dict) or payload.get("protocol") != "KK2" or payload.get("type") != expected_type:
        raise VpsTrustError(f"file is not a KK2 {expected_type}")
    return payload


def _client(config: VpsSyncConfig, backend) -> VpsSyncClient:
    return VpsSyncClient(
        base_url=config.endpoint,
        token=backend.get(SYNC_VPS_TOKEN),
        device_id=config.device_id,
        proxy=config.proxy,
    )


def _engine(paths: Paths):
    config = load_vps_config(paths)
    backend = build_backend()
    return (
        VpsSyncEngine(
            client=_client(config, backend),
            config=config,
            store=MetadataStore(paths),
            backend=backend,
            vault_key=_unb64(
                backend.get(SYNC_VPS_VAULT_KEY).unseal(), label="local vault key", length=32
            ),
            signing_private_key=_unb64(
                backend.get(SYNC_VPS_SIGNING_PRIVATE).unseal(),
                label="local signing key",
                length=32,
            ),
            paths=paths,
        ),
        config,
        backend,
    )


def _handled(fn):
    def wrapped(args):
        try:
            return fn(args)
        except (VpsSyncError, VpsClientError, KK2Error, KeychainError, SecureFileError) as exc:
            sys.stderr.write(f"error: {exc}\n")
            return 1

    return wrapped


@_handled
def cmd_vps_init(args: argparse.Namespace) -> int:
    paths = Paths()
    _require_vps_unconfigured(paths)
    _require_new_secret_file(args.recovery_file)
    backend = build_backend()
    identity = generate_device_identity()
    device_token = new_device_token()
    admin_token, admin_entry = _bootstrap_admin_token(args, paths, backend)
    bootstrap = VpsSyncClient(base_url=args.endpoint, token=admin_token, proxy=args.proxy)
    result = bootstrap.create_vault(
        device_token=Sealed(device_token),
        sign_public_key=_b64(identity.signing_public_bytes),
        wrap_public_key=_b64(identity.agreement_public_bytes),
    )
    vault_id, device_id = result.get("vault_id"), result.get("device_id")
    if not isinstance(vault_id, str) or not isinstance(device_id, str):
        raise VpsTrustError("syncd returned invalid bootstrap identifiers")

    vault_key = generate_vault_key()
    recovery_secret = generate_recovery_secret()
    recovery_wrap = wrap_vault_key_for_recovery(
        vault_key, recovery_secret=recovery_secret, vault_id=vault_id
    )
    _safe_json_file(
        args.recovery_file,
        {
            "protocol": "KK2",
            "type": "recovery-bundle",
            "vault_id": vault_id,
            "root_device_id": device_id,
            "root_sign_public_key": _b64(identity.signing_public_bytes),
            "recovery_secret": _b64(recovery_secret),
            "wrapped_vault_key": json.loads(recovery_wrap),
        },
    )
    config = VpsSyncConfig(
        endpoint=args.endpoint,
        vault_id=vault_id,
        device_id=device_id,
        root_device_id=device_id,
        root_sign_public_key=_b64(identity.signing_public_bytes),
        sign_public_key=_b64(identity.signing_public_bytes),
        wrap_public_key=_b64(identity.agreement_public_bytes),
        proxy=args.proxy,
    )
    with compensating_secret_update(
        backend,
        {
            SYNC_VPS_TOKEN: device_token,
            SYNC_VPS_VAULT_KEY: _b64(vault_key),
            SYNC_VPS_SIGNING_PRIVATE: _b64(identity.signing_private_bytes),
            SYNC_VPS_WRAPPING_PRIVATE: _b64(identity.agreement_private_bytes),
        },
    ):
        save_vps_config(config, paths)
    AuditLog(paths).record(op="sync.vps.init", name="<all>", id_="-", file_target=args.endpoint)
    if admin_entry is not None:
        AuditLog(paths).record(
            op="sync.vps.bootstrap",
            name=admin_entry.name,
            id_=admin_entry.id,
            file_target=args.endpoint,
        )
    print(f"VPS sync initialized for device {device_id}")
    print(f"recovery bundle written to {Path(args.recovery_file).expanduser()}")
    return 0


@_handled
def cmd_vps_push(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, config, _backend = _engine(paths)
    changed = engine.push()
    AuditLog(paths).record(op="sync.vps.push", name=f"<+{changed}>", id_="-", file_target=config.endpoint)
    print(f"pushed — {changed} change(s) synchronized through the VPS")
    return 0


@_handled
def cmd_vps_pull(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, config, _backend = _engine(paths)
    changed = engine.pull()
    AuditLog(paths).record(op="sync.vps.pull", name=f"<+{changed}>", id_="-", file_target=config.endpoint)
    print(f"pulled — {changed} change(s) merged from the VPS")
    return 0


@_handled
def cmd_vps_status(args: argparse.Namespace) -> int:
    engine, config, _backend = _engine(Paths())
    status = engine.status()
    print(f"endpoint:         {config.endpoint}")
    print(f"vault:            {config.vault_id}")
    print(f"device:           {config.device_id} ({config.status})")
    print(f"remote sequence:  {status.remote_sequence if status.remote_sequence is not None else '-'}")
    print(f"local sequence:   {status.local_sequence if status.local_sequence is not None else '-'}")
    print(f"local changes:    {'yes (push to publish)' if status.dirty else 'none'}")
    return 0


@_handled
def cmd_vps_invite(args: argparse.Namespace) -> int:
    paths = Paths()
    _require_new_secret_file(args.out)
    engine, config, backend = _engine(paths)
    if config.device_id != config.root_device_id:
        raise VpsSyncError("only the pinned root device can create an invitation")
    client = _client(config, backend)
    secret = invite_secret()
    created = client.create_invite(
        config.vault_id,
        secret_hash=invite_secret_hash(secret),
        expires_in_seconds=args.expires,
    )
    invite_id = created.get("invite_id")
    if not isinstance(invite_id, str):
        raise VpsTrustError("syncd returned an invalid invite id")
    verified_head = engine.verified_head()
    bundle = {
            "protocol": "KK2",
            "type": "device-invite",
            "endpoint": config.endpoint,
            "vault_id": config.vault_id,
            "root_device_id": config.root_device_id,
            "root_sign_public_key": config.root_sign_public_key,
            "inviter_device_id": config.device_id,
            "inviter_sign_public_key": config.sign_public_key,
            "invite_id": invite_id,
            "invite_secret": secret,
            "expires_at": created.get("expires_at"),
            "checkpoint_commit_id": None if verified_head is None else verified_head.commit_id,
            "checkpoint_manifest_hash": None if verified_head is None else verified_head.manifest_hash,
            "checkpoint_sequence": 0 if verified_head is None else verified_head.sequence,
    }
    _safe_json_file(args.out, bundle)
    AuditLog(paths).record(op="sync.vps.invite", name="<device>", id_=invite_id, file_target=config.endpoint)
    print(f"one-time device invitation written to {Path(args.out).expanduser()}")
    print(f"invite id: {invite_id}")
    print(f"trust fingerprint: {_invite_trust_fingerprint(bundle)}")
    print("transfer it directly to the new device; it contains a short-lived secret")
    return 0


@_handled
def cmd_vps_join(args: argparse.Namespace) -> int:
    paths = Paths()
    invite = _read_json_file(args.invite, expected_type="device-invite")
    required = (
        "endpoint", "vault_id", "root_device_id", "root_sign_public_key",
        "inviter_device_id", "inviter_sign_public_key", "invite_id", "invite_secret",
    )
    if any(not isinstance(invite.get(field), str) for field in required):
        raise VpsTrustError("device invitation is incomplete")
    _unb64(invite["root_sign_public_key"], label="root signing public key", length=32)
    _unb64(invite["inviter_sign_public_key"], label="inviter signing public key", length=32)
    if args.trust_fingerprint.lower() != _invite_trust_fingerprint(invite):
        raise VpsTrustError("invitation trust fingerprint does not match the existing device")
    checkpoint_sequence = invite.get("checkpoint_sequence")
    checkpoint_commit_id = invite.get("checkpoint_commit_id")
    checkpoint_manifest_hash = invite.get("checkpoint_manifest_hash")
    if (
        isinstance(checkpoint_sequence, bool)
        or not isinstance(checkpoint_sequence, int)
        or checkpoint_sequence < 0
        or (checkpoint_sequence == 0 and (checkpoint_commit_id is not None or checkpoint_manifest_hash is not None))
        or (
            checkpoint_sequence > 0
            and (not isinstance(checkpoint_commit_id, str) or not isinstance(checkpoint_manifest_hash, str))
        )
    ):
        raise VpsTrustError("device invitation has an invalid onboarding checkpoint")
    existing = read_secure_text(paths.root / "vps-sync.json", missing_ok=True)
    backend = build_backend()
    if existing.identity is None:
        identity = generate_device_identity()
        token = new_device_token()
        config = VpsSyncConfig(
            endpoint=invite["endpoint"],
            vault_id=invite["vault_id"],
            device_id=identity.device_id,
            root_device_id=invite["root_device_id"],
            root_sign_public_key=invite["root_sign_public_key"],
            sign_public_key=_b64(identity.signing_public_bytes),
            wrap_public_key=_b64(identity.agreement_public_bytes),
            status="pending",
            invite_id=invite["invite_id"],
            inviter_device_id=invite["inviter_device_id"],
            inviter_sign_public_key=invite["inviter_sign_public_key"],
            proxy=args.proxy,
            trusted_checkpoint_commit_id=checkpoint_commit_id or "",
            trusted_checkpoint_manifest_hash=checkpoint_manifest_hash or "",
            trusted_checkpoint_sequence=checkpoint_sequence,
        )
        # Persist the retry identity before consuming the one-time invite. If
        # the response is lost, rerunning join sends the exact same id, keys,
        # and token and the server returns the original claim.
        with compensating_secret_update(
            backend,
            {
                SYNC_VPS_TOKEN: token,
                SYNC_VPS_SIGNING_PRIVATE: _b64(identity.signing_private_bytes),
                SYNC_VPS_WRAPPING_PRIVATE: _b64(identity.agreement_private_bytes),
            },
        ):
            save_vps_config(config, paths)
    else:
        config = load_vps_config(paths)
        pinned = {
            "endpoint": config.endpoint,
            "vault_id": config.vault_id,
            "root_device_id": config.root_device_id,
            "root_sign_public_key": config.root_sign_public_key,
            "inviter_device_id": config.inviter_device_id,
            "inviter_sign_public_key": config.inviter_sign_public_key,
            "invite_id": config.invite_id,
            "checkpoint_commit_id": config.trusted_checkpoint_commit_id or None,
            "checkpoint_manifest_hash": config.trusted_checkpoint_manifest_hash or None,
            "checkpoint_sequence": config.trusted_checkpoint_sequence,
        }
        if config.status != "pending" or any(
            invite.get(field) != value for field, value in pinned.items()
        ):
            raise VpsSyncError("VPS sync is already configured for a different enrollment")
        token = backend.get(SYNC_VPS_TOKEN).unseal()

    client = VpsSyncClient(base_url=config.endpoint, proxy=config.proxy)
    claim = client.claim_invite(
        config.invite_id,
        secret=Sealed(invite["invite_secret"]),
        device_id=config.device_id,
        device_token=Sealed(token),
        sign_public_key=config.sign_public_key,
        wrap_public_key=config.wrap_public_key,
    )
    device_id = claim.get("device_id")
    if claim.get("vault_id") != config.vault_id or device_id != config.device_id:
        raise VpsTrustError("syncd returned an invalid invitation claim")
    print(f"join request submitted as device {device_id}")
    print("approve its fingerprint on an existing device, then run `keys sync vps finish`")
    print(f"fingerprint: {_fingerprint(config.sign_public_key, config.wrap_public_key)}")
    return 0


@_handled
def cmd_vps_approve(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, config, backend = _engine(paths)
    if config.device_id != config.root_device_id:
        raise VpsSyncError("only the pinned root device can approve an invitation")
    invite_bundle = _read_json_file(args.invite, expected_type="device-invite")
    expected_bindings = {
        "invite_id": args.invite_id,
        "endpoint": config.endpoint,
        "vault_id": config.vault_id,
        "root_device_id": config.root_device_id,
        "root_sign_public_key": config.root_sign_public_key,
        "inviter_device_id": config.device_id,
        "inviter_sign_public_key": config.sign_public_key,
    }
    if any(invite_bundle.get(field) != value for field, value in expected_bindings.items()):
        raise VpsTrustError("invitation file does not match this approving device")
    checkpoint_sequence = invite_bundle.get("checkpoint_sequence")
    checkpoint_commit_id = invite_bundle.get("checkpoint_commit_id")
    checkpoint_manifest_hash = invite_bundle.get("checkpoint_manifest_hash")
    if not isinstance(checkpoint_sequence, int):
        raise VpsTrustError("invitation file has no valid checkpoint")
    engine.require_checkpoint(
        checkpoint_sequence, checkpoint_commit_id, checkpoint_manifest_hash
    )
    client = _client(config, backend)
    invite = client.get_invite(config.vault_id, args.invite_id)
    claimant = invite.get("claimant") if isinstance(invite, dict) else None
    if not isinstance(claimant, dict):
        raise VpsTrustError("invitation has no pending claimant")
    device_id = claimant.get("device_id")
    sign_public_key = claimant.get("sign_public_key")
    wrap_public_key = claimant.get("wrap_public_key")
    if not all(isinstance(value, str) for value in (device_id, sign_public_key, wrap_public_key)):
        raise VpsTrustError("pending claimant record is malformed")
    actual = _fingerprint(sign_public_key, wrap_public_key)
    if args.fingerprint.lower() != actual:
        raise VpsTrustError(f"claimant fingerprint mismatch; expected the other device to show {actual}")
    statement = make_membership_statement(
        vault_id=config.vault_id,
        device_id=device_id,
        sign_public_key=sign_public_key,
        wrap_public_key=wrap_public_key,
        approved_by_device_id=config.device_id,
        checkpoint_commit_id=checkpoint_commit_id,
        checkpoint_manifest_hash=checkpoint_manifest_hash,
        checkpoint_sequence=checkpoint_sequence,
    )
    signing_private = _unb64(
        backend.get(SYNC_VPS_SIGNING_PRIVATE).unseal(), label="local signing key", length=32
    )
    wrapped = wrap_vault_key_for_recipient(
        _unb64(backend.get(SYNC_VPS_VAULT_KEY).unseal(), label="local vault key", length=32),
        recipient_public_key=_unb64(wrap_public_key, label="claimant wrapping key", length=32),
        vault_id=config.vault_id,
        recipient_device_id=device_id,
        context=canonical_json_bytes(statement),
    )
    client.approve_invite(
        config.vault_id,
        args.invite_id,
        wrapped_vault_key=wrapped.decode("utf-8"),
        membership_statement=canonical_json_bytes(statement).decode("utf-8"),
        membership_signature=sign_membership(statement, signing_private),
    )
    AuditLog(paths).record(op="sync.vps.approve", name="<device>", id_=device_id, file_target=config.endpoint)
    print(f"approved device {device_id}")
    return 0


@_handled
def cmd_vps_finish(args: argparse.Namespace) -> int:
    paths = Paths()
    config = load_vps_config(paths)
    if config.status != "pending":
        raise VpsSyncError("this device has no pending join request")
    invite = _read_json_file(args.invite, expected_type="device-invite")
    pinned_invite_fields = {
        "invite_id": config.invite_id,
        "endpoint": config.endpoint,
        "vault_id": config.vault_id,
        "root_device_id": config.root_device_id,
        "root_sign_public_key": config.root_sign_public_key,
        "inviter_device_id": config.inviter_device_id,
        "inviter_sign_public_key": config.inviter_sign_public_key,
        "checkpoint_commit_id": config.trusted_checkpoint_commit_id or None,
        "checkpoint_manifest_hash": config.trusted_checkpoint_manifest_hash or None,
        "checkpoint_sequence": config.trusted_checkpoint_sequence,
    }
    if any(invite.get(field) != value for field, value in pinned_invite_fields.items()):
        raise VpsTrustError("invitation does not match the pending device")
    backend = build_backend()
    status = _client(config, backend).invite_status(config.invite_id)
    if status.get("status") != "approved":
        raise VpsSyncError("device invitation is not approved yet")
    statement = status.get("membership_statement")
    signature = status.get("membership_signature")
    wrapped = status.get("wrapped_vault_key")
    if not isinstance(statement, str) or not isinstance(signature, str) or not isinstance(wrapped, str):
        raise VpsTrustError("approved invitation payload is incomplete")
    try:
        statement_object = json.loads(statement)
        wrapped_object = json.loads(wrapped)
    except ValueError:
        raise VpsTrustError("approved invitation contains malformed cryptographic evidence") from None
    if (
        canonical_json_bytes(statement_object).decode("utf-8") != statement
        or canonical_json_bytes(wrapped_object).decode("utf-8") != wrapped
    ):
        raise VpsTrustError("approved invitation evidence is not canonical")
    checked = verify_membership(
        statement_object,
        signature,
        _unb64(config.inviter_sign_public_key, label="pinned inviter signing key", length=32),
    )
    if (
        checked["vault_id"] != config.vault_id
        or checked["device_id"] != config.device_id
        or checked["approved_by_device_id"] != config.inviter_device_id
        or checked["sign_public_key"] != config.sign_public_key
        or checked["wrap_public_key"] != config.wrap_public_key
    ):
        raise VpsTrustError("signed membership does not match this pending device")
    if (
        checked["checkpoint_sequence"] != config.trusted_checkpoint_sequence
        or checked["checkpoint_commit_id"]
        != (config.trusted_checkpoint_commit_id or None)
        or checked["checkpoint_manifest_hash"]
        != (config.trusted_checkpoint_manifest_hash or None)
    ):
        raise VpsTrustError("approval checkpoint conflicts with the invitation")
    wrapped_blob = canonical_json_bytes(wrapped_object)
    vault_key = unwrap_vault_key_for_recipient(
        wrapped_blob,
        recipient_private_key=_unb64(
            backend.get(SYNC_VPS_WRAPPING_PRIVATE).unseal(),
            label="local wrapping key",
            length=32,
        ),
        expected_vault_id=config.vault_id,
        expected_recipient_device_id=config.device_id,
        context=canonical_json_bytes(checked),
    )
    with compensating_secret_update(backend, {SYNC_VPS_VAULT_KEY: _b64(vault_key)}):
        save_vps_config(
            replace(
                config,
                status="active",
                invite_id="",
                inviter_device_id="",
                inviter_sign_public_key="",
                trusted_checkpoint_commit_id=checked["checkpoint_commit_id"] or "",
                trusted_checkpoint_manifest_hash=checked["checkpoint_manifest_hash"] or "",
                trusted_checkpoint_sequence=checked["checkpoint_sequence"],
            ),
            paths,
        )
    AuditLog(paths).record(op="sync.vps.finish", name="<device>", id_=config.device_id, file_target=config.endpoint)
    print("device approved; run `keys sync vps pull`")
    return 0


@_handled
def cmd_vps_devices(args: argparse.Namespace) -> int:
    config = load_vps_config(Paths())
    backend = build_backend()
    response = _client(config, backend).list_devices(config.vault_id)
    records = response.get("devices")
    if not isinstance(records, list):
        raise VpsTrustError("syncd returned an invalid device list")
    for record in records:
        if not isinstance(record, dict):
            raise VpsTrustError("syncd returned an invalid device record")
        fingerprint = _fingerprint(record.get("sign_public_key"), record.get("wrap_public_key"))
        marker = " (this device)" if record.get("device_id") == config.device_id else ""
        print(f"{record.get('device_id')}  {record.get('status')}  {fingerprint}{marker}")
    return 0


@_handled
def cmd_vps_revoke(args: argparse.Namespace) -> int:
    paths = Paths()
    engine, config, backend = _engine(paths)
    if config.device_id != config.root_device_id:
        raise VpsSyncError("only the pinned root device can revoke another device")
    if args.device_id in (config.device_id, config.root_device_id):
        raise VpsSyncError("refusing to revoke this device or the pinned root device")
    verified_head = engine.verified_head()
    statement = make_revocation_statement(
        vault_id=config.vault_id,
        device_id=args.device_id,
        revoked_by_device_id=config.device_id,
        checkpoint_commit_id=None if verified_head is None else verified_head.commit_id,
        checkpoint_manifest_hash=None if verified_head is None else verified_head.manifest_hash,
        checkpoint_sequence=0 if verified_head is None else verified_head.sequence,
    )
    signature = sign_revocation(
        statement,
        _unb64(backend.get(SYNC_VPS_SIGNING_PRIVATE).unseal(), label="local signing key", length=32),
    )
    _client(config, backend).revoke_device(
        config.vault_id,
        args.device_id,
        expected_head=None if verified_head is None else verified_head.commit_id,
        revocation_statement=canonical_json_bytes(statement).decode("utf-8"),
        revocation_signature=signature,
    )
    engine.refresh_trust_anchor()
    AuditLog(paths).record(op="sync.vps.revoke", name="<device>", id_=args.device_id, file_target=config.endpoint)
    print(f"revoked server access for device {args.device_id}")
    print("important: this does not erase snapshots or VaultKey material already held by that device")
    return 0


def register_vps_sync(subparsers) -> None:
    vps = subparsers.add_parser("vps", help="zero-knowledge multi-device sync through a VPS")
    commands = vps.add_subparsers(dest="vps_sync_command", required=True)

    init = commands.add_parser("init", help="create a new encrypted vault on syncd")
    init.add_argument("--endpoint", required=True)
    init.add_argument("--recovery-file", required=True)
    init.add_argument("--proxy", default="direct")
    init.add_argument(
        "--admin-token-entry",
        help="read the bootstrap token from an existing Keys Keeper entry",
    )
    init.set_defaults(func=cmd_vps_init)

    for name, handler, help_text in (
        ("push", cmd_vps_push, "merge and publish a signed encrypted snapshot"),
        ("pull", cmd_vps_pull, "verify, decrypt, and merge the signed HEAD"),
        ("status", cmd_vps_status, "verify sync state and show local changes"),
        ("devices", cmd_vps_devices, "list device ids, states, and fingerprints"),
    ):
        parser = commands.add_parser(name, help=help_text)
        parser.set_defaults(func=handler)

    invitation = commands.add_parser("invite", help="create a short-lived one-time device invitation")
    invitation.add_argument("--out", required=True)
    invitation.add_argument("--expires", type=int, default=900)
    invitation.set_defaults(func=cmd_vps_invite)

    join = commands.add_parser("join", help="claim an invitation on a new device")
    join.add_argument("--invite", required=True)
    join.add_argument("--trust-fingerprint", required=True)
    join.add_argument("--proxy", default="direct")
    join.set_defaults(func=cmd_vps_join)

    approve = commands.add_parser("approve", help="approve a pending device after fingerprint comparison")
    approve.add_argument("invite_id")
    approve.add_argument("--invite", required=True)
    approve.add_argument("--fingerprint", required=True)
    approve.set_defaults(func=cmd_vps_approve)

    finish = commands.add_parser("finish", help="install an approved wrapped VaultKey")
    finish.add_argument("--invite", required=True)
    finish.set_defaults(func=cmd_vps_finish)

    revoke = commands.add_parser("revoke", help="block a device from syncd")
    revoke.add_argument("device_id")
    revoke.set_defaults(func=cmd_vps_revoke)


__all__ = ["register_vps_sync"]
