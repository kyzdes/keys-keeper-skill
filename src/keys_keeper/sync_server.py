"""Zero-knowledge HTTP storage for the Keys Keeper v2 sync protocol.

The service deliberately has no access to a vault key and never imports a
local secrets backend.  It stores authenticated device metadata, signed commit
manifests, and encrypted snapshot bytes only.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import parse_qs, urlsplit


# A maximum-size KK2 plaintext expands once inside the encrypted JSON envelope
# and a second time as the HTTP base64url field.  32 MiB covers that bounded
# representation while still imposing a hard request cap.
MAX_REQUEST_BODY = 32 * 1024 * 1024
DEFAULT_INVITE_TTL = 15 * 60
MAX_INVITE_TTL = 24 * 60 * 60
_OPAQUE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_COMMIT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class SyncServerError(Exception):
    """An expected request failure that is safe to return to a client."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = int(status)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AuthenticatedDevice:
    device_id: str
    vault_id: str
    status: str


def _now_seconds() -> int:
    return int(time.time())


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _json_object(data: bytes, *, label: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise SyncServerError(400, "invalid_json", f"{label} must be valid JSON") from exc
    if not isinstance(value, dict):
        raise SyncServerError(400, "invalid_json", f"{label} must be a JSON object")
    return value


def _required_string(
    value: Mapping[str, Any],
    name: str,
    *,
    min_bytes: int = 1,
    max_bytes: int = 1024 * 1024,
) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise SyncServerError(400, "invalid_request", f"{name} must be a string")
    size = len(item.encode("utf-8"))
    if size < min_bytes or size > max_bytes:
        raise SyncServerError(400, "invalid_request", f"{name} has an invalid length")
    return item


def _optional_string(
    value: Mapping[str, Any], name: str, *, max_bytes: int = 1024 * 1024
) -> str | None:
    item = value.get(name)
    if item is None:
        return None
    if not isinstance(item, str) or not item or len(item.encode("utf-8")) > max_bytes:
        raise SyncServerError(400, "invalid_request", f"{name} must be a non-empty string")
    return item


def _require_fields(
    value: Mapping[str, Any], *, required: set[str], optional: set[str] | None = None
) -> None:
    fields = set(value)
    optional = optional or set()
    if fields != required | (fields & optional):
        raise SyncServerError(400, "invalid_request", "request has invalid fields")


def _decode_base64(value: Any, name: str, *, exact_size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise SyncServerError(400, "invalid_request", f"{name} must be base64url")
    if "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise SyncServerError(400, "invalid_request", f"{name} must be base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as exc:
        raise SyncServerError(400, "invalid_request", f"{name} must be base64url") from exc
    if exact_size is not None and len(decoded) != exact_size:
        raise SyncServerError(400, "invalid_request", f"{name} has an invalid length")
    return decoded


def _encode_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _public_key(value: Mapping[str, Any], name: str) -> tuple[str, bytes]:
    encoded = _required_string(value, name, max_bytes=256)
    return encoded, _decode_base64(encoded, name, exact_size=32)


def _opaque_id(value: str, label: str) -> str:
    if not _OPAQUE_ID_RE.fullmatch(value):
        raise SyncServerError(404, "not_found", f"{label} not found")
    return value


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(24)}"


def _bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise SyncServerError(401, "unauthorized", "authentication required")
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token or " " in token:
        raise SyncServerError(401, "unauthorized", "authentication required")
    return token


class SyncServerApp:
    """SQLite-backed application implementing the ``/v1`` sync API."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        bootstrap_admin_token: str | None = None,
        *,
        clock: Callable[[], int | float] = _now_seconds,
    ):
        token = bootstrap_admin_token
        if token is None:
            token = os.environ.get("KEYS_KEEPER_SYNC_ADMIN_TOKEN")
        if not token:
            raise ValueError("bootstrap_admin_token is required")
        self.database = str(Path(database))
        self._bootstrap_token_hash = _sha256(token.encode("utf-8"))
        self._clock = clock
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30.0, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    @contextmanager
    def _transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _initialize_database(self) -> None:
        database_path = Path(self.database)
        parent_existed = database_path.parent.exists()
        database_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix" and not parent_existed:
            os.chmod(database_path.parent, 0o700)
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS vaults (
                    vault_id TEXT PRIMARY KEY,
                    head_commit_id TEXT,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                    sign_public_key TEXT NOT NULL,
                    wrap_public_key TEXT NOT NULL,
                    token_hash BLOB NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'revoked')),
                    approved_by_device_id TEXT,
                    membership_statement TEXT,
                    membership_signature TEXT,
                    wrapped_vault_key TEXT,
                    created_at INTEGER NOT NULL,
                    approved_at INTEGER,
                    revoked_at INTEGER,
                    revoked_by_device_id TEXT,
                    revocation_statement TEXT,
                    revocation_signature TEXT
                );
                CREATE INDEX IF NOT EXISTS devices_vault_idx
                    ON devices(vault_id, created_at, device_id);

                CREATE TABLE IF NOT EXISTS commits (
                    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                    commit_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    parent_commit_id TEXT,
                    manifest_hash TEXT NOT NULL,
                    commit_blob BLOB NOT NULL,
                    snapshot_ciphertext BLOB NOT NULL,
                    author_device_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (vault_id, commit_id),
                    UNIQUE (vault_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS commits_parent_idx
                    ON commits(vault_id, parent_commit_id);

                CREATE TABLE IF NOT EXISTS invites (
                    invite_id TEXT PRIMARY KEY,
                    vault_id TEXT NOT NULL REFERENCES vaults(vault_id) ON DELETE CASCADE,
                    secret_hash BLOB NOT NULL,
                    status TEXT NOT NULL
                        CHECK (status IN ('open', 'claimed', 'approved', 'expired')),
                    created_by_device_id TEXT NOT NULL,
                    claimant_device_id TEXT,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    claimed_at INTEGER,
                    approved_at INTEGER
                );
                CREATE INDEX IF NOT EXISTS invites_vault_idx
                    ON invites(vault_id, created_at, invite_id);
                """
            )
        if os.name == "posix":
            os.chmod(database_path, 0o600)

    def _authenticate_admin(self, authorization: str | None) -> None:
        supplied = _sha256(_bearer_token(authorization).encode("utf-8"))
        if not hmac.compare_digest(supplied, self._bootstrap_token_hash):
            raise SyncServerError(401, "unauthorized", "invalid credentials")

    def authenticate_device(
        self,
        device_id: str | None,
        authorization: str | None,
        *,
        vault_id: str | None = None,
        allow_pending: bool = False,
    ) -> AuthenticatedDevice:
        if not device_id or not _OPAQUE_ID_RE.fullmatch(device_id):
            raise SyncServerError(401, "unauthorized", "invalid credentials")
        token_hash = _sha256(_bearer_token(authorization).encode("utf-8"))
        with self._connect() as connection:
            row = connection.execute(
                "SELECT device_id, vault_id, token_hash, status FROM devices WHERE device_id = ?",
                (device_id,),
            ).fetchone()
        if row is None or not hmac.compare_digest(bytes(row["token_hash"]), token_hash):
            raise SyncServerError(401, "unauthorized", "invalid credentials")
        status = str(row["status"])
        allowed = status == "active" or (allow_pending and status == "pending")
        if not allowed:
            raise SyncServerError(403, "device_inactive", "device is not active")
        actual_vault_id = str(row["vault_id"])
        if vault_id is not None and not hmac.compare_digest(actual_vault_id, vault_id):
            raise SyncServerError(403, "wrong_vault", "device is not authorized for this vault")
        return AuthenticatedDevice(str(row["device_id"]), actual_vault_id, status)

    def create_vault(self, payload: Mapping[str, Any], authorization: str | None) -> dict[str, Any]:
        self._authenticate_admin(authorization)
        _require_fields(
            payload,
            required={"device_token", "sign_public_key", "wrap_public_key"},
        )
        sign_public_key, _ = _public_key(payload, "sign_public_key")
        wrap_public_key, _ = _public_key(payload, "wrap_public_key")
        device_token = _required_string(payload, "device_token", min_bytes=32, max_bytes=4096)
        vault_id = _new_id("vlt")
        device_id = _new_id("dev")
        now = int(self._clock())
        with self._transaction(immediate=True) as connection:
            connection.execute(
                "INSERT INTO vaults(vault_id, head_commit_id, created_at) VALUES (?, NULL, ?)",
                (vault_id, now),
            )
            connection.execute(
                """INSERT INTO devices(
                       device_id, vault_id, sign_public_key, wrap_public_key,
                       token_hash, status, created_at, approved_at
                   ) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)""",
                (
                    device_id,
                    vault_id,
                    sign_public_key,
                    wrap_public_key,
                    _sha256(device_token.encode("utf-8")),
                    now,
                    now,
                ),
            )
        return {"vault_id": vault_id, "device_id": device_id, "head_commit_id": None}

    def health(self) -> dict[str, str]:
        """Check that the relay process can still open and query its database."""
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}

    def get_head(self, vault_id: str, device: AuthenticatedDevice) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        with self._connect() as connection:
            row = connection.execute(
                """SELECT v.head_commit_id, c.sequence, c.manifest_hash
                   FROM vaults v
                   LEFT JOIN commits c
                     ON c.vault_id = v.vault_id AND c.commit_id = v.head_commit_id
                   WHERE v.vault_id = ?""",
                (vault_id,),
            ).fetchone()
        if row is None:
            raise SyncServerError(404, "not_found", "vault not found")
        return {
            "head_commit_id": row["head_commit_id"],
            "sequence": row["sequence"],
            "manifest_hash": row["manifest_hash"],
        }

    def get_commit(
        self, vault_id: str, commit_id: str, device: AuthenticatedDevice
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        if not _COMMIT_ID_RE.fullmatch(commit_id):
            raise SyncServerError(404, "not_found", "commit not found")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM commits WHERE vault_id = ? AND commit_id = ?",
                (vault_id, commit_id),
            ).fetchone()
        if row is None:
            raise SyncServerError(404, "not_found", "commit not found")
        return self._commit_response(row)

    def list_commits(
        self,
        vault_id: str,
        device: AuthenticatedDevice,
        *,
        after_sequence: int = 0,
        limit: int = 50,
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        if after_sequence < 0 or limit < 1 or limit > 100:
            raise SyncServerError(400, "invalid_request", "invalid commit pagination")
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM vaults WHERE vault_id = ?", (vault_id,)
            ).fetchone() is None:
                raise SyncServerError(404, "not_found", "vault not found")
            rows = connection.execute(
                """SELECT * FROM commits
                   WHERE vault_id = ? AND sequence > ?
                   ORDER BY sequence ASC LIMIT ?""",
                (vault_id, after_sequence, limit),
            ).fetchall()
            head = connection.execute(
                "SELECT head_commit_id FROM vaults WHERE vault_id = ?", (vault_id,)
            ).fetchone()
        return {
            # History discovery needs lineage metadata, not up to 100 copies of
            # the encrypted vault. Fetch one bounded snapshot via get_commit.
            "commits": [self._commit_metadata_response(row) for row in rows],
            "head_commit_id": head["head_commit_id"],
        }

    @staticmethod
    def _commit_metadata_response(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "commit_id": row["commit_id"],
            "sequence": row["sequence"],
            "parent_commit_id": row["parent_commit_id"],
            "manifest_hash": row["manifest_hash"],
            "author_device_id": row["author_device_id"],
            "stored_at": row["created_at"],
        }

    @staticmethod
    def _commit_response(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "commit_id": row["commit_id"],
            "sequence": row["sequence"],
            "parent_commit_id": row["parent_commit_id"],
            "manifest_hash": row["manifest_hash"],
            "author_device_id": row["author_device_id"],
            "commit_blob": _encode_base64(bytes(row["commit_blob"])),
            "snapshot_ciphertext": _encode_base64(bytes(row["snapshot_ciphertext"])),
            "stored_at": row["created_at"],
        }

    def append_commit(
        self, vault_id: str, payload: Mapping[str, Any], device: AuthenticatedDevice
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        _require_fields(
            payload,
            required={
                "expected_parent_commit_id",
                "commit_blob",
                "snapshot_ciphertext",
            },
        )
        expected_parent = payload.get("expected_parent_commit_id")
        if expected_parent is not None and (
            not isinstance(expected_parent, str) or not _COMMIT_ID_RE.fullmatch(expected_parent)
        ):
            raise SyncServerError(
                400, "invalid_request", "expected_parent_commit_id is invalid"
            )
        commit_blob = _decode_base64(payload.get("commit_blob"), "commit_blob")
        snapshot = _decode_base64(payload.get("snapshot_ciphertext"), "snapshot_ciphertext")
        with self._connect() as connection:
            key_row = connection.execute(
                "SELECT sign_public_key FROM devices WHERE device_id = ? AND vault_id = ?",
                (device.device_id, vault_id),
            ).fetchone()
        if key_row is None:
            raise SyncServerError(403, "wrong_vault", "device is not authorized for this vault")
        signing_key = _decode_base64(
            key_row["sign_public_key"], "stored signing public key", exact_size=32
        )
        try:
            from keys_keeper.sync_protocol_v2 import verify_commit_signature

            verified = verify_commit_signature(
                commit_blob,
                signing_public_key=signing_key,
                snapshot_ciphertext=snapshot,
                expected_vault_id=vault_id,
                expected_author_device_id=device.device_id,
            )
            if verified is False:
                raise ValueError("signature verifier rejected commit")
        except SyncServerError:
            raise
        except Exception as exc:
            raise SyncServerError(
                422, "invalid_commit", "commit signature or ciphertext is invalid"
            ) from exc

        commit_id = verified.commit_id
        sequence = verified.sequence
        parent_commit_id = verified.parent_commit_id
        parent_manifest_hash = verified.parent_manifest_hash
        manifest_hash = verified.manifest_hash
        if not isinstance(commit_id, str) or not _COMMIT_ID_RE.fullmatch(commit_id):
            raise SyncServerError(422, "invalid_commit", "commit id is invalid")
        if type(sequence) is not int or sequence < 1:
            raise SyncServerError(422, "invalid_commit", "commit sequence is invalid")
        if parent_commit_id != expected_parent:
            raise SyncServerError(422, "invalid_commit", "commit parent does not match CAS parent")
        now = int(self._clock())
        with self._transaction(immediate=True) as connection:
            self._require_active_transaction(connection, device)
            vault = connection.execute(
                "SELECT head_commit_id FROM vaults WHERE vault_id = ?", (vault_id,)
            ).fetchone()
            if vault is None:
                raise SyncServerError(404, "not_found", "vault not found")
            current_head = vault["head_commit_id"]
            if current_head != expected_parent:
                raise SyncServerError(409, "cas_conflict", "vault head changed")

            if current_head is None:
                if sequence != 1 or parent_manifest_hash is not None:
                    raise SyncServerError(422, "invalid_commit", "invalid root commit ancestry")
            else:
                previous = connection.execute(
                    """SELECT sequence, manifest_hash FROM commits
                       WHERE vault_id = ? AND commit_id = ?""",
                    (vault_id, current_head),
                ).fetchone()
                if previous is None:
                    raise SyncServerError(500, "storage_error", "vault head is inconsistent")
                if sequence != int(previous["sequence"]) + 1:
                    raise SyncServerError(422, "invalid_commit", "commit sequence is invalid")
                if parent_manifest_hash != previous["manifest_hash"]:
                    raise SyncServerError(422, "invalid_commit", "parent manifest hash is invalid")

            try:
                connection.execute(
                    """INSERT INTO commits(
                           vault_id, commit_id, sequence, parent_commit_id,
                           manifest_hash, commit_blob, snapshot_ciphertext,
                           author_device_id, created_at
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        vault_id,
                        commit_id,
                        sequence,
                        parent_commit_id,
                        manifest_hash,
                        commit_blob,
                        snapshot,
                        device.device_id,
                        now,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise SyncServerError(409, "commit_conflict", "commit already exists") from exc
            updated = connection.execute(
                """UPDATE vaults SET head_commit_id = ?
                   WHERE vault_id = ? AND head_commit_id IS ?""",
                (commit_id, vault_id, expected_parent),
            )
            if updated.rowcount != 1:
                raise SyncServerError(409, "cas_conflict", "vault head changed")
        return {"commit_id": commit_id, "sequence": sequence, "head_commit_id": commit_id}

    def list_devices(
        self, vault_id: str, device: AuthenticatedDevice
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT device_id, sign_public_key, wrap_public_key, status,
                          approved_by_device_id, membership_statement,
                          membership_signature, created_at, approved_at,
                          revoked_at, revoked_by_device_id, revocation_statement,
                          revocation_signature
                   FROM devices WHERE vault_id = ?
                   ORDER BY created_at, device_id""",
                (vault_id,),
            ).fetchall()
        return {"devices": [dict(row) for row in rows]}

    def revoke_device(
        self,
        vault_id: str,
        target_device_id: str,
        payload: Mapping[str, Any],
        device: AuthenticatedDevice,
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        _require_fields(
            payload,
            required={
                "expected_head_commit_id",
                "revocation_statement",
                "revocation_signature",
            },
        )
        _opaque_id(target_device_id, "device")
        expected_head = payload.get("expected_head_commit_id")
        if expected_head is not None and (
            not isinstance(expected_head, str) or not _COMMIT_ID_RE.fullmatch(expected_head)
        ):
            raise SyncServerError(400, "invalid_request", "expected HEAD is invalid")
        statement = _required_string(payload, "revocation_statement")
        signature = _required_string(payload, "revocation_signature", max_bytes=16 * 1024)
        now = int(self._clock())
        with self._transaction(immediate=True) as connection:
            self._require_root_transaction(connection, device)
            vault = connection.execute(
                "SELECT head_commit_id FROM vaults WHERE vault_id = ?", (vault_id,)
            ).fetchone()
            if vault is None:
                raise SyncServerError(404, "not_found", "vault not found")
            if vault["head_commit_id"] != expected_head:
                raise SyncServerError(
                    409, "cas_conflict", "vault head changed before device revocation"
                )
            target = connection.execute(
                """SELECT status, approved_by_device_id FROM devices
                   WHERE vault_id = ? AND device_id = ?""",
                (vault_id, target_device_id),
            ).fetchone()
            if target is None:
                raise SyncServerError(404, "not_found", "device not found")
            if target["approved_by_device_id"] is None:
                raise SyncServerError(
                    409, "root_revoke_forbidden", "the root device cannot revoke itself"
                )
            if target["status"] == "revoked":
                raise SyncServerError(409, "already_revoked", "device is already revoked")
            connection.execute(
                """UPDATE devices SET status = 'revoked', revoked_at = ?,
                          revoked_by_device_id = ?, revocation_statement = ?,
                          revocation_signature = ?
                   WHERE vault_id = ? AND device_id = ?""",
                (
                    now,
                    device.device_id,
                    statement,
                    signature,
                    vault_id,
                    target_device_id,
                ),
            )
        return {"device_id": target_device_id, "status": "revoked"}

    def create_invite(
        self, vault_id: str, payload: Mapping[str, Any], device: AuthenticatedDevice
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        _require_fields(
            payload,
            required={"secret_hash"},
            optional={"expires_in_seconds"},
        )
        secret_hash_hex = _required_string(payload, "secret_hash", max_bytes=64)
        if not _SHA256_RE.fullmatch(secret_hash_hex):
            raise SyncServerError(400, "invalid_request", "secret_hash must be lowercase SHA-256")
        ttl = payload.get("expires_in_seconds", DEFAULT_INVITE_TTL)
        if type(ttl) is not int or ttl < 1 or ttl > MAX_INVITE_TTL:
            raise SyncServerError(400, "invalid_request", "invite expiry is invalid")
        invite_id = _new_id("inv")
        now = int(self._clock())
        expires_at = now + ttl
        with self._transaction(immediate=True) as connection:
            self._require_root_transaction(connection, device)
            connection.execute(
                """INSERT INTO invites(
                       invite_id, vault_id, secret_hash, status,
                       created_by_device_id, created_at, expires_at
                   ) VALUES (?, ?, ?, 'open', ?, ?, ?)""",
                (
                    invite_id,
                    vault_id,
                    bytes.fromhex(secret_hash_hex),
                    device.device_id,
                    now,
                    expires_at,
                ),
            )
        return {"invite_id": invite_id, "status": "open", "expires_at": expires_at}

    def claim_invite(self, invite_id: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        _opaque_id(invite_id, "invite")
        _require_fields(
            payload,
            required={
                "secret",
                "device_id",
                "device_token",
                "sign_public_key",
                "wrap_public_key",
            },
        )
        secret = _required_string(payload, "secret", min_bytes=32, max_bytes=4096)
        device_id = _required_string(payload, "device_id", max_bytes=128)
        _opaque_id(device_id, "device")
        sign_public_key, _ = _public_key(payload, "sign_public_key")
        wrap_public_key, _ = _public_key(payload, "wrap_public_key")
        device_token = _required_string(payload, "device_token", min_bytes=32, max_bytes=4096)
        supplied_secret_hash = _sha256(secret.encode("utf-8"))
        supplied_token_hash = _sha256(device_token.encode("utf-8"))
        now = int(self._clock())
        with self._transaction(immediate=True) as connection:
            invite = connection.execute(
                "SELECT * FROM invites WHERE invite_id = ?", (invite_id,)
            ).fetchone()
            if invite is None:
                raise SyncServerError(404, "not_found", "invite not found")
            if int(invite["expires_at"]) <= now:
                if invite["status"] in ("open", "claimed"):
                    connection.execute(
                        "UPDATE invites SET status = 'expired' WHERE invite_id = ?",
                        (invite_id,),
                    )
                    connection.commit()
                raise SyncServerError(410, "invite_expired", "invite expired")
            if not hmac.compare_digest(bytes(invite["secret_hash"]), supplied_secret_hash):
                raise SyncServerError(401, "invalid_invite_secret", "invalid invite secret")
            if invite["status"] == "open":
                try:
                    connection.execute(
                        """INSERT INTO devices(
                               device_id, vault_id, sign_public_key, wrap_public_key,
                               token_hash, status, created_at
                           ) VALUES (?, ?, ?, ?, ?, 'pending', ?)""",
                        (
                            device_id,
                            invite["vault_id"],
                            sign_public_key,
                            wrap_public_key,
                            supplied_token_hash,
                            now,
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise SyncServerError(
                        409, "device_conflict", "device identity is already registered"
                    ) from exc
                connection.execute(
                    """UPDATE invites SET status = 'claimed', claimant_device_id = ?, claimed_at = ?
                       WHERE invite_id = ?""",
                    (device_id, now, invite_id),
                )
                device_status = "pending"
            elif invite["status"] in ("claimed", "approved"):
                existing = connection.execute(
                    """SELECT vault_id, sign_public_key, wrap_public_key, token_hash, status
                       FROM devices WHERE device_id = ?""",
                    (invite["claimant_device_id"],),
                ).fetchone()
                if (
                    invite["claimant_device_id"] != device_id
                    or existing is None
                    or existing["vault_id"] != invite["vault_id"]
                    or existing["sign_public_key"] != sign_public_key
                    or existing["wrap_public_key"] != wrap_public_key
                    or not hmac.compare_digest(bytes(existing["token_hash"]), supplied_token_hash)
                ):
                    raise SyncServerError(409, "invite_used", "invite is no longer available")
                device_status = str(existing["status"])
            else:
                raise SyncServerError(409, "invite_used", "invite is no longer available")
        return {
            "invite_id": invite_id,
            "vault_id": str(invite["vault_id"]),
            "device_id": device_id,
            "status": device_status,
            "expires_at": int(invite["expires_at"]),
        }

    def inspect_invite(
        self, vault_id: str, invite_id: str, device: AuthenticatedDevice
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        _opaque_id(invite_id, "invite")
        with self._transaction(immediate=True) as connection:
            invite = connection.execute(
                "SELECT * FROM invites WHERE invite_id = ? AND vault_id = ?",
                (invite_id, vault_id),
            ).fetchone()
            if invite is None:
                raise SyncServerError(404, "not_found", "invite not found")
            if int(invite["expires_at"]) <= int(self._clock()) and invite["status"] in (
                "open",
                "claimed",
            ):
                connection.execute(
                    "UPDATE invites SET status = 'expired' WHERE invite_id = ?",
                    (invite_id,),
                )
                invite = connection.execute(
                    "SELECT * FROM invites WHERE invite_id = ?", (invite_id,)
                ).fetchone()
            claimant = None
            if invite["claimant_device_id"]:
                claimant_row = connection.execute(
                    """SELECT device_id, sign_public_key, wrap_public_key, status, created_at
                       FROM devices WHERE device_id = ?""",
                    (invite["claimant_device_id"],),
                ).fetchone()
                if claimant_row is not None:
                    claimant = dict(claimant_row)
        return self._invite_response(invite, claimant=claimant)

    def invite_status(
        self, invite_id: str, device: AuthenticatedDevice
    ) -> dict[str, Any]:
        _opaque_id(invite_id, "invite")
        with self._transaction(immediate=True) as connection:
            invite = connection.execute(
                "SELECT * FROM invites WHERE invite_id = ?", (invite_id,)
            ).fetchone()
            if invite is None:
                raise SyncServerError(404, "not_found", "invite not found")
            if invite["vault_id"] != device.vault_id:
                raise SyncServerError(
                    403, "wrong_vault", "device is not authorized for this invite"
                )
            if device.status == "pending" and invite["claimant_device_id"] != device.device_id:
                raise SyncServerError(403, "forbidden", "device is not this invite's claimant")
            if int(invite["expires_at"]) <= int(self._clock()) and invite["status"] in (
                "open",
                "claimed",
            ):
                connection.execute(
                    "UPDATE invites SET status = 'expired' WHERE invite_id = ?",
                    (invite_id,),
                )
                invite = connection.execute(
                    "SELECT * FROM invites WHERE invite_id = ?", (invite_id,)
                ).fetchone()
            wrapped = None
            membership_statement = None
            membership_signature = None
            if invite["claimant_device_id"] == device.device_id:
                claimant = connection.execute(
                    """SELECT wrapped_vault_key, membership_statement, membership_signature
                       FROM devices WHERE device_id = ?""",
                    (device.device_id,),
                ).fetchone()
                if claimant is not None:
                    wrapped = claimant["wrapped_vault_key"]
                    membership_statement = claimant["membership_statement"]
                    membership_signature = claimant["membership_signature"]
        response = self._invite_response(invite)
        if wrapped is not None:
            response.update(
                {
                    "wrapped_vault_key": wrapped,
                    "membership_statement": membership_statement,
                    "membership_signature": membership_signature,
                }
            )
        return response

    @staticmethod
    def _invite_response(
        invite: sqlite3.Row, *, claimant: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        response: dict[str, Any] = {
            "invite_id": invite["invite_id"],
            "vault_id": invite["vault_id"],
            "status": invite["status"],
            "created_by_device_id": invite["created_by_device_id"],
            "claimant_device_id": invite["claimant_device_id"],
            "created_at": invite["created_at"],
            "expires_at": invite["expires_at"],
            "claimed_at": invite["claimed_at"],
            "approved_at": invite["approved_at"],
        }
        if claimant is not None:
            response["claimant"] = dict(claimant)
        return response

    def approve_invite(
        self,
        vault_id: str,
        invite_id: str,
        payload: Mapping[str, Any],
        device: AuthenticatedDevice,
    ) -> dict[str, Any]:
        self._require_vault(device, vault_id)
        _opaque_id(invite_id, "invite")
        _require_fields(
            payload,
            required={
                "wrapped_vault_key",
                "membership_statement",
                "membership_signature",
            },
        )
        wrapped_vault_key = _required_string(payload, "wrapped_vault_key")
        membership_statement = _required_string(payload, "membership_statement")
        membership_signature = _required_string(
            payload, "membership_signature", max_bytes=16 * 1024
        )
        now = int(self._clock())
        with self._transaction(immediate=True) as connection:
            self._require_root_transaction(connection, device)
            invite = connection.execute(
                "SELECT * FROM invites WHERE invite_id = ? AND vault_id = ?",
                (invite_id, vault_id),
            ).fetchone()
            if invite is None:
                raise SyncServerError(404, "not_found", "invite not found")
            if int(invite["expires_at"]) <= now:
                if invite["status"] in ("open", "claimed"):
                    connection.execute(
                        "UPDATE invites SET status = 'expired' WHERE invite_id = ?",
                        (invite_id,),
                    )
                    connection.commit()
                raise SyncServerError(410, "invite_expired", "invite expired")
            if invite["status"] != "claimed" or not invite["claimant_device_id"]:
                raise SyncServerError(409, "invite_not_claimed", "invite cannot be approved")
            if invite["created_by_device_id"] != device.device_id:
                raise SyncServerError(
                    403,
                    "wrong_approver",
                    "invite must be approved by the device that created it",
                )
            claimant_device_id = str(invite["claimant_device_id"])
            updated = connection.execute(
                """UPDATE devices SET status = 'active', approved_at = ?,
                          approved_by_device_id = ?, membership_statement = ?,
                          membership_signature = ?, wrapped_vault_key = ?
                   WHERE device_id = ? AND vault_id = ? AND status = 'pending'""",
                (
                    now,
                    device.device_id,
                    membership_statement,
                    membership_signature,
                    wrapped_vault_key,
                    claimant_device_id,
                    vault_id,
                ),
            )
            if updated.rowcount != 1:
                raise SyncServerError(409, "invite_used", "invite claimant is not pending")
            connection.execute(
                "UPDATE invites SET status = 'approved', approved_at = ? WHERE invite_id = ?",
                (now, invite_id),
            )
        return {
            "invite_id": invite_id,
            "device_id": claimant_device_id,
            "status": "approved",
        }

    @staticmethod
    def _require_vault(device: AuthenticatedDevice, vault_id: str) -> None:
        _opaque_id(vault_id, "vault")
        if not hmac.compare_digest(device.vault_id, vault_id):
            raise SyncServerError(403, "wrong_vault", "device is not authorized for this vault")

    @staticmethod
    def _require_active_transaction(
        connection: sqlite3.Connection, device: AuthenticatedDevice
    ) -> None:
        row = connection.execute(
            "SELECT status FROM devices WHERE device_id = ? AND vault_id = ?",
            (device.device_id, device.vault_id),
        ).fetchone()
        if row is None or row["status"] != "active":
            raise SyncServerError(403, "device_inactive", "device is not active")

    @staticmethod
    def _require_root_transaction(
        connection: sqlite3.Connection, device: AuthenticatedDevice
    ) -> None:
        SyncServerApp._require_active_transaction(connection, device)
        row = connection.execute(
            "SELECT approved_by_device_id FROM devices WHERE device_id = ? AND vault_id = ?",
            (device.device_id, device.vault_id),
        ).fetchone()
        if row is None or row["approved_by_device_id"] is not None:
            raise SyncServerError(
                403, "root_required", "device administration requires the root device"
            )


def make_handler(app: SyncServerApp) -> type[BaseHTTPRequestHandler]:
    """Create a request handler bound to one application instance."""

    class SyncRequestHandler(BaseHTTPRequestHandler):
        server_version = "keys-keeper-sync"
        sys_version = ""

        def log_message(self, _format: str, *args: object) -> None:
            # Request targets may contain opaque identifiers.  More importantly,
            # BaseHTTPRequestHandler logging extensions must never gain access to
            # Authorization headers or request bodies through this service.
            return

        def _send_json(self, status: int, body: Mapping[str, Any]) -> None:
            encoded = _canonical_json(body)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(encoded)

        def _send_error(self, error: SyncServerError) -> None:
            self._send_json(
                error.status,
                {"error": {"code": error.code, "message": error.message}},
            )

        def _read_json(self) -> dict[str, Any]:
            if self.headers.get("Transfer-Encoding") is not None:
                raise SyncServerError(400, "invalid_request", "transfer encoding is unsupported")
            content_types = self.headers.get_all("Content-Type", failobj=[])
            if (
                len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise SyncServerError(
                    415, "unsupported_media_type", "Content-Type must be application/json"
                )
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                raise SyncServerError(411, "length_required", "Content-Length is required")
            try:
                length = int(lengths[0], 10)
            except ValueError as exc:
                raise SyncServerError(400, "invalid_request", "invalid Content-Length") from exc
            if length < 0:
                raise SyncServerError(400, "invalid_request", "invalid Content-Length")
            if length > MAX_REQUEST_BODY:
                raise SyncServerError(413, "payload_too_large", "request body is too large")
            data = self.rfile.read(length)
            if len(data) != length:
                raise SyncServerError(400, "invalid_request", "incomplete request body")
            return _json_object(data, label="request body")

        def _device(
            self, vault_id: str | None = None, *, pending: bool = False
        ) -> AuthenticatedDevice:
            return app.authenticate_device(
                self.headers.get("X-Device-ID"),
                self.headers.get("Authorization"),
                vault_id=vault_id,
                allow_pending=pending,
            )

        def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            try:
                split = urlsplit(self.path)
                path = split.path
                if path == "/healthz" and not split.query:
                    self._send_json(200, app.health())
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/head", path)
                if match:
                    vault_id = match.group(1)
                    self._send_json(200, app.get_head(vault_id, self._device(vault_id)))
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/commits/([^/]+)", path)
                if match:
                    vault_id, commit_id = match.groups()
                    self._send_json(
                        200, app.get_commit(vault_id, commit_id, self._device(vault_id))
                    )
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/commits", path)
                if match:
                    vault_id = match.group(1)
                    query = (
                        parse_qs(split.query, keep_blank_values=True, strict_parsing=True)
                        if split.query
                        else {}
                    )
                    if set(query) - {"after_sequence", "limit"} or any(
                        len(values) != 1 for values in query.values()
                    ):
                        raise SyncServerError(400, "invalid_request", "invalid query")
                    try:
                        after = int(query.get("after_sequence", ["0"])[0])
                        limit = int(query.get("limit", ["50"])[0])
                    except ValueError as exc:
                        raise SyncServerError(400, "invalid_request", "invalid query") from exc
                    self._send_json(
                        200,
                        app.list_commits(
                            vault_id, self._device(vault_id), after_sequence=after, limit=limit
                        ),
                    )
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/devices", path)
                if match:
                    vault_id = match.group(1)
                    self._send_json(200, app.list_devices(vault_id, self._device(vault_id)))
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/invites/([^/]+)", path)
                if match:
                    vault_id, invite_id = match.groups()
                    self._send_json(
                        200, app.inspect_invite(vault_id, invite_id, self._device(vault_id))
                    )
                    return
                match = re.fullmatch(r"/v1/invites/([^/]+)/status", path)
                if match:
                    invite_id = match.group(1)
                    self._send_json(200, app.invite_status(invite_id, self._device(pending=True)))
                    return
                raise SyncServerError(404, "not_found", "endpoint not found")
            except ValueError as exc:
                self._send_error(SyncServerError(400, "invalid_request", "invalid query"))
            except SyncServerError as exc:
                self._send_error(exc)
            except Exception:
                self._send_error(SyncServerError(500, "internal_error", "internal server error"))

        def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
            try:
                split = urlsplit(self.path)
                if split.query:
                    raise SyncServerError(400, "invalid_request", "query is not allowed")
                path = split.path
                payload = self._read_json()
                if path == "/v1/vaults":
                    result = app.create_vault(payload, self.headers.get("Authorization"))
                    self._send_json(201, result)
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/commits", path)
                if match:
                    vault_id = match.group(1)
                    result = app.append_commit(vault_id, payload, self._device(vault_id))
                    self._send_json(201, result)
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/devices/([^/]+)/revoke", path)
                if match:
                    vault_id, target = match.groups()
                    result = app.revoke_device(
                        vault_id, target, payload, self._device(vault_id)
                    )
                    self._send_json(200, result)
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/invites", path)
                if match:
                    vault_id = match.group(1)
                    result = app.create_invite(vault_id, payload, self._device(vault_id))
                    self._send_json(201, result)
                    return
                match = re.fullmatch(r"/v1/invites/([^/]+)/claim", path)
                if match:
                    result = app.claim_invite(match.group(1), payload)
                    self._send_json(201, result)
                    return
                match = re.fullmatch(r"/v1/vaults/([^/]+)/invites/([^/]+)/approve", path)
                if match:
                    vault_id, invite_id = match.groups()
                    result = app.approve_invite(
                        vault_id, invite_id, payload, self._device(vault_id)
                    )
                    self._send_json(200, result)
                    return
                raise SyncServerError(404, "not_found", "endpoint not found")
            except SyncServerError as exc:
                self._send_error(exc)
            except Exception:
                self._send_error(SyncServerError(500, "internal_error", "internal server error"))

        def do_PUT(self) -> None:  # noqa: N802
            self._send_error(SyncServerError(405, "method_not_allowed", "method not allowed"))

        do_PATCH = do_PUT
        do_DELETE = do_PUT

    return SyncRequestHandler


_make_handler = make_handler


def create_http_server(
    app: SyncServerApp,
    host: str = "127.0.0.1",
    port: int = 0,
    *,
    allow_non_loopback: bool = False,
) -> ThreadingHTTPServer:
    """Build an HTTP server, refusing public binds unless explicitly enabled."""

    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = host.lower() == "localhost"
    if not is_loopback and not allow_non_loopback:
        raise ValueError("non-loopback bind requires allow_non_loopback=True")
    return ThreadingHTTPServer((host, port), make_handler(app))


__all__ = [
    "AuthenticatedDevice",
    "MAX_REQUEST_BODY",
    "SyncServerApp",
    "SyncServerError",
    "create_http_server",
    "make_handler",
]
