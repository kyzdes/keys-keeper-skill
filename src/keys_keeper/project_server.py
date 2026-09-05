"""Ciphertext-only project relay, sharing syncd's transactional SQLite adapter.

This application deliberately has no credential-backend dependency. API role
checks are independent from end-to-end verification in the receiving client.
"""
from __future__ import annotations

import hashlib
import hmac
import threading
from contextlib import contextmanager
from dataclasses import dataclass
import re
from uuid import UUID

from keys_keeper import project_protocol as protocol
from keys_keeper.sync_server import SyncServerError, _bearer_token


MAX_SUBMISSION = 2 * 1024 * 1024
MAX_SCOPE_PENDING_BYTES = 64 * 1024 * 1024
MAX_SCOPE_PENDING = 1000
MAX_DEVICE_PENDING = 100
MAX_CREATES_PER_MINUTE = 30


@dataclass(frozen=True)
class ProjectRelayLimits:
    """Logical stored-record budgets; no deletion or eviction on exhaustion."""
    scope_bytes: int = 512 * 1024 * 1024
    relay_bytes: int = 2 * 1024 * 1024 * 1024
    scope_records: int = 20_000
    relay_records: int = 100_000
    control_scope_bytes: int = 32 * 1024 * 1024
    control_relay_bytes: int = 128 * 1024 * 1024
    control_scope_records: int = 2_000
    control_relay_records: int = 10_000
    concurrent_requests: int = 4
    concurrent_connections: int = 32
    socket_timeout: int = 10

    def __post_init__(self):
        if any(type(value) is not int or value < 1 for value in vars(self).values()):
            raise ValueError("project relay limits must be positive integers")


_STORAGE_COLUMNS = {
    "kk3_scopes": ("pinned_key", "policy", "head_hash"),
    "kk3_policies": ("hash", "record"), "kk3_snapshots": ("hash", "record"),
    "kk3_wraps": ("device_id", "record"), "kk3_grants": ("grant_id", "device_id", "record"),
    "kk3_blocks": ("grant_id", "record"), "kk3_operations": ("operation_id", "digest", "response"),
    "kk3_submissions": ("device_id", "grant_id", "request_id", "digest", "policy_hash", "record", "receipt"),
}


def _error(status: int, code: str) -> None:
    raise SyncServerError(status, code, code.replace("_", " "))


def _uuid(value: object) -> str:
    if not isinstance(value, str):
        _error(422, "invalid_identifier")
    try:
        parsed = UUID(value)
    except (ValueError, TypeError, AttributeError):
        _error(422, "invalid_identifier")
    if str(parsed) != value or parsed.version != 4:
        _error(422, "invalid_identifier")
    return value


def _fields(value: object, names: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != names:
        _error(422, "invalid_fields")


def _dump(value: object) -> str:
    return protocol.canonical_bytes(value).decode("utf-8")


def _load(value: str | None):
    return None if value is None else protocol.parse_record(value)


def _unsigned_payload(record: object, *, maximum: int = protocol.MAX_RECORD_SIZE) -> tuple[dict, dict]:
    """Extract only for lookup. Authorization always follows signature verification."""
    obj = protocol.parse_record(record, maximum=maximum)
    _fields(obj, {"profile", "kind", "payload", "signature"})
    if type(obj["payload"]) is not dict:
        _error(422, "invalid_project_record")
    return obj, obj["payload"]


def _digest(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        _error(422, "invalid_digest")
    return value


class ProjectRelay:
    def __init__(self, app, *, limits: ProjectRelayLimits | None = None):
        self.app = app
        self.limits = limits or ProjectRelayLimits()
        self._request_slots = threading.BoundedSemaphore(self.limits.concurrent_requests)
        with app._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS kk3_scopes (
                    scope_id TEXT PRIMARY KEY, pinned_key TEXT NOT NULL,
                    policy TEXT NOT NULL, head_hash TEXT, sequence INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS kk3_policies (
                    scope_id TEXT NOT NULL, hash TEXT NOT NULL, version INTEGER NOT NULL,
                    record TEXT NOT NULL, PRIMARY KEY(scope_id, hash), UNIQUE(scope_id, version)
                );
                CREATE TABLE IF NOT EXISTS kk3_snapshots (
                    scope_id TEXT NOT NULL, hash TEXT NOT NULL, sequence INTEGER NOT NULL,
                    record TEXT NOT NULL, PRIMARY KEY(scope_id, hash), UNIQUE(scope_id, sequence)
                );
                CREATE TABLE IF NOT EXISTS kk3_wraps (
                    scope_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    record TEXT NOT NULL, PRIMARY KEY(scope_id, device_id)
                );
                CREATE TABLE IF NOT EXISTS kk3_grants (
                    scope_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    device_id TEXT NOT NULL, generation INTEGER NOT NULL, record TEXT NOT NULL,
                    PRIMARY KEY(scope_id, grant_id), UNIQUE(scope_id, device_id, generation)
                );
                CREATE TABLE IF NOT EXISTS kk3_blocks (
                    scope_id TEXT NOT NULL, grant_id TEXT NOT NULL, record TEXT NOT NULL,
                    PRIMARY KEY(scope_id, grant_id)
                );
                CREATE TABLE IF NOT EXISTS kk3_operations (
                    scope_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                    digest TEXT NOT NULL, response TEXT NOT NULL,
                    PRIMARY KEY(scope_id, operation_id)
                );
                CREATE TABLE IF NOT EXISTS kk3_submissions (
                    scope_id TEXT NOT NULL, device_id TEXT NOT NULL, grant_id TEXT NOT NULL,
                    request_id TEXT NOT NULL, digest TEXT NOT NULL, policy_hash TEXT NOT NULL,
                    record TEXT NOT NULL, size INTEGER NOT NULL, created INTEGER NOT NULL,
                    receipt TEXT, PRIMARY KEY(scope_id, device_id, request_id)
                );
                CREATE INDEX IF NOT EXISTS kk3_pending ON kk3_submissions(scope_id, receipt, created);
            """)

    @contextmanager
    def request_slot(self):
        if not self._request_slots.acquire(blocking=False):
            _error(429, "relay_busy")
        try:
            yield
        finally:
            self._request_slots.release()

    def request_limit(self, path: str) -> int:
        if path == "/v2/scopes":
            return protocol.MAX_POLICY_SIZE + 1024
        if path.endswith("/receipt") or path.endswith("/revoke"):
            return 17 * 1024
        if path.endswith("/submissions"):
            return MAX_SUBMISSION + 1024
        return protocol.MAX_RECORD_SIZE

    def preflight(self, method: str, path: str, headers) -> None:
        """Cheap authentication before accepting an allocating HTTP body."""
        try:
            self._unique_auth(headers)
            if method == "POST" and path == "/v2/scopes":
                self.app._authenticate_admin(headers.get("Authorization"))
                return
            match = re.fullmatch(r"/v2/scopes/([0-9a-f-]+)/([a-z]+)(?:/([0-9a-f-]+))?(?:/(receipt))?", path)
            if match is None:
                _error(404, "not_found")
            scope_id, action, object_id, suffix = match.groups()
            _uuid(scope_id)
            operation = "read"
            if method == "POST":
                operation = {"publish": "publish", "revoke": "revoke", "submissions": "receipt" if suffix else "create"}.get(action)
                if operation is None:
                    _error(404, "not_found")
            with self.app._transaction() as connection:
                self._auth(connection, scope_id, headers, operation)
        except protocol.AuthorizationError:
            _error(403, "project_authorization_failed")
        except protocol.ProtocolError:
            _error(422, "invalid_project_record")

    @staticmethod
    def _unique_auth(headers):
        if hasattr(headers, "get_all"):
            for name in ("Authorization", "X-Device-ID"):
                if len(headers.get_all(name, failobj=[])) > 1:
                    _error(400, "ambiguous_authentication")

    def storage_usage(self, connection, scope_id: str | None = None) -> tuple[int, int]:
        total_bytes, total_records = 0, 0
        for table, columns in _STORAGE_COLUMNS.items():
            expression = " + ".join(f"COALESCE(length(CAST({name} AS BLOB)),0)" for name in columns)
            where = "" if scope_id is None else " WHERE scope_id=?"
            # Include a fixed per-row metadata allowance. Physical SQLite pages,
            # indexes and WAL need additional filesystem headroom in operations.
            row = connection.execute(f"SELECT COUNT(*),COALESCE(SUM(256 + {expression}),0) FROM {table}{where}",
                                     () if scope_id is None else (scope_id,)).fetchone()
            total_records += row[0]
            total_bytes += row[1]
        return total_bytes, total_records

    def _storage_budget(self, connection, scope_id: str, *, control: bool = False) -> None:
        limits = self.limits
        for scope, byte_limit, record_limit, extra_bytes, extra_records in (
            (scope_id, limits.scope_bytes, limits.scope_records, limits.control_scope_bytes, limits.control_scope_records),
            (None, limits.relay_bytes, limits.relay_records, limits.control_relay_bytes, limits.control_relay_records),
        ):
            used_bytes, used_records = self.storage_usage(connection, scope)
            if used_bytes > byte_limit + (extra_bytes if control else 0) or used_records > record_limit + (extra_records if control else 0):
                _error(429, "storage_full")

    def _scope(self, connection, scope_id: str):
        row = connection.execute("SELECT * FROM kk3_scopes WHERE scope_id=?", (scope_id,)).fetchone()
        if row is None:
            _error(403, "scope_access_denied")
        policy = _load(row["policy"])
        pin = protocol.decode_key(row["pinned_key"])
        body = protocol.verify_policy(policy, pin, expected_scope_id=scope_id)
        return row, policy, pin, body

    def _auth(self, connection, scope_id: str, headers, operation: str):
        token_hash = hashlib.sha256(_bearer_token(headers.get("Authorization")).encode()).hexdigest()
        device = headers.get("X-Device-ID")
        if type(device) is not str:
            _error(401, "unauthorized")
        _uuid(device)
        row, policy, pin, body = self._scope(connection, scope_id)
        if device == body["master_device_id"]:
            if not hmac.compare_digest(token_hash, body["master_token_hash"]):
                _error(401, "unauthorized")
        else:
            if operation not in {"read", "create"}:
                _error(403, "master_required")
            grant = protocol.authorize_grant(body, device, operation)
            if not hmac.compare_digest(token_hash, grant["token_hash"]):
                _error(401, "unauthorized")
            if connection.execute("SELECT 1 FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                  (scope_id, grant["grant_id"])).fetchone():
                _error(403, "grant_revoked")
        return row, policy, pin, body, device

    def handle(self, method: str, path: str, headers, payload: dict | None = None):
        try:
            self._unique_auth(headers)
            if payload is not None:
                # HTTP JSON is ordinary JSON; nested signed records have their
                # own canonical byte representation. Bound the whole API object.
                payload = protocol.parse_record(payload)
            return self._handle(method, path, headers, payload)
        except protocol.AuthorizationError:
            _error(403, "project_authorization_failed")
        except protocol.ProtocolError:
            _error(422, "invalid_project_record")

    def _handle(self, method, path, headers, payload):
        if method == "POST" and path == "/v2/scopes":
            return self.create_scope(headers, payload)
        match = re.fullmatch(r"/v2/scopes/([0-9a-f-]+)/([a-z]+)(?:/([0-9a-f-]+))?(?:/(receipt))?", path)
        if not match:
            _error(404, "not_found")
        scope_id, action, object_id, suffix = match.groups()
        _uuid(scope_id)
        if method == "GET" and action == "state" and object_id is None:
            return 200, self.state(scope_id, headers)
        if method == "POST" and action == "publish" and object_id is None:
            return self.publish(scope_id, headers, payload)
        if method == "POST" and action == "revoke" and object_id is None:
            return 200, self.block(scope_id, headers, payload)
        if method == "GET" and action in {"policies", "snapshots"} and object_id and not suffix:
            return 200, self.record(scope_id, headers, action, object_id)
        if action == "submissions":
            if method == "POST" and object_id is None:
                return self.submit(scope_id, headers, payload)
            if method == "GET" and not suffix:
                return 200, self.submissions(scope_id, headers, object_id)
            if method == "POST" and object_id and suffix == "receipt":
                return 200, self.acknowledge(scope_id, headers, object_id, payload)
        _error(404, "not_found")

    def _remember_grants(self, connection, scope_id, body, previous=None):
        previous = {} if previous is None else {g["grant_id"]: g for g in previous["grants"]}
        for grant in body["grants"]:
            encoded = _dump(grant)
            known = connection.execute("SELECT * FROM kk3_grants WHERE scope_id=? AND grant_id=?",
                                       (scope_id, grant["grant_id"])).fetchone()
            if known is not None:
                if grant["grant_id"] not in previous or known["record"] != encoded:
                    _error(409, "grant_identity_reused")
            else:
                highest = connection.execute(
                    "SELECT MAX(generation) FROM kk3_grants WHERE scope_id=? AND device_id=?",
                    (scope_id, grant["device_id"]),
                ).fetchone()[0]
                if highest is not None and grant["generation"] <= highest:
                    _error(409, "grant_generation_reused")
                connection.execute("INSERT INTO kk3_grants VALUES(?,?,?,?,?)",
                                   (scope_id, grant["grant_id"], grant["device_id"], grant["generation"], encoded))
            if connection.execute("SELECT 1 FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                  (scope_id, grant["grant_id"])).fetchone():
                _error(409, "grant_revoked")

    def create_scope(self, headers, payload):
        self.app._authenticate_admin(headers.get("Authorization"))
        _fields(payload, {"policy"})
        candidate, candidate_body = _unsigned_payload(payload["policy"], maximum=protocol.MAX_POLICY_SIZE)
        pin = protocol.decode_key(candidate_body.get("master_public_key"))
        body = protocol.verify_policy(candidate, pin)
        if body["version"] != 1 or body["epoch"] != 1 or body["checkpoint_sequence"] != 0 or body["grants"]:
            _error(422, "invalid_initial_policy")
        scope_id = _uuid(body["scope_id"])
        encoded = _dump(candidate)
        with self.app._transaction(immediate=True) as connection:
            row = connection.execute("SELECT record FROM kk3_policies WHERE scope_id=? AND version=1", (scope_id,)).fetchone()
            if row:
                if row["record"] != encoded:
                    _error(409, "scope_exists")
                return 200, {"scope_id": scope_id}
            connection.execute("INSERT INTO kk3_scopes(scope_id,pinned_key,policy) VALUES(?,?,?)",
                               (scope_id, protocol.encode_key(pin), encoded))
            connection.execute("INSERT INTO kk3_policies VALUES(?,?,?,?)",
                               (scope_id, protocol.canonical_hash(candidate), 1, encoded))
            self._storage_budget(connection, scope_id)
        return 201, {"scope_id": scope_id}

    def state(self, scope_id, headers):
        with self.app._transaction() as connection:
            row, policy, pin, body, device = self._auth(connection, scope_id, headers, "read")
            snapshot = connection.execute("SELECT record FROM kk3_snapshots WHERE scope_id=? AND hash=?",
                                          (scope_id, row["head_hash"])).fetchone()
            wrap = connection.execute("SELECT record FROM kk3_wraps WHERE scope_id=? AND device_id=?",
                                      (scope_id, device)).fetchone()
            # Return only still-active blocked grants; historical revocations
            # stay durable for anti-regrant checks without unbounded responses.
            blocks = []
            for grant in body["grants"]:
                blocked = connection.execute("SELECT record FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                             (scope_id, grant["grant_id"])).fetchone()
                if blocked is not None:
                    blocks.append(blocked)
            return {"policy": policy, "snapshot": None if snapshot is None else _load(snapshot[0]),
                    "wrap": None if wrap is None else _load(wrap[0]), "head_hash": row["head_hash"],
                    "sequence": row["sequence"], "revocations": [_load(r[0]) for r in blocks]}

    def record(self, scope_id, headers, kind, digest):
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            _error(422, "invalid_identifier")
        table = {"policies": "kk3_policies", "snapshots": "kk3_snapshots"}[kind]
        with self.app._transaction() as connection:
            self._auth(connection, scope_id, headers, "read")
            row = connection.execute(f"SELECT record FROM {table} WHERE scope_id=? AND hash=?", (scope_id, digest)).fetchone()
            if row is None:
                _error(404, "not_found")
            return {"record": _load(row[0])}

    def publish(self, scope_id, headers, payload):
        _fields(payload, {"operation_id", "expected_head_hash", "policy", "snapshot", "wraps"})
        operation_id = _uuid(payload["operation_id"])
        digest = protocol.canonical_hash(payload)
        with self.app._transaction(immediate=True) as connection:
            row, previous, pin, old_body, device = self._auth(connection, scope_id, headers, "publish")
            retry = connection.execute("SELECT digest,response FROM kk3_operations WHERE scope_id=? AND operation_id=?",
                                       (scope_id, operation_id)).fetchone()
            if retry:
                if retry["digest"] != digest:
                    _error(409, "operation_conflict")
                return 200, _load(retry["response"])
            if payload["expected_head_hash"] != row["head_hash"]:
                _error(409, "cas_conflict")
            policy = payload["policy"]
            if protocol.canonical_hash(policy) == protocol.canonical_hash(previous):
                body = old_body
            else:
                body = protocol.validate_policy_transition(previous, policy, pin)
                if body["checkpoint_sequence"] != row["sequence"] or body["checkpoint_hash"] != row["head_hash"]:
                    _error(409, "checkpoint_conflict")
                self._remember_grants(connection, scope_id, body, old_body)
                connection.execute("INSERT INTO kk3_policies VALUES(?,?,?,?)",
                                   (scope_id, protocol.canonical_hash(policy), body["version"], _dump(policy)))
            snapshot = payload["snapshot"]
            checked = protocol.verify_snapshot(snapshot, policy, pin, minimum_sequence=row["sequence"],
                                               expected_parent_hash=row["head_hash"])
            if checked["sequence"] != row["sequence"] + 1:
                _error(409, "sequence_conflict")
            wraps = payload["wraps"]
            if not isinstance(wraps, list) or len(wraps) != len(body["grants"]):
                _error(422, "incomplete_wraps")
            recipients = set()
            for wrapped in wraps:
                verified = protocol.verify_scope_key_wrap(wrapped, policy, pin)
                if verified["device_id"] in recipients:
                    _error(422, "duplicate_wrap")
                recipients.add(verified["device_id"])
            if recipients != {g["device_id"] for g in body["grants"]}:
                _error(422, "incomplete_wraps")
            # A block is effective before rekey; prevent publishing to blocked grants.
            for grant in body["grants"]:
                if connection.execute("SELECT 1 FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                      (scope_id, grant["grant_id"])).fetchone():
                    _error(409, "grant_revoked")
            snapshot_hash = protocol.canonical_hash(snapshot)
            connection.execute("INSERT INTO kk3_snapshots VALUES(?,?,?,?)",
                               (scope_id, snapshot_hash, checked["sequence"], _dump(snapshot)))
            connection.execute("DELETE FROM kk3_wraps WHERE scope_id=?", (scope_id,))
            for wrapped in wraps:
                connection.execute("INSERT INTO kk3_wraps VALUES(?,?,?)",
                                   (scope_id, wrapped["payload"]["device_id"], _dump(wrapped)))
            connection.execute("UPDATE kk3_scopes SET policy=?,head_hash=?,sequence=? WHERE scope_id=?",
                               (_dump(policy), snapshot_hash, checked["sequence"], scope_id))
            response = {"head_hash": snapshot_hash, "sequence": checked["sequence"], "policy_version": body["version"]}
            connection.execute("INSERT INTO kk3_operations VALUES(?,?,?,?)", (scope_id, operation_id, digest, _dump(response)))
            old_ids = {g["grant_id"] for g in old_body["grants"]}
            new_ids = {g["grant_id"] for g in body["grants"]}
            self._storage_budget(connection, scope_id, control=new_ids < old_ids)
        return 201, response

    def submit(self, scope_id, headers, payload):
        _fields(payload, {"submission"})
        record = payload["submission"]
        encoded = protocol.canonical_bytes(record, maximum=MAX_SUBMISSION)
        with self.app._transaction(immediate=True) as connection:
            _, current, pin, _, device = self._auth(connection, scope_id, headers, "create")
            _, raw_body = _unsigned_payload(record, maximum=MAX_SUBMISSION)
            old = connection.execute("SELECT record FROM kk3_policies WHERE scope_id=? AND hash=?",
                                     (scope_id, _digest(raw_body.get("policy_hash")))).fetchone()
            if old is None:
                _error(422, "unknown_policy")
            body = protocol.verify_create(record, _load(old[0]), pin, current_policy=current)
            if body["device_id"] != device:
                _error(403, "device_mismatch")
            request_id = _uuid(body["request_id"])
            digest = protocol.canonical_hash(record)
            retry = connection.execute("SELECT digest FROM kk3_submissions WHERE scope_id=? AND device_id=? AND request_id=?",
                                       (scope_id, device, request_id)).fetchone()
            if retry:
                if retry[0] != digest:
                    _error(409, "submission_conflict")
                return 200, {"request_id": request_id, "status": "uploaded"}
            count, size = connection.execute("SELECT COUNT(*),COALESCE(SUM(size),0) FROM kk3_submissions WHERE scope_id=? AND receipt IS NULL",
                                             (scope_id,)).fetchone()
            device_count = connection.execute("SELECT COUNT(*) FROM kk3_submissions WHERE scope_id=? AND device_id=? AND receipt IS NULL",
                                              (scope_id, device)).fetchone()[0]
            if count >= MAX_SCOPE_PENDING or device_count >= MAX_DEVICE_PENDING or size + len(encoded) > MAX_SCOPE_PENDING_BYTES:
                _error(429, "queue_full")
            now = int(self.app._clock())
            recent = connection.execute("SELECT COUNT(*) FROM kk3_submissions WHERE scope_id=? AND device_id=? AND created>?",
                                        (scope_id, device, now - 60)).fetchone()[0]
            if recent >= MAX_CREATES_PER_MINUTE:
                _error(429, "rate_limited")
            connection.execute("INSERT INTO kk3_submissions VALUES(?,?,?,?,?,?,?,?,?,NULL)",
                               (scope_id, device, body["grant_id"], request_id, digest, body["policy_hash"], encoded.decode(), len(encoded), now))
            self._storage_budget(connection, scope_id)
        return 201, {"request_id": request_id, "status": "uploaded"}

    def submissions(self, scope_id, headers, request_id):
        with self.app._transaction() as connection:
            _, _, _, body, device = self._auth(connection, scope_id, headers, "read")
            master = device == body["master_device_id"]
            if request_id:
                _uuid(request_id)
                # Master resolves individual records by device through the list;
                # a device's endpoint never reveals another device's request.
                row = connection.execute("SELECT request_id,receipt,digest FROM kk3_submissions WHERE scope_id=? AND device_id=? AND request_id=?",
                                         (scope_id, device, request_id)).fetchone()
                if row is None:
                    _error(404, "not_found")
                return {"request_id": row[0], "receipt": _load(row[1]), "submission_hash": row[2]}
            if not master:
                _error(403, "master_required")
            # Bounded page by both count and bytes. Receipted rows leave this queue.
            rows = connection.execute("SELECT record,policy_hash FROM kk3_submissions WHERE scope_id=? AND receipt IS NULL ORDER BY created,device_id,request_id LIMIT 25",
                                      (scope_id,)).fetchall()
            records = []
            total = 0
            for row in rows:
                if records and total + len(row[0]) > 8 * 1024 * 1024:
                    break
                records.append({"submission": _load(row[0]), "policy_hash": row[1]})
                total += len(row[0])
            return {"items": records}

    def acknowledge(self, scope_id, headers, request_id, payload):
        _uuid(request_id)
        _fields(payload, {"receipt"})
        with self.app._transaction(immediate=True) as connection:
            _, current_policy, pin, _, _ = self._auth(connection, scope_id, headers, "receipt")
            receipt, candidate = _unsigned_payload(payload["receipt"], maximum=16 * 1024)
            device = _uuid(candidate.get("device_id"))
            row = connection.execute("SELECT * FROM kk3_submissions WHERE scope_id=? AND device_id=? AND request_id=?",
                                     (scope_id, device, request_id)).fetchone()
            if row is None:
                _error(404, "not_found")
            policy = connection.execute("SELECT record FROM kk3_policies WHERE scope_id=? AND hash=?",
                                        (scope_id, row["policy_hash"])).fetchone()
            if policy is None:
                _error(409, "policy_history_missing")
            historical_policy = _load(policy[0])
            submission = _load(row["record"])
            checked = protocol.verify_receipt(receipt, submission, historical_policy, pin)
            encoded = _dump(receipt)
            if row["receipt"] is not None:
                previous = _load(row["receipt"])
                before = protocol.verify_receipt(previous, submission, historical_policy, pin)
                if row["receipt"] == encoded:
                    return {"request_id": request_id, "status": "recorded"}
                same_entry = checked["canonical_entry_id"] == before["canonical_entry_id"]
                if before["status"] == "published" and checked["status"] == "accepted" and same_entry and checked["revision"] <= before["revision"]:
                    return {"request_id": request_id, "status": "recorded"}
                if not (before["status"] == "accepted" and checked["status"] == "published" and same_entry and checked["revision"] >= before["revision"]):
                    _error(409, "receipt_conflict")
            elif checked["status"] in {"accepted", "published"}:
                # Unaccepted pending creates cannot regain permission through a
                # master endpoint after immediate revocation or role removal.
                protocol.verify_create(submission, historical_policy, pin, current_policy=current_policy)
                if connection.execute("SELECT 1 FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                      (scope_id, row["grant_id"])).fetchone():
                    _error(403, "grant_revoked")
            connection.execute("UPDATE kk3_submissions SET receipt=? WHERE scope_id=? AND device_id=? AND request_id=?",
                               (encoded, scope_id, device, request_id))
            self._storage_budget(connection, scope_id, control=True)
            return {"request_id": request_id, "status": "recorded"}

    def block(self, scope_id, headers, payload):
        _fields(payload, {"revocation"})
        with self.app._transaction(immediate=True) as connection:
            _, current_policy, pin, current_body, _ = self._auth(connection, scope_id, headers, "revoke")
            record, candidate = _unsigned_payload(payload["revocation"], maximum=16 * 1024)
            policy_hash = _digest(candidate.get("policy_hash"))
            historical = connection.execute("SELECT record FROM kk3_policies WHERE scope_id=? AND hash=?",
                                            (scope_id, policy_hash)).fetchone()
            if historical is None:
                _error(422, "unknown_policy")
            body = protocol.verify_revocation(record, _load(historical[0]), pin)
            encoded = _dump(record)
            prior = connection.execute("SELECT record FROM kk3_blocks WHERE scope_id=? AND grant_id=?",
                                       (scope_id, body["grant_id"])).fetchone()
            if prior:
                if prior[0] != encoded:
                    _error(409, "revocation_conflict")
            else:
                # First-time blocks target the currently active grant. Historical
                # signatures are accepted only for an exact durable retry.
                protocol.authorize_grant(current_body, body["device_id"], "read",
                                         grant_id=body["grant_id"], generation=body["generation"])
                connection.execute("INSERT INTO kk3_blocks VALUES(?,?,?)", (scope_id, body["grant_id"], encoded))
            self._storage_budget(connection, scope_id, control=True)
            still_current = any(g["grant_id"] == body["grant_id"] for g in current_body["grants"])
        return {"status": "blocked", "rekey": "pending" if still_current else "complete"}
