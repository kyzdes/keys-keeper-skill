"""Single-master project publication and create-only replica synchronization.

Network work is serialized per profile. A prepared publication is saved before
HTTP and retried byte-for-byte after a lost response, including its new epoch key.
"""
from __future__ import annotations

import copy
import hashlib
import secrets
from typing import Callable
from keys_keeper.models import now_iso
from uuid import uuid4

from keys_keeper import project_protocol as protocol
from keys_keeper.operation_journal import OperationJournal, JournalNotFound
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_projection import build_project_payload, preview_scope
from keys_keeper.project_service import ProjectService


class ProjectSyncError(RuntimeError):
    pass


_STATE_ID = "7b44536c-2f0c-4d8d-a0ec-5747b5cec041"
MAX_HISTORY = 256
MAX_HISTORY_BYTES = 64 * 1024 * 1024


class ProjectState:
    """Encrypted local state; private keys never live in plain metadata JSON."""

    def __init__(self, paths, password_provider):
        self.paths = paths
        self.journal = OperationJournal(paths=paths, password_provider=password_provider)
        from keys_keeper.paths import Paths
        self._jobs = OperationJournal(paths=Paths(paths.root / "sync-job"), password_provider=password_provider)

    def load(self) -> dict:
        try:
            return copy.deepcopy(dict(self.journal.read(_STATE_ID).state))
        except JournalNotFound:
            raise ProjectSyncError("project profile is not configured") from None

    def exists(self) -> bool:
        try:
            self.journal.read(_STATE_ID)
            return True
        except JournalNotFound:
            return False

    def save(self, state: dict) -> None:
        if self.exists():
            self.journal.stage(_STATE_ID, "configured", state=state)
        else:
            self.journal.begin("project-state", operation_id=_STATE_ID, state=state)

    def locked(self):
        return self.journal.locked()

    def job_locked(self):
        """Serialize network jobs without blocking local revoke/outbox mutations."""
        return self._jobs.locked()


def _decode(state: dict, name: str) -> bytes:
    return protocol.decode_key(state[name])


def _client(state: dict) -> ProjectClient:
    from keys_keeper.backend import Sealed
    return ProjectClient(base_url=state["endpoint"], token=Sealed(state["token"]), device_id=state["device_id"])


def _policy_body(state: dict) -> dict:
    return protocol.verify_policy(state["policy"], _decode(state, "pin"),
                                  expected_scope_id=state["scope_id"], expected_vault_id=state["vault_id"])


def new_master_state(scope_id: str, vault_id: str, endpoint: str) -> dict:
    signing = protocol.generate_key()
    pin = protocol.signing_public_key(signing)
    inbox = protocol.generate_key()
    token = secrets.token_urlsafe(48)
    device = str(uuid4())
    policy = protocol.sign_policy({
        "scope_id": scope_id, "vault_id": vault_id, "version": 1, "epoch": 1,
        "master_public_key": protocol.encode_key(pin), "master_device_id": device,
        "master_token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "inbox_public_key": protocol.encode_key(protocol.agreement_public_key(inbox)),
        "grants": [], "checkpoint_sequence": 0, "checkpoint_hash": None,
        "parent_policy_hash": None,
    }, signing)
    # Validate transport before any state is committed.
    ProjectClient(base_url=endpoint)
    return {"mode": "master", "scope_id": scope_id, "vault_id": vault_id,
            "endpoint": endpoint, "device_id": device, "token": token,
            "pin": protocol.encode_key(pin), "signing_private": protocol.encode_key(signing),
            "inbox_private": protocol.encode_key(inbox), "scope_key": protocol.encode_key(protocol.generate_key()),
            "policy": policy, "checkpoint": None, "trusted_checkpoint": None, "applied_checkpoint": None, "pending": None,
            "local_revocations": [],
            "source_revision": None, "published_ids": [], "used_grants": [], "invites": []}


def _record_policy_hash(record: object) -> str:
    if type(record) is not dict or type(record.get("payload")) is not dict:
        raise ProjectSyncError("invalid signed project record")
    digest = record["payload"].get("policy_hash")
    if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ProjectSyncError("invalid signed project policy hash")
    return digest


def _verified_remote(client: ProjectClient, state: dict) -> tuple[dict, dict, dict]:
    """Verify policy ancestry and snapshot continuity from locally pinned state."""
    remaining = MAX_HISTORY_BYTES
    def account(value):
        nonlocal remaining
        remaining -= len(protocol.canonical_bytes(value))
        if remaining < 0:
            raise ProjectSyncError("trusted checkpoint refresh is required; history byte budget exceeded")
        return value
    result = account(client.state(state["scope_id"]))
    if not isinstance(result, dict) or set(result) != {"policy", "snapshot", "wrap", "head_hash", "sequence", "revocations"}:
        raise ProjectSyncError("invalid project state response")
    pin = _decode(state, "pin")
    known = state["policy"]
    known_body = _policy_body(state)
    latest = protocol.verify_policy(result["policy"], pin, expected_scope_id=state["scope_id"],
                                    expected_vault_id=state["vault_id"], minimum_version=known_body["version"],
                                    minimum_epoch=known_body["epoch"])
    policies = {protocol.canonical_hash(known): known}
    reverse = []
    cursor = result["policy"]
    for _ in range(MAX_HISTORY):
        digest = protocol.canonical_hash(cursor)
        policies[digest] = cursor
        if digest == protocol.canonical_hash(known):
            break
        body = protocol.verify_policy(cursor, pin, expected_scope_id=state["scope_id"],
                                      minimum_version=known_body["version"])
        if body["version"] <= known_body["version"]:
            raise ProjectSyncError("project policy fork detected")
        reverse.append(cursor)
        cursor = account(client.policy(state["scope_id"], body["parent_policy_hash"])["record"])
        if protocol.canonical_hash(cursor) != body["parent_policy_hash"]:
            raise ProjectSyncError("project policy hash mismatch")
    else:
        raise ProjectSyncError("trusted checkpoint refresh is required")
    prior = known
    used = {g["grant_id"]: g for g in state.get("used_grants", [])}
    for grant in known_body["grants"]:
        if grant["grant_id"] in used and used[grant["grant_id"]] != grant:
            raise ProjectSyncError("known project grant conflicts with durable history")
        used[grant["grant_id"]] = grant
    for record in reversed(reverse):
        previous = protocol.verify_policy(prior, pin)
        body = protocol.validate_policy_transition(prior, record, pin)
        active_before = {g["grant_id"] for g in previous["grants"]}
        for grant in body["grants"]:
            if grant["grant_id"] in used and grant["grant_id"] not in active_before:
                raise ProjectSyncError("retired project grant was reused")
            if grant["grant_id"] in used and used[grant["grant_id"]] != grant:
                raise ProjectSyncError("project grant identity changed")
            older = [g["generation"] for g in used.values() if g["device_id"] == grant["device_id"]]
            if grant["grant_id"] not in used and older and grant["generation"] <= max(older):
                raise ProjectSyncError("project grant generation regressed")
            used[grant["grant_id"]] = grant
        prior = record

    def fetch_policy(digest):
        if digest not in policies:
            record = account(client.policy(state["scope_id"], digest)["record"])
            if protocol.canonical_hash(record) != digest:
                raise ProjectSyncError("project policy hash mismatch")
            protocol.verify_policy(record, pin, expected_scope_id=state["scope_id"], expected_vault_id=state["vault_id"])
            policies[digest] = record
        return policies[digest]

    revocations = result["revocations"]
    if not isinstance(revocations, list) or len(revocations) > protocol.MAX_GRANTS:
        raise ProjectSyncError("invalid project revocations")
    blocked = list(_local_blocked(state))
    verified_blocks = list(state.get("local_revocations", []))
    for revocation in revocations:
        source = fetch_policy(_record_policy_hash(revocation))
        block = protocol.verify_revocation(revocation, source, pin)
        blocked.append(block["grant_id"])
        if block["grant_id"] not in {r["record"]["payload"]["grant_id"] for r in verified_blocks}:
            verified_blocks.append({"record": revocation, "policy": source})

    anchor = state.get("trusted_checkpoint") or state.get("checkpoint")
    minimum_sequence = 0 if anchor is None else anchor["sequence"]
    trusted_hash = None if anchor is None else anchor["snapshot_hash"]
    snapshot = result["snapshot"]
    if snapshot is None:
        if minimum_sequence or result["head_hash"] is not None or result["sequence"] != 0:
            raise ProjectSyncError("project snapshot disappeared")
    else:
        if protocol.canonical_hash(snapshot) != result["head_hash"]:
            raise ProjectSyncError("project snapshot hash mismatch")
        cursor = snapshot
        expected_sequence = result["sequence"]
        if type(expected_sequence) is not int or expected_sequence < minimum_sequence:
            raise ProjectSyncError("project snapshot rollback")
        for _ in range(MAX_HISTORY):
            digest = protocol.canonical_hash(cursor)
            if digest == trusted_hash:
                break
            if expected_sequence <= minimum_sequence:
                raise ProjectSyncError("project snapshot fork")
            source = fetch_policy(_record_policy_hash(cursor))
            checked = protocol.verify_snapshot(cursor, source, pin)
            if checked["sequence"] != expected_sequence:
                raise ProjectSyncError("project snapshot sequence gap")
            if trusted_hash is None and checked["sequence"] == 1:
                break
            parent = checked["parent_hash"]
            if parent == trusted_hash and checked["sequence"] == minimum_sequence + 1:
                break
            cursor = account(client.snapshot(state["scope_id"], parent)["record"])
            if protocol.canonical_hash(cursor) != parent:
                raise ProjectSyncError("project parent hash mismatch")
            expected_sequence -= 1
        else:
            raise ProjectSyncError("trusted checkpoint refresh is required")
        # The HEAD must use the current policy/epoch, even when its history is valid.
        head = protocol.verify_snapshot(snapshot, result["policy"], pin)
        if head["sequence"] != result["sequence"]:
            raise ProjectSyncError("project HEAD sequence mismatch")
    return result, latest, {"policies": policies, "blocked": blocked, "used_grants": list(used.values()), "local_revocations": verified_blocks}


def _checkpoint(snapshot: dict) -> dict:
    body = snapshot["payload"]
    return {k: body[k] for k in ("scope_id", "vault_id", "epoch", "policy_version", "policy_hash", "sequence", "parent_hash")} | {
        "snapshot_hash": protocol.canonical_hash(snapshot)}


def _local_blocked(state: dict) -> set[str]:
    blocked = set()
    for item in state.get("local_revocations", []):
        try:
            source = protocol.verify_policy(item["policy"], _decode(state, "pin"),
                                            expected_scope_id=state["scope_id"], expected_vault_id=state["vault_id"])
            record = protocol.verify_revocation(item["record"], item["policy"], _decode(state, "pin"))
        except (KeyError, TypeError, protocol.ProtocolError):
            raise ProjectSyncError("invalid durable local revocation") from None
        blocked.add(record["grant_id"])
    return blocked


def _merge_trust(current: dict, trust: dict) -> None:
    used = {g["grant_id"]: g for g in current.get("used_grants", [])}
    used.update({g["grant_id"]: g for g in trust["used_grants"]})
    current["used_grants"] = list(used.values())
    blocked = {r["record"]["payload"]["grant_id"]: r for r in current.get("local_revocations", [])}
    for record in trust.get("local_revocations", []):
        blocked.setdefault(record["record"]["payload"]["grant_id"], record)
    current["local_revocations"] = list(blocked.values())


def _remember_trust(state: ProjectState, trust: dict) -> None:
    """Keep authenticated revocations even if the subsequent local operation fails."""
    with state.locked():
        current = state.load()
        _merge_trust(current, trust)
        state.save(current)


class ProjectMaster:
    def __init__(self, state: ProjectState, store, backend, *, client=None):
        self.state, self.store, self.backend = state, store, backend
        self._client_override = client

    def client(self, data):
        return self._client_override or _client(data)

    def _adopt_pending(self, pending: dict) -> dict:
        with self.state.locked():
            current = self.state.load()
            if (current.get("pending") or {}).get("request", {}).get("operation_id") != pending["request"]["operation_id"]:
                raise ProjectSyncError("prepared publication changed concurrently")
            snapshot = pending["request"]["snapshot"]
            checkpoint = _checkpoint(snapshot)
            current.update(policy=pending["request"]["policy"], scope_key=pending["scope_key"],
                           checkpoint=checkpoint, trusted_checkpoint=checkpoint, applied_checkpoint=checkpoint,
                           source_revision=pending["source_revision"], published_ids=pending["published_ids"], pending=None)
            history = {g["grant_id"]: g for g in current.get("used_grants", [])}
            history.update({g["grant_id"]: g for g in current["policy"]["payload"]["grants"]})
            current["used_grants"] = list(history.values())
            # Mark only revisions captured with preparation. Keep the encrypted
            # pending operation until this idempotent metadata commit succeeds.
            ProjectService(self.store).mark_publications_applied(current["scope_id"], pending.get("publication_revisions", {}))
            self.state.save(current)
            return current

    def _resume(self, data: dict | None = None) -> dict:
        # Caller holds the independent job lock. Never hold state during HTTP.
        with self.state.locked():
            data = self.state.load()
            pending = data.get("pending")
            if pending is None:
                return data
            blocked = _local_blocked(data)
            stale = any(g["grant_id"] in blocked for g in pending["request"]["policy"]["payload"]["grants"])
            if stale and not pending.get("attempted", True):
                data["pending"] = None
                self.state.save(data)
                return data
            if not stale:
                # This durable dispatch marker defines the in-flight boundary.
                # A later revoke cannot unsend an already authorized HTTP call.
                pending["attempted"] = True
                self.state.save(data)
        if stale:
            # Read-only reconciliation; never re-send ciphertext/wraps for a
            # locally revoked grant, even when relay claims the write was lost.
            remote, _, _ = _verified_remote(self.client(data), data)
            if remote["head_hash"] != protocol.canonical_hash(pending["request"]["snapshot"]):
                raise ProjectSyncError("revoked publication outcome is uncertain; recovery required")
            return self._adopt_pending(pending)
        response = self.client(data).publish(data["scope_id"], **pending["request"])
        snapshot = pending["request"]["snapshot"]
        if response.get("head_hash") != protocol.canonical_hash(snapshot) or response.get("sequence") != snapshot["payload"]["sequence"]:
            raise ProjectSyncError("publication acknowledgement mismatch")
        return self._adopt_pending(pending)

    def publish(self, *, grants: list[dict] | None = None, force: bool = False) -> dict:
        with self.state.job_locked():
            return self._publish_locked(grants=grants, force=force)

    def add_grant(self, grant: dict) -> dict:
        """Add one grant against the latest committed policy under the job lock.

        Enrollment callers must not read/replace the entire membership list.
        Immediate local revoke remains independent of this network job lock.
        """
        with self.state.job_locked():
            data = self._resume()
            blocked = _local_blocked(data)
            if not isinstance(grant, dict) or grant.get("grant_id") in blocked:
                raise ProjectSyncError("active project grant required")
            grants = [g for g in data["policy"]["payload"]["grants"] if g["grant_id"] not in blocked]
            matching = [g for g in grants if g["device_id"] == grant.get("device_id") or g["grant_id"] == grant.get("grant_id")]
            if matching and matching != [grant]:
                raise ProjectSyncError("device grant already exists with different identity")
            if not matching:
                grants.append(grant)
            return self._publish_locked(grants=grants)

    def _publish_locked(self, *, grants: list[dict] | None = None, force: bool = False) -> dict:
        data = self._resume()
        if data.get("mode") != "master":
            raise ProjectSyncError("master profile required")
        remote, old, trust = _verified_remote(self.client(data), data)
        _remember_trust(self.state, trust)
        anchor = data.get("checkpoint")
        if remote["head_hash"] != (None if anchor is None else anchor["snapshot_hash"]):
            raise ProjectSyncError("master recovery is required before publishing")
        catalog = ProjectService(self.store)
        # Capture first: anything newer remains desired after this delivery.
        captured = catalog.capture_publications(data["scope_id"])
        preview = preview_scope(self.store, data["scope_id"])
        with self.state.locked():
            current = self.state.load()
            if current["policy"] != data["policy"] or current.get("checkpoint") != anchor:
                raise ProjectSyncError("project state changed during publication preview")
            blocked = _local_blocked(current)
            preview_grants = [g for g in old["grants"] if g["grant_id"] not in blocked] if grants is None else grants
            if any(g["grant_id"] in blocked for g in preview_grants):
                raise ProjectSyncError("revoked grant requires rekey before publication")
            if not force and preview_grants == old["grants"] and preview["source_revision"] == current["source_revision"]:
                catalog.mark_publications_applied(data["scope_id"], captured)
                return {"status": "unchanged", "sequence": remote["sequence"]}
        # Revalidate the metadata-only preview under the actual local
        # metadata/secret mutation boundary; never hold it across HTTP.
        payload = build_project_payload(self.store, self.backend, data["scope_id"], expected_revision=preview["source_revision"])
        with self.state.locked():
            current = self.state.load()
            if current["policy"] != data["policy"] or current.get("checkpoint") != anchor:
                raise ProjectSyncError("project state changed during publication preparation")
            _merge_trust(current, trust)
            blocked = _local_blocked(current)
            target_grants = [g for g in old["grants"] if g["grant_id"] not in blocked] if grants is None else grants
            if any(g["grant_id"] in blocked for g in target_grants):
                raise ProjectSyncError("revoked grant requires rekey before publication")
            ids = [r["id"] for r in payload["entries"]]
            changed_members = target_grants != old["grants"]
            rotate = (changed_members or (anchor is not None and ids != current["published_ids"])
                      or remote["sequence"] - old["checkpoint_sequence"] >= protocol.MAX_EPOCH_PUBLICATIONS)
            target_policy = remote["policy"]
            key = _decode(current, "scope_key")
            if rotate:
                key = protocol.generate_key()
                target = {**old, "version": old["version"] + 1, "epoch": old["epoch"] + 1,
                          "grants": target_grants, "checkpoint_sequence": remote["sequence"],
                          "checkpoint_hash": remote["head_hash"], "parent_policy_hash": protocol.canonical_hash(remote["policy"])}
                target_policy = protocol.sign_policy(target, _decode(current, "signing_private"))
            pin = _decode(current, "pin")
            snapshot = protocol.build_snapshot(payload, target_policy, pin, _decode(current, "signing_private"), key,
                                               sequence=remote["sequence"] + 1, parent_hash=remote["head_hash"])
            wraps = [protocol.wrap_scope_key(key, target_policy, pin, _decode(current, "signing_private"), g["device_id"]) for g in target_grants]
            current["pending"] = {"request": {"operation_id": str(uuid4()), "expected_head_hash": remote["head_hash"],
                "policy": target_policy, "snapshot": snapshot, "wraps": wraps}, "scope_key": protocol.encode_key(key),
                "source_revision": payload["source_revision"], "published_ids": ids, "attempted": False, "publication_revisions": captured}
            self.state.save(current)
        current = self._resume()
        return {"status": "published", "sequence": current["checkpoint"]["sequence"], "count": len(ids)}

    def request_revoke(self, device_id: str) -> dict:
        """Persist the local permission barrier before network, jobs or resume."""
        with self.state.locked():
            data = self.state.load()
            if data.get("mode") != "master":
                raise ProjectSyncError("master profile required")
            policies = [data["policy"]]
            if data.get("pending"):
                policies.append(data["pending"]["request"]["policy"])
            blocks = {r["record"]["payload"]["grant_id"]: r for r in data.get("local_revocations", [])}
            found = False
            for policy in policies:
                body = protocol.verify_policy(policy, _decode(data, "pin"))
                for grant in body["grants"]:
                    if grant["device_id"] == device_id:
                        found = True
                        if grant["grant_id"] not in blocks:
                            record = protocol.build_revocation(policy, _decode(data, "pin"), _decode(data, "signing_private"), device_id=device_id)
                            blocks[grant["grant_id"]] = {"record": record, "policy": policy}
            data["local_revocations"] = list(blocks.values())
            self.state.save(data)
            return {"status": "blocked" if found else "revoked", "rekey": "pending" if found else "complete"}

    def revoke(self, device_id: str) -> dict:
        result = self.request_revoke(device_id)
        if result["rekey"] == "complete":
            return {"status": "revoked"}
        data = self.state.load()
        # Relay failure never removes the local barrier. A caller may retry or
        # allow the next publish job to rotate using the durable local intent.
        for item in data.get("local_revocations", []):
            if item["record"]["payload"]["device_id"] == device_id:
                self.client(data).block(data["scope_id"], item["record"])
        result = self.publish(force=True)
        return {**result, "status": "revoked"}

    def receive(self, *, maximum: int = 100) -> dict:
        from keys_keeper.project_importer import ProjectImporter
        from keys_keeper.paths import Paths
        with self.state.job_locked():
            data = self._resume()
            remote, _, trust = _verified_remote(self.client(data), data)
            _remember_trust(self.state, trust)
            if remote["head_hash"] != (data.get("checkpoint") or {}).get("snapshot_hash"):
                raise ProjectSyncError("master recovery is required before importing")
            journal = OperationJournal(paths=Paths(self.state.paths.root / "imports"), password_provider=lambda: _decode(data, "inbox_private"))
            importer = ProjectImporter(self.store, self.backend, journal, signing_private_key=_decode(data, "signing_private"),
                                       inbox_private_key=_decode(data, "inbox_private"), pinned_key=_decode(data, "pin"))
            with self.state.locked():
                current = self.state.load()
                _merge_trust(current, trust)
                self.state.save(current)
                recovered = importer.recover(current_policy=remote["policy"], revoked_grant_ids=_local_blocked(current))
            # Recovery always precedes fetching new submissions. Only local
            # mutation holds state; receipt delivery is outside both local locks.
            for receipt in recovered:
                self.client(data).acknowledge(data["scope_id"], receipt["payload"]["request_id"], receipt)
            count, statuses = 0, {}
            while count < maximum:
                response = self.client(data).pending(data["scope_id"])
                items = response.get("items")
                if not isinstance(items, list) or len(items) > 25:
                    raise ProjectSyncError("invalid inbox response")
                if not items:
                    break
                for item in items[:maximum - count]:
                    source = self.client(data).policy(data["scope_id"], item["policy_hash"])["record"]
                    if protocol.canonical_hash(source) != item["policy_hash"]:
                        raise ProjectSyncError("inbox policy hash mismatch")
                    with self.state.locked():
                        current = self.state.load()
                        receipt = importer.accept(item["submission"], source, current_policy=remote["policy"], revoked_grant_ids=_local_blocked(current))
                    request_id = item["submission"]["payload"]["request_id"]
                    self.client(data).acknowledge(data["scope_id"], request_id, receipt)
                    status = receipt["payload"]["status"]
                    statuses[status] = statuses.get(status, 0) + 1
                    count += 1
            return {"processed": count, "outcomes": statuses}


class ProjectReplica:
    def __init__(self, state: ProjectState, replica_store, *, client=None):
        self.state, self.replica_store = state, replica_store
        self._client_override = client

    def client(self, data):
        return self._client_override or _client(data)

    def pull(self) -> dict:
        with self.state.job_locked():
            data = self.state.load()
            if data.get("mode") != "replica":
                raise ProjectSyncError("replica profile required")
            remote, policy, trust = _verified_remote(self.client(data), data)
            _remember_trust(self.state, trust)
            grant = protocol.authorize_grant(policy, data["device_id"], "read")
            if grant["grant_id"] in trust["blocked"]:
                raise ProjectSyncError("project grant revoked")
            if remote["snapshot"] is None:
                raise ProjectSyncError("project has no published snapshot")
            checkpoint = _checkpoint(remote["snapshot"])
            applied = data.get("applied_checkpoint", data.get("checkpoint"))
            if applied == checkpoint:
                # Confirm the generation exists; onboarding trust alone is not installation.
                _, installed = self.replica_store.load()
                if installed != checkpoint:
                    raise ProjectSyncError("applied generation checkpoint mismatch")
                return {"status": "unchanged", "sequence": checkpoint["sequence"]}
            key = protocol.unwrap_scope_key(remote["wrap"], remote["policy"], _decode(data, "pin"), data["device_id"], _decode(data, "agreement_private"))
            payload = protocol.open_snapshot(remote["snapshot"], remote["policy"], _decode(data, "pin"), key)
            with self.state.locked():
                current = self.state.load()
                if grant["grant_id"] in _local_blocked(current):
                    raise ProjectSyncError("project grant revoked")
                if current.get("applied_checkpoint", current.get("checkpoint")) != applied:
                    raise ProjectSyncError("replica installation changed during pull")
                if applied is not None and (data.get("trusted_checkpoint") or data.get("checkpoint")) != applied:
                    raise ProjectSyncError("replica checkpoint recovery is required")
                self.replica_store.install(payload, checkpoint, verified_ancestor=applied)
                _merge_trust(current, trust)
                current.update(policy=remote["policy"], checkpoint=checkpoint, applied_checkpoint=checkpoint, trusted_checkpoint=checkpoint)
                self.state.save(current)
            return {"status": "applied", "sequence": checkpoint["sequence"], "count": len(payload["entries"])}

    def create(self, payload: dict) -> dict:
        from keys_keeper.project_replica import NoReplicaGeneration
        with self.state.locked():
            data = self.state.load()
            policy = _policy_body(data)
            grant = protocol.authorize_grant(policy, data["device_id"], "create")
            if grant["grant_id"] in _local_blocked(data):
                raise ProjectSyncError("project grant revoked")
            payload = protocol.validate_create_payload(payload)
            try:
                if self.replica_store.metadata_store().get_by_name(payload["entry"]["name"]) is not None:
                    raise ProjectSyncError("entry name already exists")
            except NoReplicaGeneration:
                raise ProjectSyncError("install the enrolled project snapshot before creating entries") from None
            for item in data.get("outbox", []):
                if item["payload"]["entry"]["name"] == payload["entry"]["name"]:
                    raise ProjectSyncError("pending entry name already exists")
            request_id = str(uuid4())
            record = protocol.build_create(payload, data["policy"], _decode(data, "pin"), data["device_id"], _decode(data, "signing_private"), request_id=request_id)
            data.setdefault("outbox", []).append({"request_id": request_id, "submission": record, "source_policy": data["policy"],
                "payload": payload, "status": "local_pending", "receipt": None, "created_at": now_iso()})
            self.state.save(data)
            return {"request_id": request_id, "status": "local_pending"}

    def submit(self) -> dict:
        with self.state.job_locked():
            data = self.state.load()
            count = 0
            for original in data.get("outbox", []):
                if original["status"] in {"published", "conflict", "rejected", "quarantined"}:
                    continue
                with self.state.locked():
                    current = self.state.load()
                    grant = protocol.authorize_grant(_policy_body(current), current["device_id"], "create")
                    if grant["grant_id"] in _local_blocked(current):
                        raise ProjectSyncError("project grant revoked")
                    protocol.verify_create(original["submission"], original["source_policy"], _decode(current, "pin"),
                                           current_policy=current["policy"])
                item = copy.deepcopy(original)
                if item["status"] == "local_pending":
                    self.client(data).submit(data["scope_id"], item["submission"])
                    item["status"] = "uploaded"
                    self._save_outbox_item(item)
                result = self.client(data).submission(data["scope_id"], item["request_id"])
                if result.get("submission_hash") != protocol.canonical_hash(item["submission"]):
                    raise ProjectSyncError("submission acknowledgement mismatch")
                receipt = result.get("receipt")
                if receipt is not None:
                    checked = protocol.verify_receipt(receipt, item["submission"], item["source_policy"], _decode(data, "pin"))
                    if item.get("receipt") is not None:
                        prior = protocol.verify_receipt(item["receipt"], item["submission"], item["source_policy"], _decode(data, "pin"))
                        if checked["revision"] < prior["revision"] or (prior["canonical_entry_id"] and checked["canonical_entry_id"] != prior["canonical_entry_id"]):
                            raise ProjectSyncError("receipt regressed")
                    item["receipt"], item["status"] = receipt, checked["status"]
                    if checked["status"] in {"accepted", "published"} and self.replica_store.metadata_store().get_by_id("kk:" + checked["canonical_entry_id"]) is not None:
                        item["status"] = "published"
                self._save_outbox_item(item)
                count += 1
            latest = self.state.load()
            return {"processed": count, "pending": sum(i["status"] not in {"published", "conflict", "rejected", "quarantined"} for i in latest.get("outbox", []))}

    def _save_outbox_item(self, item: dict) -> None:
        with self.state.locked():
            current = self.state.load()
            for index, existing in enumerate(current.get("outbox", [])):
                if existing["request_id"] == item["request_id"]:
                    if existing["submission"] != item["submission"]:
                        raise ProjectSyncError("outbox submission changed")
                    current["outbox"][index] = item
                    self.state.save(current)
                    return
            raise ProjectSyncError("outbox submission disappeared")
