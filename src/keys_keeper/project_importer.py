"""Crash-recoverable, create-only imports from KK3 project contributors."""
from __future__ import annotations

import hashlib
from typing import Iterable
from uuid import UUID

from keys_keeper.backend import KeychainBackend, KeychainError
from keys_keeper.models import Entry, ValidationError, now_iso
from keys_keeper.operation_journal import JournalNotFound, OperationJournal, OperationRecord
from keys_keeper.project_models import CatalogState, ScopeEntry
from keys_keeper import project_protocol as protocol
from keys_keeper.refs import RefError, detect_cycles
from keys_keeper.store import MetadataStore, NameConflict


class ProjectImportError(RuntimeError):
    """Safe import failure; messages never include submitted metadata or values."""


class ImportStateError(ProjectImportError):
    pass


_DEDUP_FIELDS = {
    "scope_id",
    "device_id",
    "grant_id",
    "request_id",
    "submission_hash",
    "status",
    "canonical_entry_id",
    "revision",
    "receipt",
}


class ProjectImporter:
    """Import authenticated contributor creates into the master catalog.

    The profile lock serializes project importers. Metadata commits are atomic;
    backend writes precede them and the encrypted journal makes those bounded
    steps replayable. This does not claim transactional atomicity across an
    arbitrary OS keychain and the metadata file.
    """

    def __init__(
        self,
        store: MetadataStore,
        backend: KeychainBackend,
        journal: OperationJournal,
        *,
        signing_private_key: bytes,
        inbox_private_key: bytes,
        pinned_key: bytes,
    ):
        self.store = store
        self.backend = backend
        self.journal = journal
        self._signing_private_key = bytes(signing_private_key)
        self._inbox_private_key = bytes(inbox_private_key)
        self._pinned_key = bytes(pinned_key)

    def accept(
        self,
        submission: dict,
        source_policy: dict,
        *,
        current_policy: dict,
        revoked_grant_ids: Iterable[str] = (),
    ) -> dict:
        revoked = frozenset(revoked_grant_ids)
        with self.journal.locked():
            source = protocol.verify_create(submission, source_policy, self._pinned_key)
            key = _request_key(source)
            digest = protocol.canonical_hash(protocol.parse_record(submission))

            existing = self._lookup_dedup(key)
            if existing is not None:
                return self._dedup_retry(existing, digest, submission, source_policy)
            self._refuse_lost_ledger(key)

            operation_id = _deterministic_uuid("journal", key)
            try:
                pending = self.journal.read(operation_id)
            except JournalNotFound:
                pending = None
            if pending is not None:
                if pending.finished:
                    raise ImportStateError("completed import journal has no durable dedup record")
                if pending.kind != "project_import" or pending.state.get("submission_hash") != digest:
                    return self._signed_outcome(
                        submission, source_policy, status="conflict"
                    )
                return self._resume(
                    pending,
                    current_policy=current_policy,
                    revoked_grant_ids=revoked,
                )

            if source["grant_id"] in revoked:
                return self._persist_terminal(
                    submission,
                    source_policy,
                    source,
                    digest,
                    status="quarantined",
                )
            self._validate_current_policy(source_policy, current_policy)
            try:
                payload = protocol.open_create(
                    submission,
                    source_policy,
                    self._pinned_key,
                    self._inbox_private_key,
                    current_policy=current_policy,
                )
            except protocol.AuthorizationError:
                return self._persist_terminal(
                    submission,
                    source_policy,
                    source,
                    digest,
                    status="quarantined",
                )
            except (protocol.AuthenticationError, protocol.ValidationError):
                return self._persist_terminal(
                    submission,
                    source_policy,
                    source,
                    digest,
                    status="rejected",
                )

            try:
                plan = self._plan(payload, source, digest, submission, source_policy)
            except ValidationError:
                return self._persist_terminal(
                    submission,
                    source_policy,
                    source,
                    digest,
                    status="rejected",
                )
            except (RefError, NameConflict):
                return self._persist_terminal(
                    submission,
                    source_policy,
                    source,
                    digest,
                    status="conflict",
                )
            record = self.journal.begin(
                "project_import",
                operation_id=operation_id,
                state=plan,
            )
            return self._resume(
                record,
                current_policy=current_policy,
                revoked_grant_ids=revoked,
            )

    def recover(
        self,
        *,
        current_policy: dict,
        revoked_grant_ids: Iterable[str] = (),
    ) -> list[dict]:
        """Replay imports only against caller-supplied, freshly trusted policy."""
        current = protocol.verify_policy(current_policy, self._pinned_key)
        revoked = frozenset(revoked_grant_ids)
        receipts: list[dict] = []
        with self.journal.locked():
            for record in self.journal.list_unfinished():
                if record.kind != "project_import":
                    continue
                if record.state.get("scope_id") != current["scope_id"]:
                    continue
                receipts.append(
                    self._resume(
                        record,
                        current_policy=current_policy,
                        revoked_grant_ids=revoked,
                    )
                )
        return receipts

    def _resume(
        self,
        record: OperationRecord,
        *,
        current_policy: dict,
        revoked_grant_ids: frozenset[str],
    ) -> dict:
        state = dict(record.state)
        try:
            submission = state["submission"]
            source_policy = state["source_policy"]
            digest = state["submission_hash"]
            scope_id = state["scope_id"]
            source = protocol.verify_create(submission, source_policy, self._pinned_key)
        except (KeyError, TypeError, protocol.ProtocolError) as ex:
            self.journal.fail(record.operation_id, error_code="invalid_recovery_state")
            raise ImportStateError("project import journal state is invalid") from ex

        existing = self._lookup_dedup(_request_key(source))
        if existing is not None:
            receipt = self._dedup_retry(existing, digest, submission, source_policy)
            self.journal.finish(record.operation_id, result={"receipt": receipt})
            return receipt

        if source["grant_id"] in revoked_grant_ids:
            self._remove_owned_secrets(state)
            receipt = self._persist_terminal(
                submission,
                source_policy,
                source,
                digest,
                status="quarantined",
            )
            self.journal.finish(record.operation_id, result={"receipt": receipt})
            return receipt
        self._validate_current_policy(source_policy, current_policy)
        try:
            protocol.open_create(
                submission,
                source_policy,
                self._pinned_key,
                self._inbox_private_key,
                current_policy=current_policy,
            )
        except protocol.AuthorizationError:
            self._remove_owned_secrets(state)
            receipt = self._persist_terminal(
                submission,
                source_policy,
                source,
                digest,
                status="quarantined",
            )
            self.journal.finish(record.operation_id, result={"receipt": receipt})
            return receipt
        except (protocol.AuthenticationError, protocol.ValidationError):
            self._remove_owned_secrets(state)
            receipt = self._persist_terminal(
                submission,
                source_policy,
                source,
                digest,
                status="rejected",
            )
            self.journal.finish(record.operation_id, result={"receipt": receipt})
            return receipt

        entry = self._entry_from_state(state)
        writes = _secret_writes(entry.id, state.get("secret"), state.get("passphrase"))
        self._write_new_accounts(writes, allow_matching=True)
        self.journal.stage(record.operation_id, "backend_written")

        try:
            with self.store.transaction() as tx:
                catalog = CatalogState.from_dict(
                    tx.catalog_state(), entry_ids={item.id for item in tx.list()}
                )
                retry = _find_dedup(catalog, _request_key(source))
                if retry is not None:
                    receipt = self._dedup_retry(
                        retry, digest, submission, source_policy
                    )
                else:
                    _require_scope(catalog, scope_id, state["vault_id"])
                    if tx.get_by_id(entry.id) is not None:
                        raise ImportStateError("reserved import identity is already in use")
                    if tx.get_by_name(entry.name) is not None:
                        raise NameConflict("project import name collision")
                    tx.add(entry)
                    catalog.bindings.append(ScopeEntry.from_dict(state["binding"]))
                    catalog.dedup.append(dict(state["dedup"]))
                    catalog.publication_intents.append(dict(state["publication_intent"]))
                    tx.set_catalog_state(catalog.to_dict())
                    receipt = state["receipt"]
        except NameConflict:
            self._remove_owned_secrets(state)
            receipt = self._persist_terminal(
                submission,
                source_policy,
                source,
                digest,
                status="conflict",
            )
        self.journal.stage(record.operation_id, "metadata_committed")
        self.journal.finish(record.operation_id, result={"receipt": receipt})
        return receipt

    def _plan(
        self,
        payload: dict,
        source: dict,
        digest: str,
        submission: dict,
        source_policy: dict,
    ) -> dict:
        raw_uuid = _deterministic_uuid("entry", _request_key(source))
        entry_id = f"kk:{raw_uuid}"
        with self.store.transaction() as tx:
            catalog = CatalogState.from_dict(
                tx.catalog_state(), entry_ids={item.id for item in tx.list()}
            )
            _require_scope(catalog, source["scope_id"], source["vault_id"])
            if tx.get_by_id(entry_id) is not None:
                raise ImportStateError("reserved import identity is already in use")
            entry = _build_entry(payload, source, raw_uuid)
            if tx.get_by_name(entry.name) is not None:
                raise NameConflict("project import name collision")
            reserved_accounts = {entry.id, entry.id + ":passphrase"}
            if reserved_accounts & set(self.backend.list_ids()):
                raise ImportStateError("reserved import backend account is already in use")
            entry.refs = _resolve_scope_refs(entry.refs, catalog, tx, source["scope_id"])
            detect_cycles(tx.list() + [entry])
            revision = _next_import_revision(catalog)
            receipt = protocol.build_receipt(
                submission,
                source_policy,
                self._pinned_key,
                self._signing_private_key,
                status="accepted",
                canonical_entry_id=str(raw_uuid),
                revision=revision,
            )
            binding = ScopeEntry(
                scope_id=source["scope_id"],
                entry_id=entry.id,
                local_name=entry.name,
                export={
                    "fields": sorted(entry.fields),
                    "note": True,
                    "refs": True,
                    "tags": True,
                },
                approval_revision=digest,
            )
            binding = ScopeEntry.from_dict(binding.to_dict())
            dedup = _dedup_record(
                source, digest, status="accepted", raw_uuid=str(raw_uuid),
                revision=revision, receipt=receipt,
            )
            intent = {
                "scope_id": source["scope_id"],
                "entry_id": entry.id,
                "desired_revision": revision,
                "reason": "remote_create",
            }
        return {
            "scope_id": source["scope_id"],
            "vault_id": source["vault_id"],
            "submission_hash": digest,
            "submission": submission,
            "source_policy": source_policy,
            "entry": entry.to_dict(),
            "secret": payload["secret"],
            "passphrase": payload["passphrase"],
            "binding": binding.to_dict(),
            "dedup": dedup,
            "publication_intent": intent,
            "receipt": receipt,
        }

    def _persist_terminal(
        self,
        submission: dict,
        source_policy: dict,
        source: dict,
        digest: str,
        *,
        status: str,
    ) -> dict:
        receipt = self._signed_outcome(submission, source_policy, status=status)
        with self.store.transaction() as tx:
            catalog = CatalogState.from_dict(
                tx.catalog_state(), entry_ids={item.id for item in tx.list()}
            )
            _require_scope(catalog, source["scope_id"], source["vault_id"])
            existing = _find_dedup(catalog, _request_key(source))
            if existing is not None:
                return self._dedup_retry(existing, digest, submission, source_policy)
            catalog.dedup.append(
                _dedup_record(
                    source, digest, status=status, raw_uuid=None,
                    revision=0, receipt=receipt,
                )
            )
            tx.set_catalog_state(catalog.to_dict())
        return receipt

    def _lookup_dedup(self, key: tuple[str, str, str, str]) -> dict | None:
        catalog = CatalogState.from_dict(
            self.store.catalog_state(), entry_ids={item.id for item in self.store.list()}
        )
        return _find_dedup(catalog, key)

    def _validate_current_policy(self, source_policy: dict, current_policy: dict) -> None:
        source = protocol.verify_policy(source_policy, self._pinned_key)
        try:
            protocol.verify_policy(
                current_policy,
                self._pinned_key,
                expected_scope_id=source["scope_id"],
                expected_vault_id=source["vault_id"],
                minimum_version=source["version"],
                minimum_epoch=source["epoch"],
            )
        except protocol.ProtocolError as ex:
            raise ImportStateError("current policy is not a trusted descendant for this scope") from ex
        if protocol.agreement_public_key(self._inbox_private_key) != protocol.decode_key(
            source["inbox_public_key"]
        ):
            raise ImportStateError("master inbox identity does not match source policy")

    def _refuse_lost_ledger(self, key: tuple[str, str, str, str]) -> None:
        for entry in self.store.list():
            provenance = entry.provenance or {}
            if provenance.get("source") != "project_submission":
                continue
            if tuple(provenance.get(field) for field in key._fields) == tuple(key):
                raise ImportStateError("project import provenance has no durable dedup record")

    def _dedup_retry(
        self,
        record: dict,
        digest: str,
        submission: dict,
        source_policy: dict,
    ) -> dict:
        _validate_dedup(record)
        if record["submission_hash"] != digest:
            return self._signed_outcome(submission, source_policy, status="conflict")
        try:
            verified = protocol.verify_receipt(
                record["receipt"], submission, source_policy, self._pinned_key
            )
        except protocol.ProtocolError as ex:
            raise ImportStateError("project import dedup receipt is invalid") from ex
        if (
            verified["status"] != record["status"]
            or verified["canonical_entry_id"] != record["canonical_entry_id"]
            or verified["revision"] != record["revision"]
        ):
            raise ImportStateError("project import dedup receipt does not match its outcome")
        return dict(record["receipt"])

    def _signed_outcome(self, submission: dict, source_policy: dict, *, status: str) -> dict:
        return protocol.build_receipt(
            submission,
            source_policy,
            self._pinned_key,
            self._signing_private_key,
            status=status,
        )

    @staticmethod
    def _entry_from_state(state: dict) -> Entry:
        try:
            return Entry.from_untrusted_dict(state["entry"], allow_project_fields=True)
        except (KeyError, ValidationError) as ex:
            raise ImportStateError("project import journal entry is invalid") from ex

    def _write_new_accounts(self, writes: dict[str, str], *, allow_matching: bool) -> None:
        present = set(self.backend.list_ids())
        for account, value in writes.items():
            if account in present:
                if not allow_matching:
                    raise ImportStateError("reserved import backend account is already in use")
                try:
                    if self.backend.get(account).unseal() != value:
                        raise ImportStateError("recovery backend account does not match journal")
                except KeychainError as ex:
                    raise ImportStateError("cannot verify recovery backend account") from ex
                continue
            self.backend.set(account, value)
            present.add(account)

    def _remove_owned_secrets(self, state: dict) -> None:
        entry = self._entry_from_state(state)
        expected = _secret_writes(entry.id, state.get("secret"), state.get("passphrase"))
        present = set(self.backend.list_ids())
        for account, value in expected.items():
            if account not in present:
                continue
            try:
                if self.backend.get(account).unseal() == value:
                    self.backend.delete(account)
            except KeychainError as ex:
                raise ImportStateError("cannot clean staged import account") from ex


class _RequestKey(tuple):
    __slots__ = ()
    _fields = ("scope_id", "device_id", "grant_id", "request_id")

    def __new__(cls, values):
        return super().__new__(cls, values)


def _request_key(source: dict) -> _RequestKey:
    return _RequestKey(source[field] for field in _RequestKey._fields)


def _deterministic_uuid(domain: str, key: tuple[str, ...]) -> UUID:
    digest = bytearray(
        hashlib.sha256(
            ("keys-keeper/project-import/" + domain + "\0" + "\0".join(key)).encode()
        ).digest()[:16]
    )
    digest[6] = (digest[6] & 0x0F) | 0x40
    digest[8] = (digest[8] & 0x3F) | 0x80
    return UUID(bytes=bytes(digest))


def _build_entry(payload: dict, source: dict, raw_uuid: UUID) -> Entry:
    source_entry = payload["entry"]
    now = now_iso()
    record = {
        "id": f"kk:{raw_uuid}",
        "name": source_entry["name"],
        "type": source_entry["type"],
        "fields": source_entry["fields"],
        "tags": source_entry["tags"],
        "note": source_entry["note"],
        "refs": source_entry["refs"],
        "created_at": now,
        "updated_at": now,
        "folder_id": None,
        "distribution": "project_allowed",
        "provenance": {
            "source": "project_submission",
            "scope_id": source["scope_id"],
            "device_id": source["device_id"],
            "grant_id": source["grant_id"],
            "request_id": source["request_id"],
        },
        "content_revision": str(_deterministic_uuid("content", _request_key(source))),
    }
    return Entry.from_untrusted_dict(record, allow_project_fields=True)


def _resolve_scope_refs(refs, catalog: CatalogState, tx, scope_id: str) -> list[dict[str, str]]:
    resolved: list[dict[str, str]] = []
    for ref in refs:
        matches = [
            binding for binding in catalog.bindings
            if binding.scope_id == scope_id and binding.local_name == ref["name"]
        ]
        if len(matches) != 1:
            raise NameConflict("project import reference is missing or ambiguous")
        target = tx.get_by_id(matches[0].entry_id)
        if target is None:
            raise ImportStateError("project import reference target is missing")
        resolved.append({"role": ref["role"], "name": target.name})
    return resolved


def _require_scope(catalog: CatalogState, scope_id: str, vault_id: str) -> None:
    if not any(scope.id == scope_id and scope.vault_id == vault_id for scope in catalog.scopes):
        raise ImportStateError("project import scope is not configured locally")


def _find_dedup(catalog: CatalogState, key: tuple[str, str, str, str]) -> dict | None:
    found = []
    for record in catalog.dedup:
        if not isinstance(record, dict):
            raise ImportStateError("project import dedup ledger is invalid")
        if all(record.get(field) == value for field, value in zip(_RequestKey._fields, key)):
            found.append(record)
    if len(found) > 1:
        raise ImportStateError("project import dedup ledger contains duplicates")
    return found[0] if found else None


def _validate_dedup(record: dict) -> None:
    if set(record) != _DEDUP_FIELDS:
        raise ImportStateError("project import dedup record is invalid")
    if record["status"] not in {"accepted", "conflict", "rejected", "quarantined"}:
        raise ImportStateError("project import dedup record has invalid status")
    if not isinstance(record["receipt"], dict):
        raise ImportStateError("project import dedup receipt is invalid")


def _dedup_record(
    source: dict,
    digest: str,
    *,
    status: str,
    raw_uuid: str | None,
    revision: int,
    receipt: dict,
) -> dict:
    return {
        **{field: source[field] for field in _RequestKey._fields},
        "submission_hash": digest,
        "status": status,
        "canonical_entry_id": raw_uuid,
        "revision": revision,
        "receipt": receipt,
    }


def _next_import_revision(catalog: CatalogState) -> int:
    revisions = [0]
    for record in catalog.dedup:
        value = record.get("revision") if isinstance(record, dict) else None
        if type(value) is int and value >= 0:
            revisions.append(value)
    for intent in catalog.publication_intents:
        value = intent.get("desired_revision") if isinstance(intent, dict) else None
        if type(value) is int and value >= 0:
            revisions.append(value)
    return max(revisions) + 1


def _secret_writes(entry_id: str, secret: object, passphrase: object) -> dict[str, str]:
    writes: dict[str, str] = {}
    if secret is not None:
        if not isinstance(secret, str):
            raise ImportStateError("project import secret state is invalid")
        writes[entry_id] = secret
    if passphrase is not None:
        if not isinstance(passphrase, str):
            raise ImportStateError("project import passphrase state is invalid")
        writes[entry_id + ":passphrase"] = passphrase
    return writes
