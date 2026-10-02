"""One durable mutation pipeline for standalone and project master vaults.

The OS credential backends are not transactional.  This module therefore
records encrypted before/after images before touching a secret account and
recovers a bounded mutation by completing it forward.  Existing accounts are
updated in place through ``set(account, value)``; successful updates never
delete and recreate an item, preserving native item identity and ACL semantics.
"""
from __future__ import annotations

import base64
import copy
import re
import secrets as random_secrets
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from typing import TYPE_CHECKING

from keys_keeper.backend import KeychainBackend
from keys_keeper.models import (Entry, ValidationError, entry_requires_secret,
                               validate_entry_id, validate_name, validate_tombstone)
from keys_keeper.operation_journal import (
    JournalNotFound,
    OperationJournal,
    OperationRecord,
    _read_pending_index,
    pending_operation_refs,
    profile_lock,
)
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore, NameConflict, NotFound, StoreError

if TYPE_CHECKING:
    from keys_keeper.service import DeleteResult, SecretInput


MASTER_MUTATION_KIND = "master_mutation"
MASTER_UNLOCK_ACCOUNT = "kk:project-runtime-key"
_STATE_SCHEMA = 1


class MasterMutationRequired(RuntimeError):
    """A schema-v3 writer was composed without its durable manager."""


class MasterRecoveryRequired(RuntimeError):
    """A pending master mutation cannot be safely completed automatically."""


def master_unlock_material(paths: Paths, backend: KeychainBackend, *, create=False) -> str:
    """One reserved authority key for standalone and project mutations."""
    with profile_lock(Paths(paths.root / "registry-lock")):
        if MASTER_UNLOCK_ACCOUNT not in backend.list_ids():
            if not create:
                raise MasterRecoveryRequired("master project runtime is not initialized")
            backend.set(MASTER_UNLOCK_ACCOUNT, base64.urlsafe_b64encode(
                random_secrets.token_bytes(32)).rstrip(b"=").decode("ascii"))
        raw = backend.get(MASTER_UNLOCK_ACCOUNT).unseal()
        try:
            if not isinstance(raw, str) or len(raw) != 43:
                raise ValueError("invalid material")
            decoded = base64.b64decode(raw + "=", altchars=b"-_", validate=True)
            if (len(decoded) != 32
                    or base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != raw):
                raise ValueError("invalid material")
        except (ValueError, UnicodeError):
            raise MasterRecoveryRequired("master unlock material is invalid") from None
        return raw


def compose_master_mutations(store: MetadataStore, backend: KeychainBackend):
    journal = OperationJournal(paths=store.paths, password_provider=lambda:
        master_unlock_material(store.paths, backend, create=True))
    return MasterMutationManager(store, backend, journal)


def assert_no_pending(paths: Paths) -> None:
    """Fail before projection when a master mutation is not terminal.

    This reads only the metadata-only pending index.  It neither needs the
    journal key nor exposes operation state or secret values.
    """
    pending = pending_operation_refs(paths, kind=MASTER_MUTATION_KIND)
    if pending:
        raise MasterRecoveryRequired(
            f"master recovery required for {len(pending)} pending mutation(s)"
        )


@contextmanager
def projection_guard(paths: Paths):
    """Hold the profile mutation boundary for a complete project projection."""
    with profile_lock(paths):
        pending = [
            item for item in _read_pending_index(paths)
            if item["kind"] == MASTER_MUTATION_KIND
        ]
        if pending:
            raise MasterRecoveryRequired(
                f"master recovery required for {len(pending)} pending mutation(s)"
            )
        yield


class MasterMutationManager:
    """Coordinate journal, backend and metadata for ordinary master writes."""

    def __init__(
        self,
        store: MetadataStore,
        backend: KeychainBackend,
        journal: OperationJournal,
    ):
        if store.paths.root != journal.paths.root:
            raise ValueError("master store and mutation journal must share one profile root")
        self.store = store
        self.backend = backend
        self.journal = journal

    @property
    def has_pending(self) -> bool:
        return bool(self.journal.pending_refs(kind=MASTER_MUTATION_KIND))

    def assert_projection_ready(self) -> None:
        assert_no_pending(self.journal.paths)

    def _transact(self, prepare):
        """One journal/metadata/backend pipeline for every mutation shape."""
        with self.journal.locked():
            record = None
            try:
                with self.store.transaction() as tx:
                    state, result = prepare(tx)
                    state = _validate_state(state)
                    _validate_required_secrets(state, self.backend)
                    # Prepare the entire metadata change in memory first.
                    # Name, folder and catalog failures must be known before
                    # either a durable pending marker or backend writes exist.
                    _apply_metadata(tx, state)
                    tx._commit()
                    state["after_revision"] = tx.revision()
                    record = self.journal.begin(MASTER_MUTATION_KIND, state=state)
                    self._execute_inside_transaction(record, tx)
            except BaseException as cause:
                if record is not None:
                    latest = self.journal.read(record.operation_id)
                    if not latest.finished:
                        state = _validate_state(latest.state)
                        # A metadata write can report failure after replacement.
                        # Restore only when the old revision is still proven.
                        if self.store.snapshot().revision == state["before_revision"]:
                            failures = _restore_accounts(self.backend, state["accounts_before"])
                            if failures:
                                from keys_keeper.service import IncompleteRollback
                                raise IncompleteRollback(failures) from cause
                            self.journal.fail(record.operation_id, error_code="operation_failed")
                raise
            self._commit_record(record.operation_id)
            return result

    def create_entry(self, entry: Entry, *, secrets=None, replace: bool = False) -> Entry:
        def prepare(tx):
            catalog = _require_catalog(tx)
            existing = tx.get_by_name(entry.name)
            if existing is not None and not replace:
                raise NameConflict("entry name already exists; use --replace or a different name")
            if existing is None and tx.get_by_id(entry.id) is not None:
                raise NameConflict("entry id already exists; choose a new entry identity")
            if existing is not None:
                entry.id = existing.id
                _preserve_catalog_attributes(entry, existing)
            if catalog is not None:
                if entry.provenance is None:
                    entry.provenance = {"source": "local"}
                entry.content_revision = str(uuid.uuid4())
            return self._state(
                action="create", before_revision=tx.revision(),
                entry_before=existing, entry_after=entry,
                dependents_before=[], dependents_after=[],
                catalog_before=catalog, catalog_after=_catalog_with_intents(
                    catalog, entry, reason="entry_replaced" if existing else None),
                accounts_after=_writes_for(entry.id, secrets)), entry
        return self._transact(prepare)

    def update_entry(self, entry: Entry, *, secrets=None) -> Entry:
        def prepare(tx):
            catalog = _require_catalog(tx)
            existing = tx.get_by_id(entry.id)
            if existing is None:
                raise NotFound("entry does not exist")
            tx.assert_rename_safe(entry)
            _preserve_catalog_attributes(entry, existing)
            if catalog is not None:
                entry.content_revision = str(uuid.uuid4())
            return self._state(
                action="update", before_revision=tx.revision(),
                entry_before=existing, entry_after=entry,
                dependents_before=[], dependents_after=[],
                catalog_before=catalog, catalog_after=_catalog_with_intents(
                    catalog, entry, reason="entry_updated"),
                accounts_after=_writes_for(entry.id, secrets)), entry
        return self._transact(prepare)

    def delete_entry(self, name_or_id: str, *, cascade: bool = False):
        from keys_keeper.service import DeleteResult, HasDependents
        def prepare(tx):
            catalog = _require_catalog(tx)
            entry = tx.get_by_id(name_or_id) or tx.get_by_name(name_or_id)
            if entry is None:
                raise NotFound("entry does not exist")
            before = [candidate for candidate in tx.list()
                      if any(ref.get("name") == entry.name for ref in candidate.refs)]
            if before and not cascade:
                raise HasDependents([item.name for item in before])
            after = [copy.deepcopy(item) for item in before]
            updated_catalog = _catalog_after_delete(catalog, entry)
            for dependent in after:
                dependent.refs = [ref for ref in dependent.refs if ref.get("name") != entry.name]
                if catalog is not None:
                    dependent.content_revision = str(uuid.uuid4())
                    updated_catalog = _catalog_with_intents(updated_catalog, dependent, reason="entry_updated")
            return self._state(
                action="delete", before_revision=tx.revision(),
                entry_before=entry, entry_after=None,
                dependents_before=before, dependents_after=after,
                catalog_before=catalog, catalog_after=updated_catalog,
                accounts_after={entry.id: {"present": False},
                                entry.id + ":passphrase": {"present": False}}), DeleteResult(entry, [item.name for item in before])
        return self._transact(prepare)

    def bulk_create(self, items):
        prepared = list(items)
        def prepare(tx):
            from keys_keeper.store import MetadataTransaction
            before = _metadata_image(tx)
            staged = MetadataTransaction(copy.deepcopy(before))
            writes = {}
            for entry, secret in prepared:
                if tx.schema_version >= 3:
                    entry.provenance = entry.provenance or {"source": "local"}
                    entry.content_revision = str(uuid.uuid4())
                staged.add(entry)
                writes.update(_writes_for(entry.id, secret))
            return self._replacement_state(tx, before, _metadata_image(staged), writes), [entry for entry, _ in prepared]
        return self._transact(prepare)

    def apply_snapshot(self, entries, tombstones, *, secret_writes, secret_deletes, expected_revision):
        def prepare(tx):
            from keys_keeper.service import ConcurrentMutation
            from keys_keeper.store import MetadataTransaction
            if tx.schema_version >= 3:
                raise MasterMutationRequired("legacy snapshot apply is disabled for catalog schema 3")
            if tx.revision() != expected_revision:
                raise ConcurrentMutation("local metadata changed while preparing the snapshot")
            before = _metadata_image(tx)
            staged = MetadataTransaction(copy.deepcopy(before))
            staged.replace_all(entries, tombstones)
            writes = {account: {"present": True, "value": value} for account, value in secret_writes.items()}
            deletes = set(secret_deletes)
            if deletes.intersection(writes):
                raise ValueError("an account cannot be written and deleted in the same snapshot")
            writes.update({account: {"present": False} for account in deletes})
            return self._replacement_state(tx, before, _metadata_image(staged), writes), None
        return self._transact(prepare)

    def _replacement_state(self, tx, before, after, accounts_after):
        state = {"schema_version": 2, "action": "replace_all",
                 "before_revision": tx.revision(), "after_revision": None,
                 "metadata_before": before, "metadata_after": after,
                 "accounts_before": _snapshot_accounts(self.backend, accounts_after),
                 "accounts_after": accounts_after}
        return _validate_state(state)

    def recover(self) -> list[OperationRecord]:
        """Complete every indexed master mutation before sync or UI starts."""
        recovered: list[OperationRecord] = []
        with self.journal.locked():
            # Apply type/count/aggregate ceilings before indexed records can
            # derive a key or replay a backend side effect.
            self.journal._recovery_snapshot(migration=True)
            refs = self.journal.pending_refs(kind=MASTER_MUTATION_KIND)
            for ref in refs:
                try:
                    record = self.journal.read(ref["operation_id"])
                except JournalNotFound as ex:
                    raise MasterRecoveryRequired(
                        "master mutation marker has no encrypted recovery record"
                    ) from ex
                if record.kind != MASTER_MUTATION_KIND:
                    raise MasterRecoveryRequired("master mutation journal identity mismatch")
                if record.finished:
                    if record.status == "completed":
                        self.journal.finish(record.operation_id)
                    else:
                        self.journal.fail(
                            record.operation_id,
                            error_code=record.error_code or "operation_failed",
                        )
                    continue
                recovered.append(self._recover_record(record))
            # A pre-index implementation must not silently evade the guard.
            indexed = {item["operation_id"] for item in refs}
            unindexed = [
                item for item in self.journal.list_unfinished()
                if item.kind == MASTER_MUTATION_KIND
                and str(item.operation_id) not in indexed
            ]
            if unindexed:
                raise MasterRecoveryRequired(
                    "master mutation journal is missing its pending marker"
                )
        self.assert_projection_ready()
        return recovered

    def _state(
        self,
        *,
        action: str,
        before_revision: str,
        entry_before: Entry | None,
        entry_after: Entry | None,
        dependents_before: list[Entry],
        dependents_after: list[Entry],
        catalog_before: dict | None,
        catalog_after: dict | None,
        accounts_after: dict[str, dict[str, object]],
    ) -> dict:
        accounts_before = _snapshot_accounts(self.backend, accounts_after)
        return {
            "schema_version": _STATE_SCHEMA,
            "action": action,
            "before_revision": before_revision,
            "after_revision": None,
            "entry_before": _entry_dict(entry_before),
            "entry_after": _entry_dict(entry_after),
            "dependents_before": [_entry_dict(item) for item in dependents_before],
            "dependents_after": [_entry_dict(item) for item in dependents_after],
            "catalog_before": copy.deepcopy(catalog_before),
            "catalog_after": copy.deepcopy(catalog_after),
            "accounts_before": accounts_before,
            "accounts_after": copy.deepcopy(accounts_after),
        }

    def _execute_inside_transaction(self, record: OperationRecord, tx) -> None:
        state = _validate_state(record.state)
        try:
            _apply_accounts(self.backend, state["accounts_after"])
            self.journal.stage(record.operation_id, "backend_applied")
            self.journal.stage(
                record.operation_id, "metadata_prepared", state=state
            )
        except BaseException as cause:
            failures = _restore_accounts(self.backend, state["accounts_before"])
            if failures:
                try:
                    self.journal.stage(
                        record.operation_id, "rollback_required", state=state
                    )
                finally:
                    from keys_keeper.service import IncompleteRollback

                    raise IncompleteRollback(failures) from cause
            self.journal.fail(record.operation_id, error_code="operation_failed")
            raise

    def _commit_record(self, operation_id) -> OperationRecord:
        # Metadata has committed when the transaction context returned.  A
        # failure here remains indexed and startup recovery verifies the stored
        # after revision before closing it.
        record = self.journal.read(operation_id)
        state = _validate_state(record.state)
        with self.store.read_transaction() as tx:
            if (not _metadata_matches_after(tx, state)
                    or (state["after_revision"] is not None
                        and tx.revision() != state["after_revision"])):
                raise MasterRecoveryRequired("master metadata diverged after mutation commit")
            # Older pending records did not store a prepared revision. They can
            # be bound only after their complete after images have been proven.
            state["after_revision"] = tx.revision()
            self.journal.stage(operation_id, "metadata_committed", state=state)
            return self.journal.finish(operation_id, result={"status": "applied"})

    def _recover_record(self, record: OperationRecord) -> OperationRecord:
        state = _validate_state(record.state)
        _validate_required_secrets(state, self.backend)
        with self.store.transaction() as tx:
            current_revision = tx.revision()
            after_revision = state["after_revision"]
            if (
                after_revision is not None and current_revision == after_revision
            ) or _metadata_matches_after(tx, state):
                _apply_accounts(self.backend, state["accounts_after"])
            elif current_revision == state["before_revision"]:
                _apply_metadata(tx, state)
                tx._commit()
                state["after_revision"] = tx.revision()
                _apply_accounts(self.backend, state["accounts_after"])
                self.journal.stage(record.operation_id, "backend_applied")
                self.journal.stage(
                    record.operation_id, "metadata_prepared", state=state
                )
            else:
                raise MasterRecoveryRequired(
                    "master metadata diverged from pending mutation revisions"
                )
        return self._commit_record(record.operation_id)


def _require_catalog(tx) -> dict | None:
    return tx.catalog_state() if tx.schema_version >= 3 else None


def _preserve_catalog_attributes(entry: Entry, existing: Entry) -> None:
    entry.folder_id = existing.folder_id
    entry.distribution = existing.distribution
    entry.provenance = existing.provenance
    entry.content_revision = existing.content_revision


def _catalog_with_intents(catalog: dict | None, entry: Entry, *, reason: str | None) -> dict | None:
    if catalog is None:
        return None
    result = copy.deepcopy(catalog)
    if reason is None:
        return result
    scopes = sorted({
        binding["scope_id"]
        for binding in result["bindings"]
        if binding["entry_id"] == entry.id
    })
    for scope_id in scopes:
        result["publication_intents"].append({
            "scope_id": scope_id,
            "entry_id": entry.id,
            "reason": reason,
            "desired_content_revision": entry.content_revision,
        })
    return result


def _catalog_after_delete(catalog: dict | None, entry: Entry) -> dict | None:
    if catalog is None:
        return None
    result = copy.deepcopy(catalog)
    affected = [item for item in result["bindings"] if item["entry_id"] == entry.id]
    result["bindings"] = [item for item in result["bindings"] if item["entry_id"] != entry.id]
    for scope_id in sorted({item["scope_id"] for item in affected}):
        result["publication_intents"].append({
            "scope_id": scope_id,
            "entry_id": entry.id,
            "reason": "entry_deleted",
            "desired_content_revision": entry.content_revision,
        })
    if not any(
        item.get("entry_id") == entry.id and item.get("reason") == "entry_deleted"
        for item in result["dedup"]
    ):
        result["dedup"].append({"entry_id": entry.id, "reason": "entry_deleted"})
    return result


def _writes_for(entry_id: str, secrets: "SecretInput | None") -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    if secrets is None:
        return result
    if secrets.value is not None:
        result[entry_id] = {"present": True, "value": secrets.value}
    if secrets.passphrase is not None:
        result[entry_id + ":passphrase"] = {
            "present": True,
            "value": secrets.passphrase,
        }
    return result


def _validate_required_secrets(state: dict, backend: KeychainBackend) -> None:
    """Reject incomplete new/updated entries before a pending journal exists."""
    entries = (state["metadata_after"]["entries"] if state["action"] == "replace_all"
               else [state["entry_after"]] if state["entry_after"] is not None else [])
    required = [entry.id for raw in entries if entry_requires_secret(entry := _entry(raw))]
    if not required:
        return
    existing = None
    for account in required:
        desired = state["accounts_after"].get(account)
        if desired is not None:
            present = desired["present"]
        else:
            if existing is None:
                existing = set(backend.list_ids())
            present = account in existing
        if not present:
            raise ValidationError("entry requires a secret value")


def _snapshot_accounts(
    backend: KeychainBackend,
    targets: Mapping[str, Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    present = set(backend.list_ids())
    result: dict[str, dict[str, object]] = {}
    for account in targets:
        if account in present:
            result[account] = {"present": True, "value": backend.get(account).unseal()}
        else:
            result[account] = {"present": False}
    return result


def _apply_accounts(
    backend: KeychainBackend,
    desired: Mapping[str, Mapping[str, object]],
) -> None:
    present = set(backend.list_ids())
    for account, target in desired.items():
        if target["present"]:
            value = target["value"]
            if account in present and backend.get(account).unseal() == value:
                continue
            backend.set(account, value)
            present.add(account)
        elif account in present:
            backend.delete(account)
            present.discard(account)


def _restore_accounts(
    backend: KeychainBackend,
    before: Mapping[str, Mapping[str, object]],
) -> int:
    failures = 0
    for account, target in reversed(list(before.items())):
        try:
            _apply_accounts(backend, {account: target})
        except BaseException:  # noqa: BLE001 - compensation must survive interrupts
            failures += 1
    return failures


def _entry_dict(entry: Entry | None) -> dict | None:
    return None if entry is None else copy.deepcopy(entry.to_dict())


def _entry(value: object, *, optional: bool = False, legacy: bool = False) -> Entry | None:
    if value is None and optional:
        return None
    if not isinstance(value, dict):
        raise MasterRecoveryRequired("master mutation entry image is invalid")
    try:
        if legacy:
            # A before image describes existing data, not a new publication.
            # Permit explicit repair of old field shapes while retaining the
            # identity/container checks needed for exact source comparisons.
            validate_entry_id(value.get("id"))
            validate_name(value.get("name"))
            if (not isinstance(value.get("fields", {}), dict)
                    or not isinstance(value.get("tags", []), list)
                    or not isinstance(value.get("refs", []), list)
                    or any(not isinstance(ref, dict) for ref in value.get("refs", []))
                    or not isinstance(value.get("created_at"), str)
                    or not isinstance(value.get("updated_at"), str)):
                raise ValueError("invalid legacy container")
            return Entry.from_dict(value)
        return Entry.from_untrusted_dict(value, allow_project_fields=True)
    except Exception as ex:
        raise MasterRecoveryRequired("master mutation entry image is invalid") from ex


def _validate_account_images(value: object) -> dict[str, dict[str, object]]:
    if not isinstance(value, dict):
        raise MasterRecoveryRequired("master mutation account image is invalid")
    result: dict[str, dict[str, object]] = {}
    for account, image in value.items():
        if not isinstance(account, str) or not isinstance(image, dict):
            raise MasterRecoveryRequired("master mutation account image is invalid")
        if set(image) not in ({"present"}, {"present", "value"}):
            raise MasterRecoveryRequired("master mutation account image is invalid")
        if type(image.get("present")) is not bool:
            raise MasterRecoveryRequired("master mutation account image is invalid")
        if image["present"]:
            if not isinstance(image.get("value"), str):
                raise MasterRecoveryRequired("master mutation account image is invalid")
        elif "value" in image:
            raise MasterRecoveryRequired("master mutation account image is invalid")
        result[account] = dict(image)
    return result


def _validate_state(value: Mapping[str, object]) -> dict:
    if isinstance(value, Mapping) and value.get("schema_version") == 2:
        return _validate_replacement_state(value)
    expected = {
        "schema_version", "action", "before_revision", "after_revision",
        "entry_before", "entry_after", "dependents_before", "dependents_after",
        "catalog_before", "catalog_after", "accounts_before", "accounts_after",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise MasterRecoveryRequired("master mutation journal state is invalid")
    state = copy.deepcopy(dict(value))
    if state["schema_version"] != _STATE_SCHEMA or state["action"] not in {
        "create", "update", "delete"
    }:
        raise MasterRecoveryRequired("master mutation journal state is invalid")
    for field in ("before_revision",):
        if not isinstance(state[field], str) or not re.fullmatch(
            r"[0-9a-f]{64}", state[field]
        ):
            raise MasterRecoveryRequired("master mutation revision is invalid")
    if state["after_revision"] is not None and (
        not isinstance(state["after_revision"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", state["after_revision"])
    ):
        raise MasterRecoveryRequired("master mutation revision is invalid")
    before = _entry(state["entry_before"], optional=True, legacy=True)
    after = _entry(state["entry_after"], optional=True)
    for field in ("dependents_before", "dependents_after"):
        if not isinstance(state[field], list):
            raise MasterRecoveryRequired("master mutation dependent image is invalid")
        for item in state[field]:
            _entry(item, legacy=field == "dependents_before")
    if not ((state["catalog_before"] is None and state["catalog_after"] is None)
            or (isinstance(state["catalog_before"], dict)
                and isinstance(state["catalog_after"], dict))):
        raise MasterRecoveryRequired("master mutation catalog image is invalid")
    state["accounts_before"] = _validate_account_images(state["accounts_before"])
    state["accounts_after"] = _validate_account_images(state["accounts_after"])
    if set(state["accounts_before"]) != set(state["accounts_after"]):
        raise MasterRecoveryRequired("master mutation account image is incomplete")
    if state["action"] == "create":
        if after is None or (before is not None and (
            before.id != after.id or before.name != after.name
        )):
            raise MasterRecoveryRequired("master create journal state is invalid")
        if state["dependents_before"] or state["dependents_after"]:
            raise MasterRecoveryRequired("master create journal state is invalid")
    elif state["action"] == "update":
        if before is None or after is None or before.id != after.id:
            raise MasterRecoveryRequired("master update journal state is invalid")
        if state["dependents_before"] or state["dependents_after"]:
            raise MasterRecoveryRequired("master update journal state is invalid")
    else:
        if before is None or after is not None:
            raise MasterRecoveryRequired("master delete journal state is invalid")
        dependent_before = [
            _entry(item, legacy=True) for item in state["dependents_before"]
        ]
        dependent_after = [
            _entry(item) for item in state["dependents_after"]
        ]
        if [item.id for item in dependent_before] != [
            item.id for item in dependent_after
        ]:
            raise MasterRecoveryRequired("master delete dependent image is invalid")
    target = after if after is not None else before
    assert target is not None
    allowed_accounts = {target.id, target.id + ":passphrase"}
    if not set(state["accounts_after"]).issubset(allowed_accounts):
        raise MasterRecoveryRequired("master mutation account identity is invalid")
    if state["action"] == "delete" and set(state["accounts_after"]) != allowed_accounts:
        raise MasterRecoveryRequired("master delete account image is incomplete")
    return state


def _apply_metadata(tx, state: dict) -> None:
    if state["action"] == "replace_all":
        if _metadata_image(tx) != state["metadata_before"]:
            raise MasterRecoveryRequired("master snapshot source changed")
        after = state["metadata_after"]
        tx.replace_all([_entry(item) for item in after["entries"]], after["tombstones"])
        if after["schema_version"] >= 3:
            tx.set_catalog_state(after["catalog"])
        return
    before = _entry(state["entry_before"], optional=True, legacy=True)
    after = _entry(state["entry_after"], optional=True)
    action = state["action"]
    if action == "create":
        if before is None:
            assert after is not None
            if tx.get_by_id(after.id) is not None or tx.get_by_name(after.name) is not None:
                raise MasterRecoveryRequired("master create target is no longer free")
            tx.add(after)
        else:
            assert after is not None
            current = tx.get_by_id(before.id)
            if current is None or current.to_dict() != before.to_dict():
                raise MasterRecoveryRequired("master replace source changed")
            tx.update(after)
    elif action == "update":
        assert before is not None and after is not None
        current = tx.get_by_id(before.id)
        if current is None or current.to_dict() != before.to_dict():
            raise MasterRecoveryRequired("master update source changed")
        tx.update(after)
    else:
        assert before is not None
        current = tx.get_by_id(before.id)
        if current is None or current.to_dict() != before.to_dict():
            raise MasterRecoveryRequired("master delete source changed")
        for dependent_before_raw, dependent_after_raw in zip(
            state["dependents_before"], state["dependents_after"], strict=True
        ):
            dependent_before = _entry(dependent_before_raw, legacy=True)
            dependent_after = _entry(dependent_after_raw)
            assert dependent_before is not None and dependent_after is not None
            current_dependent = tx.get_by_id(dependent_before.id)
            if (
                current_dependent is None
                or current_dependent.to_dict() != dependent_before.to_dict()
            ):
                raise MasterRecoveryRequired("master delete dependent changed")
            tx.update(dependent_after)
        tx.delete_by_name(before.name)
    if state["catalog_after"] is not None:
        tx.set_catalog_state(state["catalog_after"])


def _metadata_matches_after(tx, state: dict) -> bool:
    if state["action"] == "replace_all":
        return _metadata_image(tx) == state["metadata_after"]
    after = _entry(state["entry_after"], optional=True)
    before = _entry(state["entry_before"], optional=True, legacy=True)
    if state["action"] == "delete":
        assert before is not None
        if tx.get_by_id(before.id) is not None:
            return False
        for raw in state["dependents_after"]:
            dependent = _entry(raw)
            assert dependent is not None
            current = tx.get_by_id(dependent.id)
            if current is None or current.to_dict() != dependent.to_dict():
                return False
    else:
        assert after is not None
        current = tx.get_by_id(after.id)
        if current is None or current.to_dict() != after.to_dict():
            return False
    try:
        return _require_catalog(tx) == state["catalog_after"]
    except StoreError:
        return False


def _metadata_image(tx) -> dict:
    result = {"schema_version": tx.schema_version,
              "entries": [entry.to_dict() for entry in tx.list()],
              "tombstones": tx.tombstones()}
    if tx.schema_version >= 3:
        result["catalog"] = tx.catalog_state()
    return result


def _validate_metadata_image(value, *, legacy: bool = False) -> dict:
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
            or value["schema_version"] not in {2, 3}):
        raise MasterRecoveryRequired("master metadata image is invalid")
    expected = {"schema_version", "entries", "tombstones"}
    if value["schema_version"] == 3:
        expected.add("catalog")
    if (set(value) != expected or not isinstance(value["entries"], list)
            or len(value["entries"]) > 10_000 or not isinstance(value["tombstones"], list)
            or len(value["tombstones"]) > 20_000):
        raise MasterRecoveryRequired("master metadata image is invalid")
    entries = [_entry(item, legacy=legacy) for item in value["entries"]]
    if (len({entry.id for entry in entries}) != len(entries)
            or len({entry.name for entry in entries}) != len(entries)):
        raise MasterRecoveryRequired("master metadata image has ambiguous identities")
    try:
        for item in value["tombstones"]:
            validate_tombstone(item)
        if value["schema_version"] == 3:
            from keys_keeper.project_models import CatalogState
            CatalogState.from_dict(value["catalog"], entry_ids={entry.id for entry in entries})
    except ValueError:
        raise MasterRecoveryRequired("master metadata image is invalid") from None
    return copy.deepcopy(value)


def _validate_replacement_state(value: Mapping) -> dict:
    expected = {"schema_version", "action", "before_revision", "after_revision",
                "metadata_before", "metadata_after", "accounts_before", "accounts_after"}
    if set(value) != expected or value["action"] != "replace_all":
        raise MasterRecoveryRequired("master snapshot journal state is invalid")
    state = copy.deepcopy(dict(value))
    for field in ("before_revision", "after_revision"):
        if field == "after_revision" and state[field] is None:
            continue
        if not isinstance(state[field], str) or not re.fullmatch(r"[0-9a-f]{64}", state[field]):
            raise MasterRecoveryRequired("master mutation revision is invalid")
    state["metadata_before"] = _validate_metadata_image(state["metadata_before"], legacy=True)
    state["metadata_after"] = _validate_metadata_image(state["metadata_after"])
    if state["metadata_before"]["schema_version"] != state["metadata_after"]["schema_version"]:
        raise MasterRecoveryRequired("snapshot cannot migrate the metadata schema")
    state["accounts_before"] = _validate_account_images(state["accounts_before"])
    state["accounts_after"] = _validate_account_images(state["accounts_after"])
    if set(state["accounts_before"]) != set(state["accounts_after"]):
        raise MasterRecoveryRequired("master snapshot account images are incomplete")
    ids = {item["id"] for side in ("metadata_before", "metadata_after")
           for item in state[side]["entries"] + state[side]["tombstones"]}
    allowed = ids | {identifier + ":passphrase" for identifier in ids}
    if not set(state["accounts_after"]).issubset(allowed):
        raise MasterRecoveryRequired("master snapshot account identity is invalid")
    return state
