"""Application service for coordinated metadata and secret mutations.

The OS backends do not expose transactions. ``VaultService`` therefore holds
the metadata lock, snapshots only the secret accounts it is about to change,
and compensates backend writes when a later step fails. This is the strongest
coherent boundary available before versioned physical secret generations land:
successful calls are consistent, and ordinary failures restore the prior
state. A backend that fails both the write and its compensation is reported as
an explicit incomplete rollback rather than being presented as atomic.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
import uuid
from typing import TYPE_CHECKING

from keys_keeper.backend import KeychainBackend
from keys_keeper.models import Entry
from keys_keeper.store import MetadataStore, NameConflict, NotFound
from keys_keeper.store import StoreError

if TYPE_CHECKING:
    from keys_keeper.master_journal import MasterMutationManager


class HasDependents(RuntimeError):
    def __init__(self, dependents: list[str]):
        super().__init__("entry has dependents")
        self.dependents = dependents


class IncompleteRollback(RuntimeError):
    """The requested mutation failed and one or more compensations failed."""

    def __init__(self, failed_accounts: int):
        super().__init__(
            "vault mutation failed and rollback was incomplete "
            f"for {failed_accounts} secret account(s); run `keys doctor`"
        )
        self.failed_accounts = failed_accounts


class ConcurrentMutation(RuntimeError):
    """Metadata changed after a caller computed a replacement snapshot."""


@dataclass(frozen=True)
class SecretInput:
    value: str | None = field(default=None, repr=False)
    passphrase: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class DeleteResult:
    entry: Entry
    cascaded: list[str]


@dataclass(frozen=True)
class _SecretSnapshot:
    exists: bool
    value: str | None = field(default=None, repr=False)


class _BackendUndo:
    def __init__(self, backend: KeychainBackend):
        self._backend = backend
        self._snapshots: dict[str, _SecretSnapshot] = {}
        self._order: list[str] = []

    def _snapshot(self, account: str) -> None:
        if account in self._snapshots:
            return
        # ``get`` errors are ambiguous across backends (missing vs denied).
        # Inspect account presence first so access errors are never mistaken
        # for an absent value that is safe to overwrite.
        if account not in set(self._backend.list_ids()):
            snapshot = _SecretSnapshot(False)
        else:
            snapshot = _SecretSnapshot(True, self._backend.get(account).unseal())
        self._snapshots[account] = snapshot
        self._order.append(account)

    def set(self, account: str, value: str) -> None:
        self._snapshot(account)
        self._backend.set(account, value)

    def delete(self, account: str) -> None:
        self._snapshot(account)
        self._backend.delete(account)

    def rollback(self) -> None:
        failures = 0
        for account in reversed(self._order):
            snapshot = self._snapshots[account]
            try:
                if snapshot.exists:
                    # ``value`` is non-None whenever ``exists`` is true. Empty
                    # strings remain valid values and must be restored.
                    self._backend.set(account, snapshot.value or "")
                else:
                    self._backend.delete(account)
            except BaseException:  # noqa: BLE001 -- compensation must survive interrupts
                failures += 1
        if failures:
            raise IncompleteRollback(failures)


@contextmanager
def compensating_secret_update(
    backend: KeychainBackend,
    writes: Mapping[str, str],
) -> Iterator[None]:
    """Stage backend writes and restore every touched account on failure.

    Callers keep dependent validation/persistence work inside this context so
    it either completes against the staged credentials or leaves the backend
    exactly as it was before the first write. Secret values are intentionally
    absent from exception messages and object representations.
    """
    undo = _BackendUndo(backend)
    try:
        for account, value in writes.items():
            undo.set(account, value)
        yield
    except BaseException as ex:
        VaultService._rollback_or_raise(undo, ex)
        raise


class VaultService:
    """Shared mutation boundary for CLI and local HTTP API."""

    def __init__(
        self,
        store: MetadataStore,
        backend: KeychainBackend,
        *,
        master_mutations: "MasterMutationManager | None" = None,
    ):
        self.store = store
        self.backend = backend
        self.master_mutations = master_mutations
        if master_mutations is not None and (
            master_mutations.store is not store or master_mutations.backend is not backend
        ):
            raise ValueError("master mutation manager must own this store and backend")

    def create_entry(
        self,
        entry: Entry,
        *,
        secrets: SecretInput | None = None,
        replace: bool = False,
    ) -> Entry:
        manager = self._catalog_mutation_manager()
        if manager is not None:
            return manager.create_entry(entry, secrets=secrets, replace=replace)
        undo = _BackendUndo(self.backend)
        try:
            with self.store.transaction() as tx:
                existing = tx.get_by_name(entry.name)
                if existing is not None and not replace:
                    raise NameConflict(
                        f"entry with name {entry.name!r} already exists "
                        f"(use --replace to overwrite or --rename to pick a new name)"
                    )
                if existing is not None:
                    entry.id = existing.id
                    self._preserve_catalog_entry_attributes(entry, existing)
                    self._bump_content_revision_if_catalog(tx, entry)
                    tx.replace_by_name(entry)
                    self._mark_entry_publication_intents(tx, entry, reason="entry_replaced")
                else:
                    tx.add(entry)
                self._write_secrets(undo, entry.id, secrets)
            return entry
        except BaseException as ex:
            self._rollback_or_raise(undo, ex)
            raise

    def update_entry(
        self,
        entry: Entry,
        *,
        secrets: SecretInput | None = None,
    ) -> Entry:
        manager = self._catalog_mutation_manager()
        if manager is not None:
            return manager.update_entry(entry, secrets=secrets)
        undo = _BackendUndo(self.backend)
        try:
            with self.store.transaction() as tx:
                existing = tx.get_by_id(entry.id)
                if existing is None:
                    raise NotFound(f"no entry with id {entry.id}")
                self._preserve_catalog_entry_attributes(entry, existing)
                self._bump_content_revision_if_catalog(tx, entry)
                tx.update(entry)
                self._mark_entry_publication_intents(tx, entry, reason="entry_updated")
                self._write_secrets(undo, entry.id, secrets)
            return entry
        except BaseException as ex:
            self._rollback_or_raise(undo, ex)
            raise

    def bulk_create(
        self,
        items: Iterable[tuple[Entry, SecretInput | None]],
    ) -> list[Entry]:
        if self._catalog_mutation_manager() is not None:
            from keys_keeper.master_journal import MasterMutationRequired

            raise MasterMutationRequired(
                "schema-v3 bulk create requires a durable bulk operation"
            )
        prepared = list(items)
        undo = _BackendUndo(self.backend)
        try:
            with self.store.transaction() as tx:
                seen: set[str] = set()
                for entry, _ in prepared:
                    if entry.name in seen or tx.get_by_name(entry.name) is not None:
                        raise NameConflict(f"entry with name {entry.name!r} already exists")
                    seen.add(entry.name)
                for entry, secrets in prepared:
                    tx.add(entry)
                    self._write_secrets(undo, entry.id, secrets)
            return [entry for entry, _ in prepared]
        except BaseException as ex:
            self._rollback_or_raise(undo, ex)
            raise

    def delete_entry(self, name_or_id: str, *, cascade: bool = False) -> DeleteResult:
        manager = self._catalog_mutation_manager()
        if manager is not None:
            return manager.delete_entry(name_or_id, cascade=cascade)
        undo = _BackendUndo(self.backend)
        try:
            with self.store.transaction() as tx:
                entry = tx.get_by_id(name_or_id) or tx.get_by_name(name_or_id)
                if entry is None:
                    raise NotFound(f"no entry named {name_or_id!r}")
                dependents = [
                    candidate
                    for candidate in tx.list()
                    if any(ref.get("name") == entry.name for ref in candidate.refs)
                ]
                if dependents and not cascade:
                    raise HasDependents([dependent.name for dependent in dependents])
                for dependent in dependents:
                    dependent.refs = [
                        ref for ref in dependent.refs if ref.get("name") != entry.name
                    ]
                    tx.update(dependent)
                undo.delete(entry.id)
                undo.delete(entry.id + ":passphrase")
                tx.delete_by_name(entry.name)
                self._remove_deleted_entry_from_catalog(tx, entry)
            return DeleteResult(entry, [dependent.name for dependent in dependents])
        except BaseException as ex:
            self._rollback_or_raise(undo, ex)
            raise

    def apply_snapshot(
        self,
        entries: list[Entry],
        tombstones: list[dict],
        *,
        secret_writes: Mapping[str, str],
        secret_deletes: Iterable[str],
        expected_revision: str,
    ) -> None:
        """Atomically apply sync metadata with compensating secret writes.

        The physical backend is not transactional, so every touched account is
        snapshotted first. This preserves overwritten local values as well as
        newly-created values when a later write, delete, or metadata commit
        fails.
        """
        if self._catalog_mutation_manager() is not None:
            from keys_keeper.master_journal import MasterMutationRequired

            raise MasterMutationRequired(
                "legacy snapshot apply is disabled for catalog schema 3"
            )
        deletes = tuple(secret_deletes)
        overlap = set(secret_writes).intersection(deletes)
        if overlap:
            raise ValueError(
                "secret accounts cannot be written and deleted in one snapshot apply"
            )
        undo = _BackendUndo(self.backend)
        try:
            with self.store.transaction() as tx:
                if tx.revision() != expected_revision:
                    raise ConcurrentMutation(
                        "local metadata changed while the snapshot was being prepared"
                    )
                for account, value in secret_writes.items():
                    undo.set(account, value)
                for account in deletes:
                    undo.delete(account)
                tx.replace_all(entries, tombstones)
        except BaseException as ex:
            self._rollback_or_raise(undo, ex)
            raise

    @staticmethod
    def _write_secrets(
        undo: _BackendUndo,
        entry_id: str,
        secrets: SecretInput | None,
    ) -> None:
        if secrets is None:
            return
        if secrets.value is not None:
            undo.set(entry_id, secrets.value)
        if secrets.passphrase is not None:
            undo.set(entry_id + ":passphrase", secrets.passphrase)

    @staticmethod
    def _catalog_state_or_none(tx) -> dict | None:
        """Return v3 catalog data without turning a legacy vault into v3."""
        try:
            return tx.catalog_state()
        except StoreError as ex:
            if "explicit schema-v3 migration" in str(ex):
                return None
            raise

    def _catalog_mutation_manager(self) -> "MasterMutationManager | None":
        """Require durable composition for every schema-v3 write path."""
        try:
            self.store.catalog_state()
        except StoreError as ex:
            if "explicit schema-v3 migration" in str(ex):
                return None
            raise
        if self.master_mutations is None:
            from keys_keeper.master_journal import MasterMutationRequired

            raise MasterMutationRequired(
                "catalog schema 3 requires a durable master mutation manager"
            )
        return self.master_mutations

    @staticmethod
    def _preserve_catalog_entry_attributes(entry: Entry, existing: Entry) -> None:
        """A master replace/edit cannot silently discard project access metadata."""
        entry.folder_id = existing.folder_id
        entry.distribution = existing.distribution
        entry.provenance = existing.provenance
        entry.content_revision = existing.content_revision

    @classmethod
    def _bump_content_revision_if_catalog(cls, tx, entry: Entry) -> None:
        if cls._catalog_state_or_none(tx) is not None:
            entry.content_revision = str(uuid.uuid4())

    @classmethod
    def _mark_entry_publication_intents(cls, tx, entry: Entry, *, reason: str) -> None:
        catalog = cls._catalog_state_or_none(tx)
        if catalog is None:
            return
        scopes = sorted({
            binding["scope_id"]
            for binding in catalog["bindings"]
            if binding["entry_id"] == entry.id
        })
        if not scopes:
            return
        intents = catalog["publication_intents"]
        for scope_id in scopes:
            intents.append({
                "scope_id": scope_id,
                "entry_id": entry.id,
                "reason": reason,
                "desired_content_revision": entry.content_revision,
            })
        tx.set_catalog_state(catalog)

    @classmethod
    def _remove_deleted_entry_from_catalog(cls, tx, entry: Entry) -> None:
        catalog = cls._catalog_state_or_none(tx)
        if catalog is None:
            return
        affected = [binding for binding in catalog["bindings"] if binding["entry_id"] == entry.id]
        catalog["bindings"] = [binding for binding in catalog["bindings"] if binding["entry_id"] != entry.id]
        for scope_id in sorted({binding["scope_id"] for binding in affected}):
            catalog["publication_intents"].append({
                "scope_id": scope_id,
                "entry_id": entry.id,
                "reason": "entry_deleted",
                "desired_content_revision": entry.content_revision,
            })
        # The durable ledger outlives metadata and secret deletion. A future
        # project importer must consult this record before accepting an old
        # create request for this canonical entry ID.
        if not any(item.get("entry_id") == entry.id and item.get("reason") == "entry_deleted" for item in catalog["dedup"]):
            catalog["dedup"].append({"entry_id": entry.id, "reason": "entry_deleted"})
        tx.set_catalog_state(catalog)

    @staticmethod
    def _rollback_or_raise(undo: _BackendUndo, cause: BaseException) -> None:
        try:
            undo.rollback()
        except IncompleteRollback as rollback_error:
            raise rollback_error from cause
