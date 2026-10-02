"""One durable mutation facade for standalone and project master vaults.

VaultService delegates every ordinary mutation to MasterMutationManager.
The small compensating-write helper remains for the separately journaled
project importer; it is never a fallback for ordinary vault writes.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from keys_keeper.backend import KeychainBackend
from keys_keeper.models import Entry
from keys_keeper.store import MetadataStore

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

    def _manager(self):
        if self.master_mutations is None:
            from keys_keeper.master_journal import compose_master_mutations
            self.master_mutations = compose_master_mutations(self.store, self.backend)
        self.master_mutations.recover()
        return self.master_mutations

    def create_entry(self, entry: Entry, *, secrets: SecretInput | None = None,
                     replace: bool = False) -> Entry:
        return self._manager().create_entry(entry, secrets=secrets, replace=replace)

    def update_entry(self, entry: Entry, *, secrets: SecretInput | None = None) -> Entry:
        return self._manager().update_entry(entry, secrets=secrets)

    def bulk_create(self, items: Iterable[tuple[Entry, SecretInput | None]]) -> list[Entry]:
        return self._manager().bulk_create(items)

    def delete_entry(self, name_or_id: str, *, cascade: bool = False) -> DeleteResult:
        return self._manager().delete_entry(name_or_id, cascade=cascade)

    def apply_snapshot(self, entries: list[Entry], tombstones: list[dict], *,
                       secret_writes: Mapping[str, str], secret_deletes: Iterable[str],
                       expected_revision: str) -> None:
        self._manager().apply_snapshot(
            entries, tombstones, secret_writes=secret_writes,
            secret_deletes=secret_deletes, expected_revision=expected_revision)

    @staticmethod
    def _rollback_or_raise(undo: _BackendUndo, cause: BaseException) -> None:
        try:
            undo.rollback()
        except IncompleteRollback as rollback_error:
            raise rollback_error from cause
