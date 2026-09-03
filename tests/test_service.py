from __future__ import annotations

import pytest

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.service import (
    ConcurrentMutation,
    HasDependents,
    IncompleteRollback,
    SecretInput,
    VaultService,
)
from keys_keeper.store import MetadataStore, NameConflict


class FaultBackend(KeychainBackend):
    def __init__(self, values: dict[str, str] | None = None):
        self.values = dict(values or {})
        self.fail_after: tuple[str, str] | None = None
        self.fail_rollback = False
        self._fault_fired = False

    def get(self, account: str) -> Sealed:
        if account not in self.values:
            raise KeychainError(f"missing: {account}")
        return Sealed(self.values[account])

    def set(self, account: str, value: str) -> None:
        self.values[account] = value
        if self._should_fail("set", account):
            raise KeychainError("injected set failure")
        if self.fail_rollback and self._fault_fired:
            raise KeychainError("injected rollback failure")

    def delete(self, account: str) -> None:
        self.values.pop(account, None)
        if self._should_fail("delete", account):
            raise KeychainError("injected delete failure")
        if self.fail_rollback and self._fault_fired:
            raise KeychainError("injected rollback failure")

    def list_ids(self) -> list[str]:
        return list(self.values)

    def _should_fail(self, operation: str, account: str) -> bool:
        if not self._fault_fired and self.fail_after == (operation, account):
            self._fault_fired = True
            return True
        return False


@pytest.fixture
def service_env(kk_home):
    paths = Paths()
    paths.ensure()
    store = MetadataStore(paths)
    backend = FaultBackend()
    return store, backend, VaultService(store, backend)


def _entry(name: str) -> Entry:
    return Entry.new(name=name, type=EntryType.API_KEY, fields={})


def test_secret_inputs_never_render_plaintext():
    secret = SecretInput(value="sentinel-value", passphrase="sentinel-passphrase")

    rendered = repr(secret)
    assert "sentinel-value" not in rendered
    assert "sentinel-passphrase" not in rendered


def test_create_rolls_back_backend_failure_after_write(service_env):
    store, backend, service = service_env
    entry = _entry("create-fail")
    backend.fail_after = ("set", entry.id)

    with pytest.raises(KeychainError, match="injected set failure"):
        service.create_entry(entry, secrets=SecretInput(value="sentinel-new"))

    assert store.get_by_name(entry.name) is None
    assert entry.id not in backend.values


def test_create_rolls_back_keyboard_interrupt_after_write(service_env, monkeypatch):
    store, backend, service = service_env
    entry = _entry("create-interrupt")
    original_set = backend.set
    interrupted = False

    def interrupt_once(account, value):
        nonlocal interrupted
        original_set(account, value)
        if not interrupted:
            interrupted = True
            raise KeyboardInterrupt()

    monkeypatch.setattr(backend, "set", interrupt_once)
    with pytest.raises(KeyboardInterrupt):
        service.create_entry(entry, secrets=SecretInput(value="sentinel-new"))

    assert store.get_by_name(entry.name) is None
    assert entry.id not in backend.values


def test_create_rolls_back_when_metadata_commit_fails(service_env, monkeypatch):
    store, backend, service = service_env
    entry = _entry("commit-fail")

    def fail_commit(_data):
        raise OSError("injected metadata failure")

    monkeypatch.setattr(store, "_atomic_write", fail_commit)
    with pytest.raises(OSError, match="injected metadata failure"):
        service.create_entry(entry, secrets=SecretInput(value="sentinel-new"))

    assert store.get_by_name(entry.name) is None
    assert entry.id not in backend.values


def test_update_restores_old_secret_and_metadata(service_env):
    store, backend, service = service_env
    entry = _entry("update-fail")
    service.create_entry(entry, secrets=SecretInput(value="sentinel-old"))
    changed = store.get_by_name(entry.name)
    changed.note = "new note"
    backend.fail_after = ("set", entry.id)

    with pytest.raises(KeychainError, match="injected set failure"):
        service.update_entry(changed, secrets=SecretInput(value="sentinel-new"))

    assert store.get_by_name(entry.name).note == ""
    assert backend.values[entry.id] == "sentinel-old"


def test_delete_failure_restores_secrets_and_cascade_metadata(service_env):
    store, backend, service = service_env
    parent = _entry("delete-parent")
    service.create_entry(
        parent,
        secrets=SecretInput(value="sentinel-main", passphrase="sentinel-passphrase"),
    )
    child = Entry.new(
        name="delete-child",
        type=EntryType.SERVER,
        fields={"host": "example.test", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": parent.name}],
    )
    store.add(child)
    backend.fail_after = ("delete", parent.id + ":passphrase")

    with pytest.raises(KeychainError, match="injected delete failure"):
        service.delete_entry(parent.id, cascade=True)

    assert store.get_by_name(parent.name) is not None
    assert store.get_by_name(child.name).refs == [
        {"role": "ssh_key", "name": parent.name}
    ]
    assert backend.values[parent.id] == "sentinel-main"
    assert backend.values[parent.id + ":passphrase"] == "sentinel-passphrase"


def test_delete_reports_dependents_without_mutation(service_env):
    store, backend, service = service_env
    parent = _entry("used-parent")
    service.create_entry(parent, secrets=SecretInput(value="sentinel-main"))
    child = Entry.new(
        name="used-child",
        type=EntryType.SERVER,
        fields={"host": "example.test", "user": "root", "auth": "ssh_key"},
        refs=[{"role": "ssh_key", "name": parent.name}],
    )
    store.add(child)

    with pytest.raises(HasDependents) as raised:
        service.delete_entry(parent.id)

    assert raised.value.dependents == [child.name]
    assert store.get_by_name(parent.name) is not None
    assert backend.values[parent.id] == "sentinel-main"


def test_bulk_create_is_all_or_nothing(service_env):
    store, backend, service = service_env
    first = _entry("bulk-first")
    second = _entry("bulk-second")
    backend.fail_after = ("set", second.id)

    with pytest.raises(KeychainError, match="injected set failure"):
        service.bulk_create(
            [
                (first, SecretInput(value="sentinel-one")),
                (second, SecretInput(value="sentinel-two")),
            ]
        )

    assert store.list() == []
    assert backend.values == {}


def test_bulk_create_rejects_duplicate_ids_without_mutation(service_env):
    store, backend, service = service_env
    first = _entry("duplicate-first")
    second = _entry("duplicate-second")
    second.id = first.id

    with pytest.raises(NameConflict, match="entry with id"):
        service.bulk_create(
            [
                (first, SecretInput(value="sentinel-one")),
                (second, SecretInput(value="sentinel-two")),
            ]
        )

    assert store.list() == []
    assert backend.values == {}


def test_snapshot_failure_restores_overwritten_and_deleted_values(service_env):
    store, backend, service = service_env
    first = _entry("snapshot-first")
    second = _entry("snapshot-second")
    service.bulk_create(
        [
            (first, SecretInput(value="sentinel-old-one")),
            (second, SecretInput(value="sentinel-old-two")),
        ]
    )
    replacement = Entry.from_dict({**first.to_dict(), "note": "remote"})
    backend.fail_after = ("delete", second.id)
    revision = store.snapshot().revision

    with pytest.raises(KeychainError, match="injected delete failure"):
        service.apply_snapshot(
            [replacement],
            [],
            secret_writes={first.id: "sentinel-remote-one"},
            secret_deletes=[second.id],
            expected_revision=revision,
        )

    assert [entry.to_dict() for entry in store.list()] == [
        first.to_dict(),
        second.to_dict(),
    ]
    assert backend.values[first.id] == "sentinel-old-one"
    assert backend.values[second.id] == "sentinel-old-two"


def test_snapshot_rejects_stale_revision_before_secret_mutation(service_env):
    store, backend, service = service_env
    first = _entry("revision-first")
    service.create_entry(first, secrets=SecretInput(value="sentinel-old"))
    stale = store.snapshot()
    concurrent = _entry("revision-concurrent")
    service.create_entry(concurrent, secrets=SecretInput(value="sentinel-concurrent"))

    with pytest.raises(ConcurrentMutation):
        service.apply_snapshot(
            stale.entries,
            stale.tombstones,
            secret_writes={first.id: "sentinel-new"},
            secret_deletes=[],
            expected_revision=stale.revision,
        )

    assert {entry.name for entry in store.list()} == {first.name, concurrent.name}
    assert backend.values[first.id] == "sentinel-old"
    assert backend.values[concurrent.id] == "sentinel-concurrent"


def test_snapshot_rejects_write_delete_overlap_before_mutation(service_env):
    store, backend, service = service_env
    entry = _entry("overlap-entry")
    service.create_entry(entry, secrets=SecretInput(value="sentinel-old"))
    snapshot = store.snapshot()

    with pytest.raises(ValueError, match="written and deleted"):
        service.apply_snapshot(
            snapshot.entries,
            snapshot.tombstones,
            secret_writes={entry.id: "sentinel-new"},
            secret_deletes=[entry.id],
            expected_revision=snapshot.revision,
        )

    assert backend.values[entry.id] == "sentinel-old"
    assert store.get_by_name(entry.name) is not None


def test_failed_compensation_is_reported_explicitly(service_env):
    store, backend, service = service_env
    entry = _entry("rollback-fail")
    backend.fail_after = ("set", entry.id)
    backend.fail_rollback = True

    with pytest.raises(IncompleteRollback) as raised:
        service.create_entry(entry, secrets=SecretInput(value="sentinel-new"))

    assert raised.value.failed_accounts == 1
    assert store.get_by_name(entry.name) is None
