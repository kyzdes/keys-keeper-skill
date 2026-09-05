from __future__ import annotations

import pytest

from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.master_journal import MasterMutationManager
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_projection import ProjectionError, build_project_payload, preview_scope
from keys_keeper.project_service import ProjectService
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


class SpyBackend(KeychainBackend):
    def __init__(self, values: dict[str, str], *, denied: set[str] = frozenset()):
        self.values = dict(values)
        self.denied = set(denied)
        self.get_ids: list[str] = []

    def list_ids(self) -> list[str]: return list(self.values)
    def get(self, account: str) -> Sealed:
        self.get_ids.append(account)
        if account in self.denied or account not in self.values: raise KeychainError("unavailable")
        return Sealed(self.values[account])
    def set(self, account: str, value: str) -> None: self.values[account] = value
    def delete(self, account: str) -> None: self.values.pop(account, None)


def _store(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths); store.migrate_catalog_v3()
    return store


def _scope(store, slug="alice", environment="dev"):
    projects = ProjectService(store)
    project = projects.create_project(slug, slug.title())
    return projects, projects.create_scope(project.id, environment)


def _add(store, name, *, type_=EntryType.API_KEY, fields=None, refs=None, tags=None, note="", secret="v"):
    entry = Entry.new(name=name, type=type_, fields=fields or {}, refs=refs or [], tags=tags or [], note=note)
    store.add(entry)
    return entry, secret


def _assign(projects, scope, entry, **kwargs):
    projects.set_entry_distribution(entry.id, "project_allowed")
    projects.assign(scope.id, entry.id, **kwargs)


def _service(store: MetadataStore, backend: KeychainBackend) -> VaultService:
    journal = OperationJournal(
        paths=store.paths, password_provider=lambda: b"projection-test-runtime-key"
    )
    return VaultService(
        store,
        backend,
        master_mutations=MasterMutationManager(store, backend, journal),
    )


def test_projection_reads_only_selected_secret_and_excludes_private_metadata(kk_home):
    store = _store(kk_home); projects, scope = _scope(store)
    entry, secret = _add(store, "private-api", fields={"service": "private"}, tags=["private"], note="private note")
    other, _ = _add(store, "other-api", secret="other")
    _assign(projects, scope, entry)
    backend = SpyBackend({entry.id: secret, other.id: "other"})
    payload = build_project_payload(store, backend, scope.id)
    record = payload["entries"][0]
    assert backend.get_ids == [entry.id]
    assert record["secret"] == secret and record["fields"] == {}
    assert record["tags"] == [] and record["note"] == ""
    assert not {"folder_id", "distribution", "provenance", "content_revision"} & set(record)


def test_server_requires_explicit_ssh_key_closure_and_reads_only_key_secret(kk_home):
    store = _store(kk_home); projects, scope = _scope(store)
    key, secret = _add(store, "deploy-key", type_=EntryType.SSH_KEY, fields={"public_key": "ssh-ed25519 AAA"}, secret="private")
    server, _ = _add(store, "deploy-server", type_=EntryType.SERVER, fields={"host":"host.test", "user":"root", "auth":"ssh_key"}, refs=[{"role":"ssh_key", "name":key.name}], secret="unused")
    _assign(projects, scope, server)
    with pytest.raises(ProjectionError, match="explicitly included"):
        preview_scope(store, scope.id)
    _assign(projects, scope, key)
    payload = build_project_payload(store, SpyBackend({key.id: secret}), scope.id)
    assert {item["name"] for item in payload["entries"]} == {server.name, key.name}


def test_optional_out_of_scope_refs_are_omitted_without_global_lookup(kk_home):
    store = _store(kk_home); projects, scope = _scope(store)
    target, _ = _add(store, "optional-target")
    source, secret = _add(store, "optional-source", refs=[{"role":"helper", "name":target.name}])
    _assign(projects, scope, source, export={"refs": True})
    payload = build_project_payload(store, SpyBackend({source.id: secret}), scope.id)
    assert payload["entries"][0]["refs"] == []


@pytest.mark.parametrize("backend", [SpyBackend({}), SpyBackend({"placeholder": "x"}, denied={"placeholder"})])
def test_required_secret_missing_or_denied_blocks_whole_projection(kk_home, backend):
    store = _store(kk_home); projects, scope = _scope(store)
    entry, _ = _add(store, "needed")
    _assign(projects, scope, entry)
    backend.values = {entry.id: "v"} if backend.denied else {}
    backend.denied = {entry.id} if backend.denied else set()
    with pytest.raises(ProjectionError, match="unavailable|access failed"):
        build_project_payload(store, backend, scope.id)


def test_preview_stale_aliases_are_scope_local_and_cycles_fail_closed(kk_home):
    store = _store(kk_home); projects, scope_a = _scope(store, "a")
    project_b = projects.create_project("b", "B"); scope_b = projects.create_scope(project_b.id)
    first, first_secret = _add(store, "first")
    second, second_secret = _add(store, "second")
    _assign(projects, scope_a, first, local_name="shared")
    _assign(projects, scope_b, second, local_name="shared")
    assert build_project_payload(store, SpyBackend({first.id:first_secret}), scope_a.id)["entries"][0]["name"] == "shared"
    assert build_project_payload(store, SpyBackend({second.id:second_secret}), scope_b.id)["entries"][0]["name"] == "shared"
    preview = preview_scope(store, scope_a.id)
    first.tags.append("changed")
    _service(store, SpyBackend({first.id:first_secret})).update_entry(first, secrets=SecretInput(value="rotated"))
    with pytest.raises(ProjectionError, match="stale"):
        build_project_payload(store, SpyBackend({first.id:"rotated"}), scope_a.id, expected_revision=preview["source_revision"])

    third, third_secret = _add(store, "third", refs=[{"role":"next", "name":"fourth"}])
    fourth, fourth_secret = _add(store, "fourth", refs=[{"role":"next", "name":"third"}])
    cycle_scope = projects.create_scope(scope_a.project_id, "cycle")
    _assign(projects, cycle_scope, third, export={"refs": True})
    _assign(projects, cycle_scope, fourth, export={"refs": True})
    with pytest.raises(ProjectionError, match="cycle"):
        preview_scope(store, cycle_scope.id)


def test_shared_entry_update_changes_each_scope_projection(kk_home):
    store = _store(kk_home); projects, first = _scope(store, "shared")
    second = projects.create_scope(first.project_id, "prod")
    entry, _ = _add(store, "shared-key")
    _assign(projects, first, entry); _assign(projects, second, entry)
    before_a = preview_scope(store, first.id)["source_revision"]
    before_b = preview_scope(store, second.id)["source_revision"]
    current = store.get_by_id(entry.id)
    _service(store, SpyBackend({entry.id:"old"})).update_entry(current, secrets=SecretInput(value="new"))
    assert preview_scope(store, first.id)["source_revision"] != before_a
    assert preview_scope(store, second.id)["source_revision"] != before_b
