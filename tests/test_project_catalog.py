import pytest

from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.project_service import ArchivedProjectError, LocalOnlyError, ProjectAmbiguousError, ProjectCatalogError, ProjectService
from keys_keeper.store import MetadataStore


@pytest.fixture
def project_store(kk_home):
    paths = Paths(); paths.ensure()
    store = MetadataStore(paths)
    store.add(Entry.new(name="one-key", type=EntryType.API_KEY))
    store.migrate_catalog_v3()
    return store


def test_folder_move_never_changes_explicit_scope_grants(project_store):
    service = ProjectService(project_store)
    old_folder = service.list_folders()[0]
    new_folder = service.create_folder("Work")
    project = service.create_project("alice", "Alice")
    scope = service.create_scope(project.id)
    entry = project_store.list()[0]
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(scope.id, entry.id)
    before = service.list_bindings(scope_id=scope.id)

    service.move_folder(old_folder.id, parent_id=new_folder.id)
    assert service.list_bindings(scope_id=scope.id) == before


def test_private_default_requires_explicit_distribution_before_assign(project_store):
    service = ProjectService(project_store)
    project = service.create_project("alice", "Alice")
    scope = service.create_scope(project.id)
    entry = project_store.list()[0]
    with pytest.raises(LocalOnlyError):
        service.assign(scope.id, entry.id)
    assert service.list_bindings(scope_id=scope.id) == []


def test_repeated_project_slug_has_stable_ids_and_ambiguous_lookup_fails_closed(project_store):
    service = ProjectService(project_store)
    first = service.create_project("same", "First")
    second = service.create_project("same", "Second")
    assert first.id != second.id
    first_scope = service.create_scope(first.id, "dev")
    service.create_scope(second.id, "dev")
    assert service.get_scope(first_scope.id) == first_scope
    with pytest.raises(ProjectAmbiguousError):
        service.get_scope(project_slug="same", environment="dev")


def test_folder_rename_delete_requires_destination_and_never_changes_bindings(project_store):
    service = ProjectService(project_store)
    original = service.list_folders()[0]
    destination = service.create_folder("Destination")
    entry = project_store.list()[0]
    with project_store.transaction() as tx:
        current = tx.get_by_id(entry.id); current.folder_id = original.id; tx.update(current)
    project = service.create_project("move", "Move")
    scope = service.create_scope(project.id)
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(scope.id, entry.id)
    before = service.list_bindings()
    assert service.rename_folder(original.id, "Renamed").name == "Renamed"
    with pytest.raises(ProjectCatalogError, match="explicit destination"):
        service.delete_folder(original.id)
    service.delete_folder(original.id, destination_id=destination.id)
    assert project_store.get_by_id(entry.id).folder_id == destination.id
    assert service.list_bindings() == before


def test_assignment_lifecycle_queues_desired_intents_and_archived_rejects_new_work(project_store):
    service = ProjectService(project_store)
    project = service.create_project("archive", "Archive")
    scope = service.create_scope(project.id)
    entry = project_store.list()[0]
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(scope.id, entry.id)
    service.set_entry_distribution(entry.id, "local_only")
    service.unassign(scope.id, entry.id)
    intents = project_store.catalog_state()["publication_intents"]
    assert [(item["scope_id"], item["entry_id"]) for item in intents] == [(scope.id, entry.id)]
    assert intents[0]["reason"] == "entry_unassigned"
    assert intents[0]["desired_revision"] > intents[0]["applied_revision"]
    service.list_projects(); service.list_scopes(); service.list_bindings()
    assert project_store.catalog_state()["publication_intents"] == intents
    service.archive_project(project.id)
    with pytest.raises(ArchivedProjectError):
        service.create_scope(project.id, "new")
    with pytest.raises(ArchivedProjectError):
        service.assign(scope.id, entry.id)


def test_publication_capture_and_ack_preserve_a_newer_desired_revision(project_store):
    service = ProjectService(project_store)
    project = service.create_project("publish", "Publish")
    scope = service.create_scope(project.id)
    entry = project_store.list()[0]
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(scope.id, entry.id)
    captured = service.capture_publications(scope.id)
    assert captured == {entry.id: 1}

    # A new desired state arrives after the engine captured its publication.
    service.set_entry_distribution(entry.id, "local_only")
    service.mark_publications_applied(scope.id, captured)
    intent = service.publication_intents(scope_id=scope.id)[0]
    assert intent["desired_revision"] > captured[entry.id]
    assert intent["applied_revision"] == captured[entry.id]


def test_publication_capture_compacts_legacy_drafts_without_lowering_highwater(project_store):
    service = ProjectService(project_store)
    project = service.create_project("legacy", "Legacy")
    scope = service.create_scope(project.id)
    entry = project_store.list()[0]
    with project_store.transaction() as tx:
        catalog = tx.catalog_state()
        catalog["publication_intents"] = [
            {"scope_id": scope.id, "entry_id": entry.id, "reason": "old"},
            {"scope_id": scope.id, "entry_id": entry.id, "reason": "new", "desired_revision": 9, "applied_revision": 4},
        ]
        tx.set_catalog_state(catalog)

    assert service.capture_publications(scope.id) == {entry.id: 10}
    intent = project_store.catalog_state()["publication_intents"]
    assert intent == [{"scope_id": scope.id, "entry_id": entry.id, "reason": "new", "desired_revision": 10, "applied_revision": 4}]
