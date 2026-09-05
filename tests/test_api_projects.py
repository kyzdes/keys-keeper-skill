from keys_keeper import api
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.project_service import ProjectService
from keys_keeper.store import MetadataStore


class _Handler:
    def __init__(self): self.responses = []
    def _send_json(self, status, body): self.responses.append((status, body))


def test_project_api_reports_disabled_catalog_without_migrating(kk_home):
    handler = _Handler()
    api.handle_api(handler, paths=Paths(), method="GET", path="/api/projects", body=None)
    assert handler.responses == [(200, {"enabled": False, "schema_version": 2})]
    assert not Paths().data_json.exists()


def test_project_api_does_not_migrate_without_a_recovery_backup(kk_home):
    handler = _Handler()
    api.handle_api(handler, paths=Paths(), method="POST", path="/api/projects/init", body=b"{}")
    status, payload = handler.responses[-1]
    assert status == 409
    assert "project-sync migrate" in payload["error"]
    assert not Paths().data_json.exists()


def test_project_api_exposes_explicit_shared_scope_usages_not_recipients(kk_home):
    store = MetadataStore(Paths())
    entry = Entry.new(name="shared-key", type=EntryType.API_KEY)
    store.add(entry)
    store.migrate_catalog_v3()
    service = ProjectService(store)
    alpha = service.create_project("alpha", "Alpha")
    beta = service.create_project("beta", "Beta")
    alpha_scope = service.create_scope(alpha.id, "dev")
    beta_scope = service.create_scope(beta.id, "prod")
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(beta_scope.id, entry.id)
    service.assign(alpha_scope.id, entry.id)

    handler = _Handler()
    api.handle_api(handler, paths=Paths(), method="GET", path="/api/projects", body=None)
    status, payload = handler.responses[-1]
    assert status == 200
    assert payload["shared_usages"] == {
        entry.id: [
            {"scope_id": alpha_scope.id, "project_id": alpha.id, "project_slug": "alpha",
             "project_name": "Alpha", "project_state": "active", "environment": "dev",
             "local_name": "shared-key"},
            {"scope_id": beta_scope.id, "project_id": beta.id, "project_slug": "beta",
             "project_name": "Beta", "project_state": "active", "environment": "prod",
             "local_name": "shared-key"},
        ]
    }
    assert payload["recipients"] == []


def test_project_api_moves_existing_entry_to_a_folder_without_changing_scope_bindings(kk_home):
    store = MetadataStore(Paths())
    entry = Entry.new(name="organized", type=EntryType.API_KEY)
    store.add(entry)
    store.migrate_catalog_v3()
    service = ProjectService(store)
    folder = service.create_folder("Work")
    project = service.create_project("alpha", "Alpha")
    scope = service.create_scope(project.id, "dev")
    service.set_entry_distribution(entry.id, "project_allowed")
    service.assign(scope.id, entry.id)

    handler = _Handler()
    api.handle_api(handler, paths=Paths(), method="PATCH",
                   path=f"/api/projects/entries/{entry.id}/folder",
                   body=(f'{{"folder_id":"{folder.id}"}}').encode())
    assert handler.responses[-1][0] == 200
    assert store.get_by_id(entry.id).folder_id == folder.id
    assert service.list_bindings(scope_id=scope.id)[0].entry_id == entry.id
