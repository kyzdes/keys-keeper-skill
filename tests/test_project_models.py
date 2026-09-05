import pytest

from keys_keeper.project_models import CatalogState, CatalogValidationError, Folder, Project, Scope, ScopeEntry, default_export_config, new_catalog_id


def test_catalog_accepts_explicit_scope_entry_binding():
    project = Project(id=new_catalog_id(), slug="alice", name="Alice")
    scope = Scope(id=new_catalog_id(), project_id=project.id, environment="dev", vault_id=new_catalog_id())
    binding = ScopeEntry(
        scope_id=scope.id,
        entry_id="kk:11111111-1111-4111-8111-111111111111",
        local_name="alice-api",
        export=default_export_config(),
        approval_revision="a" * 64,
    )
    catalog = CatalogState(projects=[project], scopes=[scope], bindings=[binding])
    assert CatalogState.from_dict(catalog.to_dict(), entry_ids={binding.entry_id}) == catalog


def test_catalog_rejects_folder_cycle_and_missing_binding_entry():
    first = new_catalog_id()
    second = new_catalog_id()
    cyclic = {
        "folders": [
            Folder(id=first, name="first", parent_id=second).to_dict(),
            Folder(id=second, name="second", parent_id=first).to_dict(),
        ],
        "projects": [], "scopes": [], "bindings": [], "dedup": [], "publication_intents": [],
    }
    with pytest.raises(CatalogValidationError, match="cycle"):
        CatalogState.from_dict(cyclic, entry_ids=set())

    project = Project(id=new_catalog_id(), slug="one", name="One")
    scope = Scope(id=new_catalog_id(), project_id=project.id, environment="dev", vault_id=new_catalog_id())
    missing = ScopeEntry(scope.id, "kk:11111111-1111-4111-8111-111111111111", "missing", default_export_config(), "a" * 64)
    with pytest.raises(CatalogValidationError, match="missing entry"):
        CatalogState.from_dict(CatalogState(projects=[project], scopes=[scope], bindings=[missing]).to_dict(), entry_ids=set())


def test_binding_export_is_an_explicit_allowlist_not_folder_or_tags():
    config = default_export_config()
    assert config == {"fields": [], "note": False, "refs": False, "tags": False}
    with pytest.raises(CatalogValidationError, match="exactly fields"):
        ScopeEntry.from_dict({
            "scope_id": new_catalog_id(), "entry_id": "kk:11111111-1111-4111-8111-111111111111",
            "local_name": "item", "export": {**config, "folder": True}, "approval_revision": "a" * 64,
        })
