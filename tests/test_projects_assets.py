from pathlib import Path


ROOT = Path(__file__).parents[1] / "src" / "keys_keeper"


def test_projects_assets_use_safe_client_rendering_and_delivery_status_controls():
    script = (ROOT / "static" / "projects.js").read_text()
    template = (ROOT / "templates" / "projects.html").read_text()
    assert "textContent" in script
    assert ".innerHTML" not in script
    assert "/api/project-sync/status" in script
    assert "/api/project-sync/revoke" in script
    assert "cannot be erased" in script
    assert "const safe = action" in script
    assert "catalog-message" in script
    assert "source_revision.slice" not in script
    assert "Available to selected projects" in script
    assert "/api/projects/entries/${encodeURIComponent(entry.id)}/folder" in script
    assert "Move here" in script
    assert "Assigned scopes:" in script
    assert "<h2>Delivery</h2>" in template
    assert 'id="catalog-message"' in template
    assert "projects.js" in template
