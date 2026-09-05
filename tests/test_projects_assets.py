from pathlib import Path
import shutil
import subprocess

import pytest


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
    assert 'id="folder-tools"' in template
    assert 'id="project-delivery-fallback"' in template
    assert 'role="group" aria-label="Environments"' in template
    assert "projects.js" in template
    css = (ROOT / "static" / "app.css").read_text()
    assert ".key-toolbar .catalog-search { width: 100%; flex: 0 1 auto; }" in css


def test_delivery_rendering_never_claims_remote_freshness_and_identifies_revoke_target():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to exercise the browser rendering code")
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor() { this.children = []; this.events = {}; this.textContent = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute() {}
  addEventListener(event, fn) { this.events[event] = fn; }
  get content() { return this.textContent + this.children.map(c => c instanceof Element ? c.content : c).join(''); }
}
const elements = new Map();
const document = {
  getElementById: id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement: () => new Element(), createTextNode: value => value,
};
const cases = [
  [{delivery: 'unavailable'}, 'Status unavailable'],
  [{status: 'enrolling'}, 'Setup incomplete'],
  [{delivery: 'pending'}, 'Synchronization pending'],
  [{checkpoint: null}, 'No verified snapshot yet'],
  [{outbox: [{status: 'conflict'}, {status: 'rejected'}, {status: 'quarantined'}]}, '3 submissions need attention'],
  [{pending: 1, outbox: [{status: 'accepted'}]}, '1 new key awaiting publication'],
  [{}, 'No pending local changes'],
];
const profiles = cases.map(([overrides], index) => ({
  project: `project-${index}`, environment: 'production', scope_id: `scope-${index}`,
  profile_id: `profile-${index}`, status: 'active', delivery: 'idle', checkpoint: {sequence: 1}, ...overrides,
}));
const deviceId = 'b7f2a3c4-1111-4222-8333-444444444444';
profiles[6].recipients = [{device_id: deviceId, role: 'contributor'}];
const calls = []; const confirmations = [];
const context = {
  document, URLSearchParams, window: {location: {search: ''}},
  confirm: message => { confirmations.push(message); return false; },
  fetch: async path => {
    calls.push(path);
    return {ok: true, json: async () => path === '/api/projects' ? {enabled: false} : {
      profiles, device_union: {[deviceId]: [{project: 'project-6', environment: 'production', role: 'contributor'}]},
    }};
  },
};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
setImmediate(async () => {
  const mount = elements.get('delivery-status-fallback');
  assert.equal(elements.get('project-delivery-fallback').hidden, false);
  cases.forEach(([, expected], index) => assert.ok(mount.children[index].content.includes(expected), expected));
  assert.ok(!mount.content.includes('Up to date'));
  assert.ok(mount.content.includes(deviceId));
  function findButton(element) {
    if (element.content === 'Remove access') return element;
    for (const child of element.children) if (child instanceof Element) { const match = findButton(child); if (match) return match; }
  }
  await findButton(mount).events.click();
  assert.equal(confirmations.length, 1);
  assert.ok(confirmations[0].includes(deviceId));
  assert.ok(confirmations[0].includes('project-6 / production'));
  assert.ok(!calls.some(path => path.includes('revoke')));
});
"""
    subprocess.run([node, "-e", harness, str(ROOT / "static" / "projects.js")], check=True, timeout=20)


def test_projects_default_to_one_scope_and_progressively_disclose_the_rest():
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required to exercise the browser rendering code")
    harness = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
class Element {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.events = {}; this.textContent = ''; this.attributes = {}; this.hidden = false; this.value = ''; }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = value; }
  addEventListener(event, fn) { this.events[event] = fn; }
  get content() { return this.textContent + this.children.map(c => c instanceof Element ? c.content : c).join(''); }
}
const elements = new Map();
const document = {
  getElementById: id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); },
  createElement: tag => new Element(tag), createTextNode: value => String(value),
};
const entries = [
  {id: 'entry-assigned', name: 'Assigned key', type: 'api_key', distribution: 'project_allowed'},
  {id: 'entry-available', name: 'Available key', type: 'api_key', distribution: 'project_allowed'},
];
const catalog = {
  folders: [],
  projects: [
    {id: 'project-north', slug: 'north', name: 'North'},
    {id: 'project-south', slug: 'south', name: 'South'},
  ],
  scopes: [
    {id: 'scope-north-prod', project_id: 'project-north', environment: 'production'},
    {id: 'scope-north-stage', project_id: 'project-north', environment: 'staging'},
    {id: 'scope-south-prod', project_id: 'project-south', environment: 'production'},
  ],
  bindings: [{scope_id: 'scope-north-prod', entry_id: 'entry-assigned'}],
};
const profiles = [
  {scope_id: 'scope-north-prod', profile_id: 'profile-north-prod', project: 'North', environment: 'production', status: 'active', delivery: 'idle', checkpoint: {sequence: 1}},
  {scope_id: 'scope-north-stage', profile_id: 'profile-north-stage', project: 'North', environment: 'staging', status: 'active', delivery: 'idle', checkpoint: {sequence: 1}},
  {scope_id: 'scope-south-prod', profile_id: 'profile-south-prod', project: 'South', environment: 'production', status: 'active', delivery: 'idle', checkpoint: {sequence: 1}},
];
const context = {
  document, URLSearchParams, window: {location: {search: ''}}, confirm: () => false,
  fetch: async path => ({ok: true, json: async () => path === '/api/projects'
    ? {enabled: true, catalog, entries, shared_usages: {}}
    : {profiles, device_union: {}}}),
};
vm.runInNewContext(fs.readFileSync(process.argv[1], 'utf8'), context);
setImmediate(() => {
  assert.ok(elements.get('project-list').content.includes('North'));
  assert.ok(elements.get('project-list').content.includes('South'));
  assert.ok(elements.get('scope-entries').content.includes('Assigned key'));
  assert.ok(!elements.get('scope-entries').content.includes('Available key'));
  assert.equal(elements.get('key-filter-assigned').attributes['aria-pressed'], 'true');
  assert.equal(elements.get('folder-tools').hidden, false);
  const delivery = elements.get('delivery-status');
  assert.ok(delivery.children[0].content.includes('North / production'));
  assert.ok(delivery.children.some(item => item instanceof Element && item.tag === 'details' && item.content.includes('Other delivery profiles (2)')));
  elements.get('key-filter-available').events.click();
  assert.ok(elements.get('scope-entries').content.includes('Available key'));
  assert.ok(!elements.get('scope-entries').content.includes('Assigned key'));
});
"""
    subprocess.run([node, "-e", harness, str(ROOT / "static" / "projects.js")], check=True, timeout=20)
