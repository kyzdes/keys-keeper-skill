// Run the actual admin script and form event handlers in an isolated DOM.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const script = fs.readFileSync(process.argv[2], 'utf8');

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase(); this.children = []; this.events = {};
    this.dataset = {}; this.value = ''; this.style = {}; this.textContent = '';
    this.classList = {add() {}, remove() {}, contains() { return false; }};
  }
  append(...nodes) { this.children.push(...nodes); }
  set value(value) { this._value = String(value); }
  get value() { return this._value; }
  replaceChildren(...nodes) { this.children = nodes; }
  set innerHTML(_value) { this.children = []; }
  setAttribute(name, value) { this[name] = value; }
  addEventListener(name, callback) { this.events[name] = callback; }
  focus() {}
  remove() {}
}

async function form(type, values, editing = null) {
  const body = new Element('body'); body.dataset.profileKind = 'master';
  const modal = new Element(); modal.dataset.editId = editing ? 'synthetic-id' : '';
  const ids = ['delete-dialog', 'delete-confirm', 'delete-cascade', 'delete-close',
    'delete-cancel', 'cmdk-input', 'f-name', 'f-tags', 'f-note',
    'type-specific-fields', 'save-btn', 'form-error'];
  for (const id of ids) { const element = new Element(); element.id = id; body.append(element); }
  function find(node, id) {
    if (node.id === id) return node;
    for (const child of node.children) {
      if (child instanceof Element) { const found = find(child, id); if (found) return found; }
    }
    return null;
  }
  const document = {body, documentElement: {dataset: {theme: 'dark'}},
    getElementById: id => find(body, id), createElement: tag => new Element(tag),
    createTextNode: text => text, addEventListener() {},
    querySelectorAll: () => [],
    querySelector: selector => selector === '.new-modal' ? modal :
      selector === '.type-card.selected' ? {dataset: {type}} : null,
  };
  const calls = [];
  const location = {search: '', href: ''};
  const context = {document, Node: Element, URLSearchParams, location,
    window: {location}, setInterval() {}, setTimeout() {}, clearTimeout() {},
    fetch: async (path, options = {}) => {
      if (!options.method) return {ok: true, json: async () => editing};
      calls.push({path, payload: JSON.parse(options.body)});
      return {ok: true, json: async () => ({id: 'synthetic-id', committed: true, audit_status: 'recorded'})};
    },
  };
  vm.runInNewContext(script, context);
  await new Promise(resolve => setImmediate(resolve));
  for (const [name, value] of Object.entries(values)) {
    const element = document.getElementById('f-' + name);
    assert.ok(element, 'missing field ' + name + ' for ' + type);
    element.value = value;
    if (element.events.change) element.events.change();
    if (element.events.input) element.events.input();
  }
  await document.getElementById('save-btn').onclick();
  assert.equal(calls.length, 1, document.getElementById('form-error').textContent);
  const secretField = document.getElementById('f-value') || document.getElementById('f-private_key')
    || (document.getElementById('f-note-storage')?.value === 'secret' && document.getElementById('f-body'));
  return {payload: calls[0].payload, secret_field_cleared: !secretField || secretField.value === ''};
}

(async () => {
  const cases = [
    ['api_key', {name: 'browser-api', service: 'synthetic', value: 'synthetic-api'}],
    ['ssh_key', {name: 'browser-ssh', public_key: 'ssh-ed25519 synthetic', private_key: 'synthetic-private-key'}],
    ['server', {name: 'browser-server', host: 'synthetic.example', user: 'root', auth: 'ssh_key'}],
    ['server', {name: 'browser-password', host: 'synthetic.example', user: 'root', auth: 'password', value: 'synthetic-password'}],
    ['domain', {name: 'browser-domain', host: 'synthetic.example', registrar: 'synthetic'}],
    ['note', {name: 'browser-secret-note', 'note-storage': 'secret', body: 'synthetic-sensitive-note'}],
    ['note', {name: 'browser-public-note', 'note-storage': 'public', body: '  public\nbody  '}],
  ];
  const forms = [];
  for (const [type, values] of cases) {
    const created = await form(type, values);
    const editing = {...created.payload, id: 'synthetic-id'};
    const edited = await form(type, {tags: 'edited', note: 'public description'}, editing);
    assert.ok(!('name' in edited.payload) && !('type' in edited.payload) && !('value' in edited.payload));
    forms.push({...created, edit_payload: edited.payload});
  }
  process.stdout.write(JSON.stringify(forms));
})().catch(error => { console.error(error); process.exitCode = 1; });
