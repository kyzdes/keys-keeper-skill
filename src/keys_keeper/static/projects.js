(() => {
  const $ = id => document.getElementById(id);
  const state = { data: null, delivery: null, selectedScope: null, selectedFolder: null };
  const withProfile = path => {
    const selected = new URLSearchParams(window.location.search);
    const query = new URLSearchParams();
    for (const key of ['profile', 'project', 'env']) if (selected.has(key)) query.set(key, selected.get(key));
    if (!query.size) return path;
    return `${path}${path.includes('?') ? '&' : '?'}${query}`;
  };
  const api = async (path, options = {}) => {
    const response = await fetch(withProfile(path), options);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
    return body;
  };
  const post = data => ({ method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
  const patch = data => ({ method: 'PATCH', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data) });
  const text = value => document.createTextNode(String(value ?? ''));
  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (key === 'class') node.className = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    node.append(...children.flat().map(child => typeof child === 'string' ? text(child) : child));
    return node;
  };
  const message = value => {
    const safeValue = value || '';
    $('catalog-message').textContent = safeValue;
    $('delivery-message').textContent = safeValue;
  };
  const safe = action => async (...args) => {
    try { await action(...args); }
    catch (error) { message(error?.message || 'That action could not be completed.'); }
  };
  const refresh = async () => {
    const [data, delivery] = await Promise.all([api('/api/projects'), api('/api/project-sync/status')]);
    state.data = data; state.delivery = delivery; render();
  };
  const selected = () => state.data.catalog.scopes.find(item => item.id === state.selectedScope) || null;
  const runSync = async scopeId => {
    message('Synchronizing selected profile…');
    await api('/api/project-sync/sync', post(scopeId ? {scope_id: scopeId} : {}));
    message('Synchronization completed. Refreshing status…'); await refresh();
  };
  const preview = async scopeId => {
    const data = await api(`/api/project-sync/preview?scope=${encodeURIComponent(scopeId)}`);
    message(`${data.count} selected entries · ${data.recipients.length} active recipients.`);
  };
  const initializeScope = async scope => {
    const endpoint = prompt(`Delivery endpoint for ${scope.environment}`);
    if (!endpoint) return;
    const adminTokenEntry = prompt('Existing master entry name or ID containing the project-server admin token');
    if (!adminTokenEntry) return;
    message('Initializing scope with the selected token entry…');
    const result = await api('/api/project-sync/initialize', post({scope_id: scope.id, endpoint, admin_token_entry: adminTokenEntry}));
    message(`Scope initialized. Public fingerprint: ${result.result.fingerprint}`); await refresh();
  };
  const copyFingerprint = async value => {
    try { await navigator.clipboard.writeText(value); message('Public fingerprint copied to clipboard.'); }
    catch { message('Could not copy fingerprint.'); }
  };
  const roleLabel = role => role === 'contributor' ? 'Read and create' : 'Read only';
  const distributionLabel = value => value === 'project_allowed' ? 'Available to selected projects' : 'Private to this device';
  const waitingSummary = profile => {
    const updates = Number(profile.publication_pending || 0);
    const newKeys = Number(profile.pending || 0);
    const pieces = [];
    if (updates) pieces.push(`${updates} update${updates === 1 ? '' : 's'} waiting`);
    if (newKeys) pieces.push(`${newKeys} new key${newKeys === 1 ? '' : 's'} awaiting upload`);
    return pieces.length ? pieces.join(' · ') : 'Up to date';
  };
  function render() {
    const enabled = state.data.enabled;
    $('catalog-enable').hidden = enabled;
    $('projects-grid').hidden = !enabled;
    $('catalog-status').textContent = enabled ? 'Local catalog enabled' : (state.data.profile ? 'Catalog is managed by the master profile.' : 'Catalog disabled');
    renderDelivery();
    if (!enabled) return;
    renderFolders(); renderProjects(); renderScope();
  }
  function recipientRows(profile, mount) {
    (profile.recipients || []).forEach((recipient, index) => {
      const revoke = el('button', {class:'btn btn-sm', type:'button', onclick: safe(async () => {
        if (!confirm(`Remove access for this device? It will lose future access after a rekey, but material already held on that device cannot be erased.`)) return;
        const result = await api('/api/project-sync/revoke', post({scope_id: profile.scope_id, device_id: recipient.device_id}));
        message(`${result.warning} Rekey: ${result.result.rekey || 'pending'}.`); await refresh();
      })}, 'Remove access');
      mount.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, `Connected device ${index + 1}`), el('span', {class:'catalog-meta'}, roleLabel(recipient.role))), revoke));
    });
  }
  function renderDelivery() {
    const mount = $('delivery-status'); mount.replaceChildren();
    const delivery = state.delivery || {};
    if (delivery.profile) {
      const profile = delivery.profile;
      mount.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, `${profile.project} / ${profile.environment}`), el('span', {class:'catalog-meta'}, waitingSummary(profile))), el('button', {class:'btn btn-primary btn-sm', type:'button', onclick: safe(() => runSync(null))}, 'Sync now')));
      if (profile.fingerprint) mount.append(el('button', {class:'link-button', type:'button', onclick: () => copyFingerprint(profile.fingerprint)}, 'Copy public fingerprint'));
      mount.append(el('p', {class:'catalog-meta'}, 'Worker enrollment remains CLI-led: receive an invitation, verify its public fingerprint independently, then use join / approve / finish.'));
      return;
    }
    const profiles = delivery.profiles || [];
    if (!profiles.length) mount.append(el('p', {class:'catalog-meta'}, 'No configured delivery profile. Create the catalog with a recovery-backed migration, then initialize a scope with an existing admin-token entry.'));
    for (const profile of profiles) {
      const card = el('div', {class:'project-item'}, el('strong', {}, `${profile.project} / ${profile.environment}`), el('span', {class:'catalog-meta'}, waitingSummary(profile)));
      const actions = el('div', {class:'row', style:'gap:8px;flex-wrap:wrap'});
      actions.append(el('button', {class:'btn btn-primary btn-sm', type:'button', onclick: safe(() => runSync(profile.profile_id))}, 'Sync now'));
      actions.append(el('button', {class:'btn btn-sm', type:'button', onclick: safe(() => preview(profile.profile_id))}, 'Preview'));
      if (profile.fingerprint) actions.append(el('button', {class:'link-button', type:'button', onclick: () => copyFingerprint(profile.fingerprint)}, 'Copy public fingerprint'));
      card.append(actions);
      recipientRows(profile, card);
      mount.append(card);
    }
    if (state.data.enabled) {
      const configured = new Set(profiles.map(profile => profile.scope_id));
      for (const scope of state.data.catalog.scopes.filter(item => !configured.has(item.id))) {
        mount.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, `Set up ${scope.environment}`), el('span', {class:'catalog-meta'}, 'Connect this environment to a delivery endpoint.')), el('button', {class:'btn btn-sm', type:'button', onclick: safe(() => initializeScope(scope))}, 'Set up')));
      }
    }
    const union = delivery.device_union || {};
    const devices = Object.entries(union);
    if (devices.length) {
      const block = el('div', {class:'scope-preview'}, el('strong', {}, 'Effective device access'));
      devices.forEach(([, grants], index) => block.append(el('div', {class:'catalog-meta'}, `Device ${index + 1}: ${grants.map(grant => `${grant.project} / ${grant.environment} (${roleLabel(grant.role)})`).join(', ')}.`)));
      mount.append(block);
    }
    mount.append(el('p', {class:'catalog-meta'}, 'Onboarding stays CLI-led: keys project-sync invite → join → approve → finish. The fingerprint shown here is public; do not paste invitation bundles into chat.'));
  }
  function renderFolders() {
    const mount = $('folder-tree'); mount.replaceChildren();
    const byParent = new Map();
    for (const folder of state.data.catalog.folders) {
      const list = byParent.get(folder.parent_id) || []; list.push(folder); byParent.set(folder.parent_id, list);
    }
    if (!state.selectedFolder || !state.data.catalog.folders.some(folder => folder.id === state.selectedFolder)) state.selectedFolder = state.data.catalog.folders[0]?.id || null;
    const chooseFolder = (promptText, currentId = null) => {
      const choices = state.data.catalog.folders.filter(folder => folder.id !== currentId).map(folder => folder.name);
      const answer = prompt(`${promptText}\nType a folder name, or Top level.\nAvailable: ${choices.join(', ')}`, 'Top level');
      if (answer === null) return undefined;
      if (answer.trim().toLowerCase() === 'top level') return null;
      const match = state.data.catalog.folders.find(folder => folder.id !== currentId && folder.name === answer.trim());
      if (!match) { message('Choose one of the listed folder names.'); return undefined; }
      return match.id;
    };
    const add = (parent, depth) => (byParent.get(parent) || []).forEach(folder => {
      const select = el('button', {class:'scope-choice', type:'button', 'aria-pressed': String(folder.id === state.selectedFolder), onclick: () => { state.selectedFolder = folder.id; renderFolders(); }}, folder.name);
      const move = el('button', {class:'link-button', type:'button', onclick: safe(async () => {
        const parentId = chooseFolder(`Move ${folder.name} into which folder?`, folder.id);
        if (parentId === undefined) return;
        await api(`/api/projects/folders/${encodeURIComponent(folder.id)}`, patch({parent_id: parentId})); await refresh();
      })}, 'Move folder');
      mount.append(el('div', {class:'catalog-row', style:`padding-left:${depth * 18}px`}, el('div', {}, select), move));
      add(folder.id, depth + 1);
    });
    add(null, 0);
    const active = state.data.catalog.folders.find(folder => folder.id === state.selectedFolder);
    $('folder-label').textContent = active ? `Keys in ${active.name}` : 'Choose a folder to organize keys.';
    const entries = $('folder-entries'); entries.replaceChildren();
    if (!active) return;
    const inFolder = state.data.entries.filter(entry => entry.folder_id === active.id);
    for (const entry of inFolder) entries.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, entry.name), el('span', {class:'catalog-meta'}, entry.type))));
    for (const entry of state.data.entries.filter(entry => entry.folder_id !== active.id)) {
      entries.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, entry.name), el('span', {class:'catalog-meta'}, 'Move into this folder')), el('button', {class:'btn btn-sm', type:'button', onclick: safe(async () => {
        await api(`/api/projects/entries/${encodeURIComponent(entry.id)}/folder`, patch({folder_id: active.id})); await refresh();
      })}, 'Move here')));
    }
  }
  function renderProjects() {
    const mount = $('project-list'); mount.replaceChildren();
    for (const project of state.data.catalog.projects) {
      const scopes = state.data.catalog.scopes.filter(scope => scope.project_id === project.id);
      const block = el('div', {class:'project-item'}, el('strong', {}, project.name));
      for (const scope of scopes) block.append(el('button', {class:'scope-choice', type:'button', 'aria-pressed': String(scope.id === state.selectedScope), onclick: () => {state.selectedScope = scope.id; renderScope();}}, scope.environment));
      block.append(el('button', {class:'link-button', type:'button', onclick: safe(async () => { const environment = prompt('Environment name', 'default'); if (environment) { await api('/api/projects/scopes', post({project_id: project.id, environment})); await refresh(); }})}, 'Add environment'));
      mount.append(block);
    }
  }
  function renderScope() {
    const mount = $('scope-entries'); mount.replaceChildren(); const scope = selected();
    if (!scope) { $('scope-label').textContent = 'Choose an environment to manage its explicit entries.'; return; }
    $('scope-label').textContent = `${scope.environment} · explicit assignments only`;
    const assigned = new Set(state.data.catalog.bindings.filter(item => item.scope_id === scope.id).map(item => item.entry_id));
    for (const entry of state.data.entries) {
      const isAssigned = assigned.has(entry.id);
      const usages = state.data.shared_usages[entry.id] || [];
      const usageLabel = usages.length ? `Assigned scopes: ${usages.map(item => `${item.project_slug}/${item.environment}`).join(', ')}` : 'Not assigned to a scope';
      const button = el('button', {class: isAssigned ? 'btn btn-sm' : 'btn btn-primary btn-sm', type:'button', onclick: safe(async () => {
        if (isAssigned) { await api(`/api/projects/bindings/${encodeURIComponent(scope.id)}/${encodeURIComponent(entry.id)}`, {method:'DELETE'}); }
        else if (entry.distribution === 'local_only') {
          if (!confirm(`Allow ${entry.name} to be assigned to projects? This changes only local metadata; it does not deliver a secret.`)) return;
          await api(`/api/projects/entries/${encodeURIComponent(entry.id)}/distribution`, patch({distribution:'project_allowed'}));
          await api('/api/projects/bindings', post({scope_id:scope.id, entry_id:entry.id}));
        } else await api('/api/projects/bindings', post({scope_id:scope.id, entry_id:entry.id}));
        await refresh();
      })}, isAssigned ? 'Remove' : entry.distribution === 'local_only' ? 'Allow & add' : 'Add');
      mount.append(el('div', {class:'catalog-row'}, el('div', {}, el('strong', {}, entry.name), el('span', {class:'catalog-meta'}, `${entry.type} · ${distributionLabel(entry.distribution)}`), el('span', {class:'catalog-meta'}, usageLabel)), button));
    }
  }
  $('folder-create').addEventListener('click', safe(async () => { const name = prompt('Folder name'); if (name) { await api('/api/projects/folders', post({name, parent_id: state.selectedFolder})); await refresh(); }}));
  $('project-create').addEventListener('click', safe(async () => { const slug = prompt('Project slug'); const name = slug && prompt('Project name', slug); if (slug && name) { await api('/api/projects', post({slug,name})); await refresh(); }}));
  refresh().catch(error => { $('catalog-status').textContent = error.message; message(error.message); });
})();
