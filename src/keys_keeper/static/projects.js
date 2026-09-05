(() => {
  const $ = id => document.getElementById(id);
  const MAX_VISIBLE_ENTRIES = 60;
  const state = {
    data: null,
    delivery: null,
    selectedProject: null,
    selectedScope: null,
    selectedFolder: null,
    projectQuery: '',
    keyQuery: '',
    keyFilter: 'assigned',
    folderQuery: '',
  };

  const withProfile = path => {
    const selected = new URLSearchParams(window.location?.search || '');
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
  const normalized = value => String(value || '').trim().toLocaleLowerCase();
  const message = value => {
    const safeValue = value || '';
    $('catalog-message').textContent = safeValue;
    $('delivery-message').textContent = safeValue;
    $('delivery-message-fallback').textContent = safeValue;
  };
  const safe = action => async (...args) => {
    try { await action(...args); }
    catch (error) { message(error?.message || 'That action could not be completed.'); }
  };
  const catalog = () => state.data?.catalog || {folders: [], projects: [], scopes: [], bindings: []};
  const selectedProject = () => catalog().projects.find(item => item.id === state.selectedProject) || null;
  const selected = () => catalog().scopes.find(item => item.id === state.selectedScope) || null;
  const scopesFor = projectId => catalog().scopes.filter(item => item.project_id === projectId);
  const entryFolderId = entry => entry.folder_id || null;

  const refresh = async () => {
    const [data, delivery] = await Promise.all([api('/api/projects'), api('/api/project-sync/status')]);
    state.data = data;
    state.delivery = delivery;
    render();
  };
  const runSync = async scopeId => {
    message('Synchronizing selected profile…');
    await api('/api/project-sync/sync', post(scopeId ? {scope_id: scopeId} : {}));
    message('Synchronization completed. Refreshing status…');
    await refresh();
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
    message(`Scope initialized. Public fingerprint: ${result.result.fingerprint}`);
    await refresh();
  };
  const copyFingerprint = async value => {
    try { await navigator.clipboard.writeText(value); message('Public fingerprint copied to clipboard.'); }
    catch { message('Could not copy fingerprint.'); }
  };
  const roleLabel = role => role === 'contributor' ? 'Read and create' : 'Read only';
  const distributionLabel = value => value === 'project_allowed' ? 'Available to selected projects' : 'Private to this device';
  const waitingSummary = profile => {
    if (profile.delivery === 'unavailable') return 'Status unavailable · synchronization needs attention';
    if (profile.status && profile.status !== 'active') return 'Setup incomplete · synchronization pending';
    const updates = Number(profile.publication_pending || 0);
    const newKeys = Number(profile.pending || 0);
    const blocked = (profile.outbox || []).filter(item => ['conflict', 'rejected', 'quarantined'].includes(item.status)).length;
    const pieces = [];
    if (blocked) pieces.push(`${blocked} submission${blocked === 1 ? '' : 's'} need attention`);
    if (updates) pieces.push(`${updates} update${updates === 1 ? '' : 's'} waiting`);
    if (newKeys) pieces.push(`${newKeys} new key${newKeys === 1 ? '' : 's'} awaiting publication`);
    if (pieces.length) return pieces.join(' · ');
    if (profile.delivery === 'pending') return 'Synchronization pending';
    if (!profile.checkpoint) return 'No verified snapshot yet';
    return 'No pending local changes';
  };

  function ensureSelection() {
    const projects = catalog().projects;
    if (!projects.length) {
      state.selectedProject = null;
      state.selectedScope = null;
      return;
    }
    if (!projects.some(project => project.id === state.selectedProject)) {
      const requestedSlug = new URLSearchParams(window.location?.search || '').get('project');
      state.selectedProject = (projects.find(project => project.slug === requestedSlug) || projects[0]).id;
    }
    const scopes = scopesFor(state.selectedProject);
    if (!scopes.some(scope => scope.id === state.selectedScope)) {
      const requestedEnvironment = new URLSearchParams(window.location?.search || '').get('env');
      state.selectedScope = (scopes.find(scope => scope.environment === requestedEnvironment) || scopes[0])?.id || null;
    }
  }

  function render() {
    const enabled = Boolean(state.data?.enabled);
    $('catalog-enable').hidden = enabled;
    $('projects-grid').hidden = !enabled;
    $('project-delivery-fallback').hidden = enabled;
    $('folder-tools').hidden = !enabled;
    $('catalog-status').textContent = enabled
      ? 'Local catalog enabled'
      : (state.data?.profile ? 'Catalog is managed by the master profile.' : 'Catalog disabled');
    if (!enabled) {
      renderDelivery();
      return;
    }
    ensureSelection();
    renderProjects();
    renderScope();
    renderFolders();
    renderDelivery();
  }

  function renderProjects() {
    const projects = [...catalog().projects].sort((left, right) => left.name.localeCompare(right.name));
    const query = normalized(state.projectQuery);
    const visible = query
      ? projects.filter(project => normalized(`${project.name} ${project.slug}`).includes(query))
      : projects;
    $('project-count').textContent = `${projects.length} ${projects.length === 1 ? 'project' : 'projects'}`;
    const mount = $('project-list');
    mount.replaceChildren();
    if (!visible.length) {
      mount.append(el('p', {class: 'catalog-empty'}, 'No matching project.'));
      return;
    }
    for (const project of visible) {
      const scopes = scopesFor(project.id);
      const choice = el('button', {
        class: 'project-choice',
        type: 'button',
        'aria-pressed': String(project.id === state.selectedProject),
        onclick: () => {
          state.selectedProject = project.id;
          state.selectedScope = scopes[0]?.id || null;
          render();
        },
      }, el('span', {class: 'project-choice-name'}, project.name), el('span', {class: 'project-choice-meta'}, `${scopes.length} ${scopes.length === 1 ? 'env' : 'envs'}`));
      mount.append(choice);
    }
  }

  function renderScope() {
    const project = selectedProject();
    const scope = selected();
    const scopes = project ? scopesFor(project.id) : [];
    const tabs = $('scope-tabs');
    const mount = $('scope-entries');
    tabs.replaceChildren();
    mount.replaceChildren();
    $('environment-create').hidden = !project;
    $('selected-project-name').textContent = project ? project.name : 'Choose a project';
    $('project-context').textContent = project
      ? `${scopes.length} ${scopes.length === 1 ? 'environment' : 'environments'} · explicit access only`
      : 'Choose a project to begin.';
    if (!project) {
      $('scope-count').textContent = '';
      $('scope-label').textContent = 'Choose a project to manage its explicit access.';
      mount.append(el('p', {class: 'catalog-empty'}, 'Select a project from the list.'));
      return;
    }
    for (const item of scopes) {
      tabs.append(el('button', {
        type: 'button', 'aria-pressed': String(item.id === state.selectedScope),
        onclick: () => { state.selectedScope = item.id; renderScope(); renderDelivery(); },
      }, item.environment));
    }
    if (!scope) {
      $('scope-count').textContent = '';
      $('scope-label').textContent = 'Add an environment to manage its explicit access.';
      mount.append(el('p', {class: 'catalog-empty'}, 'This project has no environments yet.'));
      return;
    }
    const assigned = new Set(catalog().bindings.filter(item => item.scope_id === scope.id).map(item => item.entry_id));
    const allEntries = [...(state.data.entries || [])].sort((left, right) => left.name.localeCompare(right.name));
    const query = normalized(state.keyQuery);
    const visible = allEntries.filter(entry => {
      const isAssigned = assigned.has(entry.id);
      const matchesFilter = state.keyFilter === 'assigned' ? isAssigned : state.keyFilter === 'available' ? !isAssigned : true;
      return matchesFilter && (!query || normalized(`${entry.name} ${entry.type}`).includes(query));
    });
    $('scope-label').textContent = `${scope.environment} · assignments are explicit and delivery occurs only after synchronization.`;
    $('scope-count').textContent = `${assigned.size} assigned · ${allEntries.length - assigned.size} available`;
    for (const filter of ['assigned', 'available', 'all']) {
      $(`key-filter-${filter}`).setAttribute('aria-pressed', String(state.keyFilter === filter));
    }
    if (!visible.length) {
      const emptyCopy = state.keyFilter === 'assigned'
        ? 'No keys are assigned yet. Choose Available or search for a key to add it.'
        : 'No keys match this view.';
      mount.append(el('p', {class: 'catalog-empty'}, emptyCopy));
      return;
    }
    for (const entry of visible.slice(0, MAX_VISIBLE_ENTRIES)) {
      const isAssigned = assigned.has(entry.id);
      const usages = state.data.shared_usages?.[entry.id] || [];
      const otherUsages = usages.filter(item => item.scope_id !== scope.id);
      const usageLabel = isAssigned
        ? (otherUsages.length
          ? `Also assigned to ${otherUsages.length} other ${otherUsages.length === 1 ? 'environment' : 'environments'}`
          : 'Assigned only to this environment')
        : (otherUsages.length
          ? `Assigned to ${otherUsages.length} other ${otherUsages.length === 1 ? 'environment' : 'environments'}`
          : 'Not assigned to an environment');
      const usageDetails = otherUsages.length
        ? el('details', {class: 'scope-usage'},
          el('summary', {}, `View other assignments (${otherUsages.length})`),
          el('span', {class: 'catalog-meta'}, `Assigned scopes: ${otherUsages.map(item => `${item.project_slug}/${item.environment}`).join(', ')}`))
        : null;
      const action = el('button', {
        class: isAssigned ? 'btn btn-sm' : 'btn btn-primary btn-sm', type: 'button', onclick: safe(async () => {
          if (isAssigned) {
            await api(`/api/projects/bindings/${encodeURIComponent(scope.id)}/${encodeURIComponent(entry.id)}`, {method: 'DELETE'});
          } else if (entry.distribution === 'local_only') {
            if (!confirm(`Allow ${entry.name} to be assigned to projects? This changes only local metadata; it does not deliver a secret.`)) return;
            await api(`/api/projects/entries/${encodeURIComponent(entry.id)}/distribution`, patch({distribution: 'project_allowed'}));
            await api('/api/projects/bindings', post({scope_id: scope.id, entry_id: entry.id}));
          } else {
            await api('/api/projects/bindings', post({scope_id: scope.id, entry_id: entry.id}));
          }
          await refresh();
        }),
      }, isAssigned ? 'Remove' : entry.distribution === 'local_only' ? 'Allow & add' : 'Add');
      mount.append(el('article', {class: 'project-key-row'}, el('div', {class: 'project-key-main'}, el('strong', {}, entry.name), el('div', {class: 'key-meta-line'}, el('span', {class: 'key-type'}, entry.type), el('span', {class: 'catalog-meta'}, distributionLabel(entry.distribution)), el('span', {class: 'catalog-meta'}, usageLabel)), usageDetails || []), action));
    }
    if (visible.length > MAX_VISIBLE_ENTRIES) {
      mount.append(el('p', {class: 'catalog-limit'}, `Showing the first ${MAX_VISIBLE_ENTRIES} keys. Refine the search to narrow the list.`));
    }
  }

  function chooseFolder(promptText, currentId = null, {topLevel = false} = {}) {
    const folders = catalog().folders.filter(folder => folder.id !== currentId);
    const destination = topLevel ? 'Top level' : 'Unassigned';
    const choices = folders.map(folder => `${folder.name} [${folder.id}]`);
    const answer = prompt(`${promptText}\nType a unique folder name, its ID, or ${destination}.\nAvailable: ${choices.join(', ')}`, destination);
    if (answer === null) return undefined;
    if (answer.trim().toLocaleLowerCase() === destination.toLocaleLowerCase()) return null;
    const matches = folders.filter(folder => folder.id === answer.trim() || folder.name === answer.trim());
    if (matches.length !== 1) {
      message('Choose a unique folder name or one of the listed folder IDs.');
      return undefined;
    }
    return matches[0].id;
  }

  function renderFolders() {
    const folders = catalog().folders;
    if (!folders.some(folder => folder.id === state.selectedFolder)) state.selectedFolder = folders[0]?.id || null;
    const byParent = new Map();
    for (const folder of folders) {
      const siblings = byParent.get(folder.parent_id) || [];
      siblings.push(folder);
      byParent.set(folder.parent_id, siblings);
    }
    const mount = $('folder-tree');
    mount.replaceChildren();
    const folderEntries = folderId => (state.data.entries || []).filter(entry => entryFolderId(entry) === folderId);
    const appendFolder = (parentId, depth) => (byParent.get(parentId) || []).forEach(folder => {
      const count = folderEntries(folder.id).length;
      const select = el('button', {
        class: 'folder-choice', type: 'button', 'aria-pressed': String(folder.id === state.selectedFolder),
        onclick: () => { state.selectedFolder = folder.id; state.folderQuery = ''; $('folder-search').value = ''; renderFolders(); },
      }, folder.name);
      const move = el('button', {class: 'link-button', type: 'button', onclick: safe(async () => {
        const parentId = chooseFolder(`Move ${folder.name} into which folder?`, folder.id, {topLevel: true});
        if (parentId === undefined) return;
        await api(`/api/projects/folders/${encodeURIComponent(folder.id)}`, patch({parent_id: parentId}));
        await refresh();
      })}, 'Move folder');
      mount.append(el('div', {class: 'folder-choice-row', style: `padding-left:${depth * 14}px`}, el('div', {}, select, el('span', {class: 'folder-count'}, ` ${count}`)), move));
      appendFolder(folder.id, depth + 1);
    });
    appendFolder(null, 0);
    if (!folders.length) mount.append(el('p', {class: 'catalog-empty'}, 'No folders yet.'));

    const active = folders.find(folder => folder.id === state.selectedFolder) || null;
    $('folder-label').textContent = active ? active.name : 'Unassigned keys';
    const entries = $('folder-entries');
    entries.replaceChildren();
    const query = normalized(state.folderQuery);
    const candidates = (state.data.entries || []).filter(entry => {
      if (query) return normalized(`${entry.name} ${entry.type}`).includes(query);
      return entryFolderId(entry) === state.selectedFolder;
    }).sort((left, right) => left.name.localeCompare(right.name));
    if (!candidates.length) {
      entries.append(el('p', {class: 'catalog-empty'}, query ? 'No matching key.' : 'No keys in this folder. Search to move one here.'));
      return;
    }
    for (const entry of candidates.slice(0, MAX_VISIBLE_ENTRIES)) {
      const belongs = entryFolderId(entry) === state.selectedFolder;
      const action = el('button', {class: belongs ? 'btn btn-sm' : 'btn btn-primary btn-sm', type: 'button', onclick: safe(async () => {
        if (!belongs) {
          await api(`/api/projects/entries/${encodeURIComponent(entry.id)}/folder`, patch({folder_id: state.selectedFolder}));
        } else {
          const destination = chooseFolder(`Move ${entry.name} to which folder?`);
          if (destination === undefined) return;
          await api(`/api/projects/entries/${encodeURIComponent(entry.id)}/folder`, patch({folder_id: destination}));
        }
        await refresh();
      })}, belongs ? 'Move…' : 'Move here');
      entries.append(el('div', {class: 'catalog-row'}, el('div', {}, el('strong', {}, entry.name), el('span', {class: 'catalog-meta'}, entry.type)), action));
    }
    if (candidates.length > MAX_VISIBLE_ENTRIES) {
      entries.append(el('p', {class: 'catalog-limit'}, `Showing the first ${MAX_VISIBLE_ENTRIES} keys. Refine the search to narrow the list.`));
    }
  }

  function recipientRows(profile, mount) {
    (profile.recipients || []).forEach(recipient => {
      const revoke = el('button', {class: 'btn btn-sm', type: 'button', onclick: safe(async () => {
        if (!confirm(`Remove access for device ${recipient.device_id} in ${profile.project} / ${profile.environment}? It will lose future access after a rekey, but material already held on that device cannot be erased.`)) return;
        const result = await api('/api/project-sync/revoke', post({scope_id: profile.scope_id, device_id: recipient.device_id}));
        message(`${result.warning} Rekey: ${result.result.rekey || 'pending'}.`);
        await refresh();
      })}, 'Remove access');
      mount.append(el('div', {class: 'catalog-row'}, el('div', {}, el('strong', {}, 'Device'), el('code', {class: 'catalog-meta'}, recipient.device_id), el('span', {class: 'catalog-meta'}, roleLabel(recipient.role))), revoke));
    });
  }

  function renderProfile(profile, mount, {currentProfile = false} = {}) {
    const actions = el('div', {class: 'delivery-actions'});
    actions.append(el('button', {class: 'btn btn-primary btn-sm', type: 'button', onclick: safe(() => runSync(currentProfile ? null : profile.profile_id))}, 'Sync now'));
    if (!currentProfile) actions.append(el('button', {class: 'btn btn-sm', type: 'button', onclick: safe(() => preview(profile.profile_id))}, 'Preview'));
    if (profile.fingerprint) actions.append(el('button', {class: 'link-button', type: 'button', onclick: () => copyFingerprint(profile.fingerprint)}, 'Copy public fingerprint'));
    const block = el('div', {class: 'delivery-profile'}, el('div', {class: 'delivery-focus'}, el('div', {}, el('strong', {}, `${profile.project} / ${profile.environment}`), el('span', {class: 'catalog-meta'}, waitingSummary(profile)))), actions);
    recipientRows(profile, block);
    mount.append(block);
  }

  function renderDeliveryOverview(profiles, mount) {
    for (const profile of profiles) renderProfile(profile, mount);
    const devices = Object.entries(state.delivery?.device_union || {});
    if (devices.length) {
      const block = el('details', {class: 'delivery-overview'}, el('summary', {}, 'Effective device access'));
      const contents = el('div', {});
      devices.forEach(([deviceId, grants]) => contents.append(el('p', {class: 'catalog-meta'}, el('code', {}, deviceId), `: ${grants.map(grant => `${grant.project} / ${grant.environment} (${roleLabel(grant.role)})`).join(', ')}.`)));
      block.append(contents);
      mount.append(block);
    }
  }

  function renderDelivery() {
    const mount = state.data?.enabled ? $('delivery-status') : $('delivery-status-fallback');
    mount.replaceChildren();
    const delivery = state.delivery || {};
    if (delivery.profile) {
      renderProfile(delivery.profile, mount, {currentProfile: true});
      mount.append(el('p', {class: 'catalog-meta'}, 'Worker enrollment remains CLI-led: receive an invitation, verify its public fingerprint independently, then use join / approve / finish.'));
      return;
    }
    const profiles = delivery.profiles || [];
    const scope = selected();
    if (!scope) {
      if (!profiles.length) mount.append(el('p', {class: 'catalog-empty'}, 'No configured delivery profile. Create the catalog with a recovery-backed migration, then initialize a scope with an existing admin-token entry.'));
      else renderDeliveryOverview(profiles, mount);
      return;
    }
    const profile = profiles.find(item => item.scope_id === scope.id);
    if (profile) {
      renderProfile(profile, mount);
    } else {
      mount.append(el('div', {class: 'delivery-profile'}, el('div', {class: 'delivery-focus'}, el('div', {}, el('strong', {}, `Set up ${scope.environment}`), el('span', {class: 'catalog-meta'}, 'Connect this environment to a delivery endpoint.')), el('button', {class: 'btn btn-sm', type: 'button', onclick: safe(() => initializeScope(scope))}, 'Set up'))));
    }
    const otherProfiles = profiles.filter(item => item.scope_id !== scope.id);
    if (otherProfiles.length) {
      const overview = el('details', {class: 'delivery-overview'}, el('summary', {}, `Other delivery profiles (${otherProfiles.length})`));
      const contents = el('div', {});
      otherProfiles.forEach(item => renderProfile(item, contents));
      overview.append(contents);
      mount.append(overview);
    }
    const devices = Object.entries(delivery.device_union || {});
    if (devices.length) {
      const deviceOverview = el('details', {class: 'delivery-overview'}, el('summary', {}, 'Effective device access'));
      const contents = el('div', {});
      devices.forEach(([deviceId, grants]) => contents.append(el('p', {class: 'catalog-meta'}, el('code', {}, deviceId), `: ${grants.map(grant => `${grant.project} / ${grant.environment} (${roleLabel(grant.role)})`).join(', ')}.`)));
      deviceOverview.append(contents);
      mount.append(deviceOverview);
    }
    mount.append(el('p', {class: 'catalog-meta'}, 'Onboarding stays CLI-led: keys project-sync invite → join → approve → finish. The fingerprint shown here is public; do not paste invitation bundles into chat.'));
  }

  $('project-search').addEventListener('input', event => { state.projectQuery = event.target.value || ''; renderProjects(); });
  $('key-search').addEventListener('input', event => { state.keyQuery = event.target.value || ''; renderScope(); });
  $('folder-search').addEventListener('input', event => { state.folderQuery = event.target.value || ''; renderFolders(); });
  for (const filter of ['assigned', 'available', 'all']) {
    $(`key-filter-${filter}`).addEventListener('click', () => { state.keyFilter = filter; renderScope(); });
  }
  $('folder-create').addEventListener('click', safe(async () => {
    const name = prompt('Folder name');
    if (!name) return;
    const result = await api('/api/projects/folders', post({name, parent_id: state.selectedFolder}));
    state.selectedFolder = result.item?.id || state.selectedFolder;
    await refresh();
  }));
  $('project-create').addEventListener('click', safe(async () => {
    const slug = prompt('Project slug');
    const name = slug && prompt('Project name', slug);
    if (!slug || !name) return;
    const result = await api('/api/projects', post({slug, name}));
    state.selectedProject = result.item?.id || state.selectedProject;
    state.selectedScope = null;
    await refresh();
  }));
  $('environment-create').addEventListener('click', safe(async () => {
    const project = selectedProject();
    if (!project) return;
    const environment = prompt('Environment name', 'default');
    if (!environment) return;
    const result = await api('/api/projects/scopes', post({project_id: project.id, environment}));
    state.selectedScope = result.item?.id || state.selectedScope;
    await refresh();
  }));
  refresh().catch(error => { $('catalog-status').textContent = error.message; message(error.message); });
})();
