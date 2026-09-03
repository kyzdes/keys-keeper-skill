// keys-keeper admin client
(() => {
  const THEME_KEY = 'keys-keeper-theme';

  function setTheme(theme, persist = false) {
    const next = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    document.querySelector('meta[name="theme-color"]')?.setAttribute(
      'content',
      next === 'light' ? '#f4f3f1' : '#0a0b0c',
    );
    const toggle = document.getElementById('theme-toggle');
    if (toggle) {
      const target = next === 'dark' ? 'day' : 'evening';
      toggle.setAttribute('aria-label', `Switch to ${target} theme`);
      toggle.setAttribute('title', `${target[0].toUpperCase()}${target.slice(1)} theme`);
    }
    if (persist) {
      try { localStorage.setItem(THEME_KEY, next); } catch {}
    }
  }

  const themeToggle = document.getElementById('theme-toggle');
  setTheme(document.documentElement.dataset.theme);
  themeToggle?.addEventListener('click', () => {
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true);
  });

  async function api(path, opts = {}) {
    const r = await fetch(path, opts);
    if (!r.ok) {
      let detail = '';
      try {
        const body = await r.json();
        if (body && body.error) detail = ` — ${body.error}`;
      } catch {}
      throw new Error(`${path}: ${r.status}${detail}`);
    }
    return r.json();
  }

  const TYPE_META = {
    api_key: { short: 'AP', color: 'var(--type-api)' },
    ssh_key: { short: 'SSH', color: 'var(--type-ssh)' },
    server:  { short: 'SV', color: 'var(--type-server)' },
    domain:  { short: 'DM', color: 'var(--type-domain)' },
    note:    { short: 'NT', color: 'var(--type-note)' },
  };

  const state = {
    entries: [],
    activeTags: new Set(),
    search: '',
  };

  function relTime(iso) {
    const t = new Date(iso).getTime();
    const ago = Math.max(0, Date.now() - t);
    const m = Math.floor(ago / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m} min ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} hr ago`;
    const d = Math.floor(h / 24);
    return `${d} d ago`;
  }

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    Object.entries(attrs).forEach(([k, v]) => {
      if (k === 'class') e.className = v;
      else if (k === 'onclick') e.onclick = v;
      else e.setAttribute(k, v);
    });
    children.flat().forEach(c => e.append(c instanceof Node ? c : document.createTextNode(c ?? '')));
    return e;
  }

  function kvRow(key, value, valueClass = '') {
    return el(
      'div',
      { class: 'kv-row' },
      el('span', { class: 'key' }, key),
      el('span', { class: `val${valueClass ? ` ${valueClass}` : ''}` }, String(value ?? '')),
    );
  }

  const ICON_PATHS = {
    copy: ['M7 6.5h7.5v9H7z', 'M5.5 13.5H4V4h8v1.5'],
    open: ['M8 5h7v7', 'M15 5 7 13', 'M13 15H5V7'],
  };

  function svgIcon(name) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 20 20');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('aria-hidden', 'true');
    (ICON_PATHS[name] || []).forEach(d => {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      svg.append(path);
    });
    return svg;
  }

  function render() {
    const mount = document.getElementById('entries-mount');
    mount.innerHTML = '';
    const filtered = state.entries.filter(e => {
      if (state.search && !(`${e.name} ${(e.tags || []).join(' ')} ${e.note || ''}`.toLowerCase().includes(state.search.toLowerCase()))) {
        return false;
      }
      if (state.activeTags.size > 0 && !(e.tags || []).some(t => state.activeTags.has(t))) {
        return false;
      }
      return true;
    });
    if (filtered.length === 0) {
      mount.append(el('div', { class: 'empty loading-state' }, state.entries.length ? 'No entries match these filters.' : 'Your vault is empty. Add an entry or import a protected list.'));
      return;
    }
    filtered.forEach(e => mount.append(rowEl(e)));
  }

  function rowEl(e) {
    const meta = TYPE_META[e.type] || { short: '?', color: 'var(--text-3)' };
    const row = el('div', {
      class: 'entry-row unified',
      tabindex: '0',
      role: 'link',
      'aria-label': `Open ${e.name}`,
    });
    row.append(
      el('span', {
        class: 'type-icon',
        style: `background:${meta.color}`,
      }, meta.short),
      el('span', { class: 'type-label-mono' }, e.type),
      (() => {
        const c = el('div', { class: 'name-block' });
        const r1 = el('div', { class: 'row', style: 'gap:10px;flex-wrap:wrap' });
        r1.append(el('span', { class: 'name' }, e.name));
        const taglist = el('div', { class: 'tag-mini-list' });
        (e.tags || []).slice(0, 4).forEach(t => taglist.append(el('span', { class: 'tag-mini' }, t)));
        r1.append(taglist);
        c.append(r1);
        return c;
      })(),
      el('span', { class: 'note-preview', style: 'margin:0;max-width:100%' }, e.note || (e.fields?.host ? `${e.fields.user || ''}@${e.fields.host}` : '')),
      el('span', { class: 'last-access' }, e.updated_at ? relTime(e.updated_at) : ''),
      (() => {
        const a = el('div', { class: 'actions' });
        const copyBtn = el('button', {
          class: 'icon-btn',
          title: 'Copy to clipboard',
          type: 'button',
          'aria-label': `Copy ${e.name}`,
          onclick: (ev) => { ev.stopPropagation(); copy(e.id, e.name); },
        }, svgIcon('copy'));
        const editBtn = el('a', {
          class: 'icon-btn',
          href: `/entry/${encodeURIComponent(e.id)}`,
          title: 'Open entry',
          'aria-label': `Open ${e.name}`,
          onclick: (ev) => ev.stopPropagation(),
        }, svgIcon('open'));
        a.append(copyBtn, editBtn);
        return a;
      })(),
    );
    row.onclick = () => { location.href = `/entry/${encodeURIComponent(e.id)}`; };
    row.onkeydown = (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') {
        ev.preventDefault();
        location.href = `/entry/${encodeURIComponent(e.id)}`;
      }
    };
    return row;
  }

  async function copy(id, name) {
    try {
      await api('/api/copy', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) });
      toast(`Copied ${name} · auto-clear in 30s`);
    } catch (ex) {
      toast(`Copy failed: ${ex.message}`, 'error');
    }
  }

  function toast(msg, kind = 'success') {
    const t = el('div', { class: 'app-toast', role: kind === 'error' ? 'alert' : 'status' }, msg);
    if (kind === 'error') t.style.borderColor = 'var(--danger)';
    document.body.append(t);
    setTimeout(() => t.remove(), 3500);
  }

  // Fade the right edge only while there is more to scroll to, so the last chip
  // is never left dimmed once you reach the end, and a rail that fits shows no fade.
  function updateRailFade(rail) {
    const overflow = rail.scrollWidth - rail.clientWidth > 1;
    const atEnd = rail.scrollLeft >= rail.scrollWidth - rail.clientWidth - 1;
    rail.classList.toggle('has-overflow', overflow && !atEnd);
  }

  function renderTagRail() {
    const rail = document.getElementById('tag-rail');
    if (!rail) return;

    // Bind once (guarded): vertical wheel -> horizontal scroll, but only while the
    // rail overflows so a short rail lets the page scroll normally; scroll/resize
    // keep the edge-fade in sync.
    if (!rail.dataset.railBound) {
      rail.addEventListener('wheel', (e) => {
        if (!e.deltaY || rail.scrollWidth <= rail.clientWidth) return;
        e.preventDefault();
        rail.scrollLeft += e.deltaY;
      }, { passive: false });
      rail.addEventListener('scroll', () => updateRailFade(rail), { passive: true });
      window.addEventListener('resize', () => updateRailFade(rail));
      rail.dataset.railBound = '1';
    }

    const allTags = new Set();
    state.entries.forEach(e => (e.tags || []).forEach(t => allTags.add(t)));
    rail.querySelectorAll('.tag-chip').forEach(n => n.remove());

    // Active chips first -> they sit flush against the pinned FILTER label and
    // never scroll out of view; everything else stays alphabetical.
    const tags = [...allTags].sort((a, b) => {
      const aOn = state.activeTags.has(a), bOn = state.activeTags.has(b);
      if (aOn !== bOn) return aOn ? -1 : 1;
      return a.localeCompare(b);
    });

    const toggle = (t) => {
      if (state.activeTags.has(t)) state.activeTags.delete(t);
      else state.activeTags.add(t);
      renderTagRail();
      rail.scrollLeft = 0;       // snap to front so the now-leading active chips are visible
      updateRailFade(rail);
      render();
    };

    tags.forEach(t => {
      const on = state.activeTags.has(t);
      const chip = el('button', {
        class: 'tag-chip' + (on ? ' active' : ''),
        type: 'button',
        'aria-pressed': on ? 'true' : 'false',
        onclick: () => toggle(t),
      }, t);
      // el() stringifies unknown attrs via setAttribute, so bind keydown as a property.
      chip.onkeydown = (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(t); }
      };
      rail.append(chip);
    });

    updateRailFade(rail);
  }

  async function load() {
    const data = await api('/api/entries');
    state.entries = data.entries;
    renderTagRail();
    render();
    loadEnvPanel().catch(() => { /* panel is best-effort; never blocks dashboard */ });
  }

  // Heuristic — purely visual hint for the user to find env-resident
  // secrets worth migrating. Does NOT classify automatically; the user
  // decides what to move. Word-boundary on `_` so KEYS_KEEPER_HOME (a
  // config path) doesn't false-positive on the substring KEY.
  const ENV_SECRETY_RE = /(?:^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|APIKEY|AUTH|PRIVATE)(?:_|$)/i;
  const envState = { names: [], filter: '' };

  async function loadEnvPanel() {
    const panel = document.getElementById('env-panel');
    if (!panel) return;
    const data = await api('/api/env-names');
    envState.names = data.names || [];
    if (envState.names.length === 0) return;
    panel.hidden = false;
    document.getElementById('env-count').textContent = `${envState.names.length} vars`;
    renderEnvList();
  }

  function renderEnvList() {
    const mount = document.getElementById('env-list');
    if (!mount) return;
    mount.innerHTML = '';
    const q = envState.filter.toLowerCase();
    const filtered = q
      ? envState.names.filter(n => n.toLowerCase().includes(q))
      : envState.names;
    if (filtered.length === 0) {
      mount.append(el('span', { class: 'env-empty' }, 'no matches'));
      return;
    }
    filtered.forEach(name => {
      const cls = 'env-name' + (ENV_SECRETY_RE.test(name) ? ' env-name-suspect' : '');
      mount.append(el('span', { class: cls, title: name }, name));
    });
  }

  document.getElementById('env-search')?.addEventListener('input', (e) => {
    envState.filter = e.target.value;
    renderEnvList();
  });

  document.getElementById('search')?.addEventListener('input', (e) => {
    state.search = e.target.value;
    render();
  });
  document.getElementById('search')?.addEventListener('focus', () => {
    document.getElementById('search-shell')?.classList.add('focused');
  });
  document.getElementById('search')?.addEventListener('blur', () => {
    document.getElementById('search-shell')?.classList.remove('focused');
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
      e.preventDefault();
      document.getElementById('search')?.focus();
    }
    if (e.key === 'Escape') {
      const s = document.getElementById('search');
      if (s) {
        s.value = '';
        state.search = '';
        state.activeTags.clear();
        renderTagRail();
        render();
      }
    }
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
      e.preventDefault();
      paletteOpen();
    }
  });

  // -- command palette --
  const palette = {
    open: false,
    query: '',
    selectedIdx: 0,
    items: [],
  };

  async function paletteOpen() {
    palette.open = true;
    palette.query = '';
    palette.selectedIdx = 0;
    document.getElementById('cmdk-overlay').hidden = false;
    document.getElementById('cmdk-input').value = '';
    document.getElementById('cmdk-input').focus();
    if (state.entries.length === 0) {
      try {
        const r = await api('/api/entries');
        state.entries = r.entries;
      } catch {}
    }
    paletteRender();
  }
  function paletteClose() {
    palette.open = false;
    document.getElementById('cmdk-overlay').hidden = true;
  }
  function paletteRender() {
    const q = palette.query.toLowerCase();
    palette.items = state.entries
      .filter(e => !q || e.name.toLowerCase().includes(q) || (e.tags || []).some(t => t.toLowerCase().includes(q)))
      .slice(0, 20);
    if (palette.selectedIdx >= palette.items.length) palette.selectedIdx = Math.max(0, palette.items.length - 1);
    const r = document.getElementById('cmdk-results');
    r.innerHTML = '';
    palette.items.forEach((e, i) => {
      const meta = TYPE_META[e.type] || {};
      const row = el('div', {
        class: 'cmdk-row' + (i === palette.selectedIdx ? ' selected' : ''),
        onclick: () => { paletteClose(); location.href = `/entry/${encodeURIComponent(e.id)}`; },
      });
      row.append(
        el('span', { class: 'type-icon', style: `background:${meta.color};color:var(--bg);font-weight:700;display:inline-flex;align-items:center;justify-content:center;border-radius:4px` }, meta.short || '?'),
        el('span', { class: 'name', style: 'flex:1' }, e.name),
        el('span', { style: 'color:var(--text-3);font-size:11px' }, e.type),
      );
      r.append(row);
    });
  }

  document.getElementById('cmdk-input').addEventListener('input', (e) => {
    palette.query = e.target.value;
    palette.selectedIdx = 0;
    paletteRender();
  });
  document.getElementById('cmdk-input').addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); palette.selectedIdx = Math.min(palette.items.length - 1, palette.selectedIdx + 1); paletteRender(); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); palette.selectedIdx = Math.max(0, palette.selectedIdx - 1); paletteRender(); }
    else if (e.key === 'Enter') {
      e.preventDefault();
      const sel = palette.items[palette.selectedIdx];
      if (sel) { paletteClose(); location.href = `/entry/${encodeURIComponent(sel.id)}`; }
    }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); paletteClose(); }
  });

  document.getElementById('cmdk-trigger')?.addEventListener('click', paletteOpen);

  setInterval(() => {
    fetch('/api/heartbeat', { method: 'POST' });
  }, 60000);

  // Note: we deliberately do NOT shutdown on beforeunload — that fires on
  // every <a href> navigation, not only on real tab close, and would kill
  // the server mid-click. Idle auto-shutdown (15 min) and the explicit
  // Settings → Shutdown button are the supported termination paths.

  if (document.getElementById('entries-mount')) {
    load().catch(err => {
      document.getElementById('entries-mount').textContent = `Failed to load: ${err.message}`;
    });
  }

  if (document.getElementById('detail-mount')) {
    const id = document.getElementById('detail-mount').dataset.entryId;
    api(`/api/entries/${encodeURIComponent(id)}`).then(e => {
      const tagsEl = document.getElementById('detail-tags');
      (e.tags || []).forEach(t => tagsEl.append(el('span', { class: 'tag-mini' }, t)));
      const fm = document.getElementById('fields-mount');
      const sec = el('div', { class: 'field-section' });
      sec.append(el('div', { class: 'field-section-title' }, 'Fields'));
      Object.entries(e.fields || {}).forEach(([k, v]) => {
        const r = el('div', { class: 'field-row' });
        r.append(el('span', { class: 'key' }, k), el('span', { class: 'value' }, String(v)), el('span'));
        sec.append(r);
      });
      fm.append(sec);
      const rm = document.getElementById('refs-mount');
      if ((e.refs || []).length || (e.used_by || []).length) {
        const r = el('div', { class: 'field-section' });
        r.append(el('div', { class: 'field-section-title' }, 'Linked entries'));
        (e.refs || []).forEach(ref => {
          const item = el('a', { class: 'refs-item', href: `/entry/${encodeURIComponent(ref.name)}` });
          item.append(
            el('span', { class: 'role' }, ref.role),
            el('div', { class: 'target' }, el('span', { class: 'name' }, ref.name)),
            el('span', { class: 'arrow' }, '→'),
          );
          r.append(item);
        });
        if ((e.used_by || []).length) {
          r.append(el('div', { class: 'field-section-title', style: 'margin-top:14px' }, 'Used by'));
          e.used_by.forEach(name => {
            const item = el('a', { class: 'refs-item', href: `/entry/${encodeURIComponent(name)}` });
            item.append(el('span', { class: 'role' }, 'used by'), el('div', { class: 'target' }, el('span', { class: 'name' }, name)), el('span', { class: 'arrow' }, '→'));
            r.append(item);
          });
        }
        rm.append(r);
      }
      const audit = document.getElementById('recent-mount');
      audit.innerHTML = '';
      (e.recent_events || []).forEach(ev => {
        const row = el('div', { class: 'mini-audit-row' });
        row.append(
          el('span', { class: 'ts' }, relTime(ev.ts)),
          el('span', { class: `op-tag op-${ev.op}` }, ev.op),
          el('span', { class: 'ctx' }, ev.file_target || ev.caller_path || ''),
        );
        audit.append(row);
      });
      document.getElementById('copy-btn').onclick = () => copy(e.id, e.name);
      document.getElementById('delete-btn').onclick = async () => {
        if (!confirm(`Delete ${e.name}?`)) return;
        const doDelete = async (cascade) => {
          const url = `/api/entries/${encodeURIComponent(e.id)}` + (cascade ? '?cascade=1' : '');
          return fetch(url, { method: 'DELETE' });
        };
        try {
          let r = await doDelete(false);
          if (r.status === 409) {
            const body = await r.json().catch(() => ({}));
            const deps = (body.dependents || []).join(', ') || 'other entries';
            if (!confirm(`${e.name} is referenced by: ${deps}\n\nDelete anyway and strip refs from dependents?`)) return;
            r = await doDelete(true);
          }
          if (!r.ok) {
            const body = await r.json().catch(() => ({}));
            toast(`Delete failed — ${body.error || r.status}`, 'error');
            return;
          }
          location.href = '/';
        } catch (ex) {
          toast(`Delete failed — ${ex.message || ex}`, 'error');
        }
      };
      document.getElementById('replace-secret-btn').onclick = () => {
        document.getElementById('replace-modal').hidden = false;
        document.getElementById('rm-input').value = '';
        document.getElementById('rm-input').focus();
      };
      document.getElementById('rm-cancel').onclick = () =>
        document.getElementById('replace-modal').hidden = true;
      document.getElementById('rm-cancel-2').onclick = () =>
        document.getElementById('replace-modal').hidden = true;
      document.getElementById('rm-save').onclick = async () => {
        const inp = document.getElementById('rm-input');
        const val = inp.value;
        inp.value = '';  // wipe DOM immediately
        try {
          await api(`/api/entries/${encodeURIComponent(id)}/replace-secret`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ value: val }),
          });
          document.getElementById('replace-modal').hidden = true;
          toast('Secret replaced');
        } catch (ex) {
          toast(`Replace failed: ${ex.message}`, 'error');
        }
      };
    }).catch(err => {
      // Surface fetch errors so the user knows why the page is empty —
      // previously a 404/etc here meant handlers never attached and the
      // page stayed visually "Loading..." with non-functional buttons.
      const audit = document.getElementById('recent-mount');
      if (audit) audit.textContent = `Failed to load entry: ${err.message}`;
    });
  }

  if (document.querySelector('.new-modal')) {
    const modal = document.querySelector('.new-modal');
    const editId = modal.dataset.editId;
    let selectedType = document.querySelector('.type-card.selected')?.dataset.type || 'api_key';
    let editingEntry = null;

    if (editId) {
      api(`/api/entries/${encodeURIComponent(editId)}`).then(e => {
        editingEntry = e;
        renderTypeFields();
      });
    } else {
      renderTypeFields();
    }

    document.querySelectorAll('.type-card').forEach(card => {
      card.onclick = () => {
        if (editId) return;
        document.querySelectorAll('.type-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        selectedType = card.dataset.type;
        renderTypeFields();
      };
    });

    function renderTypeFields() {
      const c = document.getElementById('type-specific-fields');
      c.innerHTML = '';
      const e = editingEntry;
      if (selectedType === 'api_key') {
        c.append(formRow('service', 'service', e?.fields?.service || '', false));
        if (!editId) c.append(secretRow('value', 'paste secret value · stays out of the DOM after submit', true));
      } else if (selectedType === 'ssh_key') {
        c.append(formRow('public_key', 'public key', e?.fields?.public_key || '', true));
        if (!editId) c.append(secretRow('private_key', 'paste private key (multi-line OK)', true));
        c.append(formRow('comment', 'comment', e?.fields?.comment || '', false));
      } else if (selectedType === 'server') {
        c.append(formRow('host', 'host', e?.fields?.host || '', true));
        c.append(formRow('port', 'port', e?.fields?.port || '22', false));
        c.append(formRow('user', 'user', e?.fields?.user || '', true));
        c.append(formRow('auth', 'auth', e?.fields?.auth || 'ssh_key', true));
        c.append(formRow('ssh_key_ref', 'ssh_key ref', e?.refs?.find(r => r.role === 'ssh_key')?.name || '', false));
      } else if (selectedType === 'domain') {
        c.append(formRow('host', 'host', e?.fields?.host || '', true));
        c.append(formRow('registrar', 'registrar', e?.fields?.registrar || '', false));
      } else if (selectedType === 'note') {
        c.append(formRow('body', 'body', e?.fields?.body || '', false));
      }
    }

    function formRow(name, label, val, req) {
      const r = document.createElement('div'); r.className = 'form-row';
      const lbl = document.createElement('span'); lbl.className = 'label'; lbl.textContent = label; if (req) lbl.innerHTML += ' <span class="req">*</span>';
      const inp = document.createElement('input'); inp.className = 'text-input'; inp.id = `f-${name}`; inp.value = val;
      r.append(lbl, inp); return r;
    }
    function secretRow(name, placeholder, multiline) {
      const r = document.createElement('div'); r.className = 'form-row';
      const lbl = document.createElement('span'); lbl.className = 'label'; lbl.innerHTML = `${name} <span class="req">*</span>`;
      const inp = document.createElement(multiline ? 'textarea' : 'input');
      inp.className = multiline ? 'textarea-input' : 'text-input';
      inp.id = `f-${name}`;
      inp.placeholder = placeholder;
      if (multiline) inp.rows = 3;
      r.append(lbl, inp); return r;
    }

    async function save() {
      const errEl = document.getElementById('form-error');
      errEl.textContent = '';
      const payload = {
        name: document.getElementById('f-name').value.trim(),
        type: selectedType,
        tags: document.getElementById('f-tags').value.split(',').map(s => s.trim()).filter(Boolean),
        note: document.getElementById('f-note').value,
        fields: {},
        refs: [],
      };
      ['service', 'public_key', 'comment', 'host', 'port', 'user', 'auth', 'registrar', 'body'].forEach(k => {
        const el = document.getElementById(`f-${k}`);
        if (el) {
          let v = el.value.trim();
          if (k === 'port' && v) v = parseInt(v);
          if (v) payload.fields[k] = v;
        }
      });
      const refEl = document.getElementById('f-ssh_key_ref');
      if (refEl?.value.trim()) payload.refs.push({ role: 'ssh_key', name: refEl.value.trim() });
      const valueEl = document.getElementById('f-value') || document.getElementById('f-private_key');
      if (valueEl) payload.value = valueEl.value;

      try {
        if (editId) {
          await api(`/api/entries/${encodeURIComponent(editId)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          location.href = `/entry/${encodeURIComponent(editId)}`;
        } else {
          const r = await api('/api/entries', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
          location.href = `/entry/${encodeURIComponent(r.id)}`;
        }
      } catch (ex) {
        errEl.textContent = ex.message;
      }
    }

    document.getElementById('save-btn').onclick = save;
    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') { e.preventDefault(); save(); }
    });
  }

  if (document.getElementById('bulk-shell')) {
    const input = document.getElementById('bulk-input');
    const rowsEl = document.getElementById('preview-rows');
    let lastParse = [];

    document.getElementById('format-toggle').onclick = () => {
      const h = document.getElementById('format-help');
      h.hidden = !h.hidden;
    };

    let timer = null;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(parsePreview, 200);
    });

    async function parsePreview() {
      const text = input.value;
      document.getElementById('line-count').textContent = `${text.split('\n').length} lines`;
      const r = await api('/api/bulk-import?dry-run=1', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ source: text }),
      });
      lastParse = r.rows;
      renderPreview(r.rows);
      const errs = r.rows.filter(r => r.error).length;
      document.getElementById('preview-count').textContent = `${r.rows.length} entries · ${errs} errors`;
      document.getElementById('bulk-summary').textContent = errs > 0
        ? `${r.rows.length - errs} ready · ${errs} error${errs > 1 ? 's' : ''} blocking save`
        : `Will save ${r.rows.length} entries · 0 errors`;
      const btn = document.getElementById('bulk-save');
      btn.disabled = (r.rows.length === 0 || errs > 0);
    }

    function renderPreview(rows) {
      rowsEl.innerHTML = '';
      rows.forEach(r => {
        const row = el('div', { class: 'bulk-preview-row' + (r.error ? ' error' : '') });
        row.append(
          el('span', { class: 'status-dot' }),
          el('span', { class: 'row-num' }, String(r.line)),
          el('span', { class: 'name' }, r.name),
          (() => {
            const sel = document.createElement('select');
            sel.className = 'type-dropdown';
            ['api_key', 'ssh_key', 'server', 'domain', 'note'].forEach(t => {
              const opt = document.createElement('option');
              opt.value = t; opt.textContent = t;
              if (t === r.type) opt.selected = true;
              sel.append(opt);
            });
            sel.onchange = () => { r.type = sel.value; };
            return sel;
          })(),
          el('span', { class: 'summary' },
            el('span', { class: 'muted' }, r.has_value ? 'value present' : 'no value'),
            ' ',
            el('span', { style: 'color:var(--type-domain)' }, r.tags.length ? `[${r.tags.join(',')}]` : ''),
          ),
          el('span', { class: 'muted', style: 'font-size:10px' }, '↗ line'),
          el('span'),
        );
        rowsEl.append(row);
        if (r.error) {
          rowsEl.append(el('div', { class: 'bulk-error-detail' },
            el('span', { class: 'line-no' }, `line ${r.line}:`),
            ' ',
            r.error,
          ));
        }
      });
    }

    document.getElementById('bulk-save').onclick = async () => {
      try {
        const r = await api('/api/bulk-import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ source: input.value, rows: lastParse }),
        });
        if (r.ok) {
          location.href = '/';
        } else {
          alert(`Import failed: ${r.error}`);
        }
      } catch (ex) {
        alert(`Import failed: ${ex.message}`);
      }
    };
  }

  if (document.getElementById('audit-shell')) {
    const filters = { ops: new Set(), range: '7d' };

    function rangeSeconds(r) {
      return { '24h': 86400, '7d': 604800, '30d': 2592000 }[r] || 604800;
    }

    document.querySelectorAll('.preset-btn').forEach(b => {
      b.onclick = () => {
        document.querySelectorAll('.preset-btn').forEach(x => x.classList.remove('active'));
        b.classList.add('active');
        filters.range = b.dataset.range;
        load();
      };
    });
    document.querySelectorAll('.op-filter').forEach(c => {
      c.onclick = () => {
        c.classList.toggle('active');
        c.setAttribute('aria-pressed', c.classList.contains('active') ? 'true' : 'false');
        if (filters.ops.has(c.dataset.op)) filters.ops.delete(c.dataset.op);
        else filters.ops.add(c.dataset.op);
        load();
      };
    });

    async function load() {
      const all = (await api('/api/audit?limit=2000')).events;
      const cutoff = (Date.now() - rangeSeconds(filters.range) * 1000);
      const inRange = all.filter(e => new Date(e.ts).getTime() >= cutoff);
      const filtered = filters.ops.size === 0
        ? inRange
        : inRange.filter(e => filters.ops.has(e.op));

      // top entries
      const counts = {};
      inRange.forEach(e => { counts[e.name] = (counts[e.name] || 0) + 1; });
      const top = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
      const max = Math.max(...top.map(([, c]) => c), 1);
      const topEl = document.getElementById('top-bars');
      topEl.innerHTML = '';
      if (top.length === 0) topEl.append(el('div', { class: 'chart-empty' }, 'No access events in this range'));
      top.forEach(([name, c]) => {
        const r = el('div', { class: 'bar-row' });
        r.append(
          el('span', { class: 'name' }, name),
          el('span', { class: 'bar-track' }, el('span', { class: 'bar-fill', style: `width:${c / max * 100}%` })),
          el('span', { class: 'num' }, String(c)),
        );
        topEl.append(r);
      });

      // daily activity (locked: bar style)
      const days = Array(30).fill(0);
      const now = Date.now();
      all.forEach(e => {
        const t = new Date(e.ts).getTime();
        const dayIdx = Math.floor((now - t) / 86400000);
        if (dayIdx >= 0 && dayIdx < 30) days[29 - dayIdx]++;
      });
      const dmax = Math.max(...days, 1);
      let svg = `<svg viewBox="0 0 300 120" preserveAspectRatio="none" style="height:120px;width:100%">`;
      days.forEach((v, i) => {
        const w = 300 / 30;
        const h = (v / dmax) * 110;
        svg += `<rect x="${i * w + 1}" y="${120 - h}" width="${w - 2}" height="${h}" fill="var(--accent)" fill-opacity="0.85"/>`;
      });
      svg += `<line x1="0" y1="119" x2="300" y2="119" stroke="var(--border-subtle)" stroke-width="0.5"/></svg>`;
      document.getElementById('daily-svg').innerHTML = svg;
      document.getElementById('daily-total').textContent = `${days.reduce((s, v) => s + v, 0)} events`;

      // op-type distribution
      const opCounts = {};
      inRange.forEach(e => { opCounts[e.op] = (opCounts[e.op] || 0) + 1; });
      const opPairs = Object.entries(opCounts).sort((a, b) => b[1] - a[1]);
      const opMax = Math.max(...opPairs.map(([, c]) => c), 1);
      const opsEl = document.getElementById('ops-bars');
      opsEl.innerHTML = '';
      if (opPairs.length === 0) opsEl.append(el('div', { class: 'chart-empty' }, 'No operations in this range'));
      opPairs.forEach(([op, c]) => {
        const r = el('div', { class: 'bar-row' });
        r.append(
          el('span', { class: 'name' }, op),
          el('span', { class: 'bar-track' }, el('span', { class: 'bar-fill', style: `width:${c / opMax * 100}%` })),
          el('span', { class: 'num' }, String(c)),
        );
        opsEl.append(r);
      });
      document.getElementById('ops-total').textContent = `${inRange.length} ops`;

      // table — built via createElement + textContent (NEVER innerHTML).
      // caller_path comes from `ps -p PID -o command=` which any local
      // process can poison via argv[0]; file_target comes verbatim from
      // user CLI flags. Treating them as HTML would let a poisoned audit
      // row hijack the admin session via a stored XSS in the same origin
      // as the API surface.
      const tbody = document.getElementById('audit-rows');
      tbody.innerHTML = '';
      filtered.slice(0, 200).forEach(e => {
        const tr = document.createElement('tr');
        tr.append(
          el('td', { class: 'ts' }, relTime(e.ts)),
          el('td', {}, el('span', {
            class: `op-tag op-${(e.op || '').replace(/[^a-z_]/g, '')}`,
            style: 'padding:1px 7px;border-radius:3px;font-size:10px',
          }, e.op || '')),
          el('td', { class: 'name' },
            el('a', { href: `/entry/${encodeURIComponent(e.name || '')}` }, e.name || '')),
          el('td', { class: 'caller' }, e.caller_path || ''),
          el('td', { class: 'file' }, e.file_target || '—'),
          el('td', { class: e.success ? 'ok' : 'fail' }, e.success ? '✓' : '✗'),
        );
        tbody.append(tr);
      });
    }

    load();
  }

  if (document.querySelector('.settings-shell')) {
    api('/api/status').then(s => {
      const uptime = Math.max(0, Math.floor(Number(s.uptime_sec) || 0));
      document.getElementById('status-body').replaceChildren(
        kvRow('version', s.version),
        kvRow('port', location.port),
        kvRow('uptime', `${Math.floor(uptime / 60)} min ${uptime % 60} s`),
        kvRow('config_dir', s.config_dir, 'mono'),
      );

      const securityBody = document.getElementById('security-body');
      const securityRows = [
        kvRow(
          'KEYS_KEEPER_ALLOW_REVEAL',
          s.reveal_env_set ? '✓ set' : '✗ not set',
          s.reveal_env_set ? 'success' : 'danger',
        ),
      ];
      if (s.keychain_mode) {
        securityRows.push(kvRow(
          'Keychain interaction',
          s.keychain_mode === 'bypass' ? 'bypass · dialogs disabled' : 'prompt · macOS may ask',
          s.keychain_mode === 'bypass' ? 'success' : '',
        ));
      }
      securityRows.push(kvRow('URL token', '✓ active · HttpOnly · stripped from history', 'success'));
      securityBody.replaceChildren(...securityRows);
      if (!s.reveal_env_set) {
        securityBody.append(el(
          'div',
          {
            style: "margin-top:14px;padding:10px 12px;background:var(--bg);border:1px solid var(--border);border-radius:5px;font-family:var(--font-ui);font-size:11px;line-height:1.6",
          },
          el('div', { style: 'color:var(--text-4);margin-bottom:4px' }, '# add to ~/.zshrc to enable'),
          el('div', { style: 'color:var(--accent)' }, 'export KEYS_KEEPER_ALLOW_REVEAL=1'),
        ));
      }
    });

    document.getElementById('shutdown-btn').onclick = async () => {
      if (!confirm('Shutdown the server now?')) return;
      await api('/api/shutdown', { method: 'POST' });
      document.body.innerHTML = '<div class="curtain"><div class="glyph">K</div><div class="title">Server stopped</div><div class="sub">Re-run <span class="mono">keys serve</span> to restart.</div></div>';
    };

    // --- cloud sync (S3) ---
    const syncBody = document.getElementById('sync-body');
    const escH = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const SYNC_MODES = ['off', 'manual', 'auto'];
    const modeOpts = sel => SYNC_MODES.map(m => `<option value="${m}"${m === sel ? ' selected' : ''}>${m}</option>`).join('');
    const post = body => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : null });
    const trimVal = id => (document.getElementById(id).value || '').trim();
    const rawVal = id => document.getElementById(id).value || '';  // secrets: never trim
    const setSyncMsg = t => { const m = document.getElementById('sync-msg'); if (m) m.textContent = t; };

    function syncFormHTML(p) {
      p = p || {};
      return `
        <div class="field-section-title">${p.configured ? 'reconfigure' : 'connect an s3 bucket'}</div>
        <div class="form-row"><div class="label">endpoint <span class="req">*</span></div>
          <input class="text-input" id="sf-endpoint" placeholder="https://<acct>.r2.cloudflarestorage.com" value="${escH(p.endpoint)}"></div>
        <div class="form-row"><div class="label">bucket <span class="req">*</span></div>
          <input class="text-input" id="sf-bucket" value="${escH(p.bucket)}"></div>
        <div class="form-row"><div class="label">access key id <span class="req">*</span></div>
          <input class="text-input" id="sf-akid" autocomplete="off" value="${escH(p.akid)}"></div>
        <div class="form-row"><div class="label">secret key <span class="req">*</span></div>
          <input class="text-input" id="sf-secret" type="password" autocomplete="new-password"></div>
        <div class="form-row"><div class="label">passphrase <span class="req">*</span></div>
          <input class="text-input" id="sf-pass" type="password" autocomplete="new-password" placeholder="encrypts the cloud copy"></div>
        <div class="form-row"><div class="label">region</div>
          <input class="text-input" id="sf-region" value="${escH(p.region || 'us-east-1')}"></div>
        <div class="form-row"><div class="label">prefix</div>
          <input class="text-input" id="sf-prefix" value="${escH(p.prefix || 'keys-keeper')}"></div>
        <div class="form-row"><div class="label">addressing</div>
          <select class="text-input" id="sf-addr"><option value="path"${(p.addressing || 'path') === 'path' ? ' selected' : ''}>path</option><option value="virtual"${p.addressing === 'virtual' ? ' selected' : ''}>virtual</option></select></div>
        <div class="form-row"><div class="label">mode</div>
          <select class="text-input" id="sf-mode">${modeOpts(p.mode || 'manual')}</select></div>
        <div class="row gap-4 sync-actions">
          <button class="btn btn-primary" id="sf-connect">${p.configured ? 'Save' : 'Connect'}</button>
          ${p.configured ? '<button class="btn btn-ghost btn-sm" id="sf-cancel">Cancel</button>' : ''}
          <span class="mono sync-msg" id="sync-msg"></span>
        </div>
        <div class="sync-note">Credentials go straight to your OS keychain over this loopback-only admin — never written to config or shown again.</div>`;
    }

    function syncStatusHTML(s) {
      const rv = s.remote_version == null ? '—' : s.remote_version;
      const lv = s.local_synced == null ? '—' : s.local_synced;
      return `
        <div class="kv-row"><span class="key">mode</span><span class="val">${escH(s.mode)}</span></div>
        <div class="kv-row"><span class="key">bucket</span><span class="val">${escH(s.bucket)}</span></div>
        <div class="kv-row"><span class="key">endpoint</span><span class="val mono">${escH(s.endpoint)}</span></div>
        <div class="kv-row"><span class="key">remote version</span><span class="val">${rv}</span></div>
        <div class="kv-row"><span class="key">local synced</span><span class="val">${lv}</span></div>
        <div class="kv-row"><span class="key">local changes</span><span class="val ${s.dirty ? 'danger' : 'success'}">${s.dirty ? 'yes — push to publish' : 'in sync'}</span></div>
        ${s.reachable === false ? `<div class="kv-row"><span class="key">remote</span><span class="val danger">unreachable (${escH(s.note)})</span></div>` : ''}
        <div class="row gap-4 sync-actions">
          <select class="text-input sync-mode-sel" id="sync-mode">${modeOpts(s.mode)}</select>
          <button class="btn" id="sync-pull">Pull</button>
          <button class="btn btn-primary" id="sync-push">Sync now</button>
          <button class="btn btn-ghost btn-sm" id="sync-reconfig">Reconfigure</button>
          <span class="mono sync-msg" id="sync-msg"></span>
        </div>`;
    }

    async function syncRefresh() {
      let s;
      try { s = await api('/api/sync/status'); } catch { syncBody.textContent = 'status unavailable'; return; }
      if (s.configured) { syncBody.innerHTML = syncStatusHTML(s); wireSyncStatus(s); }
      else { syncBody.innerHTML = syncFormHTML({ mode: s.mode === 'off' ? 'manual' : s.mode }); wireSyncForm(); }
    }

    async function runSync(path, verb) {
      setSyncMsg(verb + '…');
      try { const r = await api(path, post()); setSyncMsg(`${verb} ${r.synced ?? r.merged ?? 0} change(s)`); syncRefresh(); }
      catch (err) { setSyncMsg(err.message); }
    }

    function wireSyncStatus(s) {
      document.getElementById('sync-mode').onchange = async e => {
        try { await api('/api/sync/mode', post({ mode: e.target.value })); setSyncMsg('mode → ' + e.target.value); }
        catch (err) { setSyncMsg(err.message); }
      };
      document.getElementById('sync-pull').onclick = () => runSync('/api/sync/pull', 'pulled');
      document.getElementById('sync-push').onclick = () => runSync('/api/sync/push', 'synced');
      document.getElementById('sync-reconfig').onclick = () => {
        syncBody.innerHTML = syncFormHTML({ ...s, akid: '', configured: true });
        wireSyncForm();
      };
    }

    function wireSyncForm() {
      const connect = document.getElementById('sf-connect');
      const cancel = document.getElementById('sf-cancel');
      if (cancel) cancel.onclick = syncRefresh;
      connect.onclick = async () => {
        const payload = {
          endpoint: trimVal('sf-endpoint'), bucket: trimVal('sf-bucket'),
          access_key_id: trimVal('sf-akid'), secret_key: rawVal('sf-secret'),
          passphrase: rawVal('sf-pass'), region: trimVal('sf-region'),
          prefix: trimVal('sf-prefix'), addressing: trimVal('sf-addr'), mode: trimVal('sf-mode'),
        };
        connect.disabled = true; setSyncMsg('connecting…');
        try { await api('/api/sync/setup', post(payload)); syncRefresh(); }
        catch (err) { setSyncMsg(err.message); connect.disabled = false; }
      };
    }

    syncRefresh();
  }
})();
