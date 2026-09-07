// Connection material exists only in the authenticated page's memory.
// Never put codes in URLs, browser storage, telemetry, or error messages.
(() => {
  const body = document.getElementById('personal-body');
  if (!body) return;
  const message = document.getElementById('personal-message');
  const pairing = document.getElementById('personal-pairing');
  const requests = document.getElementById('personal-requests');
  let state = null, busy = false, codeTimer = null, polls = 0;

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function button(text, action, primary = false) {
    const node = el('button', primary ? 'btn btn-primary' : 'btn', text);
    node.type = 'button';
    node.onclick = () => run(action, node);
    return node;
  }
  function field(label, input) {
    const node = el('label', 'personal-field');
    node.append(el('span', '', label), input);
    return node;
  }
  function input(value = '', type = 'text') {
    const node = el('input', 'text-input');
    node.type = type; node.value = value; node.autocomplete = 'off';
    return node;
  }
  async function api(action, data) {
    const response = await fetch('/api/personal-sync/' + action, data === undefined ? {} : {
      method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data),
    });
    const value = await response.json();
    if (!response.ok) throw new Error(value.error || 'Could not connect. Please retry.');
    return value;
  }
  async function run(action, target) {
    if (busy) return;
    busy = true; if (target) target.disabled = true;
    message.textContent = 'Working…';
    try { await action(); }
    catch (error) { message.textContent = error.message; }
    finally { busy = false; if (target) target.disabled = false; }
  }
  function startupMessage(result) {
    message.textContent = result.autostart === false ? (result.error || 'Background sync is unavailable. Use Retry background sync.') : '';
  }
  function setup(options) {
    const grid = el('div', 'personal-grid');
    const main = el('div', 'personal-choice');
    main.append(el('h3', '', 'This is my main computer'), el('p', '', `${options.count} keys now. Future keys will be included automatically. Other computers can read keys and add new ones.`));
    const name = input(options.name), endpoint = input(options.endpoint, 'url');
    const token = el('select', 'text-input');
    const placeholder = el('option', '', 'Choose a saved VPS credential'); placeholder.value = ''; token.append(placeholder);
    for (const entry of options.token_entries) {
      const option = el('option', '', entry); option.value = entry; token.append(option);
    }
    token.value = options.admin_token_entry;
    main.append(field('Computer name', name), field('VPS address', endpoint), field('Saved administrator credential', token));
    main.append(button('Enable sync for all keys', async () => {
      const result = await api('setup', {name: name.value.trim(), endpoint: endpoint.value.trim(), admin_token_entry: token.value, all_keys: true});
      await refresh(); startupMessage(result);
    }, true));
    const join = el('div', 'personal-choice');
    join.append(el('h3', '', 'Connect this computer'), el('p', '', 'On your main computer, choose Add computer. Paste its connection code here.'));
    const workerName = input(options.name), code = el('textarea', 'text-input personal-code-input');
    code.rows = 3; code.autocomplete = 'off'; code.spellcheck = false;
    join.append(field('Computer name', workerName), field('Connection code', code));
    join.append(button('Connect to my keys', async () => {
      const result = await api('join', {code: code.value.trim(), name: workerName.value.trim()});
      code.value = ''; await refresh(); startupMessage(result);
    }, true));
    grid.append(main, join); body.replaceChildren(grid);
  }
  function clearCode() {
    clearTimeout(codeTimer);
    pairing.replaceChildren();
  }
  async function invite() {
    const value = await api('invite', {});
    const panel = el('section', 'personal-connect');
    panel.append(el('h3', '', 'Connect your other computer'), el('p', '', 'Open Settings → My computers there and paste this code. It expires in 10 minutes. Then compare the verification code on both screens.'));
    const code = el('textarea', 'text-input personal-code-input');
    code.rows = 3; code.readOnly = true; code.value = value.code;
    code.setAttribute('aria-label', 'One-time connection code'); code.spellcheck = false;
    const actions = el('div', 'row gap-4');
    actions.append(button('Copy connection code', async () => {
      try { await navigator.clipboard.writeText(code.value); }
      catch { code.focus(); code.select(); if (!document.execCommand('copy')) throw new Error('Select the code and copy it manually.'); }
      message.textContent = 'Code copied. Paste it only on your other computer.';
    }, true), button('Hide code', async () => { clearCode(); message.textContent = ''; }));
    panel.append(code, actions); pairing.replaceChildren(panel);
    codeTimer = setTimeout(() => { clearCode(); message.textContent = 'Connection code expired. Choose Add computer for a new one.'; }, Math.max(0, value.expires_at * 1000 - Date.now()));
    message.textContent = '';
  }
  function connected(value) {
    const summary = el('div', 'personal-summary');
    const detail = value.role === 'master' ? 'Main computer · all current and future keys' : 'Connected computer · read keys and add new ones';
    summary.append(el('strong', '', value.name), el('span', 'personal-muted', detail));
    const last = value.last_sync;
    const status = last?.status === 'synced' ? `Last synced ${new Date(last.at).toLocaleString()}` : last?.error || 'Ready to synchronize';
    summary.append(el('span', 'personal-muted', `${value.count ?? 0} keys · ${status}`));
    if (value.auto && value.background?.autostart === false) summary.append(el('span', 'personal-muted', value.background.error));
    const actions = el('div', 'row gap-4 personal-actions');
    actions.append(button('Sync now', async () => { await api('sync', {}); await refresh(); message.textContent = 'Sync complete'; }));
    if (value.role === 'master') actions.append(button('Add computer', invite, true));
    const auto = input('', 'checkbox'); auto.checked = value.auto;
    auto.onchange = () => run(async () => {
      const result = await api('auto', {enabled: auto.checked});
      await refresh(); startupMessage(result);
    }, auto);
    actions.append(field('Automatic sync every minute', auto));
    if (value.auto && value.background?.autostart !== true) actions.append(button('Retry background sync', async () => {
      const result = await api('auto', {enabled: true}); await refresh(); startupMessage(result);
    }));
    const list = el('div', 'personal-device-list');
    for (const device of value.devices || []) {
      const row = el('div', 'personal-device');
      row.append(el('strong', '', device.name), el('span', 'personal-muted', 'Read + add'));
      if (value.role === 'master') row.append(button('Disconnect', async () => {
        if (!window.confirm(`Disconnect ${device.name}? Future updates will stop. Keys already downloaded stay on that computer.`)) { message.textContent = ''; return; }
        await api('revoke', {device_id: device.device_id}); await refresh(); message.textContent = 'Computer disconnected';
      }));
      list.append(row);
    }
    body.replaceChildren(summary, actions, list);
  }
  async function refresh() {
    state = await api('status'); body.setAttribute('aria-busy', 'false');
    if (!state.configured) setup(state.options);
    else if (state.state === 'pending') {
      body.replaceChildren(el('h3', '', 'Confirm on your main computer'), el('p', '', 'Check that both screens show this verification code, then approve this computer on the main one.'), el('strong', 'personal-verification', state.comparison_code));
      body.append(button('Cancel connection', async () => {
        await api('cancel', {}); await refresh();
        message.textContent = 'Connection cancelled. You can paste a new code. If you already approved the old request, disconnect that device on your main computer.';
      }));
    } else if (state.state === 'setup_incomplete') {
      body.replaceChildren(el('p', '', 'Setup was interrupted. Retry with the same VPS and saved credential.'), button('Retry setup', async () => { const options = await api('options'); setup(options); message.textContent = ''; }));
    } else connected(state);
  }
  async function pending() {
    const result = await api('pending');
    const nodes = [];
    for (const request of result.requests) {
      const panel = el('section', 'personal-connect');
      panel.append(el('h3', '', `${request.name} wants to connect`), el('p', '', 'Compare this verification code with the one on your other computer. Approve only when they match.'), el('strong', 'personal-verification', request.comparison_code));
      panel.append(button('Codes match — approve computer', async () => {
        await api('approve', {pair_id: request.pair_id, fingerprint: request.fingerprint});
        clearCode(); requests.replaceChildren(); await refresh(); message.textContent = 'Computer approved. Its keys will appear automatically.';
      }, true));
      nodes.push(panel);
    }
    requests.replaceChildren(...nodes);
  }
  run(async () => { await refresh(); message.textContent = ''; });
  setInterval(async () => {
    if (busy || !state?.configured || document.hidden) return;
    busy = true;
    try {
      if (state.state === 'pending') {
        const result = await api('poll', {});
        if (result.status === 'active') window.location.reload();
      } else {
        if (state.role === 'master') await pending();
        if (++polls % 6 === 0) await refresh();
      }
    } catch (error) { message.textContent = error.message; }
    finally { busy = false; }
  }, 5000);
  window.addEventListener('pagehide', clearCode);
})();
