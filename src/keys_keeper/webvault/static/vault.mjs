// vault.mjs — the zero-knowledge web vault SPA.
//
// Flow: the user types uid + passphrase. We derive the AUTH hash (separate salt)
// to log in, then derive the BLOB key (the blob's own salt) to decrypt the
// snapshot — both in WebCrypto, in this page. The passphrase and plaintext never
// leave the browser. Decrypted entries live only in memory and are wiped on
// idle auto-lock. Secrets are masked by default, revealed/copied on demand.
//
// Security discipline: all DOM is built with el()/textContent — never innerHTML
// (the server also sets `require-trusted-types-for 'script'`). Nothing secret is
// ever written to localStorage/sessionStorage/IndexedDB.

import { decryptBlob, deriveAuthHash, hex, BadPassword } from "/static/kkcrypto.mjs";

const APP = document.getElementById("app");
const IDLE_MS = 5 * 60 * 1000;
const COPY_CLEAR_MS = 30 * 1000;
const AUTH_ITERS = 600000;     // must match the server's _AUTH_ITERS_DEFAULT
const THEME_KEY = "keys-keeper-theme";

let vault = null;          // decrypted payload { entries, tombstones } — in memory only
let idleTimer = null;

const TYPE_SHORT = {
  api_key: "AP", ssh_key: "SSH", server: "SV", domain: "DM", note: "NT",
};

function setTheme(theme, persist = false) {
  document.documentElement.dataset.theme = theme;
  document.querySelector('meta[name="theme-color"]')?.setAttribute(
    "content", theme === "light" ? "#f4f3f1" : "#0a0b0c");
  if (persist) {
    try { localStorage.setItem(THEME_KEY, theme); } catch { /* storage may be disabled */ }
  }
}

try {
  const saved = localStorage.getItem(THEME_KEY);
  setTheme(saved === "light" || saved === "dark"
    ? saved
    : (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
} catch {
  setTheme(matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
}

// ---- tiny helpers (no innerHTML) ----
function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids) {
    if (kid == null) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
}
const hexToBytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function mount(node) { clear(APP); APP.append(node); }
function themeControl() {
  const btn = el("button", { class: "btn btn-ghost btn-sm kkv-theme-toggle", type: "button" });
  const refresh = () => {
    const dark = document.documentElement.dataset.theme === "dark";
    btn.textContent = dark ? "Day" : "Evening";
    btn.setAttribute("aria-label", dark ? "Switch to day theme" : "Switch to evening theme");
  };
  btn.addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark", true);
    refresh();
  });
  refresh();
  return btn;
}

async function postJSON(path, body, headers = {}) {
  const r = await fetch(path, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, status: r.status, j: await r.json().catch(() => ({})) };
}
async function getJSON(path) {
  const r = await fetch(path, { credentials: "same-origin" });
  return { ok: r.ok, status: r.status, j: await r.json().catch(() => ({})) };
}
async function getBytes(path) {
  const r = await fetch(path, { credentials: "same-origin" });
  if (!r.ok) throw new Error("fetch " + r.status);
  return new Uint8Array(await r.arrayBuffer());
}

// ---- idle auto-lock ----
function bumpIdle() {
  if (!vault) return;
  clearTimeout(idleTimer);
  idleTimer = setTimeout(lock, IDLE_MS);
}
function lock() {
  vault = null;                                  // drop decrypted state
  clearTimeout(idleTimer);
  fetch("/auth/logout", { method: "POST", credentials: "same-origin" }).catch(() => {});
  renderUnlock("Locked — re-enter your passphrase.");
}
["click", "keydown", "mousemove"].forEach((ev) =>
  document.addEventListener(ev, bumpIdle, { passive: true }));

// ---- unlock screen ----
function renderUnlock(msg) {
  const uid = el("input", { class: "text-input", id: "kkv-uid", autocomplete: "username",
    placeholder: "account" });
  const pass = el("input", { class: "text-input", id: "kkv-pass", type: "password",
    autocomplete: "current-password", placeholder: "passphrase" });
  const err = el("div", { class: "kkv-err", role: "alert", "aria-live": "polite", text: msg || "" });
  const btn = el("button", { class: "btn btn-primary", type: "button", text: "Unlock" });

  async function doUnlock() {
    err.textContent = "";
    btn.disabled = true; btn.textContent = "Unlocking…";
    try {
      await unlock(uid.value.trim(), pass.value);
    } catch (e) {
      err.textContent = e instanceof BadPassword ? "Wrong account or passphrase."
        : (e.message || "Unlock failed.");
      btn.disabled = false; btn.textContent = "Unlock";
    } finally {
      pass.value = "";                            // wipe the passphrase field immediately
    }
  }
  btn.addEventListener("click", doUnlock);
  pass.addEventListener("keydown", (e) => { if (e.key === "Enter") doUnlock(); });

  mount(el("div", { class: "kkv-unlock" },
    themeControl(),
    el("div", { class: "kkv-brand" }, el("span", { class: "glyph", text: "K" }), "keys-keeper"),
    el("div", { class: "kkv-sub", text: "Your vault is decrypted in this browser. The passphrase never reaches the server." }),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-uid", text: "Account" }), uid),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-pass", text: "Passphrase" }), pass),
    err,
    btn,
    el("button", { class: "kkv-link", type: "button", text: "Create account →", onclick: () => renderRegister() }),
    el("div", { class: "kkv-note" },
      el("span", { class: "lock", text: "● zero-knowledge" }),
      " — we only ever store ciphertext. A lost passphrase cannot be reset.")));
  setTimeout(() => uid.focus(), 0);
}

// ---- register (account creation; AH derived client-side) ----
function renderRegister() {
  const uid = el("input", { class: "text-input", id: "kkv-register-uid", placeholder: "account", autocomplete: "username" });
  const pass = el("input", { class: "text-input", id: "kkv-register-pass", type: "password", placeholder: "vault passphrase", autocomplete: "new-password" });
  const conf = el("input", { class: "text-input", id: "kkv-register-confirm", type: "password", placeholder: "confirm passphrase", autocomplete: "new-password" });
  const token = el("input", { class: "text-input", id: "kkv-register-token", placeholder: "register token (from your admin)" });
  const err = el("div", { class: "kkv-err", role: "alert", "aria-live": "polite" });
  const btn = el("button", { class: "btn btn-primary", type: "button", text: "Create account" });

  btn.addEventListener("click", async () => {
    err.textContent = "";
    if (!uid.value.trim() || !pass.value) { err.textContent = "Account and passphrase required."; return; }
    if (pass.value !== conf.value) { err.textContent = "Passphrases don't match."; return; }
    btn.disabled = true; btn.textContent = "Creating…";
    try {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const ah = await deriveAuthHash(pass.value, salt, AUTH_ITERS);
      const r = await postJSON("/auth/register",
        { uid: uid.value.trim(), auth_salt: hex(salt), auth_iters: AUTH_ITERS, auth_hash: ah },
        token.value ? { "X-Register-Token": token.value } : {});
      if (!r.ok) throw new Error(r.j.error || "registration failed");
      await unlock(uid.value.trim(), pass.value);   // straight into the vault
    } catch (e) {
      err.textContent = e.message || "registration failed";
      btn.disabled = false; btn.textContent = "Create account";
    } finally { pass.value = ""; conf.value = ""; }
  });

  mount(el("div", { class: "kkv-unlock" },
    themeControl(),
    el("div", { class: "kkv-brand" }, el("span", { class: "glyph", text: "K" }), "new account"),
    el("div", { class: "kkv-sub", text: "Use the SAME passphrase that encrypts your vault. It never leaves this browser; only a one-way auth hash is sent." }),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-register-uid", text: "Account" }), uid),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-register-pass", text: "Passphrase" }), pass),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-register-confirm", text: "Confirm passphrase" }), conf),
    el("div", { class: "kkv-field" }, el("label", { for: "kkv-register-token", text: "Register token" }), token),
    err, btn,
    el("button", { class: "kkv-link", type: "button", text: "← back to unlock", onclick: () => renderUnlock() })));
}

// ---- unlock: login (AH) then decrypt (blob key) ----
async function unlock(uid, passphrase) {
  if (!uid || !passphrase) throw new Error("Enter your account and passphrase.");
  const params = await postJSON("/auth/params", { uid });
  if (!params.ok) throw new Error("Cannot reach the server.");
  const ah = await deriveAuthHash(passphrase, hexToBytes(params.j.auth_salt), params.j.auth_iters);
  const login = await postJSON("/auth/login", { uid, auth_hash: ah });
  if (!login.ok) throw new BadPassword();        // 401 → wrong account/passphrase

  const head = await getJSON("/vault/head");
  if (head.status === 404) { vault = { entries: [], tombstones: [] }; return renderVault(); }
  if (!head.ok) throw new Error("Vault unavailable (" + (head.j.error || head.status) + ").");
  const blob = await getBytes("/vault/object?key=" + encodeURIComponent(head.j.snapshot));
  vault = await decryptBlob(blob, passphrase);   // throws BadPassword on tamper/wrong pass
  renderVault();
}

// ---- vault list ----
function renderVault(query = "") {
  bumpIdle();
  const entries = (vault.entries || [])
    .filter((e) => !query || (e.name + " " + (e.tags || []).join(" ")).toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name));

  const search = el("input", { class: "text-input kkv-search", placeholder: "search…",
    value: query, oninput: (e) => { rerenderList(e.target.value); } });
  const list = el("div", { class: "kkv-list" });
  const inner = el("div", { class: "kkv-inner" });
  list.append(inner);

  function fillList(items) {
    clear(inner);
    if (!items.length) { inner.append(el("div", { class: "kkv-empty", text: "no entries" })); return; }
    for (const e of items) inner.append(rowEl(e));
  }
  function rerenderList(q) { fillList((vault.entries || [])
    .filter((e) => !q || (e.name + " " + (e.tags || []).join(" ")).toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => a.name.localeCompare(b.name))); }
  fillList(entries);

  mount(el("div", { class: "kkv-shell" },
    el("div", { class: "kkv-top" },
      el("div", { class: "kkv-brand" }, el("span", { class: "glyph", text: "K" }), "vault"),
      search,
      el("div", { class: "kkv-lockpill" }, el("span", { class: "dot" }), "unlocked"),
      themeControl(),
      el("button", { class: "btn btn-sm", type: "button", text: "Lock", onclick: lock })),
    list));
}

function rowEl(e) {
  const icon = el("div", { class: "kkv-icon", "data-type": e.type, text: TYPE_SHORT[e.type] || "?" });
  const open = () => renderEntry(e);
  return el("div", { class: "kkv-row", role: "button", tabindex: "0", onclick: open,
    onkeydown: (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
    } },
    icon,
    el("div", {}, el("div", { class: "kkv-name", text: e.name }),
      (e.tags && e.tags.length) ? el("div", { class: "kkv-tags" },
        ...e.tags.map((t) => el("span", { class: "kkv-tag", text: t }))) : null),
    el("div", { class: "kkv-meta", text: e.type }));
}

// ---- entry detail: reveal / copy ----
function renderEntry(e) {
  bumpIdle();
  const fields = [];
  for (const [k, v] of Object.entries(e.fields || {})) {
    fields.push(el("div", { class: "field-row" },
      el("span", { class: "key", text: k }), el("span", { class: "value", text: String(v) }), el("span")));
  }
  const secrets = [];
  if (e._secret != null) secrets.push(secretRow("secret", e._secret));
  if (e._secret_passphrase != null) secrets.push(secretRow("passphrase", e._secret_passphrase));

  mount(el("div", { class: "kkv-shell" },
    el("div", { class: "kkv-top" },
      el("button", { class: "kkv-detail-back", type: "button", text: "← back", onclick: () => renderVault() }),
      el("div", { class: "grow" }),
      themeControl(),
      el("button", { class: "btn btn-sm", type: "button", text: "Lock", onclick: lock })),
    el("div", { class: "kkv-list" }, el("div", { class: "kkv-inner" },
      el("h1", { class: "kkv-detail-name", text: e.name }),
      el("h2", { class: "field-section-title", text: "metadata" }),
      ...(fields.length ? fields : [el("div", { class: "kkv-empty", text: "—" })]),
      el("h2", { class: "field-section-title", text: "secret" }),
      ...(secrets.length ? secrets : [el("div", { class: "kkv-empty", text: "no secret" })])))));
}

function secretRow(label, value) {
  const val = el("div", { class: "kkv-secret-val masked", text: "••••••••••••" });
  let revealed = false;
  const reveal = el("button", { class: "btn btn-sm", text: "Reveal" });
  reveal.addEventListener("click", () => {
    revealed = !revealed;
    if (revealed) { val.textContent = value; val.classList.remove("masked"); reveal.textContent = "Hide"; }
    else { val.textContent = "••••••••••••"; val.classList.add("masked"); reveal.textContent = "Reveal"; }
    bumpIdle();
  });
  const copy = el("button", { class: "btn btn-sm", text: "Copy" });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      copy.textContent = "Copied · clears 30s";
      setTimeout(() => { copy.textContent = "Copy"; }, 2500);
      // best-effort auto-clear: overwrite the clipboard if it's still our value
      setTimeout(async () => {
        try { if ((await navigator.clipboard.readText()) === value) await navigator.clipboard.writeText(""); }
        catch { /* clipboard-read may be blocked; best-effort only */ }
      }, COPY_CLEAR_MS);
    } catch { copy.textContent = "Copy failed"; }
    bumpIdle();
  });
  return el("div", { class: "field-row" },
    el("span", { class: "key", text: label }), val,
    el("div", { class: "kkv-actions" }, reveal, copy));
}

// ---- boot ----
(async () => {
  const who = await getJSON("/auth/whoami").catch(() => ({ j: {} }));
  // Even with a live session we still need the passphrase to decrypt, so always
  // start at the unlock screen.
  void who;
  renderUnlock();
})();
