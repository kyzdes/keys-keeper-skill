# keys-keeper · Web Admin · UX Spec

> Generated: 2026-05-04 · Source language: ru (mixed)
> Archetype: internal-tool

## 1. Product Framing

- **Type:** Internal tool (local admin panel for personal CLI)
- **Audience:** A single developer/ops engineer who runs many AI agents and many servers, and constantly juggles API keys, SSH keys, server credentials, and domain info. Power user, terminal-fluent, wants speed and density over polish.
- **Core JTBD:** "When I need to store, look up, edit, or hand off any of the dozens of secrets and credentials I work with daily, I want a fast local admin for my `keys` CLI, so I can browse, search, copy, and bulk-import — without ever exposing plaintext values to my chat agent or my browser DOM."
- **Success metric:** time-to-find-and-copy a credential (target ≤5 sec from `keys serve` to clipboard) · zero accidental plaintext exposures · share of personal secret-handling that lives in this tool vs. scattered notes files (target: 100% migration within 2 weeks of v1).
- **Out of scope:** multi-user / teams · remote access · cloud sync · mobile/tablet · plaintext display of any secret value in the DOM · onboarding wizards · marketing surfaces.

## 2. Functional Scope

### Must-have features (v1)

- Browse all entries grouped by type (`api_key`, `ssh_key`, `server`, `domain`, `note`) on one dashboard.
- Fuzzy search across `name`, `tags`, `note` from a single auto-focused search bar.
- Multi-select tag-chip filters at the top of the dashboard.
- Server-mediated copy-to-clipboard (CLI reads keychain → `pbcopy` → 30 s auto-clear; UI never sees the value).
- Create / edit / delete entries via type-specific forms.
- Replace a secret value via an inline paste field whose contents are wiped from the DOM as soon as the form is submitted.
- Linked-entry navigation: clicking a `ssh_key` ref-chip on a `server` entry jumps to that ssh_key entry; reverse refs ("Used by: ...") shown on the target.
- Bulk paste import (`/paste`) — split-pane textarea + live preview table; supports `=`/`:` separators, triple-quoted multiline, `#` comments, `[tag1,tag2]` suffix, `(type)` prefix.
- Audit log table with filters (time range, op, name, caller path, success).
- Three audit charts: top-10 entries by access (7 d), daily activity (30 d), op-type distribution.
- Settings / status: server uptime, port, version, idle countdown, "shutdown now" button, `KEYS_KEEPER_ALLOW_REVEAL` env-var status, last export date.
- Command palette (`Cmd+K`) — fuzzy-jump to any entry by name from anywhere.
- Keyboard shortcuts: `/` focuses search, `Esc` clears filters / closes modal, `Cmd+Enter` submits form.

### Nice-to-have (v1.5+)

- Export / import via UI (currently CLI only).
- Touch-ID-gated reveal of single field for inspection (deferred — DOM-side reveal is the highest-risk surface).
- Light theme (default is dark).
- Per-entry edit-history diff view.

### Explicitly out of scope

- Multi-user / teams / RBAC — single-user product, single machine.
- Remote / mobile access — localhost-only by design; security model breaks if remote.
- Plaintext value display in DOM — even with reveal-flow, the value would land in browser memory / extension reach. Reveal stays CLI-only via `keys reveal`.
- Heavy charting framework — inline SVG sparklines only; the audit panel is informational, not analytical.

## 3. User Flows

### Flow 1: Find and copy a secret [primary]

1. **Entry:** Run `keys serve` in terminal → browser opens with `http://127.0.0.1:7777/?t=TOKEN` → token is read into JS, `history.replaceState` strips it from the URL bar.
2. Search bar is auto-focused. Type "openrouter" → fuzzy match list updates live across all types.
3. Click matching row (or `Enter` to select first result) → entry detail panel slides in (or row expands inline depending on §8.4 DIM 2 layout choice).
4. Click "Copy" on the secret field → backend reads from keychain, pipes to `pbcopy`, returns success.
5. UI shows toast: "Copied. Auto-clear in 30 s." Countdown indicator on the toast.
6. **Outcome:** secret in clipboard, ready to paste into target app. Server clears clipboard at 30 s if it still contains the value it wrote.

**Failure paths:**
- Keychain access prompt fired (Touch ID / password) → toast reflects the wait, no auto-clear timer until paste resolves.
- Clipboard already changed by user before 30 s → server detects mismatch, skips clear, no surprise wipe.

### Flow 2: Bulk import old secrets file

1. **Entry:** Click "+ Bulk import" header button or visit `/paste` directly.
2. Left pane: large monospace textarea (~50% width, ~30 lines tall) with placeholder showing the supported format.
3. User pastes content from old notes file. Parser runs debounced (200 ms).
4. Right pane: preview table updates live — columns: row #, parsed name, guessed type (icon), value summary ("48 chars" or "12 lines"), parsed tags, error indicator.
5. User edits raw text on the left until the right preview is correct. Per-row dropdown can override the guessed type or tag set without touching the source text.
6. Click "Save all" (disabled while any row has an error).
7. Backend validates all entries against the existing namespace (no name collisions unless `--replace` mode), writes atomically to `data.json`+keychain in a single transaction.
8. **Outcome:** redirect to dashboard with toast "Imported N entries." All new rows highlighted for ~3 s.

**Failure paths:**
- Name collision → row marked red with "exists — choose: skip / overwrite / rename"; commit blocked.
- Multiline value mid-paste (still inside `"""`) → parser shows "open multiline block" error; commit blocked.
- Atomic write fails after validation → rollback, toast "Import failed: <reason>", source text preserved.

### Flow 3: Add a single new entry

1. **Entry:** Click "+ New" header button.
2. Modal slides over dashboard: type selector (5 radio cards with icons), name input (auto-slug as you type), then type-specific fields appear below.
3. Secret fields are paste-only textareas labeled "Paste secret value". They never round-trip back to the DOM after submit.
4. Tags input with autocomplete from existing tag set. Refs picker (server / ssh_key linkage) is a search-as-you-type field that lists existing entries by name.
5. `Cmd+Enter` saves; `Esc` cancels with a dirty-check confirm if any field was edited.
6. **Outcome:** new entry appears in dashboard, scrolled into view, briefly highlighted.

**Failure paths:**
- Validation error (name collision, missing required field) → inline red message under the field, save button disabled until resolved.
- Network blip mid-save (server died) → toast "Server unreachable — re-run `keys serve`", form data preserved in memory until page reload.

### Flow 4: Investigate access pattern in audit log

1. **Entry:** Click "Audit" tab in the top nav.
2. Three charts render at top: top-10 entries by access count (last 7 d, sparkline bars), daily activity (last 30 d, area-style sparkline), op-type distribution (horizontal stacked bar).
3. Filter bar below charts: date range presets (24 h / 7 d / 30 d / custom), op type multi-select, name search, success/failure toggle.
4. Table below: timestamp, op, name (clickable → entry detail), caller path, file target (for inject/resolve), success indicator.
5. Click a chart bar → filter table to that entry / day / op type. Click an entry name → jump to S2.
6. **Outcome:** user can see e.g., "this api_key was injected into `.env` 4 times this week from these caller paths" and decide whether to rotate it.

**Failure paths:**
- No events yet → empty state with copy "No access events yet — start using `keys` and they'll appear here."
- Audit log file corrupted (rare) → red banner with "Audit log unreadable. CLI can rebuild via `keys doctor`."

## 4. Screen Inventory

| ID | Screen | Purpose | Entry points | Key actions |
|----|--------|---------|--------------|-------------|
| S1 | Dashboard | Browse / search / filter all entries grouped by type | `/` (default) or token URL | Search, filter by tag, copy, click row |
| S2 | Entry detail | View / edit a single entry, navigate refs | Click row in S1 · Cmd+K palette · Audit table click | Edit fields, replace secret, delete, jump to refs |
| S3 | New / Edit modal | Create or edit any entry | "+ New" header button · Edit on S2 | Fill type-specific fields, save |
| S4 | Bulk paste | Mass-import secrets via parsed paste | "+ Bulk import" button · `/paste` deeplink | Paste, verify preview, save all |
| S5 | Audit | Table + charts of access events | "Audit" top-nav tab | Filter, sort, click-through to entry |
| S6 | Settings | Server status, shutdown, env-var status, backup info | "Settings" top-nav tab | Shutdown, view config |

## 5. Per-Screen Briefs

### S1 · Dashboard

- **Information hierarchy:** H1 — single search bar + tag-chip rail spanning the top width. H2 — type-grouped entry rows occupying ~75% of the viewport. H3 — per-row hover actions (copy, edit, more) on the right edge. Header chrome and footer kept minimal so the grid is the figure.
- **Key elements:**
  - Auto-focused search input with `/` shortcut hint.
  - Tag-chip rail (multi-select, additive AND filter).
  - Type group headers (api_key · ssh_key · server · domain · note) with counts.
  - Entry rows: type icon, monospaced name, fingerprint-style hash for secrets, tag chips, last-access relative time, copy button (always visible) + edit/more (on hover).
  - Header bar: logo glyph, "+ New", "+ Bulk import", `Cmd+K` palette hint, top-nav tabs (Dashboard / Audit / Settings).
- **States:**
  - **Empty:** large dashed panel "No secrets yet" + two CTAs ("Add one" → S3, "Import in bulk" → S4) + a small example block showing the bulk-paste format.
  - **Loading:** skeleton rows for ~150 ms (rare on local backend).
  - **Error:** red banner "Backend unreachable — re-run `keys serve`" with retry button.
  - **Success:** dense list, ~30+ rows visible at desktop ≥1280px.
- **Interactions:** `/` focuses search, `Cmd+K` opens palette overlay, `Esc` clears filters, click row → S2 (slide-in panel — does not navigate away), hover row → action buttons fade in, copy → toast.

### S2 · Entry detail

- **Information hierarchy:** H1 — entry name (inline-editable) + type badge + tag chips. H2 — fields panel (type-specific). H3 — links / refs panel + per-entry mini-audit history + danger zone (delete).
- **Key elements:**
  - Type badge color-coded subtly (one accent hue per type).
  - Inline-editable name (click to edit, blur to save).
  - Tags as removable chips + "+ add tag" inline button.
  - Type-specific field rows: label · value · per-field actions.
    - For secret fields: `••••• · last set Apr 12` + "[Replace]" button (opens inline paste field).
    - For non-secret fields: text shown directly + edit pencil.
  - "Linked entries" panel: one chip per ref (`server: do-prod-droplet → ssh_key: my-do-key`) — clickable.
  - "Used by" panel (reverse refs): if any other entry references this one.
  - Mini-audit: last 5 access events for this specific entry.
  - Action bar: Copy primary value · Edit full form · Delete (with confirm).
- **States:**
  - **Loading:** skeleton field rows.
  - **Error:** field-level red text, banner for entry-level failures.
  - **Success:** clean panel.
  - **Deleting:** modal confirms; if reverse-refs exist, shows them and offers `--cascade` checkbox before allowing delete.
- **Interactions:** click name → inline edit · click chip → navigate to that entry · hover field → edit affordance · `Cmd+S` saves dirty edits · `Esc` discards with confirm.

### S3 · New / Edit modal

- **Information hierarchy:** H1 — modal title ("New entry" / "Edit `<name>`") + type selector. H2 — fields (mandatory first, then notes/refs). H3 — save bar (footer).
- **Key elements:**
  - Type selector: 5 radio cards with icons, only on "New" (locked on "Edit").
  - Name input with auto-slug suggestion (`Open Router Cline` → `open-router-cline`).
  - Type-specific field set (api_key: service + value paste · ssh_key: public-key paste + private-key paste + optional passphrase paste + comment · server: host · port · user · auth radio · refs picker · domain: host · registrar · nameservers list · note: body textarea + secret toggle).
  - Tags input with autocomplete from existing tag set.
  - Refs picker (where applicable): search-as-you-type chooser that lists existing entries.
  - Notes textarea (always available).
  - Save bar: "Cancel" / "Save" + keyboard hint `Cmd+Enter`.
- **States:**
  - **Validating:** field borders red, message under field.
  - **Saving:** save button shows spinner.
  - **Success:** modal closes, dashboard scrolls to new row, brief highlight.
- **Interactions:** keyboard nav between fields (Tab) · `Cmd+Enter` saves · `Esc` cancels with dirty-check.

### S4 · Bulk paste

- **Information hierarchy:** H1 — page title "Bulk import" + format hint link ("see format"). H2 — split-pane (left textarea, right preview table). H3 — sticky save bar at bottom with summary ("Will save 14 entries · 0 errors").
- **Key elements:**
  - Left: monospace textarea, ~50% width, ~30 lines tall, with rich placeholder showing the full format example (API keys, SSH keys with `"""`, comments, tags suffix).
  - Right: preview table — row #, name, type-guess (with override dropdown), value summary ("48 chars" / "12 lines / multiline"), tags (with override input), error indicator (red dot + tooltip).
  - Below right: row-level errors expanded with line numbers and concrete fix hints.
  - Sticky save bar: aggregate count + "Save all" button (disabled if any error).
  - Format help collapsible card: shows full grammar with examples (default closed).
- **States:**
  - **Empty:** placeholder example visible in textarea, preview table shows "Paste content to begin" empty state.
  - **Parsing:** debounced spinner (rarely visible since parsing is local).
  - **Errors:** rows highlighted red, save disabled.
  - **Success:** redirect to dashboard with toast.
- **Interactions:** live parse on input · click preview row → focuses corresponding line in textarea · per-row dropdown overrides type · per-row tag input adds tags without editing source · `Cmd+Enter` saves if no errors.

### S5 · Audit

- **Information hierarchy:** H1 — three charts row. H2 — filter bar. H3 — table.
- **Key elements:**
  - Charts row: (a) top-10 entries by access count over last 7 d as sparkline-style horizontal bars · (b) daily activity over last 30 d as area-style sparkline · (c) op-type distribution as horizontal stacked bar (reveal vs inject vs copy vs resolve vs add vs delete vs export). All inline SVG, ~120 px tall each.
  - Filter bar: date range preset buttons (24 h / 7 d / 30 d / Custom) · op type multi-select chips · name search · success/failure toggle · clear-all.
  - Table: timestamp (relative + absolute on hover), op (color-coded chip), name (clickable → S2), caller path (truncated mid, full on hover), file target (for inject/resolve), success indicator.
  - Pagination at bottom: 100 rows per page, infinite scroll preferred.
- **States:**
  - **Empty:** "No access events yet" with copy explaining when events will appear.
  - **Loading:** skeleton chart bars + skeleton rows.
  - **Error:** "Audit log unreadable" banner with `keys doctor` hint.
- **Interactions:** click chart bar → filter table to that scope · click name → S2 · click op chip in row → filter to that op.

### S6 · Settings

- **Information hierarchy:** H1 — server status card. H2 — config + maintenance cards in a 2-col layout.
- **Key elements:**
  - Status card: uptime · port · version · idle countdown to auto-shutdown · current admin sessions count.
  - Config card: port preference (next-launch only) · theme (dark / light / system).
  - Maintenance card: shutdown button (confirm modal) · last export date · "How to export" hint with `keys export` command (UI does not run it) · `KEYS_KEEPER_ALLOW_REVEAL` env-var status (✓ set / ✗ not set, with `.zshrc` snippet).
  - Footer link: "Open audit log" · "Open config dir" (copies path).
- **States:**
  - **Idle:** read-only, light interactions.
  - **Shutdown confirm:** modal "Server will stop. You'll need to re-run `keys serve`. Continue?".
  - **Post-shutdown:** browser tab shows "Server stopped" curtain, no fetches succeed.
- **Interactions:** mostly read · shutdown is the only destructive action (always confirmed).

## 6. Constraints & Context

- **Platform & breakpoints:** macOS, desktop only. Layouts target **≥1280 px** primary. No mobile or tablet adaptation.

- **Per-breakpoint feature parity** (always required):

| Screen | Mobile (375–767) | Tablet (768–1279) | Desktop (≥1280) |
|--------|------------------|--------------------|------------------|
| S1 Dashboard | desktop-only | desktop-only | full |
| S2 Entry detail | desktop-only | desktop-only | full |
| S3 New/Edit modal | desktop-only | desktop-only | full |
| S4 Bulk paste | desktop-only | desktop-only | full |
| S5 Audit | desktop-only | desktop-only | full |
| S6 Settings | desktop-only | desktop-only | full |

  Below 1280 px the app shows a "Window too narrow — admin needs ≥1280 px" curtain rather than degrading layouts. This is a personal tool used at a desk; we don't burn design budget on responsive.

- **Accessibility:** WCAG AA contrast in both dark and light themes. Full keyboard navigation. Focus-visible rings on every interactive element. ARIA labels on all icon-only buttons. Live regions for toast notifications.
- **Localization:** English only (single-user, English-speaking shell environment).
- **Performance budget:** TTI < 500 ms on local backend. All UI interactions < 100 ms. No animations longer than 150 ms (this is a developer tool; speed beats polish).
- **Auth model:** one-time URL token (random 32-byte hex, URL-encoded). Token is read into JS on load and stripped from URL via `history.replaceState`. All API endpoints validate the token from a `Sec-Keys-Token` header (set by the page, not from the URL after first read).
- **Data sources:** local Python backend reads/writes `~/.config/keys-keeper/data.json` (metadata) and `~/.config/keys-keeper/audit.jsonl` (access log) and the macOS Keychain (secrets) via `security` CLI.
- **Offline behavior:** the app is local-only; "offline" and "online" are the same thing. Backend death is the only "offline" state and is signalled with the red "Backend unreachable" banner.

## 7. Design Context (for huashu)

- **Existing design system:** no.
- **Brand assets available:**
  - Logo: not provided. A monogram glyph (`KK` or a key-shaped mark) is acceptable; designer's choice. Personal tool — a strong distinctive logo is not critical, but the app should not look unfinished. Skip Core Asset Protocol (intentional — no brand to gather).
  - Colors: not specified. Designer chooses palette consistent with the references below.
  - Fonts: not specified. **Recommend monospace** for primary (entry names, fingerprints, code-like content) and a neutral sans for secondary copy. JetBrains Mono / IBM Plex Mono / Berkeley Mono-style are all on-vibe.
  - Product images / UI screenshots: N/A.
- **References / inspiration (user-provided):** 1Password Pro view × Stripe Dashboard × Linear's command palette. Terminal-adjacent, monospaced, low-chrome, fast, slightly utilitarian — NOT consumer-glossy.
- **Design direction known:** yes — terminal-adjacent monospaced power-user dashboard, dark-mode default, dense typography, monochrome palette with one accent hue used sparingly for status (success / danger / focus). Whitespace is engineered for scan-density, not for breathing room.
- **Brand voice / tone:** matter-of-fact, no marketing copy. Errors are direct ("Backend unreachable. Re-run `keys serve`."), success messages are short ("Copied. Auto-clear in 30 s."), empty states are functional ("No secrets yet — Add one or Import in bulk.").

## 8. Hand-off to huashu-design

### 8.1 Recommended delivery format

- [x] **`cjm-canvas`** — interactive HTML canvas with iframe-wrapped screen preview, right-sidebar tweaks (filtered per active screen), clickable CJM flow nav, alternate-states block, meta footer, "Copy lock-in prompt" button.
- [ ] `hi-fi-static`

**Reasoning:** 6 screens · 4 flows · multiple state branches (empty / error / dirty-edit / pending shutdown / bulk-paste error states / token-expired) · variation dimensions worth toggling live (type grouping, row density, paste split direction). Skip-conditions for `hi-fi-static` clearly fail (≤2 screens, ≤1 flow, no branching). `cjm-canvas` is the right shape — the user is a power user who will benefit from flipping through flows and state variants in one place.

### 8.2 Information density type

- [ ] Restrained
- [x] **High-density**

**Reasoning:** This is a power-user admin panel for someone with 50–200 entries across 5 types. The whole value prop is "show me a lot at once and let me find / copy fast." Restrained density would force scrolling and waste a desk-class screen. The references the user named (1Password Pro, Stripe Dashboard, Linear) all sit firmly on the dense side.

### 8.3 Per-screen position-4 answers

| Screen | Narrative role | Audience distance | Visual temperature | Capacity check |
|--------|---------------|-------------------|---------------------|----------------|
| S1 Dashboard | hero | 1m laptop | analytical | high-density risk (intentional — main reason to use the app) |
| S2 Entry detail | data | 1m laptop | calm | OK |
| S3 New/Edit modal | transition | 1m laptop | neutral | OK |
| S4 Bulk paste | transition | 1m laptop | analytical | risk-tight (textarea + preview table compete for width) |
| S5 Audit | data | 1m laptop | analytical-cold | OK |
| S6 Settings | end | 1m laptop | calm | OK |

### 8.4 Variation dimensions to explore

> All three §8.4 dimensions were locked on 2026-05-04 via the cjm-canvas Copy lock-in round-trip. Non-chosen variants archived in §9.5.

- **Dimension 1 — Type grouping in S1 Dashboard:** locked `unified-table` `[locked 2026-05-04]` — single table with a type column, sortable. Chosen because the user maintains 50–200 entries and prefers a single dense surface to compare across types in one glance, instead of switching tabs or scrolling sectioned headers.
- **Dimension 2 — Entry row density:** locked `comfortable` `[locked 2026-05-04]` — 2 lines per row (name + tags + last-access on top, note preview below). Chosen as the right balance between `compact` (loses note context) and `expanded` (refs inline crowd the unified-table layout).
- **Dimension 3 — Bulk-paste layout in S4:** locked `split-horizontal` `[locked 2026-05-04]` — textarea left, parsed preview right. Chosen because the user works on ≥1280 px desktop where horizontal real estate is plentiful and the eye-tracking pattern (paste → scan preview right) maps to Western reading order without vertical context-switching.

**Variation count recommendation:** 0 remaining open dimensions (all 3 locked). Future iteration can re-open via fresh canvas if the data set grows or a new screen is added.

### 8.5 Tweaks worth exposing

> Defaults below reflect the canvas iteration on 2026-05-04. Tweaks remain live-tunable in the production admin (Settings panel) for future iteration; the locked default is what the production app boots with.

- Color accent (rust / teal / amber) `[scope: global]` — **default `rust`** (locked 2026-05-04 across S1/S4/S5)
- Density (compact / comfortable / spacious) `[scope: global]` — **default `compact`** (locked 2026-05-04). Note: this is the global vertical-padding multiplier; `comfortable` row layout from §8.4 DIM 2 stacks on top of this.
- Theme (dark / light / system) `[scope: global]` — **default `system`** (locked 2026-05-04 — follows OS pref, falls back to dark)
- Command palette trigger position (sticky-header pill / floating-corner button / off) `[scope: global]` — **default `header`** (locked 2026-05-04)
- Type grouping (`tabs` / `sectioned-scroll` / `unified-table`) `[scope: S1]` — cross-references §8.4 DIM 1, locked to `unified-table`. Tweak retained for future iteration.
- Row layout (`compact` / `comfortable` / `expanded`) `[scope: S1]` — cross-references §8.4 DIM 2, locked to `comfortable`. Tweak retained.
- Hover-reveal action buttons (always-visible / on-hover / on-focus) `[scope: S1]` — **default `always`** (locked 2026-05-04)
- Bulk paste split direction (`split-horizontal` / `split-vertical` / `tabbed`) `[scope: S4]` — cross-references §8.4 DIM 3, locked to `split-horizontal`. Tweak retained.
- Audit chart style (sparkline / bar / hybrid) `[scope: S5]` — **default `bar`** (locked 2026-05-04)

### 8.6 Brand asset checklist

- [ ] Logo provided / found — designer chooses monogram or skip
- [ ] Product images / UI screenshots provided — N/A (no prior product)
- [ ] Colors specified — designer chooses palette consistent with references
- [ ] Fonts specified — designer chooses (monospace recommended for primary)
- [x] Reference inspiration provided — 1Password Pro · Stripe Dashboard · Linear command palette
- [ ] **Recommend huashu run §1.a Core Asset Protocol** — skip (no brand to gather; intentional)

### 8.7 Canvas construction hint (for huashu)

`cjm-canvas` form. Single HTML file (React + Babel via CDN, no build step).

**Layout:**
- Left/center stage: iframe-wrapped active-screen render with fake browser chrome (3 traffic-light dots, URL bar showing `127.0.0.1:7777/?t=•••`). Above the chrome a small pill: `S<id> · <SCREEN-NAME>`.
- Right sidebar (~360–400 px, sticky): four blocks in this order:
  1. **Tweaks** — render only §8.5 entries whose `[scope]` tag matches the active screen or `global`. Each tweak is a labeled toggle group of 3 buttons. Tweaks tied to a §8.4 dimension carry the heading `§8.4 DIM <n> <NAME>` so the user sees which axis they're touching.
  2. **Flow steps** — numbered list of the active CJM flow from §3 (Flow 1 active by default; selector at the top of this block lets user switch among Flows 1–4). Active step = filled dot + accent text. Clicking a step swaps the active screen and re-filters tweaks.
  3. **Alternate states** — corner-case states / variant swaps reachable from any step. Sourced from §5 (non-success branches: empty dashboard, bulk-paste error rows, delete-confirm with reverse-refs, post-shutdown curtain) and §9 (token-expired, backend unreachable). Each row labeled `<screen> · <state>` with `VARIANT N` or `SWAP` tag.
  4. **Meta footer** — three lines: `SOURCE · ux-spec-2026-05-04-keys-keeper-admin.md`, `SYSTEM · — (no design system)`, `DENSITY · HIGH-DENSITY`.
- **"Copy lock-in prompt" button** — sticky at the sidebar bottom. On click, assembles the §8.8 prompt with current state and writes to clipboard via `navigator.clipboard.writeText`. 2 s "Copied" toast.

**State management:** all tweak picks held in React state. Switching screen via flow-step click updates active screen + re-filters tweaks. No page reload, no router.

### 8.8 Lock-in prompt template (for the cjm-canvas Copy button)

The Copy button assembles this exact prompt:

```
Lock these design choices into the UX spec at /Users/viacheslavkuznetsov/Desktop/Projects/keys-keeper-skill/keys-keeper-skill/ux-spec-2026-05-04-keys-keeper-admin.md:

Screen <ACTIVE-S-id> · <ACTIVE-SCREEN-NAME>:
- §8.4 DIM <n> <NAME>: <SELECTED-VARIANT>
- §8.4 DIM <n> <NAME>: <SELECTED-VARIANT>
(repeat per active tweak)

Action: update §8.4 — mark these variants as "locked" for this screen and move non-chosen variants to §9.5 Considered Alternatives. Re-run §6 self-review and regenerate the §8 hand-off phrase.
```

Absolute path is embedded in the canvas as a constant (`SPEC_PATH`).

## 9. Open Questions & Assumptions

### Assumptions made (verify these)

- **Assumption:** Charts render as inline SVG sparkline-style; no Chart.js / D3 dependency. (Reasoning: keep payload tiny for a dev tool, three small charts don't justify a charting library.)
- **Assumption:** Default port is 7777, falling back to next free port if occupied; printed in the CLI startup banner.
- **Assumption:** Idle auto-shutdown after 15 minutes of no activity (no heartbeat from any open tab); tab-close fires `/shutdown` via `navigator.sendBeacon` for instant teardown.
- **Assumption:** `Cmd+K` palette is global — available from every screen including modals.
- **Assumption:** Refs panel on S2 shows reverse refs ("Used by: ...") in addition to outgoing refs.
- **Assumption:** Bulk-paste atomic write uses fcntl flock on `data.json` to coordinate with concurrent CLI processes.
- **Assumption:** Token is stored in `sessionStorage` after stripping from URL; never logged to console.
- **Assumption:** Theme defaults to dark; light theme is v1.5+ but token slot exists in design system from day 1.

### Open questions (need user input later)

- **Q:** Should S5 audit log allow CSV export from the UI? — **why it matters:** audit-style tools usually offer CSV; for v1 likely deferred to CLI (`keys audit > file.csv`). Decision can wait.
- **Q:** Should `Cmd+K` palette also support fuzzy actions (e.g., "copy openrouter-cline" as a one-shot command), or only entry navigation? — **why it matters:** Linear-style action palette would compress workflow further but doubles the surface of secret-handling commands; safer to start navigation-only.
- **Q:** When deleting an entry that other entries reference, should the default be `block` (require explicit cascade) or `cascade-with-confirm`? — **why it matters:** ergonomic vs. safe default. Recommend `block-with-suggested-cascade-button`.

### Inferred from archetype defaults

- High-density dashboard hero with searchable / filterable main table — standard internal-tool archetype.
- Top-nav tabs for major sections (Dashboard / Audit / Settings) — internal-tool default.
- Cmd+K palette for power-user navigation — Linear-influenced but a standard productivity-tool pattern.
- Tag-chip filter rail at top of main list — Notion / Linear pattern.

### Product Risks

- **Token leak via browser history:** the URL contains the token at first load. Mitigation — `history.replaceState` strips `?t=` before any external script can run; CSP forbids inline scripts; Sec-Keys-Token header used for all API calls after the initial read.
- **Cross-process localhost attack:** another local process scans `127.0.0.1:7777`. Mitigation — token is required on every endpoint; without it, server returns 403 immediately and audits the failed attempt.
- **Server clipboard left dirty after 30 s:** if user copied something else in the meantime, naive clear would wipe their unrelated data. Mitigation — server stores a hash of the value it wrote; on the 30 s timer it re-reads `pbpaste`, hashes, and only clears if the hash matches.
- **Bulk paste atomic failure mid-write:** partial writes leave inconsistent state. Mitigation — pre-validate all rows, write to `data.json.tmp`, fsync, atomic rename; rollback on any error; keychain writes only after `data.json` rename succeeds (and entry IDs are reusable on retry).
- **Race between concurrent CLI and admin server writes:** two processes touching `data.json` simultaneously. Mitigation — fcntl flock on every write; reads use atomic-rename guarantee.
- **DOM accidentally storing a revealed value:** any code path that lets a secret near React state risks devtools / extension exfil. Mitigation — hard architectural ban on showing values in DOM; copy is server→`pbcopy` only; replace flow uses uncontrolled paste field whose `value` is never stored in state and is sent over fetch then DOM-cleared.

### Considered Alternatives

> Populated via cjm-canvas Copy lock-in round-trips. Format: `S<id> · §8.4 DIM <n> <NAME>: considered <list>; locked <chosen> on YYYY-MM-DD.`

- **S1 · §8.4 DIM 1 TYPE-GROUPING:** considered `tabs`, `sectioned-scroll`; locked `unified-table` on 2026-05-04. Reason archived: tabs forced screen state per type and lost the ability to compare across types in one view; sectioned-scroll was visually nice but ate vertical space with sticky group headers.
- **S1 · §8.4 DIM 2 ROW-DENSITY:** considered `compact`, `expanded`; locked `comfortable` on 2026-05-04. Reason archived: compact dropped the note preview which is a key disambiguation signal in a flat unified-table layout; expanded crowded the row when refs were rendered inline alongside the type column.
- **S4 · §8.4 DIM 3 BULK-LAYOUT:** considered `split-vertical`, `tabbed`; locked `split-horizontal` on 2026-05-04. Reason archived: vertical compressed the textarea height so multi-line SSH keys scrolled awkwardly; tabbed forced context-switching between paste and preview which broke the live-feedback loop.

### Locked tweak defaults (non-DIM, from canvas iteration)

> §8.5 tweaks remain live-tunable in production. These are the boot defaults locked on 2026-05-04:

- color accent → `rust`
- density → `compact`
- theme → `system` (follows OS, dark fallback)
- palette trigger → `header`
- hover-reveal actions → `always` (S1)
- audit chart style → `bar` (S5)

---

**Hand-off phrase suggestion** (paste into a fresh huashu session):

```
Read this UX spec at /Users/viacheslavkuznetsov/Desktop/Projects/keys-keeper-skill/keys-keeper-skill/ux-spec-2026-05-04-keys-keeper-admin.md. All §8.4 dimensions are locked (see file for chosen variants); produce a hi-fi-static rendering of the locked design across all 6 screens, no variant toggles needed. Density type: high-density. Honor §8.3 per-screen position-4 answers and §8.5 locked tweak defaults. If mid-flow alternate states (empty / errors / delete-with-refs / shutdown-curtain / token-expired) need rendering, include them as additional artboards on the same canvas.
```

> The original cjm-canvas (`keys-keeper-admin-canvas.html`) is preserved as the live exploration tool and remains usable for re-opening any §8.4 dimension via fresh round-trip.
