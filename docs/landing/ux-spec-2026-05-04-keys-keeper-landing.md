# keys-keeper · Landing Page · UX Spec

> Generated: 2026-05-04 · Source language: ru (mixed)
> Archetype: landing
> Inferred from full brief (no Phase 1 batch needed)

## 1. Product Framing

- **Type:** Landing / marketing site (single long-scroll page)
- **Audience:** macOS power-user developer who runs many AI coding agents (Claude Code, Cursor, Aider, Cline, Codex CLI). HN, Twitter/X, Anthropic Discord, and r/ClaudeAI traffic. Technical, comfortable with CLI and pipx, privacy-conscious. Has been bitten by — or worried about — an AI agent leaking an API key into a transcript, PR, or vendor log.
- **Core JTBD:** "When I land here from an HN headline or a Tweet, I want to grasp in <60 seconds what makes keys-keeper different from 1Password CLI / doppler / vault, see proof it works, and decide whether to clone+install."
- **Success metric:** GitHub-star CTR (primary), `git clone` rate from the install snippet (proxy via referrer-tagged install hint), time-on-page > 60s, scroll-depth > 80%. No conversion funnel beyond GitHub.
- **Out of scope:** signup, auth, billing, blog, documentation site (docs live in repo README), analytics dashboard, contact form, newsletter capture.

## 2. Functional Scope

### Must-have (v1 launch)

- Hero with the UVP headline, sub, autoplay-muted-loop demo video (~30-45s), GitHub-stars badge, primary CTA (`git clone`), secondary CTA (Read on GitHub).
- "The contrast" — side-by-side terminal mock comparing Claude leaking a key via `Edit` vs Claude using `keys inject` (no value visible).
- Output-safe command surface — restyled README table as visual cards.
- Admin screenshot tour — 5 screens, dashboard hero + 1-line caption per screen.
- Architecture diagram — redrawn as SVG, not ASCII.
- Install snippet with one-click copy.
- Roadmap — checkbox-list of next backends and integrations.
- Honest limitations — verbatim from README.
- Threat model — single paragraph.
- Footer — GitHub link, MIT badge, author handle.

### Nice-to-have (v1.1+)

- "Trusted by ⭐ N developers" auto-pulled from the GitHub stars API once N > 200.
- Lightbox for admin screenshots (click to enlarge).
- Inline mini-player for the demo video with chapter markers (act 1 / act 2 / act 3 / act 4).
- A `?dev=1` query toggle that opens a debug panel showing all CSS variables — useful when iterating from the deployed URL.

### Explicitly out of scope

- Email signup / newsletter — landing has no list to capture for; redirect intent to GitHub stars instead.
- "Pricing" section — product is free MIT and has no commercial tier on the roadmap.
- Comparison table against 1Password / doppler / vault — too combative for a personal-tool launch; the contrast section already implies the diff.
- Multilingual (RU/EN) — copy is English-only; Russian audience reads English fine, and a translation toggle adds chrome we don't need.

## 3. User Flows

### Flow 1: HN / Tweet click → install [primary]

1. **Entry:** click from HN front page or Twitter card → land on hero.
2. Watch demo video (autoplay starts within 1s of viewport entry).
3. Scroll past contrast section, output-safe surface table, admin tour.
4. Hit Install section → click copy on install snippet.
5. Switch to terminal, paste, install.
6. **Outcome:** local `keys` binary on PATH, repo starred on GitHub.

**Failure paths:**
- Demo video fails to load (slow connection / blocked CDN) → poster image with play icon stays visible; user can click to load.
- Visitor on a phone — install snippet still copyable, but the value is "save to read on desktop later"; primary CTA on mobile becomes "Star on GitHub" instead of "Copy install" (intent split below the cut-off, see §10).

### Flow 2: Skeptical scan → leave or star

1. **Entry:** lands from a Discord/Reddit reference, expects to bounce.
2. Reads hero in 5s.
3. Scrolls fast, scans output-safe surface table headings.
4. Stops at "Limitations" or "Threat model" — wants to confirm honest framing.
5. **Outcome:** either bounces with a star (low-friction "I'll check this later") or leaves with no action.

**Failure paths:** none — bounce is fine.

### Flow 3: Architecture nerd deep-read

1. **Entry:** sent the link by a friend with "you'll like the architecture".
2. Hero → Contrast → fast-scrolls past surface table.
3. Stops at Architecture diagram, reads carefully.
4. Scrolls to Install, then to GitHub link in footer.
5. **Outcome:** opens repo in a new tab, reads `docs/superpowers/specs/...design.md`.

**Failure paths:** repo link broken / repo private — would be catastrophic, mitigated by hard-coding `https://github.com/kyzdes/keys-keeper` and verifying public visibility before launch.

## 4. Screen Inventory

> Treating each section of the long-scroll landing as a "screen" so per-section briefs and position-4 answers stay precise. Single page, contiguous IDs.

| ID | Section | Purpose | Entry points | Key actions |
|----|---------|---------|--------------|-------------|
| S1 | Hero | UVP + demo + CTAs above the fold | top of page · `#` | watch demo · star · clone |
| S2 | The contrast | Side-by-side leak vs protected terminal mock | scroll · `#contrast` | read · scan diff |
| S3 | Output-safe surface | Claude-safe vs shell-only command table, restyled | scroll · `#surface` | scan · copy commands |
| S4 | Admin tour | 5 admin screens with captions | scroll · `#admin` | scan · open repo |
| S5 | Architecture | SVG diagram of CLI ↔ Keychain ↔ data.json ↔ admin | scroll · `#architecture` | trace data flow |
| S6 | Install | Copyable bash snippet (pipx + skill install) | scroll · `#install` | copy · paste · run |
| S7 | Roadmap | Checkbox list of next backends and integrations | scroll · `#roadmap` | gauge investment |
| S8 | Limitations | Honest scope (macOS, single-user, etc.) | scroll · `#limitations` | trust check |
| S9 | Threat model | Defended-against vs not, 1 paragraph | scroll · `#threat` | trust check |
| S10 | Footer | GitHub link, MIT badge, author tagline | scroll · `#footer` | open repo |

## 5. Per-Screen Briefs

### S1 · Hero

- **Information hierarchy:** H1 — UVP headline (1 line, ≤60 chars). H2 — sub (≤120 chars). H3 — demo video (largest single element on first viewport). H4 — paired CTAs. H5 — supporting badges (stars, MIT, tests passing).
- **Key elements:**
  - Top-left: monogram K + word "keys-keeper" (same glyph as admin)
  - Top-right: nav links — "GitHub" · "Docs" (anchors to README sections) · star count badge auto-pulled
  - Center stage: headline + sub + autoplay-muted-loop demo video (16:9, ~960×540 displayed, source 1920×1080) with rounded corners and subtle border matching admin's `.browser-frame` style
  - Below video: 2 CTAs side-by-side. Primary `Copy install` (rust accent button) reveals one-shot bash on click; secondary `Read on GitHub` (ghost button) opens repo in new tab
  - Foot of hero: row of micro-badges — ⭐ stars · MIT · 103 tests passing · macOS · Python 3.10+
- **States:**
  - **Default:** video loops silently. CTAs idle.
  - **Loading:** poster image with play overlay if video bytes still streaming.
  - **Video failed:** poster image stays, "play" overlay becomes "watch on GitHub" link (graceful no-JS).
  - **CTA hover:** primary subtly brightens; secondary border becomes solid.
- **Mobile adaptation:** video stacks above headline (first thing visible — the demo IS the pitch). CTAs stack vertically. Star badge collapses to icon.

### S2 · The contrast

- **Information hierarchy:** H1 — section title "the leak vs the fix". Below: 2-column grid (side-by-side desktop, stacked mobile). Each column is a stylized terminal window with fake-browser chrome.
- **Key elements:**
  - Left column header: red-tinted bar reading "without keys-keeper". Body: simulated Claude Code transcript. User prompt → assistant uses `Edit` tool → the `new_string` parameter contains `OPENROUTER_API_KEY=sk-or-v1-DEMO0…abc`. The key is highlighted with a danger-red underline. Caption below: "value lives in the transcript, in the model provider's logs, in your shell history".
  - Right column header: rust-accent bar reading "with keys-keeper". Body: same prompt → assistant uses `keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY` → tool result reads `injected 1 secret`. Caption below: "value lives only in keychain + the destination file. transcript stays clean".
- **States:** static; no interactive states. Hover on a column dims the other (subtle visual reinforcement of "look at this side now").
- **Mobile adaptation:** columns stack with the leak ON TOP (problem before solution — this is intentional). Captions move below each terminal mock.

### S3 · Output-safe surface

- **Information hierarchy:** H1 — section title "command surface, by design". Below: 2-column comparison. Left: "for Claude (safe)". Right: "for shell (gated)". Each row in left has a ✓ in success-green; right has a ⚠ in danger-amber.
- **Key elements:**
  - Left column: 6 rows — `keys add NAME --from-clipboard` · `keys list / info / audit` · `keys copy NAME` (auto-clear 30s) · `keys inject NAME --file F --as ENV` · `keys resolve FILE` · `keys ssh NAME`. Each row has the command in JetBrains Mono + a 1-line description.
  - Right column: 1 row — `keys reveal NAME` requires `KEYS_KEEPER_ALLOW_REVEAL=1` env-var. Description ends with "the structural guard that fires before any prose can override it".
  - Below grid: callout blockquote — "the shipped skill markdown tells Claude: 'You MUST NOT run keys reveal. You CAN use keys copy / inject / resolve / ssh.'"
- **States:** static. Optional hover reveals a tooltip with the full command syntax.
- **Mobile adaptation:** columns stack. The "for Claude" 6 rows become a vertical list. The single "for shell" row collapses to a single warning card.

### S4 · Admin tour

- **Information hierarchy:** H1 — section title "and a local admin". Below: 5 screenshots arranged in a 2-3-grid (dashboard hero + 4 smaller). Each has a 1-line caption underneath.
- **Key elements:**
  - Hero screenshot (top, full-width): dashboard with ~10 entries visible in unified-table layout. Caption: "everything in one searchable list".
  - 4 smaller cards (2×2 grid below hero):
    1. Entry detail — refs panel visible. Caption: "type-aware fields, linked entries, mini-audit per entry"
    2. Bulk paste — split-pane with preview. Caption: "import 50 keys from your old notes file in one paste"
    3. Audit — 3 charts visible. Caption: "every op logged, every chart inline-SVG, never a third-party tracker"
    4. Settings — KEYS_KEEPER_ALLOW_REVEAL row visible. Caption: "the env-var gate, plain to see"
  - All screenshots in fake-browser-chrome wrapper with "127.0.0.1:7777" in the URL bar (visual reinforcement that this is local-only).
- **States:** click on a screenshot → lightbox opens at full resolution. ESC closes.
- **Mobile adaptation:** screenshots stack vertically. Hero screenshot first, then 4 in single column. Lightbox behaves identically.

### S5 · Architecture

- **Information hierarchy:** H1 — section title "how it fits together". Below: SVG diagram with grouped boxes connected by directed lines.
- **Key elements:**
  - Top row: 2 source nodes — "Claude Code (skill)" · "Shell / scripts"
  - Middle: central node "`~/.local/bin/keys`" with subtitle listing 14 subcommands in 2 lines of mono
  - Bottom-left: "Keychain (`security`)" · Bottom-right: "data.json + audit.jsonl"
  - Side-mounted: "Web admin (127.0.0.1:7777)" — connects to both keychain and data.json
  - Lines: directional arrows. No animation by default (autoplay video is enough). Optional subtle pulse on the data.json arrow when in viewport (CSS keyframe).
  - Below diagram: 1-line caption "Two-layer storage: secrets in macOS Keychain (Touch-ID protected). Metadata in JSON (Time Machine-friendly)."
- **States:** static. Optional hover on a box dims the others (focus mode). No click actions.
- **Mobile adaptation:** simplified vertical flow — sources at top, central CLI in middle, two storage backends below, admin as a side note. Drop the side-mount geometry.

### S6 · Install

- **Information hierarchy:** H1 — section title "install in 5 minutes". Below: single code block (terminal-styled) with 4 commands. Copy button top-right of the block.
- **Key elements:**
  - Code block content:
    ```
    git clone https://github.com/kyzdes/keys-keeper.git
    cd keys-keeper
    pipx install .
    ./scripts/install_skill.sh
    ```
  - Copy button: clicking copies the entire 4-line block to clipboard, button label briefly flips to "✓ copied".
  - Below code: prerequisite line in muted color — "requires Python 3.10+ and macOS. Linux/Windows on the roadmap."
  - Optional secondary block (smaller, muted): "if you don't have pipx: `brew install pipx && pipx ensurepath`"
- **States:**
  - **Default:** copy button shows clipboard icon
  - **Copied:** label flips for 2s, then reverts
  - **Failed (clipboard API blocked):** falls back to selecting the block text for manual copy
- **Mobile adaptation:** code block scrolls horizontally if needed. Copy button still top-right. Tap-to-copy works the same.

### S7 · Roadmap

- **Information hierarchy:** H1 — section title "roadmap". Below: bulleted list with checkbox-style indicators.
- **Key elements:** list of items, each with `[ ]` prefix:
  - Linux backend via `secret-tool` (libsecret)
  - Windows backend via Credential Manager (with chunking for SSH keys)
  - Touch ID-gated reveal in admin (auto-wipe DOM after 10s)
  - Cursor / Aider / Cline rule-file generators beyond the Claude skill
  - CSV export from `/audit`
  - Bulk-paste parser extension for ssh_key / server / domain
  - Light theme polish
  - Below list: 1-line invitation — "PRs welcome. See [contributing](#contributing-link) below."
- **States:** static. Optional hover shows tooltip with rough effort estimate (skip for v1).
- **Mobile adaptation:** identical (already a single column).

### S8 · Limitations

- **Information hierarchy:** H1 — section title "honest limitations". Below: 5 items in a horizontal row of cards (or stacked on mobile). Each card has a single label + 1 sentence.
- **Key elements:** 5 cards:
  1. **macOS only.** Keychain backend is the only one shipped.
  2. **Single user, single machine.** No team / multi-user / sharing.
  3. **No cloud sync.** Use `keys export` + your encrypted file sync route.
  4. **Bulk paste is api_key-only.** Other types via `+ New` form in admin.
  5. **`caller_path` is best-effort.** Forensics-level, not court-evidence.
- **States:** static.
- **Mobile adaptation:** cards stack vertically.

### S9 · Threat model

- **Information hierarchy:** H1 — section title "threat model". Below: 2 paragraphs in body copy, no bullets.
- **Key elements:**
  - Para 1: "Defends against — AI agents extracting plaintext into transcripts (the original motivation), accidental `git add` of `.env` files, plaintext clipboard residue, ad-hoc shell scripts that need a key without you retyping it."
  - Para 2: "Does NOT defend against — a root-level adversary on your Mac, malware with full keychain access, screen-recording on a compromised host, or network attackers (the admin is localhost-only and never reachable from outside the loopback interface anyway)."
- **States:** static.
- **Mobile adaptation:** identical.

### S10 · Footer

- **Information hierarchy:** Single horizontal row of 4 elements + 1 tagline below.
- **Key elements:**
  - Left: monogram K + "keys-keeper · v0.1.0"
  - Center: 3 links — `GitHub` · `Issues` · `MIT License`
  - Right: author handle `@kyzdes`
  - Below: italicized 1-liner — "designed by an over-caffeinated dev who got tired of redacting agent transcripts"
- **States:** links underline on hover.
- **Mobile adaptation:** stacks into 4 lines, tagline last.

## 6. Constraints & Context

- **Platform & breakpoints:** static HTML, no framework, no build step. Single `index.html` + inline `<style>` + inline minimal `<script>` (or split into `landing.css` and `landing.js` if size warrants — but inline is fine at this scale). Desktop primary; mobile responsive via media queries. Breakpoints:
  - Desktop ≥ 1280 px
  - Tablet 768–1279 px
  - Mobile 375–767 px

- **Per-breakpoint feature parity table:**

| Screen | Mobile (375–767) | Tablet (768–1279) | Desktop (≥1280) |
|--------|------------------|-------------------|-----------------|
| S1 Hero | full · video stacks above title · CTAs vertical | full · video and title side-by-side at smaller scale | full · widescreen video, side-by-side CTAs |
| S2 Contrast | full · columns stacked, leak first | full · side-by-side at narrower widths | full · side-by-side at full width |
| S3 Surface | full · columns stacked | full · side-by-side | full · side-by-side |
| S4 Admin tour | full · screenshots stack vertically | full · 2×2 grid + hero | full · 2×2 grid + hero, lightbox enabled |
| S5 Architecture | simplified vertical flow diagram | full SVG, scaled | full SVG |
| S6 Install | full · horizontal-scroll on long lines | full | full |
| S7 Roadmap | full · single column | full | full |
| S8 Limitations | full · cards stack | full · cards in 3+2 row | full · cards in 5-column row |
| S9 Threat | full | full | full |
| S10 Footer | full · stacks into 4 lines | full · single row | full · single row |

- **Accessibility:** WCAG AA contrast in dark theme (already audited for the admin; same tokens). Full keyboard navigation — tab through CTAs, copy buttons, footer links. Focus-visible rings on every interactive element. ARIA labels on icon-only nav buttons. `<video>` has descriptive `aria-label`. Captions baked into the video for sound-off viewers.
- **Localization:** English-only.
- **Performance budget:** LCP < 1.5s on a 4G connection. Hero video uses `preload="metadata"` not `preload="auto"` — load on viewport entry via IntersectionObserver. Admin screenshots WebP with `loading="lazy"`. No external scripts.
- **Auth model:** none — public landing.
- **Data sources:** static. Optional: GitHub stars badge fetched once on load via the GitHub API.
- **Offline behavior:** static page works offline once cached.

## 7. Design Context (for huashu)

- **Existing design system:** yes. Two source files for tokens:
  - `src/keys_keeper/static/app.css` — production admin CSS, ~1370 lines. The token block at top is the source of truth (`:root { --bg, --surface, --accent, --text, ... }`).
  - `keys-keeper-admin-canvas.html` — interactive design canvas, same tokens. Use for visual reference of components like fake-browser-chrome, dense data tables, dark monospaced typography.
- **Brand assets available:**
  - Logo: monogram "K" in a 22-24px rounded square with rust fill (already used in admin's topbar). Reuse verbatim.
  - Colors: locked. `--bg: #0a0b0c` · `--surface: #131517` · `--surface-2: #181b1e` · `--border: #24282d` · `--text: #e8e9eb` · `--text-2: #a3a8af` · `--text-3: #6c7178` · `--accent: #d97550` (rust) · `--success: #6fb37a` (green) · `--danger: #d96565` (red).
  - Fonts: JetBrains Mono primary (display, code, table headers), Inter secondary (long-form prose). Same Google Fonts CDN as admin.
  - Product images: 5 admin screenshots (placeholders for now — the production admin can be captured fresh once the demo seed data from `scripts/demo/setup.sh` is loaded).
  - Demo video: placeholder (mp4 + gif; designer mocks an animated terminal frame in the layout, real video swaps in later).
- **References / inspiration (locked):** Stripe Dashboard data-density × Linear changelog calm clarity × Tailscale terminal-like landing. NOT modern SaaS startup with shiny gradient hero or "10x productivity" copy.
- **Design direction known:** yes — terminal-adjacent dark monospaced one-pager, rust accent used sparingly for CTAs and status, monochrome elsewhere. Hero video is the centerpiece; everything else recedes around it.
- **Brand voice / tone:** matter-of-fact technical. Self-deprecating in the footer, dry in the body, never ironic about security. Lowercase headings (`the leak vs the fix`, not `The Leak vs The Fix`) reinforces the engineering vibe. No exclamation points. No emoji except a sparing ✓ ⚠ ⭐ where they earn their place.

## 8. Hand-off to huashu-design

### 8.1 Recommended delivery format

- [ ] `cjm-canvas`
- [x] **`hi-fi-static`** — single full-fidelity HTML page in `docs/landing/index.html`, no canvas chrome, no flow nav, no sidebar, no Copy lock-in button. Production-shaped landing ready to deploy to a static host.

**Reasoning:** 1 long-scroll page · 1 primary flow (read → install / star) · no anon↔authed transitions · no multi-state branching worth toggling. The visual direction is already locked by the existing admin token system, so there's no exploration to facilitate via canvas. User explicitly requested hi-fi-static.

### 8.2 Information density type

- [ ] Restrained
- [x] **High-density**

**Reasoning:** the audience is power-user developers who scan fast and dismiss SaaS-fluff landings. They expect a lot of signal per scroll-screen — code blocks, comparison tables, architecture diagrams, multiple admin screenshots. Restrained density would feel like a marketing site and trigger their bullshit detector. High-density matches Stripe Docs / Linear / Tailscale, the reference set.

### 8.3 Per-screen position-4 answers

| Screen | Narrative role | Audience distance | Visual temperature | Capacity check |
|--------|---------------|-------------------|---------------------|----------------|
| S1 Hero | hero | 1m laptop | inviting-warm | OK (max breathing — video is the figure, everything else is ground) |
| S2 Contrast | data | 1m laptop | cold-cautious (left col) / calm-confident (right col) | OK |
| S3 Surface | data | 1m laptop | authoritative | risk-tight (table is dense by design) |
| S4 Admin tour | data | 1m laptop | inviting | OK |
| S5 Architecture | data | 1m laptop | calm-clarity | OK |
| S6 Install | transition | 1m laptop | focused | OK |
| S7 Roadmap | data | 1m laptop | calm | OK |
| S8 Limitations | end | 1m laptop | honest-calm | OK |
| S9 Threat | end | 1m laptop | authoritative | OK |
| S10 Footer | end | 1m laptop | calm | OK |

### 8.4 Variation dimensions to explore

> Note: hi-fi-static + locked visual direction. There is no fork of variants to explore at v1 launch. Dimensions listed for documentation and possible future iteration only — all locked to the chosen variant.

- **Dimension 1 — Hero video aspect ratio:** `16:9 widescreen` `[locked 2026-05-04]` vs `1:1 square` vs `9:16 portrait`. Locked widescreen because the demo will be embedded on Twitter (via separate square asset) and HN (link-only); the on-landing version stays widescreen for desktop primacy.
- **Dimension 2 — S2 Contrast layout:** `side-by-side at desktop, stacked at mobile` `[locked 2026-05-04]` vs `always stacked` vs `tabbed (toggle leak ↔ fix)`. Locked side-by-side because the comparison IS the rhetorical move; tabbed hides one half at a time and breaks the punch.

**Variation count recommendation:** 1 (production deliverable, design direction locked).

**Reasoning:** user explicitly said "Don't propose 3 directions — visual direction is locked". §8.4 is documented for future iteration if traffic data later suggests testing alternatives.

### 8.5 Tweaks worth exposing

> hi-fi-static has no live tweak panel. These are listed only as design knobs the implementer should keep cleanly factored as CSS variables so future iteration is one-line edits.

- Hero video aspect ratio (`16:9` / `1:1` / `9:16`) `[scope: S1]`
- S2 contrast layout breakpoint (768px / 1024px / always stacked) `[scope: S2]`
- Admin tour grid (`2×2 + hero` / `5×1 row` / `vertical scroll`) `[scope: S4]`
- Architecture diagram color emphasis (`mono` / `rust accent on data flow lines` / `success-green on safe paths`) `[scope: S5]`
- Install snippet expansion (`single block` / `step-by-step with separators`) `[scope: S6]`
- Footer tagline visibility (`always` / `hover-only` / `hidden`) `[scope: S10]`
- Color accent (`rust` / `teal` / `amber`) `[scope: global]` — locked rust to match admin

### 8.6 Brand asset checklist

- [x] Logo provided / found — monogram K from admin, reuse verbatim
- [ ] Product images — 5 admin screenshots pending (post-demo-seed; placeholders for first pass)
- [x] Colors specified — locked tokens above
- [x] Fonts specified — JetBrains Mono + Inter
- [x] Reference inspiration provided — Stripe Docs × Linear × Tailscale
- [ ] **Recommend huashu run §1.a Core Asset Protocol** — skip (we own the brand, no external assets needed)

### 8.7 Canvas construction hint (for huashu)

`hi-fi-static` form. Single HTML file, ready to drop into `docs/landing/index.html`. No canvas chrome, no sidebar, no flow nav, no Copy lock-in button.

**Layout:**
- Single full-page document.
- Inline `<style>` at top of `<head>` (or external `landing.css` if size > 1500 lines).
- Inline `<script>` at end of `<body>` for: copy-button handlers, video lazy-load via IntersectionObserver, GitHub stars badge fetch, optional `?dev=1` debug panel.
- Sections demarcated by anchor IDs (`#contrast`, `#surface`, etc.) for nav-link smooth-scroll.
- Demo video element: `<video autoplay muted loop playsinline preload="metadata" poster="hero-poster.png" aria-label="30-second demo: AI agent leaks key vs keys-keeper protects it">`.
- Admin screenshot lightbox: small vanilla JS or CSS-only via `:target` pseudoclass.

**Placeholder content for first pass:**
- Demo video → use a stylized animated SVG / CSS keyframe of a fake terminal showing the "leak" and "fix" text scrolling. Real mp4 swaps in via single `src` change later.
- 5 admin screenshots → use stylized div mockups with the existing admin CSS classes (`.entry-row`, `.unified-table-head`, `.audit-table`, etc.) as fake DOM. They're already valid markup; just dummy data inside. Real PNG/WebP captures swap in later.
- GitHub stars count → render as `★ —` until first JS fetch resolves.
- The 4-line install snippet → real strings, no placeholders.

**No tweak panel, no Copy lock-in, no flow nav — this is production HTML.**

### 8.8 Lock-in prompt template (N/A for hi-fi-static)

No Copy lock-in button on this deliverable. If future iteration converts this to a `cjm-canvas`, the round-trip prompt would be:

```
Lock these design choices into the UX spec at /Users/viacheslavkuznetsov/Desktop/Projects/keys-keeper-skill/keys-keeper-skill/docs/landing/ux-spec-2026-05-04-keys-keeper-landing.md:

Screen <ACTIVE-S-id> · <ACTIVE-SCREEN-NAME>:
- §8.4 DIM <n> <NAME>: <SELECTED-VARIANT>
(repeat per active tweak)

Action: update §8.4 — mark these variants as "locked" for this screen and move non-chosen variants to §9.5 Considered Alternatives. Re-run §6 self-review and regenerate the §8 hand-off phrase.
```

Absolute path: `/Users/viacheslavkuznetsov/Desktop/Projects/keys-keeper-skill/keys-keeper-skill/docs/landing/ux-spec-2026-05-04-keys-keeper-landing.md`.

## 9. Open Questions & Assumptions

### Assumptions made (verify these)

- **Assumption:** demo video is mp4 (≤2 MB) primary + gif (≤5 MB) fallback. Ready in ~1 day post-spec.
- **Assumption:** admin screenshots captured from the seeded demo state (`scripts/demo/setup.sh`) — 10 entries, populated audit log. Ready when user records the demo.
- **Assumption:** GitHub stars badge fetches via the public GitHub REST API (`GET https://api.github.com/repos/kyzdes/keys-keeper`). No auth, anonymous rate limit (60/h per IP) is fine for landing-scale traffic.
- **Assumption:** the `?dev=1` debug toggle is nice-to-have, not v1.
- **Assumption:** copy button uses Clipboard API with text-selection fallback.
- **Assumption:** hosting will be Cloudflare Pages or Vercel (decision deferred to user), but the deliverable is hosting-agnostic — single HTML + assets in `docs/landing/`. Domain choice (`keys-keeper.dev`? `keys.kuzdes.dev`?) is out of scope for this spec.

### Open questions (need user input later)

- **Q:** Should the demo video on the landing be the same mp4 we ship in the README, or a slightly different cut tuned for in-feed autoplay (e.g. starting on the leak frame instead of a title card)? — **why it matters:** in-feed autoplay benefits from grabbing attention in the first 0.5s; a title card wastes that window.
- **Q:** Domain choice and what the deployed URL looks like in the footer/og:url — **why it matters:** social cards (`og:image`, `og:url`) need to be set before HN/Twitter launch; defer until domain resolves.
- **Q:** OG image — should it be a static PNG with the headline + hero video poster, or a dynamic Vercel-OG-style render? — **why it matters:** for HN/Twitter share cards. Static PNG is simpler and good enough.

### Inferred from archetype defaults

- Single-page long-scroll layout matches the `landing` archetype default.
- Sections roughly mirror archetype's standard flow (hero · proof · features · how-it-works · install · faq-as-roadmap · footer), reordered to match the user's brief.
- Position-4 defaults: 1m laptop distance, calm-to-warm temperature scale.

### Product Risks

- **Demo video doesn't autoplay on iOS:** iOS Safari requires `playsinline` + muted + user gesture for some flows. Mitigation — `playsinline` set; muted set; if autoplay still blocked, IntersectionObserver triggers `.play()` on viewport entry (this works in modern Safari).
- **GitHub API rate-limit on stars badge:** anonymous limit is 60 requests/hour per IP; a sudden HN traffic spike could exhaust. Mitigation — cache the count in `localStorage` for 1h; render stale count on rate-limit error.
- **Visitor copies install snippet, hits a `pipx not found` error:** common — pipx isn't preinstalled on macOS. Mitigation — secondary muted block under the install code shows the brew install fallback.
- **Visitor on a corporate Mac without Homebrew or admin rights:** can't install pipx. Mitigation — link to a "manual install" doc in the README; landing doesn't try to handle this case.
- **Future domain change breaks social cards:** Mitigation — set canonical URL via `<link rel="canonical">` and update on deploy. Document the deploy step explicitly so future domain swaps don't lose meta.
- **Visitor lands on the page after the demo video has been recorded but before the recording is uploaded:** Mitigation — placeholder poster image with "demo coming soon" text is visible until video src is set.

### Considered Alternatives

> Initially empty. Populated automatically when the user pastes a "lock-in prompt" from a future cjm-canvas conversion. Format:
>
> - **S<id> · §8.4 DIM <n> <NAME>:** considered `<variant-A>`, `<variant-B>`; locked `<variant-C>` on YYYY-MM-DD.

(none yet)

## 10. Mobile / Responsive Design Block

### 10.1 Mobile-first principles for this product

- **Navigation pattern:** none — single-page scroll, no menu. The top-right "GitHub" link collapses to an icon on mobile.
- **Gesture model:** standard scroll. No swipe interactions, no pull-to-refresh. Tap-to-copy on install snippet. Tap on admin screenshot to enter lightbox.
- **Performance budget:** LCP < 2.5s on 4G mobile. Hero video uses `preload="metadata"`; full bytes load lazily on viewport entry. Admin screenshots use WebP + `loading="lazy"`.

### 10.2 Per-screen mobile adaptation

| ID | Desktop layout | Mobile adaptation | Hidden / collapsed | Mobile-specific gestures |
|----|----------------|-------------------|--------------------|---------------------------|
| S1 Hero | video centered, headline above, paired CTAs below | video stacks above headline (video first — it IS the pitch); CTAs stack vertically (primary on top); star badge collapses to icon | nav links collapse to "GitHub" icon only | tap CTAs |
| S2 Contrast | side-by-side terminal columns | stack vertically, leak first; both columns at 100% width | none | scroll past contrast (no horizontal interaction) |
| S3 Surface | 2-column comparison | columns stack; "for Claude" 6 rows become a vertical list, "for shell" single warning card sits below | none | tap a row to expand tooltip (defer to v1.5) |
| S4 Admin tour | hero + 2×2 grid | screenshots stack vertically; hero first then 4 in single column | full-resolution lightbox kept (works on phone too) | tap screenshot for lightbox |
| S5 Architecture | full SVG diagram, side-mounted admin | simplified vertical flow: sources at top, CLI in middle, two storage backends below, admin as a footnote | side-mount geometry | none |
| S6 Install | code block with copy button top-right | code block at full-width, horizontal-scroll inside if needed; copy button top-right | none | tap copy button |
| S7 Roadmap | bullet list single column | identical | none | none |
| S8 Limitations | 5 cards in horizontal row | cards stack vertically | none | none |
| S9 Threat | 2 paragraphs | identical | none | none |
| S10 Footer | single horizontal row | stacks into 4 lines (logo · links · author · tagline) | none | tap links |

### 10.3 Touch interactions vs pointer

- Hover-only patterns (column dimming on S2, tooltip on S3) are replaced by always-visible state on mobile (both columns fully visible, no tooltip).
- Tap targets ≥ 44×44pt — copy button, CTAs, footer links, admin screenshot cards.
- No swipe / drag / long-press gestures introduced.

### 10.4 Mobile-only screens or modes

- None. Same content surface, just reflowed.

### 10.5 Mobile column for §8.3 position-4

| Screen | Mobile audience distance | Mobile capacity check |
|--------|--------------------------|------------------------|
| S1 Hero | 10cm phone | risk-tight (video + headline + CTAs all fight for first viewport — video must dominate) |
| S2 Contrast | 10cm phone | OK (stacked so each column gets full width) |
| S3 Surface | 10cm phone | OK (vertical list reads natively) |
| S4 Admin tour | 10cm phone | OK |
| S5 Architecture | 10cm phone | risk-tight (SVG must simplify to vertical flow) |
| S6 Install | 10cm phone | risk-tight (long bash lines need horizontal scroll) |
| S7 Roadmap | 10cm phone | OK |
| S8 Limitations | 10cm phone | OK |
| S9 Threat | 10cm phone | OK |
| S10 Footer | 10cm phone | OK |

---

**Hand-off phrase suggestion** (paste into a fresh huashu session):

```
Read this UX spec at /Users/viacheslavkuznetsov/Desktop/Projects/keys-keeper-skill/keys-keeper-skill/docs/landing/ux-spec-2026-05-04-keys-keeper-landing.md. Produce a hi-fi-static rendering — single HTML file ready to drop into docs/landing/index.html. Density type: high-density. Honor §8.3 per-screen position-4 answers, §6 per-breakpoint feature parity, and §10 mobile/responsive specifications. Visual direction is locked by §7 (existing admin tokens in src/keys_keeper/static/app.css and keys-keeper-admin-canvas.html); do NOT enter advisor mode for design direction. Use stylized placeholders for the demo video and 5 admin screenshots per §8.7 — real assets swap in later via a single src change.
```
