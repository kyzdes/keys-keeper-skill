# Changelog

All notable changes to keys-keeper. Format loosely follows [Keep a Changelog](https://keepachangelog.com/) + [Semver](https://semver.org/).

Distribution: install via the Claude Code marketplace (`/plugin install keys-keeper@claude-skills` after `/plugin marketplace add https://github.com/kyzdes/claude-skills`), the repository's Codex marketplace (`codex plugin marketplace add https://github.com/kyzdes/keys-keeper-skill`), or standalone `pipx install git+https://github.com/kyzdes/keys-keeper-skill`. Marketplace updates are explicit by default; mutable-HEAD SessionStart updates remain an opt-in compatibility mode.

## [Unreleased]

### Added

- Folders, projects, environments and explicit shared-entry assignments in the
  CLI and Admin UI, with metadata-only previews and device access summaries.
- Independent encrypted project profiles, read/create-only workers, authenticated
  enrollment, immutable submission queues, idempotent master import and scoped
  publication through a bounded `/v2/` relay API.
- Durable local revocation, epoch rekey, encrypted mutation recovery, verified
  migration backups, recovery-only restore and fresh-authority takeover.
- `keys project-sync watch` for background delivery and `keys-keeper-syncd backup`
  for consistent relay backups. Generated agent instructions describe these flows.

### Security

- Project selection reaches CLI/API/sinks without a master-backend fallback.
  Legacy full-vault writers refuse the migrated catalog. Read/create permission
  is enforced independently by the worker service, master importer and relay.
- Custom KK3 wire composition has cross-author internal review and independent
  byte tests; no external audit or production rollout is claimed.

### Fixed

- `python -m keys_keeper` propagates command failures to the process exit code.

---

## [0.8.0] — 2026-09-04

### Added

- Added S3-free KK2 multi-device sync through a private `keys-keeper-syncd`
  service: encrypted snapshots, Ed25519-signed hash-chain commits, SQLite CAS,
  root-key pinning, one-time device enrollment, X25519 VaultKey wrapping, and a
  separate offline recovery bundle.
- Added a hardened stdlib HTTP client, the `keys-keeper-syncd` process entrypoint,
  a non-root container definition, and VPS deployment/threat-model guidance.

### Security

- VPS sync requires HTTPS outside loopback, refuses redirects, bounds all wire
  payloads, keeps bearer tokens and private key material out of local sidecars,
  and fails closed on rollback, a branch that does not descend from the local
  checkpoint, pointer swap, unknown-device, or invalid membership/signature
  evidence. Independent split-view detection still requires witness/gossip.
- Device enrollment claims are idempotent across lost responses, and root-only
  device administration is enforced consistently by the CLI and sync service.
- Device revocation is deliberately labelled as server-access revocation; key
  epoch rotation for cryptographic post-revocation secrecy remains future work.

### Fixed

- Added `keys init codex-skill`, which installs Keys Keeper into Codex's stable
  personal skill directory instead of a versioned plugin-cache path. This keeps
  new tasks from inheriting paths that disappear after a plugin upgrade.

### Added

- Added per-row deletion and multi-select deletion to the local admin dashboard, including selection across search/tag filters and a visible-entry select-all control.
- Replaced browser deletion prompts with a themed, keyboard-accessible confirmation showing entry names, explicit linked-entry consent, progress, and retry of remaining entries after a partial failure.

---

## [0.7.8] — 2026-09-03

### Changed

- Aligned the admin and WebVault dark themes with the landing page's graphite surfaces, terracotta action color, semantic status colors, and restrained shadow system.
- Replaced the warm beige daylight palette with a neutral, high-contrast light theme that preserves the same product identity without a green or sepia cast.
- Added release contracts for landing-palette parity, browser chrome colors, quiet-text readability, and control-boundary contrast across both themes.

---

## [0.7.7] — 2026-09-03

### Added

- Added `keys keychain status --check` for a metadata-only, no-dialog readiness probe and `keys keychain prepare NAME [--check]` for bounded preparation of one original Keychain item's native decrypt ACL.
- Added an explicit access-context model so automatic sync, the local admin, and WebVault adapters cannot open macOS authorization UI or use the legacy compatibility bridge.

### Security

- Bulk-import preview now returns only secret presence, never the parser's secret-bearing value field.
- CLI, admin, bulk import, sync apply, and sync setup now share compensating mutation boundaries so ordinary failures restore prior metadata and credential values instead of leaving partial state.
- Tombstone pruning and snapshot application now reject or serialize concurrent metadata changes rather than overwriting them.

### Changed

- Split the agent skill into a short invariant-first entrypoint with six routed references, synchronized byte-for-byte between the source and Codex plugin payloads.
- Centralized admin and WebVault theme tokens while preserving the warm evening and high-contrast daylight themes.
- Decomposed the macOS native adapter, sync merge, and HTTP dispatch into smaller internal components without changing public formats or routes.
- Expanded CI across supported Python versions and a live Linux Secret Service job, and added clean-wheel verification for versions, command surface, runtime assets, and generated skill hashes.

---

## [0.7.6] — 2026-09-02

### Fixed

- Bypass now reads original legacy Keychain items whose decrypt ACL trusts only Apple's fixed `/usr/bin/security`: it first proves that exact authorization from native ACL metadata and verifies that the Keychain is already unlocked, then uses the trusted executable without rewriting or migrating the item.
- Unknown, locked, or untrusted ACLs still fail closed before a compatibility process starts, preventing authorization-dialog loops.

---

## [0.7.5] — 2026-09-02

### Fixed

- Replaced every runtime `/usr/bin/security` read/delete/list call with in-process Security.framework operations. Existing macOS Keychain items stay in place and plaintext never enters child-process arguments or output pipes.
- Added persistent `keys keychain bypass`: Keychain UI is disabled process-wide around each serialized native operation, so trusted items work silently and an untrusted legacy ACL returns an error instead of an authorization-dialog loop. `keys keychain prompt` restores the interactive policy.
- Settings now reports the active prompt/bypass policy without opening Keychain, and agent instructions stop the exact retrying caller before enabling bypass only on an explicit user request.

---

## [0.7.4] — 2026-09-02

### Changed

- Replaced the green-tinted neutral system with a warm evening palette and a high-contrast daylight palette, both applied through shared semantic tokens.
- Added a persistent, system-aware day/evening theme switch that initializes through a CSP-compatible local script before the page is painted.
- Removed the redundant dashboard footer disclaimer while preserving the Process env metadata boundary.

---

## [0.7.3] — 2026-09-02

### Changed

- Expanded the agent contract with deterministic temporary-sink cleanup, protected plaintext-export rules, install-path diagnostics, shell-argument hygiene, and an explicit distinction between item presence, successful secret resolution, and external service validity.
- Corrected repeatable tag examples so each tag uses its own `--tag` flag, and corrected audit guidance to use exact stored operation names.
- Refined the local admin around one UI typeface with monospace reserved for code and measurements, authored SVG icons, stronger hierarchy and focus states, and a responsive mobile layout for the dashboard, details, forms, audit, and settings surfaces.

---

## [0.7.2] — 2026-08-09

### Security

- Hardened plaintext file sinks with owner-only creation and replacement semantics, while preserving existing destination permissions where appropriate. Audit metadata no longer records secret-adjacent source paths.
- Kept macOS Keychain writes and clipboard-clear verification values out of process arguments. Linux Secret Service enumeration no longer requests or parses secret values.
- Added strict validation and size bounds for imported metadata before any vault mutation.
- Hardened SSH execution: trusted executable resolution, owner-only key tempfiles, and safer cleanup across supported platforms.
- Moved the local admin token from navigable URLs into an `HttpOnly` session cookie and bounded request bodies before parsing.
- Replaced unsupported same-user isolation claims with the accurate compatibility-mode boundary: normal commands reduce transcript exposure, while clipboard/file sinks and arbitrary same-user shell code remain outside the guarantee.

### Added

- A minimal, implicitly invokable Codex plugin bundle under `plugins/keys-keeper`.
- A repository-local Codex marketplace manifest at `.agents/plugins/marketplace.json`, so the GitHub repository URL is sufficient to discover and install the plugin.
- Regression contracts for release-version parity, Codex bundle isolation, prompt-injection handling, secure sinks, SSH execution, Keychain argv hygiene, and local-admin authentication.

### Changed

- Claude's SessionStart updater is now fail-closed by default. Mutable `HEAD` updates require the explicit `KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE=1` opt-in; reviewed release updates remain the recommended path.
- The dashboard FILTER rail stays on one horizontally scrolling row, keeping the entries table visible even with many tags.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.7.1...v0.7.2)

---

## [0.7.1] — 2026-06-12

### Security

- **Web vault: the per-IP login/registration rate limiter is now correct behind a reverse proxy.** It previously keyed on the socket peer — always the proxy — so every client shared one bucket (a single source could DoS-lock auth for everyone, and online password guessing wasn't throttled per source). With `--behind-proxy` it now keys on the rightmost `X-Forwarded-For` hop (the one the trusted proxy appended; leftmost, client-spoofable entries are never trusted). (KI-023)
- **Web vault: the `Server` response header no longer leaks the Python interpreter version** (it is now just `"kkvault"`). (KI-024)

### Internal

- Expanded web-vault proxy test coverage: session logout/idle-expiry, tampered-cookie rejection, whoami gating, multi-tenant prefix-from-session isolation, HEAD-rebuild + empty-vault, upstream-error→502 and NotFound→404 mapping, the key allow-list (valid + malformed), register edge cases, `/static/` traversal, absence of any write surface, malformed Content-Length, anti-enumeration determinism, and the two hardening fixes above. Added ~20 web-vault hardening/edge tests.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.7.0...v0.7.1)

---

## [0.7.0] — 2026-06-05

### Added

- **Zero-knowledge web vault (`keys webvault serve`) — read-only v1.** Open your vault from a browser. Because the cloud copy is a self-contained `KK1` blob (`PBKDF2-600k → AES-256-GCM`, all native to WebCrypto), the browser fetches it and **decrypts it in-page with your passphrase** — the passphrase and plaintext never reach the server. The server is a hardened, authenticated **ciphertext shuttle** that reuses `S3Remote` and never imports `crypto` (a test asserts it). The browser is a *third client* on the same encrypted blob the CLI + local admin sync to; this generalises the project's promise from "an agent can't leak your secrets" to "**the server can't**." v1 is read-only (unlock → view/search → reveal/copy → idle auto-lock); add/edit stay in the CLI/local admin.
  - **Auth split (multi-tenant-ready, blob unchanged).** Login sends an *auth hash* derived from the passphrase with a **different** salt; the server stores only stdlib-`scrypt(auth_hash)`. It can authenticate you without being able to decrypt your vault. The blob key stays `PBKDF2(passphrase, blob.salt, 600k)` exactly as the CLI writes it, so the same blob is readable everywhere. Per-account S3 prefix is derived **server-side from the session**, never from the request.
  - **Hardening for an internet-exposed, in-DOM secret app.** Strict CSP with **no `unsafe-inline`** + `require-trusted-types-for 'script'`, all DOM via `textContent` (never `innerHTML`), SRI on the bundle, self-hosted fonts, HSTS + `nosniff`/`DENY`/`no-referrer`/COOP/CORP, `no-store`, `HttpOnly; SameSite=Strict; Secure` cookies, reveal-on-demand, clipboard auto-clear, idle auto-lock, **non-extractable** `CryptoKey`, session anti-enumeration. The honest caveat of any web vault — "trust the server to serve honest JS" — is answered by self-hosting + the published SRI hash, not overclaimed.
  - **Zero new dependencies** (stdlib `http.server` + `hashlib.scrypt` + `S3Remote`; the frontend is vanilla WebCrypto). Ships as `docs/webvault/Dockerfile`; falls back to the local `keys sync` config for a quick self-host demo.

### Internal

- New subpackage `keys_keeper/webvault/` (`server.py`, `store.py`, `remote.py`, `cli.py`) + a static SPA (`index.html`, `kkcrypto.mjs` WebCrypto port, `vault.mjs`, `vault.css`, reused `app.css`). Tests: a Node known-answer test that the browser port decrypts a CLI-produced blob byte-identically (`test_webvault_crypto.py`), and proxy tests for auth gating, session-derived namespacing, key validation, hardened headers, and the never-decrypts invariant (`test_webvault_server.py`). Test count: 307 passing + 13 platform-gated skips on macOS.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.6.0...v0.7.0)

---

## [0.6.0] — 2026-06-03

### Added

- **S3 cloud sync — back up and sync your vault across machines.** `keys sync setup/push/pull/status/mode/rollback`, plus an opt-in auto-sync on session start. Connect any S3-compatible bucket (AWS S3, Cloudflare R2, Backblaze B2, MinIO, Wasabi); the whole vault is encrypted into a single AES-256-GCM blob (the same format as `keys export`) before it ever leaves the machine.
  - **Git-like versioned snapshots.** Each push writes an immutable `snapshots/NNNNNN-<device>.kk` blob and a plaintext `versions/NNNNNN.json` commit (`{version, parent, device, ts, snapshot, entries_hash}` — never an entry field or secret), with a `HEAD` cache. `keys sync rollback <version>` restores any earlier snapshot and republishes it so peers converge.
  - **Id-keyed merge, no duplicates.** Entries merge by their UUID `id` (not name) with last-write-wins on `updated_at` and a deterministic content tiebreak, so re-pulling is idempotent and two machines converge without dupes. Deletes propagate via new **soft-delete tombstones** (`data.json` schema **v1→v2**, auto-migrated with a `.bak`) instead of being resurrected by an older peer snapshot.
  - **Portable optimistic concurrency.** Commits use `PUT … If-None-Match:*` (create-if-absent) with bounded re-pull/re-merge/retry. Providers that ignore the precondition (older MinIO/B2) are detected at setup and fall back to a read-back-after-write check; a CAS-capable provider is recommended and noted in `keys sync setup`.
  - **Auto mode.** `keys sync mode auto` enables a non-interactive SessionStart hook (`scripts/sync-hook.sh`) that pulls+pushes in a debounced, backgrounded, **fail-open** worker — any missing credential or network error exits 0 and never blocks or noises up a session. The encryption passphrase is read from the OS keychain (set once at setup); manual mode prompts.
  - **Web `/settings` Sync panel.** Status, mode toggle, and Pull / “Sync now” buttons. By design there is **no secret entry in the browser** — first-time setup (which stores the S3 access key id, secret key, and passphrase in the OS keychain under reserved `kk:sync-*` accounts) stays in the CLI.
  - **Zero new dependencies.** AWS Signature V4 is hand-rolled over the stdlib (`urllib`/`hashlib`/`hmac`) — no boto3 — and locked to the official AWS `get-vanilla` known-answer test vector. `config.toml` (non-secret settings only) is read/written by a tiny hand-rolled flat-TOML parser since the Python floor is 3.10 (no `tomllib`).

### Security

- Snapshots are uploaded only after passing `encrypt_blob` (asserted `KK1` magic before every PUT); the S3 secret key never leaves its `Sealed` envelope except as the derived SigV4 signing key, and is never placed in a header, URL, log, or exception. S3 provider error bodies (which can echo the access key id / StringToSign) are deliberately **not** spliced into exception messages. `versions/`/`HEAD` carry no entry data. `config.toml`, `sync-state.json`, and `sync.log` are written `0600` on POSIX. A full adversarial multi-agent review (security/leak · correctness/concurrency · requirements · SigV4/S3 protocol) plus a dedicated security-review pass were run; all confirmed findings fixed.

### Internal

- New modules: `config.py`, `sync_remote.py` (SigV4 + S3 verbs), `sync.py` (merge engine + version chain), `cli_sync.py` (commands + web API + auto hook). `store.py` gains tombstones + the v2 migration + `apply_merge`; `paths.py` gains `sync_state_json`; `api.py`/`settings.html`/`hooks.json` gain the sync surface. ~70 new tests (SigV4 vector, transport, merge/CAS/rollback/GC, migration, CLI, auto, web API, hooks). Test count: 295 passing + 13 platform-gated skips on macOS.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.5.2...v0.6.0)

---

## [0.5.2] — 2026-06-02

### Fixed

- **Linux `keys doctor` reported the keyring as empty even when it wasn't.** `SecretToolBackend.list_ids()` parsed only `secret-tool search`'s stdout, but `secret-tool` writes its item dump (the `attribute.account = …` lines) to **stderr** — stdout carries only the secret value. So `list_ids()` always returned `[]` on a real keyring, which made `keys doctor`'s keychain/metadata sync check misreport. `set`/`get`/`delete` were unaffected. Now parses stderr (plus stdout as a fallback) and de-dupes. Caught by the `ubuntu-latest` CI job's live `secret-tool` tests; added an off-keyring regression test so it's covered on every platform.

### Internal

- **Marketplace description stays in sync automatically.** `scripts/sync-marketplace.sh` mirrors `plugin.json`'s `description` into the `kyzdes/claude-skills` marketplace manifest (versions already auto-sync — the marketplace sources the plugin by git URL). A maintainer-local `PostToolUse` hook on `git commit` (`.claude/settings.local.json`, gitignored) runs it after every skill commit; it no-ops cleanly for contributors who don't have the marketplace clone. Marketplace clone path overridable via `KEYS_KEEPER_MARKETPLACE_DIR`.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.5.1...v0.5.2)

---

## [0.5.1] — 2026-06-02

### Fixed

- **Windows migration crashed past ~20 secrets with a cryptic `WinError 8`.** A real macOS→Windows `keys import` died at the 21st entry with `KeychainError: CredWriteW failed ... WinError 8` — on a 64-byte value, so not a size issue. Root cause: Windows Credential Manager enforces a **20-credentials-per-app** cap (`HKLM\…\Vault\MaxPerAppCredentialNumber`, default 20), and keys-keeper stores one credential per secret (chunked SSH keys cost several). CredMan reports the cap as the misleadingly-named `ERROR_NOT_ENOUGH_MEMORY` (8). `backend_windows._write_blob` now maps error 8 to an actionable message — raise `MaxPerAppCredentialNumber`, reboot, retry — with the docs link, instead of a raw traceback. Distinct from the 2560-byte blob cap (KI-016 / error 24). (KI-021)
- **`keys import` is now resumable.** Previously a mid-import keychain write failure left orphan metadata (entry added to `data.json`, secret never stored) and aborted with a traceback; re-running skipped the orphan as "already imported", so its secret was lost. Import now rolls back the failed entry's metadata and stops with a clear "fix the cause, then re-run — already-stored entries are skipped and the rest resume" message. A re-run (default `--merge`) completes the migration.

### Internal

- `backend_windows.py` guards its advapi32 ctypes bindings behind `sys.platform == "win32"`, so the module imports on any OS. This keeps the pure `_credwrite_error` helper unit-testable off-Windows (new `test_backend_windows_errors.py`) and adds a cross-platform resumable-import regression test (`test_cli_export.py`). Test count: 220 passing + 13 platform-gated skips on macOS.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.5.0...v0.5.1)

---

## [0.5.0] — 2026-06-02

### Fixed

- **`pipx install` was broken on up-to-date toolchains.** `pyproject.toml` declared a `force-include` for `templates/` and `static/` that are already shipped by `packages = ["src/keys_keeper"]`, so the wheel build mapped those files twice. hatchling ≥1.19 rejects the duplicate (`ValueError: A second file is being added to the wheel archive at the same path: keys_keeper/static/app.css`), making every clean `pipx install git+https://github.com/kyzdes/keys-keeper-skill.git` fail. Older hatchling silently deduped, which masked the bug locally. Removed the redundant `force-include`; verified the wheel builds, still contains templates/static/icons, and installs cleanly.

### Added

- **`keys quickstart` — friendly onboarding.** A read-only getting-started command that shows the config dir, entry count, the four core commands, and a first-key walkthrough — and never prints a secret value. On an empty store `keys list` now points new users to it ("no entries yet — run `keys quickstart` …"), while a filtered no-match says "no entries match those filters" instead.
- **`FLOW_SETUP` onboarding section in the agent rules.** Claude / Cursor / Aider / Codex / Cline now get an explicit, opt-in setup flow: detect whether the CLI is installed, OFFER to install and wait for the user's OK (correct per-platform `pipx` commands), then orient via `keys quickstart`. It explicitly forbids silent installs and unprompted bulk-migration of existing secrets — fixing a first-run experience where the agent jumped straight to migrating keys and fumbled the install.

- **Linux support — third platform.** `pipx install` + `keys` now works on Ubuntu (desktop and server). The `KeychainBackend` interface gains two Linux implementations, selected automatically:
  - **`SecretToolBackend`** (`backend_linux.py`) — the OS-native **Secret Service** (GNOME Keyring / KWallet) driven via the `secret-tool` CLI, mirroring how macOS shells out to `security`. No new Python dependency (`secret-tool` is a system package — `sudo apt install libsecret-tools`). Secret values are passed via **stdin**, never argv.
  - **`EncryptedFileBackend`** (`backend_file.py`) — for headless servers with no D-Bus / keyring daemon. A single AES-256-GCM blob at `~/.config/keys-keeper/secrets.enc`, unlocked by `KEYS_KEEPER_MASTER_KEY`. Reuses the existing `crypto.encrypt_blob`/`decrypt_blob` (AES-256-GCM + PBKDF2-600k) and the cross-platform advisory lock — still zero new dependencies.
- **Auto-detection + override.** On Linux, keys-keeper uses the keyring when a live Secret Service answers, else the encrypted file. `KEYS_KEEPER_BACKEND=secret-tool|file` forces a choice. `keys doctor` now prints the active backend (and whether `KEYS_KEEPER_MASTER_KEY` is set for the file backend).
- **Linux clipboard.** `keys copy` shells out to `wl-copy` (Wayland) → `xclip` → `xsel` (X11). On a headless host with none present, it fails with a clear "use `keys inject`/`resolve`" message instead of a traceback.

### Changed

- All user-facing copy updated to "macOS + Windows + Linux" — README, landing page, `pyproject.toml` (added `Operating System :: POSIX :: Linux` classifier), `plugin.json`, and the generated agent rule files (`canonical.py` / `render.py`; goldens regenerated).
- CI matrix adds `ubuntu-latest`. The Linux job installs `gnome-keyring` + `dbus-x11` and runs the suite under `dbus-run-session` with an unlocked keyring, so the real `secret-tool` path is exercised — not just the file fallback.

### Internal

- `composition.py` stays the sole `sys.platform` dispatch (D-017): the Linux branch lives there.
- `ssh_runner.py` unchanged — its POSIX `chmod 0600` path already covers Linux.
- `EncryptedFileBackend` does its read-modify-write fully under the advisory lock (re-reading from disk, not a cached copy), so parallel `keys` processes serialize and can't lose each other's updates — same guarantee as `MetadataStore`. Covered by a concurrency regression test.
- New tests: `test_backend_file.py` (incl. multi-instance concurrency + corruption), `test_backend_linux.py` (live tests runtime-skip without a keyring), `test_composition_linux.py`, `test_clipboard_linux.py`; `linux` pytest marker added. Test count: 216 passing + 13 platform-gated skips on macOS.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.4.1...v0.5.0)

---

## [0.4.1] — 2026-05-30

### Fixed

- **macOS quick-launch app showed "Keys Keeper is no longer open" and didn't open the browser.** The `keys app install` launcher ended with `exec "${KEYS_BIN}" serve`, which replaced the bundle's `/bin/sh` process with the pipx Python interpreter living *outside* the `.app`. LaunchServices saw the running process leave the bundle, deregistered the app (the "…is no longer open" alert), and the same deregistration silently broke the server's own `webbrowser.open()` — even though `keys serve` kept running in the background. The launcher now runs `keys serve` as a **child** (no `exec`), so the bundle-resident process stays registered for as long as the server runs.
- **Re-launching the shortcut while a server is already running now re-opens the admin tab** instead of only firing a "check your existing tab" notification. `keys serve` persists its tokened URL to `~/.config/keys-keeper/serve-url` (`0600`, removed on shutdown) and the launcher's already-running branch opens that URL via `/usr/bin/open`.

### Internal

- `tests/test_serve_url.py` (URL-file round-trip, `0600` perms, missing-file safety) + two launcher regression tests in `tests/test_app_install.py` (`test_launcher_does_not_exec_foreign_binary`, `test_launcher_reopens_running_server_via_url_file`). Test count: 180 passing + Windows-skipped on macOS.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.4.0...v0.4.1)

---

## [0.4.0] — 2026-05-19

### Added

- **`keys app install` / `keys app uninstall` — OS-native quick-launch shortcut.** On macOS, drops `Keys Keeper.app` into `~/Applications` (`--system` for `/Applications`) so the admin can be opened from Spotlight (Cmd+Space → "Keys Keeper") without a terminal. On Windows, creates a `Keys Keeper.lnk` in the per-user Start Menu Programs folder.
- **Sub-second launcher.** The macOS bundle ships an `/bin/sh` launcher that skips `~/.zshrc` and calls the pipx venv binary directly — ~0.7s cold-start vs ~7s for naive `zsh -l` wrappers (measured on a machine with conda init in zshrc). Logs to `~/Library/Logs/keys-keeper.log`.
- **"Already running" guard.** Re-triggering the shortcut while `keys serve` is already listening on :7777 surfaces a Notification Center toast instead of failing on bind.
- **Shipped icon.** Bundled `keys-keeper.icns` (navy rounded square + warm-gold key glyph, 10 size variants) — generator script at `scripts/build-icon.py` is pure stdlib + macOS-preinstalled `sips` / `iconutil`, no Pillow dep.
- **First-run tip after `keys serve`.** On macOS, when the shortcut is not yet installed, the CLI prints a one-line tip suggesting `keys app install`. Tip disappears once the bundle is present (idempotent — no nag state to track).
- **Skill / agent rules updated.** Added `FLOW_APP_INSTALL` section to `canonical.py` so Claude / Cursor / Aider / Codex / Cline rule files all surface the command. Golden fixtures regenerated.

### Internal

- `src/keys_keeper/macos_app.py` and `src/keys_keeper/windows_app.py` follow the existing `backend.py` / `backend_windows.py` split convention.
- `tests/test_app_install.py` covers bundle layout, Info.plist parsing, executable bits, icon embedding, force-overwrite semantics, CLI dispatch, serve-tip idempotency, and Windows path resolution (running on macOS via stdlib mocks).
- Test count: 171 passing + 9 Windows-skipped on macOS.

---

## [0.3.0] — 2026-05-14

### Added

- **`keys init <target>` — agent rule generators for 6 agents.** One canonical source of truth (`src/keys_keeper/agent_rules/canonical.py`) renders consistent rule files for Claude Code (`skills/keys-keeper/SKILL.md`), Cursor (`.cursor/rules/keys-keeper.mdc`), Aider (`CONVENTIONS.md`), Codex (`AGENTS.md`), Cline (`.clinerules/00-keys-keeper.md`), and a generic stdout fallback. Eliminates copy-paste drift across the AI-coding-tool ecosystem.
- **Marker-append write mode** for Aider / Codex: splices `<!-- keys-keeper:begin/end -->` section into existing `CONVENTIONS.md` / `AGENTS.md`, preserving user content byte-for-byte outside the markers. Idempotent.
- **`--check` drift detection** with unified-diff output and exit-1 — wired into CI to catch when canonical prose drifts from shipped artifacts.
- **`--force` / `--out <path>` / `--stdout`** flags for explicit overwrite, custom destination, and stdout streaming.
- Marketplace SessionStart auto-update hook (`hooks/hooks.json` + `scripts/auto-update.sh`) with shared 4h debounce stamp at `~/.cache/kyzdes-claude-skills/last-update`. Friends never run `/plugin marketplace update` manually.

### Changed

- **Monolith merge.** `kyzdes/keys-keeper` (old CLI repo) merged into `kyzdes/keys-keeper-skill`. Single source of truth for plugin + CLI + tests. Old repo archived.
- **`SKILL.md` is now generated** from `canonical.py` (with frontmatter preservation for the user-customizable `name` / `description`). Hand-edits flagged at CI via `keys init claude --check`.
- README rewritten with plugin-first install path. Cross-platform install snippets (macOS + Windows). Test count: 150 passing + 9 Windows-skipped on macOS.
- Landing page (`docs/landing/index.html`) refreshed: v0.2 cross-platform branding, monolith repo URLs, hero badge at 150 tests.
- Plugin `description` in `plugin.json` updated to mention `keys init` so marketplace surface matches reality.

### Fixed

- I/O error handling around `path.read_text()` / `path.write_text()` in `init_cmd`: unwriteable parents, `--out` at a directory, malformed markers, broken frontmatter — now raise `_InitError` with friendly messages (exit 2) instead of raw tracebacks.
- Render registry unified: removed the lambda-with-hardcoded-path indirection for the Claude target. All 6 renderers share the `(Path | None) -> str` signature.

### Removed

- `scripts/install_skill.sh` / `scripts/install_skill.ps1` — obsolete pre-marketplace install scripts. Marketplace and pipx are the supported channels.

### Internal

- `.gitattributes` forces LF for `*.md` / `*.py` / `*.json` / etc. — prevents Windows CI runners from creating CRLF drift in golden fixtures.
- `tests/conftest.py` gained a `--regen` pytest flag for regenerating golden rule fixtures.
- `promo-concepts/` gitignored (AI-art scratch + run metadata, not for the repo).
- 4 new negative-path tests in `test_cli_init.py` covering unwriteable dirs, --out collision, malformed markers, broken frontmatter.

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.2.0...v0.3.0)

---

## [0.2.0] — 2026-05-11

### Added

- **Windows Credential Manager backend** (`src/keys_keeper/backend_windows.py`). `composition.py` dispatches on `sys.platform`. Full cross-platform parity for `add`/`get`/`set`/`delete`/`list` across macOS Keychain and Windows.
- Admin web UI: env-names panel showing which env vars an entry would resolve to.
- CI matrix expanded for Windows runners.

### Changed

- All user-facing copy switched from "macOS Keychain" to "OS-native credential store (macOS Keychain / Windows Credential Manager)" — SKILL.md, plugin.json, README.
- Plugin description in `plugin.json` reflects cross-platform support.

### Fixed

- `/api/entries/<id>` DELETE handler now surfaces 409 with `{"dependents": [...]}` instead of failing silently when an entry is referenced by others.
- `clear_after` parameter in `/api/copy` now matches CLI's `--clear-after` semantics across both surfaces.
- Stored XSS in `/audit` table render — server-side `_sanitize_untrusted()` + client-side `el()` helper replaces `innerHTML` interpolation.
- 8 admin-UI bugs from initial e2e session (session cookie auth, URL token strip, modal hidden attr, query string preservation, link-click shutdown beacon, etc.) — see commit log for the full litany.

### Internal

- **`Sealed` wrapper** for plaintext: `KeychainBackend.get()` returns `Sealed`, whose `__repr__` / `__str__` is `"<sealed>"`. Accidental `print` / f-string / log renders the marker, not the value. Only `.unseal()` produces plaintext — `grep -rn '\.unseal()' src/` enumerates every leakage-relevant site (currently 7, one stdout-bound and env-gated).
- Composition root: `_backend()` factory hoisted to `composition.py`, imported by both `cli.py` and `api.py`. Removes the literal copy-paste factory and creates the single swap point for Linux backend (future).
- `now_iso` renamed from `_now_iso` (the underscore had leaked across module boundaries via `__import__` and local imports).

[Diff](https://github.com/kyzdes/keys-keeper-skill/compare/v0.1.0...v0.2.0)

---

## [0.1.0] — 2026-05-04

Initial public release. macOS-only.

### Surface

- **CLI** (`keys`): `add`, `list`, `info`, `reveal`, `copy`, `inject`, `resolve`, `rm`, `edit`, `doctor`, `ssh`, `serve`, `export`, `import`, `audit` — 15 subcommands.
- **Output-safe design.** `reveal` is the only command that writes plaintext to stdout, and it requires `KEYS_KEEPER_ALLOW_REVEAL=1` in env. AI agents are nudged toward `copy` (clipboard, 30s auto-clear) / `inject` (writes to file, no stdout) / `resolve` (substitutes placeholders in files).
- **Local web admin** (`keys serve`): 7 screens (dashboard, entry detail, new/edit form, bulk import, audit charts, settings). Token in URL → `HttpOnly` cookie on first hit. Idle timeout 15 min.
- **Claude Code skill** (`skills/keys-keeper/SKILL.md`): friction-stop instructions for agents who might accidentally route plaintext through the transcript.
- **Encrypted export/import** (`keys export` / `import`): AES-256-GCM + PBKDF2-HMAC-SHA256 (600k iterations) for offsite backup.

### Storage

- macOS Keychain via the `security` CLI. Multi-line values decoded from the `0x<HEX>` form on stderr (necessary for SSH key PEMs that contain newlines).
- Metadata in `~/.config/keys-keeper/data.json` with atomic-write + `fcntl.flock` exclusive lock.
- Append-only JSONL audit log with monthly rotation.

### Tests

- 103 pytest cases over isolated test keychain. Real `security` CLI invoked.

---

[Unreleased]: https://github.com/kyzdes/keys-keeper-skill/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.5.0
[0.4.1]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.4.1
[0.4.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.4.0
[0.3.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.3.0
[0.2.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.2.0
[0.1.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.1.0
