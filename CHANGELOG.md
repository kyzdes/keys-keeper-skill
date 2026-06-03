# Changelog

All notable changes to keys-keeper. Format loosely follows [Keep a Changelog](https://keepachangelog.com/) + [Semver](https://semver.org/).

Distribution: install via Claude Code marketplace (`/plugin install keys-keeper@claude-skills` after `/plugin marketplace add https://github.com/kyzdes/claude-skills`) or standalone `pipx install git+https://github.com/kyzdes/keys-keeper-skill`. Marketplace auto-update on every Claude Code session start.

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
