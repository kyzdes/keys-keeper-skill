# Changelog

All notable changes to keys-keeper. Format loosely follows [Keep a Changelog](https://keepachangelog.com/) + [Semver](https://semver.org/).

Distribution: install via Claude Code marketplace (`/plugin install keys-keeper@claude-skills` after `/plugin marketplace add https://github.com/kyzdes/claude-skills`) or standalone `pipx install git+https://github.com/kyzdes/keys-keeper-skill`. Marketplace auto-update on every Claude Code session start.

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

[Unreleased]: https://github.com/kyzdes/keys-keeper-skill/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.3.0
[0.2.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.2.0
[0.1.0]: https://github.com/kyzdes/keys-keeper-skill/releases/tag/v0.1.0
