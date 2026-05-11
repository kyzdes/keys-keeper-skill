# keys-keeper · Design

> Generated 2026-05-04 · single-user macOS-first secrets manager for Slava (kuzdes)
> Companion artefacts:
> - **UX spec** for the admin: `ux-spec-2026-05-04-keys-keeper-admin.md`
> - **Interactive canvas** of the admin UI: `keys-keeper-admin-canvas.html`
> - **Memory pointer**: `~/.claude/projects/-Users-viacheslavkuznetsov-Desktop-Projects-keys-keeper-skill-keys-keeper-skill/memory/project_keys_keeper_ux_spec.md`

## 0. Locked decisions

| # | Decision | Pick |
|---|----------|------|
| 1 | Delivery format | Skill (`SKILL.md`) + standalone Python CLI (`keys`) — option **C** (hybrid) |
| 2 | Storage layout | Two-layer: macOS Keychain for secrets · JSON file for metadata — option **C** |
| 3 | Platform v1 | macOS only — option **A** (with clean backend interface for Win later) |
| 4 | CLI language | Python 3 — option **B** |
| 5 | Output safety | Paranoid mode + audit log surfaced in admin — option **C** |
| 6 | Input flow | Web paste portal (`/paste`) for long secrets · clipboard import (`pbpaste`) for short · bulk paste in admin with editable preview |
| 7 | Data model | 5 typed entries (`api_key` · `ssh_key` · `server` · `domain` · `note`) with refs between records · no expiration tracking |
| 8 | Admin UI scope | Full CRUD + fuzzy search + tag chips + audit tab + 3 sparkline charts + Cmd+K palette |
| 9 | Admin auth | Bind 127.0.0.1 + one-time URL token · history.replaceState strips on load · no-cache · idle 15-min auto-shutdown — option **B** |
| 10 | Backup | `keys export FILE` / `keys import FILE` AES-256-GCM with user password — option **B** |

## 1. Architecture

```
┌──────────────────┐         ┌─────────────────────────────────┐
│   Claude Code    │ ──Bash──▶  ~/bin/keys (Python CLI)         │
│   (skill triggers)│        │                                 │
└──────────────────┘         │  add inject copy resolve list   │
                             │  info reveal serve export       │
┌──────────────────┐         │  import ssh edit rm doctor      │
│  Shell / scripts │ ──exec──▶                                 │
│  (zsh, deploy)   │         └────┬────────────┬───────────────┘
└──────────────────┘              │            │
                                  ▼            ▼
                        ┌──────────────┐  ┌──────────────────┐
                        │  Keychain    │  │  MetadataStore   │
                        │  Backend     │  │  (data.json)     │
                        │              │  │  + AuditLog      │
                        │  `security`  │  │  (audit.jsonl)   │
                        └──────────────┘  └──────────────────┘
                                  │            │
                                  └─────┬──────┘
                                        ▼
                             ┌──────────────────────┐
                             │  Web admin           │
                             │  `keys serve`        │
                             │  127.0.0.1:7777      │
                             │  Jinja2 + vanilla JS │
                             └──────────────────────┘
```

### Components

- **CLI `keys`** — single Python file ~700-1000 lines in `~/bin/keys`. argparse subcommands. The whole public surface.
- **`KeychainBackend`** — abstraction with `get/set/delete/list_ids`. macOS impl wraps `security add-generic-password / find-generic-password / delete-generic-password`. Service name fixed at `"keys-keeper"`. Account = entry's UUID id (e.g. `kk:7f3a2c10-...`). Suffix `:passphrase` for `ssh_key` passphrase, no other fan-out.
- **`MetadataStore`** — wraps `~/.config/keys-keeper/data.json`. Atomic writes via temp+fsync+rename. `fcntl.flock` for cross-process write coordination. Lazy schema migration on load.
- **`AuditLog`** — append-only JSONL at `~/.config/keys-keeper/audit.jsonl`. Rotates monthly to `audit.YYYY-MM.jsonl.gz`. Records every op except read-only `list/info/audit/doctor`.
- **`Skill`** — `~/.claude/skills/keys-keeper/SKILL.md` + `references/examples.md`. Triggers on Russian + English keywords for keys/secrets/server/ssh/api operations. Forbids `keys reveal` and any pattern that exposes plaintext into Edit/Write/Bash echo.
- **Web admin** — `keys serve` boots Python `http.server` (or `wsgiref.simple_server` for cleaner routing). Jinja2 templates. Light vanilla JS for interactivity (Alpine.js optional — kept minimal). Auto-shutdown thread polls heartbeat. `navigator.sendBeacon('/shutdown')` on tab close.

### Dependencies

- Python 3.10+ (macOS bundled or via Homebrew)
- `jinja2` for templates
- `cryptography` for AES-GCM in export/import
- No other runtime deps. Standard install: `pipx install keys-keeper` or `pip install --user .` from a local clone.

## 2. Data model

### File layout

```
~/.config/keys-keeper/
├── data.json              # metadata (no secrets), atomic write
├── data.json.bak          # last successful version (1 file kept)
├── audit.jsonl            # current month's append log
├── audit.2026-04.jsonl.gz # rotated previous month
└── config.toml            # user prefs (port, theme)
```

### Entry schema

```jsonc
{
  "schema_version": 1,
  "entries": [
    {
      "id": "kk:7f3a2c10-...",     // UUID4, also the keychain account
      "name": "openrouter-cline",   // unique slug, primary key for UX
      "type": "api_key",            // api_key | ssh_key | server | domain | note
      "fields": { /* type-specific, see below */ },
      "tags": ["llm", "personal"],
      "note": "Cline + RooCode + всякие cli",
      "refs": [],                   // [{role, name}] for server / ssh_key linkage
      "created_at": "2026-05-04T10:23:00Z",
      "updated_at": "2026-05-04T10:23:00Z"
    }
  ]
}
```

**Convention:** the entry's primary secret lives in keychain at `account = entry.id`. There is no `value_ref` field. For `ssh_key` with passphrase, the secondary secret lives at `account = entry.id + ":passphrase"`.

### `fields` per type

| type | fields | secrets in keychain |
|------|--------|---------------------|
| `api_key` | `service?: str` | `kk:<id>` → API key string |
| `ssh_key` | `public_key: str`, `comment?: str`, `has_passphrase: bool` | `kk:<id>` → private key (multi-line OK), `kk:<id>:passphrase` → passphrase if present |
| `server` | `host: str`, `port: int = 22`, `user: str`, `auth: "ssh_key"\|"password"\|"none"` | — (own secrets none; secrets resolved via `refs`) |
| `domain` | `host: str`, `registrar?: str`, `nameservers?: str[]` | — |
| `note` | `secret_body: bool`, `body?: str` | If `secret_body`: `kk:<id>` → body. If not: `body` lives in `fields.body`. |

### Refs

```jsonc
"refs": [
  { "role": "ssh_key", "name": "my-do-key" }
]
```

`name` references another entry by its slug. CLI resolves `name → entry → entry.id` lazily. Validates absence of cycles on `add`/`update`/`edit`. Reverse refs are computed on demand (no separate index).

### Concurrency

- All writes acquire `fcntl.flock(LOCK_EX)` on `data.json` for the duration.
- Reads are lock-free; the temp+rename atomic-write pattern guarantees they observe a consistent snapshot.
- Schema migration on load: if `schema_version > KNOWN`, refuse with "upgrade required". If `<`, migrate in memory and write back with backup (`data.v1.json.bak`).

### Naming

- Slug-style names recommended: lowercase, kebab-case (`openrouter-cline`, `do-prod-droplet`). Validation: `^[a-z0-9][a-z0-9._-]*[a-z0-9]$`, length 2-64.
- Conflict on `add` → error with suggestion `--rename NAME` or `--replace`.
- Hard delete only. If reverse refs exist: error with list of dependents and `--cascade` flag option.

## 3. CLI surface

### Public commands

```
keys add NAME [--type TYPE] [--from-clipboard | --from-file PATH | --web | --stdin]
              [--service SVC] [--tag T...] [--note "..."] [--ref ROLE=NAME]
              [--rename | --replace]
keys add-bulk --web                       # opens /paste page in admin
keys list [--type T] [--tag T] [--search Q]   # names + meta, no values
keys info NAME                            # all metadata of one entry
keys reveal NAME                          # ⚠ plaintext to stdout · gated by env-var
keys copy NAME [--clear-after SEC=30]     # to pbcopy with auto-clear
keys inject NAME --file PATH --as ENV     # appends ENV=value to file
keys resolve PATH                         # rewrites __KEYS:name__ placeholders in file
keys ssh NAME [--cmd "..."]               # type=server: ssh with resolved key
keys edit NAME [--name X] [--add-tag T] [--rm-tag T] [--note "..."] [--field K=V] [--ref ROLE=NAME]
keys rm NAME [--cascade]
keys serve [--port N=7777] [--no-open]    # web admin · auto-shutdown 15min idle
keys export FILE                          # AES-GCM, prompts for password
keys import FILE [--merge | --replace]
keys audit [--name N] [--op O] [--since "7d"] [--tail]
keys doctor                               # health check, paths, version, keychain access
keys --help / --version
```

### Output-safety contract

- `reveal` is the **only** command that prints plaintext to stdout. Refuses to run unless `KEYS_KEEPER_ALLOW_REVEAL=1` is set in env. Logged in audit with `caller_path` for forensics. **Skill never mentions or allows this command.**
- All other commands print confirmations only (`copied`, `injected 1 secret`, `saved`).
- `keys add` requires an explicit input source flag (`--from-clipboard | --from-file | --web | --stdin`) to prevent accidental interactive prompts where the agent might paste a value.
- `keys inject` writes `ENV_NAME=value\n` to file. If `ENV_NAME` already present → error unless `--replace`.
- `keys resolve` placeholder syntax: `__KEYS:name__` for primary secret · `__KEYS:name:field__` for non-secret structured fields (`host`, `user`, `port` of `server`).
- `keys copy` reads from keychain, pipes to `pbcopy`, stores SHA-256 of value. After 30 s, re-reads `pbpaste`, compares hashes — only clears if it still matches. Avoids overwriting unrelated user content.
- `keys ssh` resolves server fields + `refs[ssh_key]`, writes private key to `tempfile.NamedTemporaryFile(delete=True)` with `chmod 600`, execs `ssh -i <tmp> user@host [cmd]`, deletes tmp on exit (Python guarantees deletion via `delete=True`).

### Audit log entry shape

```jsonc
{
  "ts": "2026-05-04T10:23:18Z",
  "op": "inject",                     // reveal|inject|copy|resolve|add|update|delete|export|import|cascade
  "name": "openrouter-cline",
  "id": "kk:7f3a2c10-...",
  "caller_pid": 12345,
  "caller_path": "/Users/.../claude-code",  // resolved via ps -p $PPID
  "file_target": "~/proj/.env",        // for inject/resolve
  "success": true,
  "error": null
}
```

## 4. Skill (markdown)

`~/.claude/skills/keys-keeper/SKILL.md`:

```markdown
---
name: keys-keeper
description: Securely save/retrieve API keys, SSH keys, server credentials, and domain info using macOS Keychain via the `keys` CLI. Use when the user mentions saving, getting, or referencing secrets, API keys, tokens, SSH keys, server addresses, or domain configs. Never produces plaintext secret values in output — uses CLI commands that handle files and clipboard directly.
---

# keys-keeper

Storage CLI is `keys` at `~/bin/keys`. Run `keys --help` for the full surface.

## CRITICAL: never expose secret values

You MUST NOT:
- run `keys reveal` (this command exists for the human, not for you)
- pipe `keys` output containing values into Edit/Write/Bash echo
- ask the user to paste a secret value into chat (it lands in transcript)

You CAN:
- list/info commands (no values)
- `keys copy NAME` — value goes to clipboard, never stdout
- `keys inject NAME --file PATH --as ENV` — value goes directly to file
- `keys resolve PATH` — placeholder substitution in file
- `keys add NAME --from-clipboard` / `--from-file` / `--web`
- `keys ssh NAME` — opens ssh session with resolved key

## Common flows

### User wants to save a secret

1. **If user pastes the value into chat → STOP.** Tell them: «не пастьте значение в чат — скопируйте в буфер и скажите 'сохрани из буфера как X', либо я открою веб-форму». The transcript is a leak surface.
2. Preferred path: `keys add NAME --type TYPE --from-clipboard --tag ... --note "..."`.
3. For multi-line secrets (SSH keys): `keys add NAME --type ssh_key --web` (opens paste portal in browser).
4. For mass import from old notes file: `keys add-bulk --web`.

### User wants to put a secret into a file

ALWAYS use `keys inject` or `keys resolve`. Never `Edit` with the value. Never `Bash` with `$(keys ...)` substitution that echoes the value.

Examples:
- "вставь ключ openrouter в .env" → `keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY`
- ".env.template со ссылками на ключи, проставь их" → `keys resolve .env`

### User asks for server credentials

- `keys info NAME` for non-sensitive fields (host, user, port).
- `keys ssh NAME` to actually connect — CLI handles key material itself.
- For deploy scripts that need ENV vars from `keys`: write `__KEYS:name__` placeholders, then `keys resolve PATH` at runtime.

### User opens admin

- `keys serve` — opens browser to a tokenized URL. Tell user the URL contains a session token; closing the tab terminates the server.

## Search & discovery

- `keys list` for everything, with filters `--type`, `--tag`, `--search`.
- Partial match on names is OK; ambiguous → ask user to disambiguate.
- `keys info NAME` shows refs both ways (used-by reverse refs).

## When in doubt

If you're not sure whether an operation might leak a value, **ask the user first** rather than guess. The cost of asking is one round-trip; the cost of leaking is permanent.
```

Plus `references/examples.md` with concrete worked patterns (set up env for new project · rotate a key · investigate audit log).

## 5. Web admin

The full UX spec lives at `ux-spec-2026-05-04-keys-keeper-admin.md`. The interactive canvas at `keys-keeper-admin-canvas.html` (open in browser) demonstrates all 6 screens, 4 flows, alternate states, and 9 tweaks.

Implementation notes:

> **Two artefacts, two stacks**: the **canvas HTML** (React + Babel via CDN) is a design exploration tool — variant toggles, flow nav, alternate states — used to lock in §8.4 dimensions. The **production admin** is server-rendered Jinja2 + vanilla JS, no React, no build step.

- **Backend**: Python `http.server.ThreadingHTTPServer` with a custom request handler. Routes — `/` `/entry/<id>` `/paste` `/audit` `/settings` plus JSON API at `/api/entries`, `/api/audit`, `/api/copy`, `/api/shutdown`, `/api/heartbeat`.
- **Token**: 32-byte hex generated at boot, printed in CLI banner as part of the URL. UI reads from `?t=...`, stores in `sessionStorage`, strips via `history.replaceState`. Subsequent fetches send `Sec-Keys-Token` header. Server returns 403 on missing/wrong token and audits the failed attempt.
- **Heartbeat**: page sends `POST /api/heartbeat` every 60 s. Server tracks `last_seen`. Idle thread checks every 30 s; if `now - last_seen > 15 min`, server stops.
- **Tab close**: `window.addEventListener('beforeunload', () => navigator.sendBeacon('/api/shutdown'))`.
- **Copy endpoint**: `POST /api/copy {id}` reads from keychain, calls `pbcopy` via subprocess pipe, stores SHA-256 of value with timestamp. Schedules 30 s clear (also via subprocess `pbcopy` with re-check of current `pbpaste` hash).
- **Templates**: Jinja2. Server-rendered initial pages; vanilla JS only (search debounce, filter chips, modals, tweak toggles). No Alpine, no React, no framework — keep payload tiny.
- **Charts**: inline SVG sparklines. Hand-rolled — top-10 horizontal bars, daily activity line/area, op-type horizontal bars.
- **Security headers** on every response: `Cache-Control: no-store, no-cache, must-revalidate, private`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'`.

## 6. Security model (consolidated)

Threat → mitigation:

| Threat | Mitigation |
|---|---|
| Plaintext secret leaks into Claude transcript via `Edit`/`Write` | CLI never returns plaintext to Claude; commands operate on files/clipboard themselves; skill markdown explicitly forbids `reveal` |
| User pastes a secret into chat by accident | Skill instruction: STOP and redirect to `--from-clipboard` / `--web` / `--from-file` |
| `pbcopy` value lingers after copy | Server stores SHA-256 hash; clears clipboard at 30 s only if hash still matches current pbpaste |
| Token leaks via browser history | `history.replaceState` on load · token never in `<a>` hrefs · all API calls via header |
| Cross-origin or cross-process localhost attack | Token required on every endpoint · 403 on missing/wrong token logged to audit |
| Concurrent writes corrupt data.json | `fcntl.flock(LOCK_EX)` on every write · atomic temp+fsync+rename pattern |
| Admin server abandoned (left running) | 15-min idle auto-shutdown · `sendBeacon('/api/shutdown')` on tab close |
| Lost laptop / disk failure | `keys export` AES-256-GCM with user password to a single portable file |
| Forgotten reveal in shell history | `reveal` requires `KEYS_KEEPER_ALLOW_REVEAL=1` env-var; user can choose not to set it and use `copy` instead |
| Audit log tampering (single-user, low risk) | Append-only JSONL · monthly rotation; not actively defended (out of scope for personal tool) |

Out of scope:
- Defending against root-level adversary on the user's own Mac (impossible at this layer)
- Multi-user / team threat models
- Network adversary (the app is localhost-only)

## 7. Installation & first-run

### Bootstrap

```bash
# clone the repo or pip install
pipx install /path/to/keys-keeper

# first run — CLI scaffolds config dir
keys doctor

# Output:
# ✓ Created ~/.config/keys-keeper/
# ✓ data.json initialized (empty)
# ✓ Keychain access verified (service=keys-keeper)
# ⚠ KEYS_KEEPER_ALLOW_REVEAL not set in shell
#    To enable `keys reveal` for shell use, add to ~/.zshrc:
#       export KEYS_KEEPER_ALLOW_REVEAL=1
#
# Next steps:
#   keys add SOME-NAME --from-clipboard
#   keys add-bulk --web        # to mass-import from a notes file
#   keys serve                  # to open the admin
```

### Skill installation

The repo ships `skills/keys-keeper/SKILL.md` + `skills/keys-keeper/references/examples.md`. Install with:

```bash
cp -r skills/keys-keeper ~/.claude/skills/
```

(Or symlink if developing.)

### Shell integration (optional)

```bash
# ~/.zshrc snippet
export KEYS_KEEPER_ALLOW_REVEAL=1

# convenience aliases
alias k='keys'
alias ks='keys serve'

# load a key into current shell
keys-load() { eval "export $(keys reveal "$1" --as-env)"; }
```

(`--as-env` is a shorthand for printing `NAME=value` when reveal is allowed.)

### First entries

The bulk-paste portal (`/paste` route in admin) is the recommended on-ramp: paste content from existing notes file, parser previews, save all atomically.

## 8. Open questions / future work

These are deliberately deferred — surface them in a v1.5+ session if needed:

- **Touch ID for `reveal`** — gate plaintext output behind `LocalAuthentication` framework call. Requires PyObjC.
- **Linux backend** — wrap `secret-tool` (libsecret). Same `KeychainBackend` interface, no other changes.
- **Windows backend** — wrap `cmdkey` / Windows Credential Manager. Limited by 2560-byte value size — SSH keys would need chunking.
- **Light theme polish** — token slot exists; full audit needed.
- **Csv export from admin audit** — currently CLI-only via `keys audit > file.csv`.
- **Cmd+K action palette** — currently navigation-only; could add one-shot actions like "copy openrouter" or "ssh do-prod".
- **Per-entry edit history diff** — would require storing old values; out of scope for v1 (Time Machine + manual exports cover this for now).

## 9. Implementation roadmap (high-level)

This is the design doc. The actionable plan is the writing-plans output, structured as phases:

1. **Phase 1 — CLI core**: `KeychainBackend` (macOS), `MetadataStore` with locking + atomic writes, `AuditLog`. Commands: `add` (--from-clipboard, --from-file, --stdin) · `list` · `info` · `reveal` · `copy` · `inject` · `resolve` · `rm` · `edit` · `doctor`. Tests against a temp keychain + temp data dir.
2. **Phase 2 — `keys ssh` + refs validation**: server type, refs resolution, cycle detection, `keys ssh` flow with tempfile cleanup.
3. **Phase 3 — Web admin scaffold**: `keys serve`, token auth, JSON API for `/api/entries`, basic Dashboard render (S1 with sectioned grouping, server-rendered + a sprinkle of JS). No CRUD UI yet.
4. **Phase 4 — Admin CRUD**: S2 entry detail, S3 new/edit modal, S4 bulk paste with parser. Tweaks system (CSS variables flipped via JS).
5. **Phase 5 — Admin audit + settings**: S5 with charts, S6 status/maintenance.
6. **Phase 6 — Backup/export**: `keys export`, `keys import`. Cryptography-based AES-GCM with PBKDF2 stretching.
7. **Phase 7 — Skill + docs**: SKILL.md, examples reference, install script. Manual smoke test through Claude Code.
8. **Phase 8 — Polish + ship**: light theme, doctor command exhaustive checks, README.

Each phase has explicit verification criteria: passing tests + manual test of one realistic flow before moving on.
