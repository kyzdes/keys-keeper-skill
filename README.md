# keys-keeper

[![tests](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml/badge.svg)](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml)

> **A local secrets workflow that keeps plaintext out of normal agent tool responses.**

Stores API keys, SSH keys, server credentials, and domain info in the OS-native credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service — with an encrypted-file fallback on headless servers). Ships with rule files for **Claude Code, Cursor, Aider, Codex CLI, Cline** — and any other agent via `keys init generic`. The normal command surface routes values to explicit sinks without returning plaintext in tool output. This reduces accidental transcript exposure; it does not isolate secrets from arbitrary code running as the same OS user.

**Status:** v0.8.0 · macOS + Windows + Linux · single-user · MIT license

The development branch adds folders and project-scoped delivery: a master keeps
the complete catalog, while each worker receives only explicitly assigned
project environments and can submit new entries without editing existing ones.
Setup is opt-in and starts with a verified recovery backup. See the
[project sync guide](docs/PROJECT-SCOPED-SYNC.md),
[relay operations](docs/PROJECT-RELAY-OPERATIONS.md), and
[implementation evidence](docs/architecture/PROJECT-SCOPED-VAULTS-EVIDENCE.md).
This feature is not part of the published v0.8.0 tag.

<!--
  TODO(launch): record 30-45s demo gif showing
    1. Claude leaks key into transcript via Edit
    2. Same task via `keys inject` — value never leaves the CLI process
    3. beauty shot of admin (dashboard / audit)
  Embed here as docs/landing/demo.gif before public launch.
-->

---

## Why this exists

Modern coding agents (Claude Code, Cursor, Aider, Cline, Codex CLI…) need credentials to do real work — `OPENROUTER_API_KEY` here, `STRIPE_SECRET_KEY` there, an SSH key to deploy. The standard playbook today:

1. You paste the key into the chat.
2. The agent calls `Edit` or `Bash` to write it into a file.
3. The plaintext is now in the transcript, in the model provider's logs, in your clipboard, in your shell history.

`1Password CLI` and friends help with storage, but the moment the agent runs `op read 'op://…/credential'` the secret value still flows through its context window. **The leak surface is the agent itself**, not the vault.

`keys-keeper` is built around a different primitive: normal agent-facing commands write secrets *to a target* (file, clipboard, SSH tempfile) without returning the value in their output. The shipped rules forbid `keys reveal`, and its environment gate prevents accidental invocation.

This is transcript hygiene, not a same-user security boundary. A shell-capable agent can set the reveal environment variable, read the clipboard, read a generated file, or call the backend directly. High-assurance isolation requires the planned broker mode with the agent running under a separate security principal.

## Install

### 1. Install the `keys` CLI

```bash
pipx install 'git+https://github.com/kyzdes/keys-keeper-skill.git@v0.8.0'
keys doctor                                            # smoke check
```

No pipx? macOS: `brew install pipx && pipx ensurepath`. Windows: `python -m pip install --user pipx && python -m pipx ensurepath`.

### 2. Wire it into your AI agent

Pick whichever agents you use. Run project-scoped targets inside the project
directory; the personal Codex skill can be installed from anywhere:

| Agent | Command | What it does |
|---|---|---|
| **Claude Code** | Run as **two separate** slash commands (one at a time):<br>`/plugin marketplace add kyzdes/claude-skills`<br>then `/plugin install keys-keeper@claude-skills` | Marketplace plugin: skill + auto-sync hook; mutable-HEAD updates are disabled by default |
| **Cursor** | `keys init cursor` | Writes `.cursor/rules/keys-keeper.mdc` (auto-loaded) |
| **Aider** | `keys init aider` | Writes `CONVENTIONS.md`; prints how to wire it via `aider --read` or `.aider.conf.yml` |
| **Codex app / CLI** | `keys init codex-skill` | Installs a personal skill at `$CODEX_HOME/skills/keys-keeper` (or `~/.codex/skills/keys-keeper`), outside Codex's versioned plugin cache; project-only fallback: `keys init codex` |
| **Cline** | `keys init cline` | Writes `.clinerules/00-keys-keeper.md` |
| **Any other agent** | `keys init generic` | Prints to stdout — redirect wherever your agent reads rules from |

You can mix targets — `keys init cursor` and `keys init codex` in the same project both work and stay consistent. The `aider`/`codex` writes use HTML-comment markers so re-running just refreshes the keys-keeper section and leaves the rest of the file alone.

For Codex, prefer `keys init codex-skill`. The personal skill path is stable
across CLI and marketplace updates, while a running Codex task keeps the exact
skill path it received at startup. A marketplace update may replace a path such
as `.../plugins/cache/keys-keeper/keys-keeper/0.7.8/...` with `0.8.0`; the old
task will then report that its catalog path is stale. Re-run
`keys init codex-skill --force` after upgrading Keys Keeper, then start a new
Codex task to reload the catalog.

If `keys-keeper@keys-keeper` was previously installed as a Codex plugin, disable
or remove that plugin after installing the personal skill so Codex sees only the
stable copy. The minimal marketplace bundle remains in `plugins/keys-keeper` for
packaging compatibility; it deliberately ships no startup hook, application
code, or virtual environment.

The repository is also a Codex marketplace via `.agents/plugins/marketplace.json`.
That route is useful for testing the packaged plugin, but the personal install
above is the recommended day-to-day setup because its path is not versioned.

Already installed in Claude Code? Refresh the marketplace and the reviewed
plugin release, then start a new session:

```text
/plugin marketplace update claude-skills
/plugin update keys-keeper@claude-skills
```

Run `keys init claude --check` from your CI to fail builds on prose drift.

Security default: the Claude SessionStart hook does not fetch or install plugin
updates. Update to a reviewed release explicitly. The legacy mutable-HEAD flow
can be restored with `KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE=1`, but it trusts the
GitHub account and marketplace at update time and is not recommended for a
secrets tool.

### 3. Optional shell config

```bash
# Human convenience only; this caller-controlled gate is not authorization.
echo 'export KEYS_KEEPER_ALLOW_REVEAL=1' >> ~/.zshrc   # macOS / Linux
setx KEYS_KEEPER_ALLOW_REVEAL 1                        # Windows (effective in new shells)
```

Requires Python 3.10+ on macOS, Windows, or Linux.

#### Linux backend selection

On Linux, keys-keeper picks storage automatically:

- **Desktop** (GNOME / KDE with a running keyring): uses the OS-native **Secret Service** via `secret-tool`. Install it once with `sudo apt install libsecret-tools` (Debian/Ubuntu) if it's missing.
- **Headless server** (no D-Bus / no keyring daemon): falls back to an **encrypted file** (`~/.config/keys-keeper/secrets.enc`, AES-256-GCM) unlocked by `KEYS_KEEPER_MASTER_KEY` in your environment. Any agent inheriting that environment can obtain the decryption key, so this backend is compatibility mode only.

Force a backend explicitly with `KEYS_KEEPER_BACKEND=secret-tool` or `KEYS_KEEPER_BACKEND=file`. `keys doctor` prints which backend is active.

#### macOS Keychain bypass (no authorization dialogs)

Keys Keeper keeps the original generic-password items in macOS Keychain. Ordinary read, write, delete, and enumeration go directly through Security.framework inside the Keys Keeper process.

If macOS starts showing repeated authorization windows, enable the persistent no-UI policy:

```bash
keys keychain status     # metadata only; does not open Keychain
keys keychain status --check  # no-UI lock/readiness probe; reads no secret
keys keychain bypass    # keep native items, disable authorization dialogs
keys keychain prepare NAME --check  # no-UI ACL preflight for one item
keys keychain prepare NAME          # explicit one-item ACL setup
```

Current items that already trust Keys Keeper continue working normally. For an older item whose decrypt ACL explicitly trusts Apple's fixed `/usr/bin/security`, bypass first verifies that ACL and that the Keychain is unlocked, then uses that already-authorized path for the read. The original item is not rewritten. Unknown, locked, or untrusted ACLs fail cleanly before any compatibility process starts, so they cannot open a system window. Nothing is exported, copied, migrated, or moved. Restore the standard interactive policy with `keys keychain prompt`.

Admin, WebVault-adapter, and automatic sync operations use a stricter
background context: Keychain UI and the compatibility bridge are both
disabled, regardless of the persistent prompt/bypass preference. A background
access problem therefore returns one error instead of opening an authorization
dialog. If one legacy item fails because it does not trust the native runtime,
`prepare NAME` updates only that original item's decrypt ACL; it neither reads
nor copies the stored value. There is deliberately no bulk preparation mode.

## Quick start

```bash
# macOS
pbcopy <<<"sk-or-v1-..."
keys add openrouter-cline --type api_key --from-clipboard --tag llm

# Windows (PowerShell)
Set-Clipboard "sk-or-v1-..."
keys add openrouter-cline --type api_key --from-clipboard --tag llm

# Now any Claude session can ask:
#   "вставь openrouter-cline в .env как OPENROUTER_API_KEY"
# The command output contains only metadata. The resulting .env is still an
# exposure sink: any process allowed to read it can recover the value.

# Browse the admin
keys serve
```

## Transcript-safer command surface (compatibility mode)

| Normal agent workflow (does not print plaintext) | Human convenience |
|---|---|
| `keys add NAME --from-clipboard / --from-file / --stdin` | `keys reveal NAME` (refuses unless `KEYS_KEEPER_ALLOW_REVEAL=1`) |
| `keys list / info / audit` | |
| `keys copy NAME` — value goes to the OS clipboard, auto-clears in 30s with hash check | |
| `keys inject NAME --file F --as ENV` — appends `ENV=value` to file | |
| `keys resolve FILE` — substitutes `__KEYS:name__` placeholders | |
| `keys ssh NAME` — opens session via tempfile-resolved key, file shredded on exit | |

The shipped skill markdown (`skills/keys-keeper/SKILL.md`) tells Codex and Claude:

> You MUST NOT run `keys reveal`. You CAN use `keys copy / inject / resolve / ssh`.

Clipboard and file destinations are exposure sinks: a shell-capable agent can read them back. `KEYS_KEEPER_ALLOW_REVEAL` is also caller-controlled, so it is an accident guard rather than an authorization boundary. Use the current mode to reduce accidental transcript leaks, not to contain a malicious or prompt-injected same-user agent.

## Local web admin

`keys serve` opens a localhost-only admin (token in URL, stripped via `history.replaceState`, then session cookie). Six screens:

- **Dashboard** — fuzzy search across name/tags/notes, tag chip filters, copy-to-clipboard, command palette (Cmd+K)
- **Entry detail** — type-specific fields, linked entries, "used by" reverse refs, mini per-entry audit history
- **New / Edit** — typed forms (api_key / ssh_key / server / domain / note), refs picker
- **Bulk paste** — split-pane DSL importer with live preview parser
- **Audit** — top-10 entries chart, daily activity bar chart, op-type distribution, filterable event table
- **Settings** — server status, KEYS_KEEPER_ALLOW_REVEAL state, manual shutdown

Designed terminal-adjacent: JetBrains Mono, dark by default, dense, low-chrome. No framework, no build step — Jinja2 + vanilla JS.

## Cloud sync

`keys sync setup / push / pull / status / mode / rollback` — back up and sync your vault across machines. Connect any S3-compatible bucket (AWS S3, Cloudflare R2, Backblaze B2, MinIO, Wasabi); the whole vault is encrypted into a single AES-256-GCM blob (the same format as `keys export`) before it ever leaves the machine.

- **Git-like versioned snapshots.** Each push writes an immutable snapshot and a plaintext commit (`{version, parent, device, ts, …}` — never an entry field or secret), with a `HEAD` cache. `keys sync rollback <version>` restores any earlier snapshot and republishes it so peers converge.
- **Id-keyed merge, no duplicates.** Entries merge by their UUID `id` (not name) with last-write-wins on `updated_at`, so re-pulling is idempotent and two machines converge without dupes. Deletes propagate via soft-delete tombstones.
- **Optional auto-sync.** `keys sync mode auto` enables a non-interactive SessionStart hook that pulls+pushes in a debounced, backgrounded, **fail-open** worker — any missing credential or network error exits 0 and never blocks a session. The passphrase is read from the OS keychain (set once at setup).

Zero new dependencies — AWS Signature V4 is hand-rolled over the stdlib (no boto3). First-time setup (which stores the S3 access key id, secret key, and passphrase in the OS keychain) stays in the CLI; the web `/settings` Sync panel exposes status, the mode toggle, and Pull / "Sync now".

### Private VPS sync (KK2)

`keys sync vps init / push / pull / status / invite / join / approve / finish / devices / revoke` provides a separate S3-free transport through `keys-keeper-syncd`. The VPS stores an SQLite CAS log containing only opaque AES-256-GCM snapshots, signed hash-chain commits, public device keys, and hashed bearer/invite tokens. A random VaultKey and device private keys remain in each device's OS credential store.

New devices use a short-lived one-time invitation, an out-of-band fingerprint comparison, an Ed25519-signed membership statement, and an X25519-wrapped VaultKey. The client pins the root device key and verifies the full chain before decrypting; device enrollment and revocation are root-only. See [the deployment and threat-model guide](docs/architecture/VPS-SYNC-KK2.md). Revocation currently blocks future server access but does not erase data already downloaded or rotate the VaultKey; the CLI reports that limitation explicitly. A malicious VPS split view still requires independent device gossip/witnessing to detect.

## Zero-knowledge web vault

`keys webvault serve` — open your vault from a browser. Because the cloud copy is a self-contained encrypted blob (`PBKDF2-600k → AES-256-GCM`, all native to WebCrypto), the browser fetches it and decrypts it in-page. Under the shipped, unmodified client code, the passphrase and plaintext are not sent to the server. As with any browser-delivered cryptographic app, a compromised server that can replace the JavaScript is outside that guarantee.

v1 is **read-only** (unlock → view/search → reveal/copy → idle auto-lock); add/edit stay in the CLI and local admin. Self-host it via [`docs/webvault/Dockerfile`](docs/webvault/Dockerfile), or fall back to your local `keys sync` config for a quick demo.

## Architecture

```
┌──────────────────┐   Bash    ┌─────────────────────────────────┐
│   Claude Code    │ ────────► │  ~/.local/bin/keys (Python CLI) │
│   (skill)        │           │                                 │
└──────────────────┘           │  add list info reveal copy      │
                               │  inject resolve rm edit ssh     │
┌──────────────────┐   exec    │  serve export import audit      │
│  Shell / scripts │ ────────► │  doctor sync webvault           │
└──────────────────┘           └────┬────────────┬───────────────┘
                                    │            │
                                    ▼            ▼
                          ┌──────────────┐  ┌──────────────────┐
                          │  Keychain    │  │  data.json       │
                          │ (`security`) │  │  + audit.jsonl   │
                          └──────────────┘  └──────────────────┘
                                    │            │
                                    └────┬───────┘
                                         ▼
                              ┌──────────────────────┐
                              │  Web admin           │
                              │  127.0.0.1:7777      │
                              └──────────────────────┘
```

Two-layer storage: secrets in macOS Keychain (tied to the user's login keychain and its configured OS access policy), metadata in `~/.config/keys-keeper/data.json` (so you can back it up, diff it, and sync it through Time Machine). This version does not enforce Touch ID or per-operation user presence.

Append-only audit log records every `add / copy / inject / resolve / reveal / ssh / export` operation with caller PID and executable path, never the caller's full argv — visible in the admin's `/audit` page.

Encrypted backup via `keys export` (AES-256-GCM with PBKDF2-HMAC-SHA256, 600k iterations). Single portable file, restorable via `keys import` on a new machine.

## Roadmap

Open source, accepting PRs.

- [x] ~~**Linux backend** via `secret-tool` (libsecret), with an encrypted-file fallback for headless servers~~ — shipped in v0.5
- [x] ~~**Windows backend** via Credential Manager (with chunking for SSH keys — CredMan has a 2560-byte cap)~~ — shipped in v0.2
- [x] ~~**Cursor / Aider / Codex / Cline rule-file generators** beyond the Claude skill format~~ — shipped in v0.3 (`keys init <target>`)
- [x] ~~**Cloud sync** to any S3-compatible bucket (AWS S3 / Cloudflare R2 / Backblaze B2 / MinIO / Wasabi), whole vault encrypted into one blob, git-like versioned snapshots, id-keyed merge~~ — shipped in v0.6 (`keys sync setup/push/pull/status/mode/rollback`)
- [x] ~~**Browser-decrypted web vault** — the reviewed client decrypts the blob in-page and the normal server request path handles ciphertext only (read-only v1)~~ — shipped in v0.7 (`keys webvault serve`)
- [x] ~~**Native macOS Keychain bypass** — in-process Security.framework access with a persistent no-dialog policy~~ — shipped in v0.7.5 (`keys keychain status/bypass/prompt`)
- [ ] **MCP stdio server** (`keys mcp`) — typed-tool surface for any MCP-compatible client (Cursor / Cline / Codex have native MCP)
- [ ] **Touch ID-gated reveal in admin** with auto-wipe from DOM after 10s
- [ ] **CSV export from `/audit`** (already CLI-only via `keys audit > file.csv`)
- [ ] **Bulk-paste parser extension** for ssh_key / server / domain (currently clean only for api_key)
- [ ] **Light theme polish** (CSS tokens exist; not all surfaces tested)
- [ ] **Isolated broker mode** — run agents under a separate OS principal and expose only scoped SSH/API/signing capabilities
- [ ] **Authenticated sync manifest v2 + transactional secret generations** — prevent rollback/pointer substitution and partial-write data loss

See [`docs/superpowers/specs/2026-05-04-keys-keeper-design.md`](docs/superpowers/specs/2026-05-04-keys-keeper-design.md) for the full design including security model and threat boundaries.

## Honest limitations

- **macOS, Windows, Linux.** On a headless Linux server without a keyring daemon, the encrypted-file backend needs `KEYS_KEEPER_MASTER_KEY` in the environment to unlock.
- **Single user.** No team / multi-user / sharing. Cloud sync (v0.6) keeps your *own* vault in step across machines via an S3 bucket; it is not a way to share secrets with someone else.
- **Web vault is read-only (v1).** `keys webvault serve` lets you view/search/reveal/copy from a browser; adding and editing still happen in the CLI or local admin.
- **Bulk paste cleanly handles `api_key` only.** Other types need their type-specific fields filled by hand or via `+ New` in the admin.
- **The `caller_path` in audit log** is a best-effort executable identity without argv; useful context, not forensic proof.
- **Same-user shell access is outside the current boundary.** A process running as you can set the reveal environment variable, read clipboard/file sinks, or invoke OS credential tooling directly.
- **File and clipboard commands deliberately expose plaintext to their destination.** Do not use them when the destination is readable by an untrusted agent.

## Threat model

- **Reduces:** accidental plaintext in normal agent tool output and transcripts when the agent follows the generated rules; accidental long-lived clipboard residue; ad-hoc manual secret handling.
- **Does NOT defend against:** a malicious or prompt-injected agent with arbitrary shell access as the same OS user; code that can read a chosen clipboard/file sink; direct OS credential-store access; an inherited `KEYS_KEEPER_MASTER_KEY`; root/malware; a compromised plugin/update source; screen recording on a compromised host.

## Contributing

Issues and PRs welcome. The repo is reasonably well-tested (369 passing + platform-gated tests in the current baseline; fixtures use real isolated macOS keychains via `security create-keychain`, and the Linux CI job exercises the real `secret-tool` keyring under `dbus-run-session`). Run `pytest -q` after any change.

The implementation plan is at [`docs/superpowers/plans/2026-05-04-keys-keeper-plan.md`](docs/superpowers/plans/2026-05-04-keys-keeper-plan.md). The interactive design canvas (a Tailwind/React playground showing the locked UX choices) is at [`keys-keeper-admin-canvas.html`](keys-keeper-admin-canvas.html) — open it in your browser.

## License

MIT — see [`LICENSE`](LICENSE).
