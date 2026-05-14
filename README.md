# keys-keeper

[![tests](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml/badge.svg)](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml)

> **A secrets manager AI coding agents architecturally cannot leak from.**

Stores API keys, SSH keys, server credentials, and domain info in the OS-native credential store (macOS Keychain on macOS, Credential Manager on Windows). Ships with rule files for **Claude Code, Cursor, Aider, Codex CLI, Cline** — and any other agent via `keys init generic`. All variants share one safety contract: the agent can *put* secrets into your files without ever *seeing* the value.

**Status:** v0.2.0 · macOS + Windows · single-user · MIT license

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

`keys-keeper` is built around a different primitive: every Claude-facing command writes secrets *to a target* (file, clipboard, ssh tempfile) — the value never returns to the agent's view. Plus an `os.environ`-gated `keys reveal` that the shipped skill markdown explicitly forbids the agent from invoking.

It's not a policy. It's the command surface.

## Install

### 1. Install the `keys` CLI

```bash
pipx install git+https://github.com/kyzdes/keys-keeper-skill.git
keys doctor                                            # smoke check
```

No pipx? macOS: `brew install pipx && pipx ensurepath`. Windows: `python -m pip install --user pipx && python -m pipx ensurepath`.

### 2. Wire it into your AI agent

Pick whichever agents you use — run inside the project directory you want the agent to use it in:

| Agent | Command | What it does |
|---|---|---|
| **Claude Code** | `/plugin marketplace add kyzdes/claude-skills`<br>`/plugin install keys-keeper@kyzdes-claude-skills` | Marketplace plugin: skill + SessionStart auto-update hook |
| **Cursor** | `keys init cursor` | Writes `.cursor/rules/keys-keeper.mdc` (auto-loaded) |
| **Aider** | `keys init aider` | Writes `CONVENTIONS.md`; prints how to wire it via `aider --read` or `.aider.conf.yml` |
| **Codex CLI** | `keys init codex` | Writes `AGENTS.md` (also read by Cursor / Amp / Jules in 2026 per the AGENTS.md open spec) |
| **Cline** | `keys init cline` | Writes `.clinerules/00-keys-keeper.md` |
| **Any other agent** | `keys init generic` | Prints to stdout — redirect wherever your agent reads rules from |

You can mix targets — `keys init cursor` and `keys init codex` in the same project both work and stay consistent. The `aider`/`codex` writes use HTML-comment markers so re-running just refreshes the keys-keeper section and leaves the rest of the file alone.

Run `keys init claude --check` from your CI to fail builds on prose drift.

### 3. Optional shell config

```bash
# Lets shell users print plaintext via `keys reveal` (env-gated, agents can't override)
echo 'export KEYS_KEEPER_ALLOW_REVEAL=1' >> ~/.zshrc   # macOS / Linux
setx KEYS_KEEPER_ALLOW_REVEAL 1                        # Windows (effective in new shells)
```

Requires Python 3.10+ on macOS or Windows (Linux backend via libsecret is on the roadmap).

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
# The agent runs `keys inject` — it sees `injected 1 secret`, never the value.

# Browse the admin
keys serve
```

## Output-safe command surface

| For Claude (safe — never returns plaintext) | For shell (gated — env-var required) |
|---|---|
| `keys add NAME --from-clipboard / --from-file / --stdin` | `keys reveal NAME` (refuses unless `KEYS_KEEPER_ALLOW_REVEAL=1`) |
| `keys list / info / audit` | |
| `keys copy NAME` — value goes to the OS clipboard, auto-clears in 30s with hash check | |
| `keys inject NAME --file F --as ENV` — appends `ENV=value` to file | |
| `keys resolve FILE` — substitutes `__KEYS:name__` placeholders | |
| `keys ssh NAME` — opens session via tempfile-resolved key, file shredded on exit | |

The shipped skill markdown (`skills/keys-keeper/SKILL.md`) tells Claude:

> You MUST NOT run `keys reveal`. You CAN use `keys copy / inject / resolve / ssh`.

If Claude tries to bypass — `KEYS_KEEPER_ALLOW_REVEAL=1` is a per-shell env-var most users never set, so the structural guard fires before any prose can override it.

## Local web admin

`keys serve` opens a localhost-only admin (token in URL, stripped via `history.replaceState`, then session cookie). Six screens:

- **Dashboard** — fuzzy search across name/tags/notes, tag chip filters, copy-to-clipboard, command palette (Cmd+K)
- **Entry detail** — type-specific fields, linked entries, "used by" reverse refs, mini per-entry audit history
- **New / Edit** — typed forms (api_key / ssh_key / server / domain / note), refs picker
- **Bulk paste** — split-pane DSL importer with live preview parser
- **Audit** — top-10 entries chart, daily activity bar chart, op-type distribution, filterable event table
- **Settings** — server status, KEYS_KEEPER_ALLOW_REVEAL state, manual shutdown

Designed terminal-adjacent: JetBrains Mono, dark by default, dense, low-chrome. No framework, no build step — Jinja2 + vanilla JS.

## Architecture

```
┌──────────────────┐   Bash    ┌─────────────────────────────────┐
│   Claude Code    │ ────────► │  ~/.local/bin/keys (Python CLI) │
│   (skill)        │           │                                 │
└──────────────────┘           │  add list info reveal copy      │
                               │  inject resolve rm edit ssh     │
┌──────────────────┐   exec    │  serve export import audit      │
│  Shell / scripts │ ────────► │  doctor                          │
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

Two-layer storage: secrets in macOS Keychain (so they're tied to your login session and Touch-ID-protected), metadata in `~/.config/keys-keeper/data.json` (so you can back it up, diff it, sync it through Time Machine).

Append-only audit log records every `add / copy / inject / resolve / reveal / ssh / export` operation with caller PID and process command line — visible in the admin's `/audit` page.

Encrypted backup via `keys export` (AES-256-GCM with PBKDF2-HMAC-SHA256, 600k iterations). Single portable file, restorable via `keys import` on a new machine.

## Roadmap

Open source, accepting PRs.

- [ ] **Linux backend** via `secret-tool` (libsecret) — `KeychainBackend` interface already abstracted
- [x] ~~**Windows backend** via Credential Manager (with chunking for SSH keys — CredMan has a 2560-byte cap)~~ — shipped in v0.2
- [x] ~~**Cursor / Aider / Codex / Cline rule-file generators** beyond the Claude skill format~~ — shipped in v0.3 (`keys init <target>`)
- [ ] **MCP stdio server** (`keys mcp`) — typed-tool surface for any MCP-compatible client (Cursor / Cline / Codex have native MCP)
- [ ] **Touch ID-gated reveal in admin** with auto-wipe from DOM after 10s
- [ ] **CSV export from `/audit`** (already CLI-only via `keys audit > file.csv`)
- [ ] **Bulk-paste parser extension** for ssh_key / server / domain (currently clean only for api_key)
- [ ] **Light theme polish** (CSS tokens exist; not all surfaces tested)

See [`docs/superpowers/specs/2026-05-04-keys-keeper-design.md`](docs/superpowers/specs/2026-05-04-keys-keeper-design.md) for the full design including security model and threat boundaries.

## Honest limitations

- **macOS + Windows only.** Linux (libsecret) backend is on the roadmap.
- **Single user, single machine.** No team / multi-user / sharing.
- **No cloud sync.** Use `keys export` + your favorite encrypted-file-sync route if you need it.
- **Bulk paste cleanly handles `api_key` only.** Other types need their type-specific fields filled by hand or via `+ New` in the admin.
- **The `caller_path` in audit log** is best-effort (parsed from `ps -p PID -o command=`); enough for forensics, not court evidence.

## Threat model

- **Defends against:** AI agents extracting plaintext into transcripts (the original motivation), accidental `git add` of `.env` files, plaintext clipboard residue, ad-hoc shell scripts that need a key without the user retyping it.
- **Does NOT defend against:** A root-level adversary on your Mac, malware that has your full keychain access, screen-recording on a compromised host, network attackers (the admin is localhost-only and never reachable from outside the loopback interface anyway).

## Contributing

Issues and PRs welcome. The repo is reasonably well-tested (146 tests + 9 Windows-only auto-skipped on macOS; fixtures use real isolated macOS keychains via `security create-keychain`). Run `pytest -q` after any change.

The implementation plan is at [`docs/superpowers/plans/2026-05-04-keys-keeper-plan.md`](docs/superpowers/plans/2026-05-04-keys-keeper-plan.md). The interactive design canvas (a Tailwind/React playground showing the locked UX choices) is at [`keys-keeper-admin-canvas.html`](keys-keeper-admin-canvas.html) — open it in your browser.

## License

MIT — see [`LICENSE`](LICENSE).
