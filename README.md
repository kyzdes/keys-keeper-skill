# keys-keeper

[![tests](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml/badge.svg)](https://github.com/kyzdes/keys-keeper-skill/actions/workflows/tests.yml)

> **A secrets manager AI coding agents architecturally cannot leak from.**

Stores API keys, SSH keys, server credentials, and domain info in the OS-native credential store (macOS Keychain on macOS, Credential Manager on Windows). Ships with a Claude skill that lets agents *put* secrets into your files without ever *seeing* the value.

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

### Claude Code plugin (recommended — auto-updates)

```
/plugin marketplace add kyzdes/claude-skills
/plugin install keys-keeper@kyzdes-claude-skills
```

Then install the CLI (the plugin requires it):

```bash
pipx install git+https://github.com/kyzdes/keys-keeper-skill.git
```

### Standalone (no marketplace)

#### macOS

```bash
git clone https://github.com/kyzdes/keys-keeper-skill.git
cd keys-keeper-skill
pipx install .

keys doctor                                            # creates ~/.config/keys-keeper/, probes keychain
echo 'export KEYS_KEEPER_ALLOW_REVEAL=1' >> ~/.zshrc   # optional — lets shell users print plaintext
./scripts/install_skill.sh                             # copies the Claude skill into ~/.claude/skills/
```

#### Windows

```powershell
git clone https://github.com/kyzdes/keys-keeper-skill.git
cd keys-keeper-skill
pipx install .

keys doctor                                            # creates %APPDATA%\keys-keeper\, probes Credential Manager
setx KEYS_KEEPER_ALLOW_REVEAL 1                        # optional — effective in NEW shells
.\scripts\install_skill.ps1                            # copies the Claude skill into %USERPROFILE%\.claude\skills\
```

Requires Python 3.10+ (Linux backend is on the roadmap).

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
- [ ] **Touch ID-gated reveal in admin** with auto-wipe from DOM after 10s
- [ ] **Cursor / Aider / Cline rule-file generators** beyond the Claude skill format
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

Issues and PRs welcome. The repo is reasonably well-tested (103 tests, fixtures use real isolated macOS keychains via `security create-keychain`). Run `pytest -q` after any change.

The implementation plan is at [`docs/superpowers/plans/2026-05-04-keys-keeper-plan.md`](docs/superpowers/plans/2026-05-04-keys-keeper-plan.md). The interactive design canvas (a Tailwind/React playground showing the locked UX choices) is at [`keys-keeper-admin-canvas.html`](keys-keeper-admin-canvas.html) — open it in your browser.

## License

MIT — see [`LICENSE`](LICENSE).
