---
name: keys-keeper
description: Securely save/retrieve API keys, SSH keys, server credentials, and domain info using the OS-native credential store (macOS Keychain / Windows Credential Manager) via the `keys` CLI. Use when the user mentions saving, getting, or referencing secrets, API keys, tokens, SSH keys, server addresses, or domain configs. Never produces plaintext secret values in output — uses CLI commands that handle files and clipboard directly.
---

# keys-keeper

Storage CLI is `keys` (run `which keys` / `Get-Command keys` to find the install path; typically wherever pipx installed it). Run `keys --help` for the full surface.

## CRITICAL: never expose secret values

You MUST NOT:
- run `keys reveal` (this command exists for the human, not for you)
- pipe `keys` output containing values into Edit/Write/Bash echo
- ask the user to paste a secret value into chat (it lands in transcript)

You CAN:
- `keys list` / `keys info NAME` — metadata only, no values
- `keys copy NAME` — value goes to clipboard with 30s auto-clear, never stdout
- `keys inject NAME --file PATH --as ENV` — value goes directly to file
- `keys resolve PATH` — placeholder substitution in file (writes back to the same path)
- `keys add NAME --from-clipboard` / `--from-file PATH` / `--stdin` (when the user already piped)
- `keys ssh NAME` — opens ssh session with resolved key (CLI manages tempfile with locked-down permissions: POSIX 0600 on macOS, icacls user-restricted ACL on Windows)
- `keys rm NAME` (use `--cascade` if the entry is referenced by others)
- `keys edit NAME` — change tags / note / non-secret fields (`--field key=value`)
- `keys audit --name X --since 7d` / `--op copy` — search the audit log
- `keys doctor` — paths + keychain sync check, useful when a value is missing

## Common flows

### User wants to save a secret

1. **If user pastes the value into chat → STOP.** Tell them: «не пастьте значение в чат — скопируйте в буфер и скажите 'сохрани из буфера как X', либо открой веб-админку». The transcript is a leak surface.
2. Preferred path: `keys add NAME --type TYPE --from-clipboard --tag ... --note "..."`.
3. For multi-line secrets (SSH keys, PEM blobs): tell the user to either save to a file (`--from-file path`) or open `keys serve` and use the web form (clipboard truncation can corrupt long PEMs).
4. For mass import from a notes file: `keys serve` → Bulk import page (the parser handles `key=value` lines, multi-line PEMs, tags, and type override per-line).

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

- `keys serve` — opens browser to a tokenized URL. The token migrates from `?t=` into an `HttpOnly` session cookie on first hit; subsequent navigations don't carry it in the URL. The server idle-shuts-down after 15 min, or via the Settings → Shutdown button.

### User asks "why was X accessed" / "who used X"

- `keys audit --name X` — most recent first, shows op + caller + file target where applicable.
- Filters: `--op {copy,inject,reveal,resolve,add,edit,delete}`, `--since 24h` / `7d` / `30d` (free-form), `--limit N`.
- The web admin's `/audit` page has the same data plus charts; either is fine.

## Search & discovery

- `keys list` for everything, with filters `--type`, `--tag`, `--search`.
- Partial match on names is OK; ambiguous → ask user to disambiguate.
- `keys info NAME` shows refs both ways (used-by reverse refs).

## Structural defenses (informational)

Even if you accidentally bypass the rules above by importing the Python package directly (e.g. running `python -c "from keys_keeper.composition import build_backend; print(build_backend().get('kk:...'))"`), the keychain backend returns a `Sealed` wrapper whose `__repr__`/`__str__` is `"<sealed>"` — bare `print` / f-string / log statement renders `<sealed>`, not the value. The only path to plaintext is an explicit `.unseal()` call. This is defense-in-depth, not a license to try; the rules above still apply.

## When in doubt

If you're not sure whether an operation might leak a value, **ask the user first** rather than guess. The cost of asking is one round-trip; the cost of leaking is permanent.
