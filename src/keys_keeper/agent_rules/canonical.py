"""Canonical agent-facing prose — single source of truth.

Every per-target rule file (SKILL.md, .cursor/rules/*.mdc, AGENTS.md, …) and
the MCP server's `instructions` field is composed from the constants below.
When you edit this file:

  1. Bump the patch version in `pyproject.toml`, `__init__.py`, and
     `.claude-plugin/plugin.json` so the SessionStart auto-update hook picks
     up the change.
  2. Regenerate the shipped SKILL.md:  `keys init claude --force`
  3. CI runs `keys init claude --check` to catch drift on subsequent commits.

Language is English. Agents translate at use-time.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Identity — one paragraph: what is this thing, how do you call it.
# ---------------------------------------------------------------------------

IDENTITY = """\
Storage CLI is `keys` (run `which keys` / `Get-Command keys` to find the install path; typically wherever pipx installed it). Run `keys --help` for the full surface."""


# ---------------------------------------------------------------------------
# Forbidden — what the agent must NOT do.
# ---------------------------------------------------------------------------

FORBIDDEN_TITLE = "CRITICAL: never expose secret values"

FORBIDDEN = """\
You MUST NOT:
- run `keys reveal` (this command exists for the human, not for you)
- pipe `keys` output containing values into Edit/Write/Bash echo
- ask the user to paste a secret value into chat (it lands in the transcript)"""


# ---------------------------------------------------------------------------
# Allowed — the agent-safe command surface.
# ---------------------------------------------------------------------------

ALLOWED = """\
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
- `keys doctor` — paths + keychain sync check, useful when a value is missing"""


# ---------------------------------------------------------------------------
# Flows — how to compose the commands for common user requests.
# ---------------------------------------------------------------------------

FLOW_SAVE = """\
### User wants to save a secret

1. **If the user pastes the value into chat → STOP.** Tell them: "don't paste the value into chat — copy it to the clipboard and say 'save from clipboard as X', or open the web admin." The transcript is a leak surface.
2. Preferred path: `keys add NAME --type TYPE --from-clipboard --tag ... --note "..."`.
3. For multi-line secrets (SSH keys, PEM blobs): tell the user to either save to a file (`--from-file path`) or open `keys serve` and use the web form (clipboard truncation can corrupt long PEMs).
4. For mass import from a notes file: `keys serve` → Bulk import page (the parser handles `key=value` lines, multi-line PEMs, tags, and type override per-line)."""


FLOW_INJECT = """\
### User wants to put a secret into a file

ALWAYS use `keys inject` or `keys resolve`. Never `Edit` with the value. Never `Bash` with `$(keys ...)` substitution that echoes the value.

Examples:
- "put the openrouter key into .env" → `keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY`
- ".env.template has references to keys, fill them in" → `keys resolve .env`"""


FLOW_SERVER = """\
### User asks for server credentials

- `keys info NAME` for non-sensitive fields (host, user, port).
- `keys ssh NAME` to actually connect — the CLI handles key material itself.
- For deploy scripts that need ENV vars from `keys`: write `__KEYS:name__` placeholders, then `keys resolve PATH` at runtime."""


FLOW_ADMIN = """\
### User opens the admin

- `keys serve` — opens a browser to a tokenized URL. The token migrates from `?t=` into an `HttpOnly` session cookie on the first hit; subsequent navigations don't carry it in the URL. The server idle-shuts-down after 15 min, or via the Settings → Shutdown button."""


FLOW_AUDIT = """\
### User asks "why was X accessed" / "who used X"

- `keys audit --name X` — most recent first, shows op + caller + file target where applicable.
- Filters: `--op {copy,inject,reveal,resolve,add,edit,delete}` (matches both bare ops and the `mcp.*` prefix used when the call came in via MCP), `--since 24h` / `7d` / `30d` (free-form), `--limit N`.
- The web admin's `/audit` page has the same data plus charts; either is fine."""


# ---------------------------------------------------------------------------
# Search and structural defenses.
# ---------------------------------------------------------------------------

SEARCH = """\
## Search & discovery

- `keys list` for everything, with filters `--type`, `--tag`, `--search`.
- Partial match on names is OK; ambiguous → ask the user to disambiguate.
- `keys info NAME` shows refs both ways (used-by reverse refs)."""


STRUCTURAL_DEFENSE = """\
## Structural defenses (informational)

Even if you accidentally bypass the rules above by importing the Python package directly (e.g. running `python -c "from keys_keeper.composition import build_backend; print(build_backend().get('kk:...'))"`), the keychain backend returns a `Sealed` wrapper whose `__repr__`/`__str__` is `"<sealed>"` — a bare `print` / f-string / log statement renders `<sealed>`, not the value. The only path to plaintext is an explicit `.unseal()` call. This is defense-in-depth, not a license to try; the rules above still apply."""


WHEN_IN_DOUBT = """\
## When in doubt

If you're not sure whether an operation might leak a value, **ask the user first** rather than guess. The cost of asking is one round-trip; the cost of leaking is permanent."""


# ---------------------------------------------------------------------------
# MCP instructions — shorter paragraph shown to MCP clients via the
# `instructions=` field of `FastMCP`. Same contract, framed for typed tools.
# ---------------------------------------------------------------------------

MCP_INSTRUCTIONS = """\
keys-keeper exposes credentials through controlled sinks: clipboard (with auto-clear), file injection, and placeholder resolution. Tool responses never include secret values — `keys_copy` reports only the target name and clear timeout, `keys_inject` reports only the file and env-var name written, etc. The plaintext primitive (`Sealed.unseal()`) is invoked once inside each handler and routed straight to its sink; the JSON response is metadata only.

Forbidden surface (not exposed as tools): `reveal` (env-gated for humans only), `serve` (long-running), `export`/`import` (admin operations), `add`/`edit`/`rm` (secret ingestion is user-driven via the local admin UI), and `ssh` (remote command echoing is a leak surface not yet fully bounded).

If a workflow needs a forbidden operation, ask the human to run it via `keys` directly. The CLI provides one-line equivalents for everything."""


# ---------------------------------------------------------------------------
# Section composers — assemble bodies for each renderer in render.py.
# Keep render.py free of conditional logic by exporting pre-composed bodies
# here, parameterised by the things that legitimately vary per target.
# ---------------------------------------------------------------------------


def common_body(*, include_admin: bool = True, include_when_in_doubt: bool = True) -> str:
    """The shared body used by every rule file, in canonical order.

    Targets that need to trim sections (e.g. Cursor's alwaysApply caveat
    on length) can pass include_admin=False to drop the admin paragraph.
    """
    parts = [
        IDENTITY,
        "",
        f"## {FORBIDDEN_TITLE}",
        "",
        FORBIDDEN,
        "",
        ALLOWED,
        "",
        "## Common flows",
        "",
        FLOW_SAVE,
        "",
        FLOW_INJECT,
        "",
        FLOW_SERVER,
    ]
    if include_admin:
        parts.extend(["", FLOW_ADMIN])
    parts.extend(["", FLOW_AUDIT, "", SEARCH, "", STRUCTURAL_DEFENSE])
    if include_when_in_doubt:
        parts.extend(["", WHEN_IN_DOUBT])
    return "\n".join(parts).rstrip() + "\n"
