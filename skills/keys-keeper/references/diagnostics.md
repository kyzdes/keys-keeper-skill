# Diagnostics

### User asks whether Keys Keeper is installed, current, or healthy

- Do not guess or hard-code a plugin-cache path. Plugin namespace and package directories may repeat (for example `.../cache/keys-keeper/keys-keeper/<version>/...`). Use the skill path provided by the current runtime; for CLI health use `command -v keys` / `Get-Command keys`, `keys --version`, and `keys doctor`.
- For Codex plugin verification, also check the plugin registry (`codex plugin list`) and compare the reported plugin version with `keys --version`. A missing hand-constructed file path is a path-resolution error, not evidence that the skill moved or is broken.
- Treat `keys doctor` as vault-wide diagnostics. Separate installation/runtime health from data-hygiene findings such as reference cycles, orphaned metadata, or a single missing entry; unrelated warnings do not invalidate the current credential or task.
- If a checkout was moved and `.venv/bin/pytest` has a stale shebang, run that environment's Python with `-m pytest` rather than diagnosing the product from a broken wrapper.

## Command effects

| Command | Reads a secret | Network | Mutates state | User approval |
|---|---:|---:|---:|---:|
| `keys list`, `keys info`, `keys quickstart` | no | no | no | no |
| `keys keychain status` | no | no | no | no |
| `keys doctor` | presence only | no | no | no |
| `keys sync status` | sync credentials | yes | no | setup must already exist |
| `keys copy`, `inject`, `resolve`, `ssh` | yes | SSH only | explicit sink/session | request authorizes sink |
| `keys add`, `edit`, `rm`, `sync push/pull` | as required | sync only | yes | explicit task required |

"Metadata-only output" does not mean an operation is local or credential-free.
Use the narrowest command that answers the request.

## Structural defenses (informational)

Even if you accidentally bypass the rules above by importing the Python package directly (e.g. running `python -c "from keys_keeper.composition import build_backend; print(build_backend().get('kk:...'))"`), the keychain backend returns a `Sealed` wrapper whose `__repr__`/`__str__` is `"<sealed>"` — a bare `print` / f-string / log statement renders `<sealed>`, not the value. The only path to plaintext through that wrapper is an explicit `.unseal()` call. This is defense-in-depth, not a license to try; the rules above still apply.

**Scope of the guarantee (be precise).** The default command surface avoids printing secret values during normal operation. This is **not** an airtight "plaintext can never reach you" claim or an authorization boundary. The `KEYS_KEEPER_ALLOW_REVEAL` environment check is caller-controlled and prevents accidents only; a shell-capable caller can set it. The sanctioned sinks deliberately put plaintext somewhere on the host — `keys copy` writes the clipboard (an agent with shell access can `pbpaste`/`xclip -o`), and `keys inject`/`keys resolve` write the value into a file you can then read. So an agent with shell access on the same machine *can* recover values it routed through these sinks. Do not round-trip a value back into the transcript: don't `pbpaste` after a `keys copy`, don't `cat` a file you just injected into, and don't log resolved output. Treat "I have the value in a readable sink" and "the value is available to me" as the same exposure.
