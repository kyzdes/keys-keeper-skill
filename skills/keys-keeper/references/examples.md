# keys-keeper · worked examples

These are concrete patterns Claude should match. Each starts with the user's natural-language request and shows the exact `keys` command(s) to run.

## "Set up env for new project"

User: "Create .env for this project with my OpenRouter and GitHub keys."

Sequence:
1. `keys list --tag llm` — confirm the user has `openrouter-cline` (or similar).
2. `keys list --tag dev` — confirm a github token exists.
3. `keys inject openrouter-cline --file .env --as OPENROUTER_API_KEY`
4. `keys inject github-token-cli --file .env --as GITHUB_TOKEN`

Never read the values into your context. Never use `Edit` to write the secret values directly.

## "Save this API key"

User: "Save this OpenRouter key as openrouter-roo: sk-or-v1-..."

STOP — the value is now in transcript. Tell the user: "don't paste the value into chat — copy it to the clipboard and say 'save from clipboard as openrouter-roo'." Then: `keys add openrouter-roo --type api_key --from-clipboard --tag llm --service openrouter`.

## "What servers do I have?"

User: "List my servers."

`keys list --type server` — names + tags only.

## "SSH into prod"

User: "Open ssh to do-prod-droplet."

`keys ssh do-prod-droplet` — CLI handles tempfile lifecycle.

## "Why was my key accessed yesterday?"

User: "Show audit log for openrouter-cline."

`keys audit --name openrouter-cline --since 7d` — most recent first, shows op + caller path + file target.

Other shapes:
- `keys audit --op copy --since 24h` — every copy in the last day.
- `keys audit --since 30d --limit 200` — bulk dump for grep.
- `keys serve` → `/audit` page if the user wants charts.

## "Rotate my Stripe key"

User: "Replace stripe-test with the new value."

1. STOP if the user pastes the value.
2. Tell the user: "put the new key on the clipboard and say 'replace stripe-test'".
3. Run: `keys add stripe-test --type api_key --from-clipboard --replace --tag payments,dev`.

(Or open admin: `keys serve` → entry detail → "Replace secret".)

## "Back up my vault to the cloud"

User: "Sync my keys to my R2 bucket so I have them on my laptop too."

1. `keys sync setup` ingests the secret key + passphrase, so it's user-driven — give them the command to run themselves: `keys sync setup --endpoint https://<acct>.r2.cloudflarestorage.com --bucket my-vault --access-key-id <id>` (it then prompts for the secret key + a backup passphrase). Remind them: a lost passphrase means an unrecoverable backup.
2. Once configured, you can run `keys sync push` (upload) / `keys sync pull` (merge) / `keys sync status` (metadata only). Only the encrypted blob moves — no values touch stdout.

## "Open my vault in a browser"

User: "Let me view my keys in a web page on this box."

1. Needs `keys sync` already configured (or `WEBVAULT_S3_*` env). Then: `keys webvault serve --register-token <token>` — the browser decrypts in-page; the server never sees plaintext.
2. For internet exposure, put TLS / a reverse proxy in front and add `--behind-proxy`. v1 is read-only (view / search / reveal / copy); adding and editing stay in the CLI.
