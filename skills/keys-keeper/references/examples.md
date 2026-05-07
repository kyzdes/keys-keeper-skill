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

STOP — the value is now in transcript. Tell the user: "не пастьте значение в чат — скопируйте в буфер и скажите 'сохрани из буфера как openrouter-roo'." Then: `keys add openrouter-roo --type api_key --from-clipboard --tag llm --service openrouter`.

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
2. Tell the user: "положи новый ключ в буфер и скажи 'замени stripe-test'".
3. Run: `keys add stripe-test --type api_key --from-clipboard --replace --tag payments,dev`.

(Or open admin: `keys serve` → entry detail → "Replace secret".)
