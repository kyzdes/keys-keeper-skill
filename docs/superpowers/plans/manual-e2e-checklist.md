# keys-keeper · Manual E2E checklist

Run before each release. Each step should produce no plaintext in any visible terminal/transcript output.

## Setup

- [ ] `pipx install --force .`
- [ ] `keys doctor` — clean output (no errors)
- [ ] `./scripts/install_skill.sh --force`

## CLI flow

- [ ] `pbcopy <<<"sk-test"` then `keys add e2e-test --type api_key --from-clipboard`
- [ ] `keys list` shows `e2e-test`
- [ ] `keys info e2e-test` shows metadata, no value
- [ ] `keys reveal e2e-test` errors (env unset)
- [ ] `KEYS_KEEPER_ALLOW_REVEAL=1 keys reveal e2e-test` prints value
- [ ] `echo "OTHER=foo" > /tmp/.env-test; keys inject e2e-test --file /tmp/.env-test --as MY_KEY` — file has both lines
- [ ] `cat /tmp/.env-test` — visible to user only
- [ ] `keys copy e2e-test`; `pbpaste` shows value; wait 30s; `pbpaste` is empty
- [ ] `keys export /tmp/backup.kk` (password "test"); `keys rm e2e-test`; `keys import /tmp/backup.kk` — restored
- [ ] `keys audit --since 24h` — shows recent events including the test ops above

## Web admin flow

- [ ] `keys serve` opens browser at tokenized URL
- [ ] Dashboard shows entries with unified-table layout
- [ ] Search "e2e" filters list to matches
- [ ] Click entry → detail page renders (fields, refs, recent events)
- [ ] Cmd+K palette opens, type-and-Enter navigates to entry
- [ ] /paste → paste 3 entries → preview shows them → Save all → dashboard updated
- [ ] /audit shows recent events + bar chart for daily activity
- [ ] /settings → shutdown button stops the server
- [ ] DOM never contains the secret value at any point — verify in DevTools that fetch responses for /api/entries don't include any `value` field

## Claude Code flow

- [ ] In Claude Code: "сохрани ключ из буфера как claude-test" — runs `keys add claude-test --from-clipboard`
- [ ] "вставь claude-test в /tmp/.env-test как CLAUDE_KEY" — runs `keys inject ...` (no plaintext in transcript)
- [ ] "покажи мои ключи" — runs `keys list`
- [ ] "что в audit за последние 24 часа?" — runs `keys audit --since 24h`
- [ ] Verify the transcript: search for `sk-` or any obvious value pattern → must be ZERO matches
