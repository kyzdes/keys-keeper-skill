# keys-keeper · launch demo · shot list

**Goal:** 30-45 second video for the README hero, HN Show post, and Twitter thread. Single take if possible per act, then edit cuts in iMovie / Final Cut / Davinci.

**Format:** 1920×1080 mp4 @ 60fps, no audio. (We add ambient music or just keep silent — silent works fine for in-feed autoplay on HN/Twitter.)

**Theme:** macOS dark mode. Hide menu bar via Hide and Seek if possible. Close all unrelated windows. Use a clean wallpaper. Terminal: same JetBrains Mono font as the admin to keep visual cohesion.

---

## Pre-flight (do once before recording)

```bash
# 1. seed isolated demo data (does NOT touch real ~/.config/keys-keeper)
cd ~/Desktop/Projects/keys-keeper-skill/keys-keeper-skill
bash scripts/demo/setup.sh

# 2. open a NEW terminal window, source env, start admin
source scripts/demo/env.sh
keys serve --no-open      # prints URL with token, keep it open

# 3. open the URL in Chrome — admin should show 10 entries
# 4. open Claude Code app, hide it

# 5. when done recording, teardown (real data is safe through the whole thing):
bash scripts/demo/teardown.sh
```

---

## Act 1 · the leak (≈ 8 seconds)

**Setup:** Claude Code window. **Skill keys-keeper temporarily disabled** — easiest way: rename `~/.claude/skills/keys-keeper` to `~/.claude/skills/keys-keeper.disabled` for the duration of act 1, then put it back for act 3.

```bash
mv ~/.claude/skills/keys-keeper ~/.claude/skills/keys-keeper.disabled
# restart Claude Code so it re-reads available skills
```

A blank `.env` file is open in Claude Code's pane.

**Action:** type into the chat:

> "вставь openrouter ключ в .env: `sk-or-v1-DEMO00000000000000000000000000abc`"

**Beat 1 (≈3s):** Claude calls `Edit` tool. The `new_string` parameter, **including the full key**, scrolls past in the visible transcript.

**Beat 2 (≈3s):** zoom + red highlight box on the key in the transcript: `OPENROUTER_API_KEY=sk-or-v1-DEMO0…abc`. Add caption text overlay:

> "the key is now in the transcript — and in the model provider's logs forever"

**Beat 3 (≈2s):** transition card "but what if the agent simply couldn't see the value?"

**Re-enable skill before Act 3:**

```bash
mv ~/.claude/skills/keys-keeper.disabled ~/.claude/skills/keys-keeper
# restart Claude Code
```

---

## Act 2 · install (≈ 6 seconds, fast cuts)

Terminal window, screen-record at higher zoom for legibility.

```bash
pipx install keys-keeper      # cut after "installed package keys-keeper 0.1.0"
./scripts/install_skill.sh    # cut after "installed skill at ..."
```

(In editing: cut to ~2s per command. Use jump-cuts.)

---

## Act 3 · the protected flow (≈ 14 seconds)

**Setup:** Claude Code window with the skill restored. Same blank `.env` file open. Have the fake key already in `pbcopy`:

```bash
pbcopy <<<"sk-or-v1-DEMO00000000000000000000000000abc"
```

**Action:** type into the chat:

> "сохрани ключ openrouter из буфера и вставь в .env как `OPENROUTER_API_KEY`"

**Beat 1 (≈4s):** Claude calls `Bash`:

```
keys add openrouter-key --type api_key --from-clipboard --tag llm
```

Tool result line shown: `added api_key 'openrouter-key'`. **No key value anywhere on screen.**

**Beat 2 (≈4s):** Claude calls `Bash` again:

```
keys inject openrouter-key --file .env --as OPENROUTER_API_KEY
```

Tool result: `injected openrouter-key → .env as OPENROUTER_API_KEY`.

**Beat 3 (≈4s):** cut to the editor pane. `.env` now contains:

```
OPENROUTER_API_KEY=sk-or-v1-DEMO00000000000000000000000000abc
```

Highlight the file. Caption overlay:

> "agent never saw the value. transcript stays clean."

**Beat 4 (≈2s):** transition card "and there's a local admin."

---

## Act 4 · admin tour (≈ 12 seconds)

**Setup:** the Chrome window with `keys serve` admin already open at `http://127.0.0.1:7777/`.

I (the AI assistant) can drive this part for you via `claude-in-chrome` while you start the macOS screen recorder (`Cmd+Shift+5` → record selection → Chrome window). The route I'll take:

1. **(2s)** dashboard: 10 entries visible, type "stripe" in search → 2 rows
2. **(2s)** clear search, click `do-prod-droplet` row
3. **(3s)** entry detail page: type badge, name, tags, fields (host/port/user), **Linked entries → my-do-key chip**, recent access mini-audit
4. **(2s)** Cmd+K → palette opens → type "open" → highlights matching entries → Esc
5. **(3s)** click `Audit` in topbar: 3 charts render (top-10 bars, daily activity bars, op-type distribution), table below

End frame: dashboard with 10 entries + caption overlay "github.com/kyzdes/keys-keeper".

---

## Final ~3 seconds: end card

Static frame:

```
keys-keeper
github.com/kyzdes/keys-keeper
MIT
```

Same dark mono aesthetic as the admin (`#0a0b0c` bg, JetBrains Mono, accent `#d97550`).

---

## Recording tools

* **macOS native:** `Cmd+Shift+5` → "Record Selected Portion" → choose the Claude Code / Chrome window. Saves mp4 to Desktop. Good enough for everything.
* **Better:** [CleanShot X](https://cleanshot.com/) (60fps, easier trimming, can add cursor highlight). Paid but kills the noise.
* **Alternative for terminal cuts:** [asciinema](https://asciinema.org/) → cleaner-looking terminal cuts. Then export as gif via `agg`.

## Editing

Stitch the 4 acts in iMovie / Davinci Resolve. Add 0.3s crossfades between acts. No audio. Export as 1920×1080 mp4 H.264 @ 60fps.

Then run the post-process pipeline in `RECORD.md` to produce optimized assets for README + Twitter + HN.
