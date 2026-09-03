# Install and local admin

### First-time setup / onboarding

Only run this flow when the user explicitly asks to set up, install, or get
started with keys-keeper (or invokes the skill directly). Do NOT volunteer to
migrate existing secrets or restructure their setup unprompted.

1. **Check whether the CLI is already there.** Run `keys --version` (or
   `which keys` / `Get-Command keys`). If it works → skip to step 4.
2. **If it's missing, OFFER to install and WAIT for a yes** — don't install
   silently. One line on what it is, then the platform command:
   - macOS / Linux: `pipx install 'git+https://github.com/kyzdes/keys-keeper-skill.git@v0.7.7'`
     (no pipx? macOS `brew install pipx && pipx ensurepath`; Linux
     `python3 -m pip install --user pipx && pipx ensurepath`)
   - Windows: `python -m pipx install "git+https://github.com/kyzdes/keys-keeper-skill.git@v0.7.7"`
   - Linux desktop also wants the keyring tool: `sudo apt install libsecret-tools`.
3. **After install, note that `keys` may need a fresh terminal** for PATH to
   pick it up. Re-check with `keys --version`.
4. **Orient the user — run `keys quickstart`.** It's read-only, shows no secret
   values, and prints the config dir, entry count, the core commands, and a
   first-key walkthrough. Then offer concrete next steps and let the user pick:
   (a) add their first key, (b) open the admin with `keys serve`, (c) install a
   quick-launch shortcut with `keys app install`.
5. **Never bulk-migrate existing secrets on your own.** If the user has a pile
   of plaintext keys somewhere, prepare the `keys add NAME --from-clipboard …`
   commands for them to run, and remind them any value already pasted into this
   chat is compromised and should be rotated.

### User opens the admin

- `keys serve` — opens a browser to a tokenized URL. The token migrates from `?t=` into an `HttpOnly` session cookie on the first hit; subsequent navigations don't carry it in the URL. The server idle-shuts-down after 15 min, or via the Settings → Shutdown button.

### User wants a quick-launch shortcut (Spotlight / Start Menu)

- `keys app install` — drops an OS-native shortcut so the user can launch `keys serve` without a terminal. On macOS: a Spotlight-searchable `Keys Keeper.app` in `~/Applications` (Cmd+Space → "Keys Keeper"). On Windows: a `Keys Keeper.lnk` in the per-user Start Menu Programs folder.
- `--force` overwrites an existing install. `--system` (macOS only) targets `/Applications` and may need sudo.
- `keys app uninstall` removes it.
- The macOS launcher detects port 7777 already bound and emits a Notification Center toast instead of failing — safe to re-trigger. Logs go to `~/Library/Logs/keys-keeper.log`.
- After the first successful `keys serve`, the CLI prints a one-line tip suggesting this command; once installed, the tip stops showing.
