# Sync and WebVault

### User wants cloud backup / sync across machines

- `keys sync setup` connects an S3-compatible bucket (AWS S3 / Cloudflare R2 / Backblaze B2 / MinIO / Wasabi) and stores the access-key id, secret key, and a backup passphrase in the OS keychain. This step INGESTS secrets (it prompts for the secret key + passphrase), so it's user-driven — walk them through `keys sync setup --endpoint ... --bucket ... --access-key-id ...`, don't run it unprompted. The passphrase encrypts the whole cloud copy; a lost passphrase = unrecoverable backup, so tell the user to keep it somewhere safe.
- Once configured you CAN run `keys sync push` / `keys sync pull` / `keys sync status` yourself — they move only the encrypted AES-256-GCM blob (same zero-knowledge format as `keys export`); no plaintext hits stdout or the transcript. `keys sync status` reads the saved sync credentials and contacts the remote even though its output contains metadata only.
- `keys sync rollback N` restores an earlier snapshot version; `keys sync mode {off,manual,auto}` switches modes. `auto` enables a fail-open SessionStart auto-sync that exits silently on any error and never prompts.

### User wants the vault in a browser (self-hosted)

- `keys webvault serve` runs the browser-decrypted web vault: the shipped client fetches the encrypted blob and decrypts it in-page, so the normal server request path receives ciphertext rather than vault plaintext. A compromised server can replace the JavaScript it serves; self-hosting and verifying the reviewed release remain part of the trust model. It reads the same S3 vault `keys sync` writes.
- Prerequisite: `keys sync` must be configured (or pass the `WEBVAULT_S3_*` env vars). Defaults to `127.0.0.1:8333`.
- Gate sign-up with `--register-token TOKEN` (registration is closed by default). For internet exposure, terminate TLS — put a reverse proxy in front and add `--behind-proxy`, or hand it `--certfile/--keyfile` directly.
- v1 is read-only (view / search / reveal / copy in the browser). Adding and editing entries stay in the CLI or the local `keys serve` admin.
