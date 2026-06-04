# keys-keeper web vault (zero-knowledge, read-only v1)

Open your keys-keeper vault from a browser. The browser fetches the encrypted
`KK1` blob and **decrypts it in-page with WebCrypto** using your passphrase —
the passphrase and the decrypted secrets never reach the server. The server is a
hardened, authenticated **ciphertext shuttle** that reuses `S3Remote` and never
imports `crypto`. It's a third client on the *same* encrypted blob the CLI and
local admin sync to.

v1 is **read-only**: unlock → view/search → reveal/copy → idle auto-lock. Add
and edit still happen via the CLI / local admin; the web reflects them on the
next unlock.

## Security model (short)

- **Zero-knowledge**: `PBKDF2(passphrase, salt, 600k) → AES-256-GCM` runs only in
  the browser. The server holds ciphertext + non-secret commit JSON.
- **Auth split**: login sends an *auth hash* derived from the passphrase with a
  *different* salt; the server stores only `scrypt(auth_hash)`. It can verify you
  without being able to decrypt your vault.
- **Hardening**: strict nonce-free CSP with **no `unsafe-inline`**, Trusted
  Types, all DOM via `textContent` (never `innerHTML`), SRI on the bundle,
  self-hosted fonts, HSTS, `no-store`, reveal-on-demand, clipboard auto-clear,
  idle auto-lock, non-extractable `CryptoKey`, session-derived tenant prefix
  (never from the request).
- **The one honest caveat** of *any* web vault: you must trust the server to
  serve honest JS. **Self-host** (then it's your own box) + verify the published
  SRI hash. We don't claim past this.
- **No recovery**: a lost passphrase = lost data, by design. Keep a Recovery Kit
  (`keys export`).

## Run it (self-host)

```bash
docker build -t kk-webvault docs/webvault
docker run -p 8333:8333 -v kkvault:/data \
  -e WEBVAULT_S3_ENDPOINT=https://s3.example.com \
  -e WEBVAULT_S3_BUCKET=my-bucket \
  -e WEBVAULT_S3_ACCESS_KEY_ID=... \
  -e WEBVAULT_S3_SECRET_KEY=... \
  -e WEBVAULT_VAULT_PREFIX=keys-keeper \
  -e WEBVAULT_REGISTER_TOKEN=$(openssl rand -hex 16) \
  kk-webvault
```

Put a TLS-terminating reverse proxy in front (or pass `--certfile/--keyfile`).
`WEBVAULT_VAULT_PREFIX` must match the prefix your CLI syncs to so the web reads
the same vault. Set `WEBVAULT_MULTI_TENANT=1` to namespace each account under
`tenants/<uid>/` instead.

Locally, without env vars, the server falls back to your `keys sync` config +
keychain creds — handy for trying it against your existing bucket:

```bash
keys webvault serve --register-token $(openssl rand -hex 16)
```

## First use

1. Visit the URL → **Create account** → enter an account name, the register
   token, and your **vault passphrase** (the same one that encrypts the blob).
   The browser derives the auth hash locally and registers.
2. Unlock with that account + passphrase → your entries render. Reveal/copy a
   secret (auto-clears in 30s); the vault auto-locks when idle.
