# VPS sync (KK2)

Status: implemented locally; deployment to a production VPS is not performed by the repository test suite.

## Security boundary

```text
macOS / Windows / Linux device                 private VPS
┌───────────────────────────────┐              ┌──────────────────────────┐
│ OS keychain                   │   HTTPS      │ keys-keeper-syncd        │
│ • random VaultKey             ├─────────────►│ • SQLite CAS HEAD        │
│ • Ed25519 private key         │ ciphertext   │ • signed commits         │
│ • X25519 private key          │ + signatures │ • public device keys     │
│ • random bearer token         │              │ • token/ invite hashes   │
└───────────────┬───────────────┘              └──────────────────────────┘
                │
                └─ plaintext exists only while the local process merges it
```

The service never imports a Keys Keeper backend and has no decrypt operation.
Snapshots are encrypted locally with a random 256-bit VaultKey using
AES-256-GCM and an HKDF-SHA256 domain-separated key. Every immutable commit is
signed with the author's Ed25519 key and binds the vault id, sequence, parent
commit id, parent manifest hash, ciphertext hash, device id, timestamp, and
format profile. The client pins the root device key and verifies the complete
membership and commit chains before decryption.

The VPS can observe vault/device identifiers, timing, object sizes, and the
device graph. It can deny service. It cannot read snapshot contents or create a
valid commit, but an attacker controlling an authorized device can use that
device's keys. Signed revocation checkpoints prevent a revoked device from
authoring later accepted commits, while that device still retains anything it
downloaded before revocation. A client rejects a branch that no longer descends
from its locally pinned checkpoint. Without an independent witness or gossip
between devices, however, a malicious VPS can maintain separate internally
valid views for devices that have never compared checkpoints. The current
implementation does not yet rotate the VaultKey for all remaining devices.

## Deploy behind HTTPS

Build from the repository root:

```bash
cd docs/syncd
umask 077
printf 'KEYS_KEEPER_SYNC_ADMIN_TOKEN=%s\n' "$(openssl rand -base64 48)" > .env
docker compose up -d --build
```

The provided Compose file publishes syncd only on `127.0.0.1:8787`. Put Caddy,
nginx, or an authenticated tailnet reverse proxy in front and expose only an
`https://` URL. Keep the SQLite volume private and include it in normal VPS
disk backups: it contains ciphertext rather than plaintext, but availability
still depends on it. Restrict the public route to `/v1/*`, rate-limit failed
authentication, and keep request-body limits unchanged.

For a tailnet-only deployment, terminate TLS on a tailnet hostname and grant
only enrolled user devices access to the HTTPS port. The bearer token and KK2
signatures remain required even inside the tailnet.

## Create the vault

On the first trusted device:

```bash
keys sync vps init \
  --endpoint https://keys.example.net \
  --recovery-file /path/on/offline-media/keys-keeper-recovery.json
keys sync vps push
```

`init` prompts for the bootstrap admin token. It never accepts that token on
the command line. The recovery bundle contains a random recovery secret and is
written as an owner-only file; move it offline. Device tokens, the VaultKey,
and private signing/wrapping keys stay in the OS credential backend.

For unattended setup, keep the bootstrap token in an existing Keys Keeper
entry and pass only its non-sensitive name:

```bash
keys sync vps init \
  --endpoint https://keys.example.net \
  --recovery-file /path/on/offline-media/keys-keeper-recovery.json \
  --admin-token-entry keys-keeper-syncd-admin
```

The CLI resolves that entry directly through the credential backend and keeps
the value sealed until it builds the authenticated HTTPS request. The token is
never placed in argv, stdout, or a temporary plaintext file.

## Add a device

On the original root device:

```bash
keys sync vps invite --out /secure-transfer/device-invite.json
```

Transfer the short-lived file directly to the new device. On the new device:

```bash
keys sync vps join \
  --invite /secure-transfer/device-invite.json \
  --trust-fingerprint 0123-4567-89ab-cdef-0123-4567
```

Compare the printed fingerprint over a separate channel. Back on the root
device, approve only the matching fingerprint:

```bash
keys sync vps approve INVITE_ID \
  --invite /secure-transfer/device-invite.json \
  --fingerprint 89ab-cdef-0123-4567-89ab-cdef
```

Then finish and pull on the new device:

```bash
keys sync vps finish --invite /secure-transfer/device-invite.json
keys sync vps pull
```

Remove the transferred invitation file from both devices after `finish`.

The invitation is one-time and expires server-side. `join` persists a private
retry identity before claiming it, so the same command is idempotent after a
lost HTTP response. The root device wraps
the VaultKey directly to the claimant's X25519 public key; syncd only relays the
opaque wrapped value.

## Operations

```bash
keys sync vps status
keys sync vps push
keys sync vps pull
keys sync vps devices
keys sync vps revoke DEVICE_ID
```

Concurrent writers are serialized with a SQLite transaction and compare-and-
swap on the signed parent commit. A losing client re-pulls, merges, and retries.
Normal clients keep a local highest trusted commit anchor and reject a missing,
older, rewritten, ciphertext-swapped, or non-descendant chain. Device
administration (`invite`, `approve`, and `revoke`) is root-only; all active
devices may publish ordinary vault commits.

## Recovery and remaining work

The recovery bundle cryptographically unwraps the VaultKey but is intentionally
not an automatic server login credential. Recovery still requires creating and
approving a new device identity, or an administrative recovery workflow added
in a later protocol version.

Before treating revocation as cryptographic erasure, add a signed key-epoch
commit that rotates the VaultKey and wraps the new epoch key to every remaining
device. Server-side access revocation alone is implemented and is labelled as
such in CLI output.
