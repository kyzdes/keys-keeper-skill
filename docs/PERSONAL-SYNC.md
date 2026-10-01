# Personal VPS sync

This is the default path for the owner's computers. The main computer publishes
all current and future entries. Replicas can read those entries and create new
ones. Existing-key edits, deletions, enrollment and revocation remain on the main
computer. Project delivery remains a separate, explicitly scoped workflow.

## Everyday setup

1. Update the client and the existing `keys-keeper-syncd` relay to a build with
   personal pairing. `GET /v2/capabilities` reports `personal_pairing: 1`.
2. On the main computer, open **Settings → My computers**. The existing relay
   address is suggested when unambiguous. Select the saved relay administrator
   entry, name this computer and choose **Enable sync for all keys**.
3. Choose **Add computer**. On the other computer, open the same Settings panel,
   name it and paste the connection code into **Connect this computer**.
4. Compare the verification code on the two screens. On the main computer choose
   **Codes match — approve computer**. The other computer installs its encrypted
   local copy automatically. No invitation files, SSH keys or administrator
   tokens need to be transferred to it for the enrollment protocol.

Connections expire after ten minutes. A connection has one immutable request.
If another device claimed it, create a new invitation; do not approve a code
that differs from your intended device. A code is sensitive and must not be
pasted into an agent conversation, command line, URL or issue.

The secondary installation must be empty. Existing keys/profiles are preserved
and onboarding refuses to reclassify them silently. UI startup files and logs in
an otherwise empty installation are fine: the actual replica has its own root.

### Windows installation

Download and run `scripts/install-windows.ps1` in PowerShell. It finds Python
3.10+ or installs Python 3.13 through the current user's WinGet, creates a
dedicated virtual environment under `%LOCALAPPDATA%\KeysKeeper`, adds only a
`keys` wrapper to the user PATH, installs a Start Menu shortcut and opens the
local app. It does not require Git, SSH, administrator rights or any vault token.
The default download source is the personal-sync development branch until this
feature is released; `-Source` accepts a reviewed archive URL or local checkout.

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/kyzdes/keys-keeper-skill/codex/personal-vps-sync/scripts/install-windows.ps1 -OutFile "$env:TEMP\install-keys-keeper.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:TEMP\install-keys-keeper.ps1"
```

The execution-policy override applies only to this process. Once the app opens,
use **Settings → My computers → Connect this computer**.

## Background and offline behavior

Setup enables a job for the signed-in OS user: LaunchAgent on macOS, Task
Scheduler with `InteractiveToken` on Windows, or a systemd user unit on Linux.
The job uses the same installed Python runtime and vault directory and runs
every minute without authorization dialogs. It works independently of the
Settings window. If the OS cannot install/start the job, Settings shows the
failure and **Retry background sync**; the UI never treats that as success.

Keys already received remain usable offline. New entries on a replica stay in
its durable outbox until submitted. The main computer must run to accept and
publish them; all replicas eventually fetch that publication. Name conflicts
keep the canonical existing key and are not resolved by overwriting it.

`keys devices status` reports local state; `keys devices sync` retries now.
`keys devices autostart on|off` controls automatic startup. Background processes
use `keys devices watch --home PATH`. A network error is recorded as pending with
a fixed message. It does not erase keys or log decrypted payloads.

## Access and protocol

- A dedicated scope uses the existing KK3 policy, grant, signature, epoch,
  encrypted snapshot, create-submission and receipt machinery. The explicit
  `personal_vault` flag is inside encrypted master state. It authorizes full
  entry projection, including fields, notes, tags and references. It does not
  copy hidden backend service accounts, master signing keys, or local runtime
  unlock files. Every catalog entry is included, even entries containing
  infrastructure administrator credentials: choose this mode only for your own
  fully trusted computers.
- Personal snapshots use payload schema 2 and preserve informational reference
  cycles already present in the main catalog. References still cannot leave the
  installed copy, and new submissions are checked against current canonical
  entry identities. Ordinary scoped payloads remain schema 1 and acyclic.
- Entry distribution and ordinary project bindings are never widened. A new
  main-computer entry remains local-only for project delivery while personal
  replicas receive it through their separate authority.
- A connection code carries a random 256-bit key, scope/mailbox IDs, endpoint and
  master fingerprint. AES-256-GCM encrypts each mailbox slot with associated
  data containing its protocol version, mailbox ID and slot name. A
  domain-separated SHA-256 authentication token is sent to the relay; only its
  hash is stored. That token does not expose the mailbox encryption key.
- The existing signed invitation/request/answer protocol still pins the master
  and binds device keys, token hash, role, snapshot and key wrap. The local
  approval endpoint receives the full request fingerprint displayed by the
  main computer; the human compares a 96-bit prefix on both screens.
- Pairing writes require master or mailbox authentication before reading the
  HTTP body. Mailboxes expire, requests and responses are immutable, retries
  are idempotent, and per-scope/global count and byte budgets bound storage.
  Revocation uses KK3 immediate blocking and epoch rotation. It cannot erase
  credentials already downloaded to the disconnected computer.

## Backup, upgrades and compatibility

Setup and each invitation create and verify a local encrypted recovery bundle
under `recovery/personal-*.kk3`. Its generated password is a hidden backend
service account, not a synced catalog entry. These automatic copies support
local recovery; they are not an independently recoverable off-device backup if
the OS credential store is lost. Keep an independent password-protected KK3
recovery backup using the existing `keys project-sync backup` workflow for that
case. Recovery/takeover remains an explicit action, not secondary onboarding.
After a recovery takeover, enable personal sync on the recovered main computer
and reconnect the other computers to its new authority.

The new relay table is additive and can coexist with old clients/scoped jobs.
Take the existing SQLite online backup before upgrading. Older relay builds do
not support the new pairing endpoints and must be updated first. Older clients
do not understand personal routing/all-entry projection and must not run a
personal scope's watcher; existing ordinary scopes remain compatible.

S3 and KK2 commands remain available as legacy compatibility features. The S3
panel is collapsed and makes no status/credential request until opened. Legacy
full-vault exports and writers still reject schema 3.
