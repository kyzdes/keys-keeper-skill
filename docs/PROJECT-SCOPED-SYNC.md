# Project-scoped synchronization runbook

Project scopes are explicit allowlists. A folder, tag, project name, or repeated
slug never grants an entry to a project. Entries begin as `local_only`; only a
canonical entry ID bound to a scope becomes eligible for that scope's projected
payload.

All commands emit metadata only. Do not put recovery passwords, invitation
bundles, bootstrap tokens, or secret values in shell history, chat, issue
trackers, or command output.

## 1. Back up, then enable the catalog

On the master device, create a password file owned by the current user and run:

```sh
keys project-sync migrate --out /secure/path/master-before-catalog.kk3 --password-file /secure/path/recovery-password
```

`migrate` creates and verifies an encrypted master recovery bundle before it
changes metadata to schema 3. The normal `keys export`, `keys import`, and
legacy whole-vault sync commands intentionally refuse a schema-3 catalog; they
cannot preserve scope bindings or delivery state.

## 2. Organize locally and bind an exact scope

Folders affect local navigation only:

```sh
keys folders create Infrastructure
keys folders assign-entry kk:ENTRY_UUID --folder FOLDER_UUID
keys projects create payments Payments
keys projects scopes PROJECT_UUID --create --environment production
keys projects distribution kk:ENTRY_UUID --distribution project_allowed
keys projects add kk:ENTRY_UUID --scope-id SCOPE_UUID
```

Use `keys folders list --json`, `keys projects list --json`, and `keys projects
scopes PROJECT_UUID --json` to obtain stable IDs. Reusing a project slug is
allowed; choose `--scope-id` whenever a slug/environment is ambiguous. A folder
move or rename leaves grants unchanged. Assigning an entry to a scope is the
only catalog action that changes its projected eligibility.

## 3. Initialize the delivery scope and back up again

Store the project-server administrator token as an existing master entry, then
initialize the scope without printing that token:

```sh
keys project-sync init --scope SCOPE_UUID --endpoint https://project-sync.example --admin-token-entry PROJECT_SERVER_ADMIN_NAME
keys project-sync status --scope SCOPE_UUID
keys project-sync preview --scope SCOPE_UUID
keys project-sync backup --out /secure/path/master-after-init.kk3 --password-file /secure/path/recovery-password
```

The local Projects page can show profile state, public fingerprints, pending
outbox work, scope previews, and a **Sync now** button. Initialization there
accepts an existing token-entry name or ID; it never accepts the token value.
It does not replace the CLI enrollment ceremony.

## 4. Enroll a worker device

On the master, create a bounded invitation and transfer the invitation file only
to the user-selected worker through a channel appropriate for a short-lived
secret. Do not inspect or paste the bundle into an agent-visible tool.

```sh
keys project-sync invite --scope SCOPE_UUID --out /secure/path/invite.json --ttl 900
```

Verify the public master fingerprint through an independent channel. On a clean
worker root, the human then runs:

```sh
keys project-sync join --invite /secure/path/invite.json --fingerprint MASTER_FINGERPRINT --role contributor --out /secure/path/request.json
```

Transfer `request.json` to the master. The master verifies the worker's public
request fingerprint, approves it, and transfers the response bundle back:

```sh
keys project-sync approve --request /secure/path/request.json --fingerprint WORKER_REQUEST_FINGERPRINT --out /secure/path/response.json
keys project-sync finish --scope SCOPE_UUID --bundle /secure/path/response.json
keys project-sync sync --scope SCOPE_UUID
```

The worker can then use its configured replica profile. A contributor may create
an entry locally; it cannot edit, delete, replace secrets, change the catalog,
or use legacy full-vault writers:

```sh
printf '%s\n' "$NEW_VALUE" | keys add worker-created-key --stdin
keys project-sync sync
```

The value travels through the controlled stdin sink, not stdout. The master
receives and publishes accepted worker submissions during `project-sync sync`.

## 5. Operate and revoke deliberately

Use `keys project-sync status --scope SCOPE_UUID` to inspect public policy
version, active recipient roles, pending outbox state, and synchronization
state. `keys project-sync preview --scope SCOPE_UUID` is metadata-only: it
checks the exact projected entry set without returning secret payloads.

To remove a device, verify its device ID and scope with the human, then run this
only on the master after explicit authorization:

```sh
keys project-sync revoke --scope SCOPE_UUID --device DEVICE_UUID
keys project-sync sync --scope SCOPE_UUID
```

Revocation blocks future server access and triggers the durable rekey/publish
intent. It cannot erase snapshots, plaintext, or key material already held by
the removed device. Check status until the rekey no longer reports pending.

A foreground systemd worker can keep a configured scope synchronized without
interactive credential prompts:

```ini
[Unit]
Description=Keys Keeper project scope sync
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=keys
Environment=KEYS_KEEPER_HOME=/var/lib/keys-keeper
ExecStart=/usr/local/bin/keys project-sync watch --scope SCOPE_UUID --interval 60
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
```

Use a dedicated OS account with only the selected profile's local state and
backend access. Do not point a worker service at the master vault directory.

## Offline recovery and resume

Project operations use durable local state. After a network interruption, run
`keys project-sync status --scope SCOPE_UUID`, then retry `keys project-sync
sync --scope SCOPE_UUID`; do not delete state files or recreate a profile to
"unstick" it.

For loss of a device, preserve the encrypted recovery bundle and restore it to a
new empty root:

```sh
keys project-sync restore --file /secure/path/master-after-init.kk3 --password-file /secure/path/recovery-password --root /secure/path/recovery-root
```

If that restore is interrupted, repeat the same command against the same root
and authenticated bundle with `--resume`. It refuses any different or unrelated
partial root:

```sh
keys project-sync restore --file /secure/path/master-after-init.kk3 --password-file /secure/path/recovery-password --root /secure/path/recovery-root --resume
```

The restored root remains recovery-only until a deliberate master takeover.
After the human has verified the original backup and has a protected file
containing a fresh project-server administrator token, run takeover with the
restored root as its active local root:

```sh
KEYS_KEEPER_HOME=/secure/path/recovery-root keys project-sync recover-takeover \
  --file /secure/path/master-after-init.kk3 \
  --password-file /secure/path/recovery-password \
  --root /secure/path/recovery-root \
  --endpoint https://project-sync.example \
  --admin-token-file /secure/path/project-server-admin-token
```

`recover-takeover` is idempotent for that restored root and endpoint: it creates
fresh signed scope authority, verifies relay acknowledgements and local state,
then activates the recovery root with an explicit encrypted-file backend. It
does not restore trust to prior device grants; enroll required workers again
through the normal invitation ceremony. Do not manually copy registry, state,
journal, or relay files between roots.
