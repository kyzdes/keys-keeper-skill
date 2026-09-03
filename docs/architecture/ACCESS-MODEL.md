# Keys Keeper access architecture

Status: implementation plan with the first compatibility-mode slice present in
the current worktree. It is not a release claim.

## Product invariants

1. The original OS credential record is the source of truth. Bypass does not
   export, copy, migrate, or replace it with an encrypted backup.
2. A background operation never opens credential UI. It either completes
   silently or returns one bounded error.
3. A caller receives a capability for the requested operation, not a generic
   plaintext reveal primitive.
4. Metadata, secret storage, sync state, and UI share one application service
   for mutations.
5. Security labels distinguish `implemented`, `tested`, `proposed`, and
   `unresolved`.

## Access contexts

| Context | Intended callers | Keychain UI | Legacy bridge | Failure behavior |
|---|---|---:|---:|---|
| `INTERACTIVE` + prompt | explicit CLI action | allowed | no | macOS may ask once |
| `INTERACTIVE` + bypass | explicit CLI action | forbidden | ACL-gated | fail closed without a dialog |
| `UI_FORBIDDEN` | admin API, WebVault adapter, sync automation | forbidden | forbidden | fail closed without a dialog |
| `ACL_PREPARATION` | explicit `prepare NAME` setup | allowed for one item | forbidden | one ACL commit or fail closed |

The current implementation enforces this distinction in-process through
Security.framework. It preserves the original Keychain item and updates an
existing item in place, retaining its identity and ACL.

For a legacy item that does not trust the native runtime,
`keys keychain prepare NAME` adds the OS-derived current executable identity to
that one original item's decrypt ACL without reading or copying its value.
There is no bulk mode. Partitioned ACLs are refused rather than weakened.

## Client policy

The target policy is:

| Client class | Desired default |
|---|---|
| signed Codex and Claude clients | silent access to explicitly granted Keys Keeper capabilities |
| OpenCode and registered third-party clients | one approval per process lifetime |
| unknown or unsigned client | deny or one explicit registration flow |
| background/server caller | never display UI |

This policy is **proposed, not implemented**. A same-user Python process cannot
reliably prove that a request originated from Codex or Claude. Environment
variables, executable names, parent PIDs, and user-supplied client labels are
spoofable and must not become authorization evidence.

## Broker boundary for 0.9+

The broker is the only component allowed to open the vault. It authenticates a
code-signed peer, maps that peer to a stored policy, and issues scoped,
short-lived, replay-resistant capabilities. Supported operations are concrete:

- copy to a user-visible clipboard;
- inject into one pre-authorized path;
- sign or open one SSH destination;
- sign or execute one allowlisted HTTP request;
- return metadata and audit receipts.

There is no arbitrary `exec` with a secret environment and no generic agent
reveal. A one-time setup flow may normalize ACLs or register a signed client,
but it must enumerate the exact affected records and verify the result without
printing a value.

## Mutation consistency

The current application service serializes metadata changes, snapshots only
the affected backend accounts, and compensates completed backend writes when a
later step fails. This closes ordinary partial-failure gaps across CLI and the
local API.

It is **not crash-atomic**. The 0.8 transaction target remains versioned
physical secret generations plus a durable journal:

1. write a new secret generation;
2. verify it without exposing plaintext;
3. journal the intended metadata switch;
4. atomically switch metadata;
5. recover or roll back on startup;
6. garbage-collect the old generation after a safety window.

## Release gates

| Gate | Required evidence |
|---|---|
| compatibility bypass | original-item test, no-UI failure test, one-shot diagnostic |
| shared mutation service | fault injection around every backend and metadata step |
| 0.8 | no open Critical/High compatibility findings; real macOS/Windows/Linux CI |
| 0.9 broker preview | signed-peer identity tests and sandbox escape suite |
| 1.0 isolated mode | independent review, red-team sign-off, migration and rollback proof |
