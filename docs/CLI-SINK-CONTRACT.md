# CLI credential and file contracts

This contract describes the hardened CLI paths. It deliberately supports a
small, explicit set of credential sinks rather than guessing configuration
formats or silently producing partial backups. No new storage format or
dependency is introduced.

## Complete legacy backups

`keys export FILE` uses the complete `vault_snapshot` builder shared with KK2
full-vault sync. This is a schema 1/2 compatibility path; schema 3 continues to
use project recovery and cannot be flattened by legacy export.

- Account presence is checked once before credential reads. Required primary
  secrets must exist. An absent optional passphrase is valid; any failed read
  of a present account aborts preparation.
- Missing, denied and unavailable provider results are distinct. Unclassified
  errors are failures, never evidence that an account is absent. Linux
  `secret-tool lookup` has ambiguous failure statuses, so optional presence is
  established through account metadata rather than its exit code.
- A pending master mutation blocks snapshot projection until recovery. Export
  and sync share this guard and the snapshot serializer.
- Existing backup files require `keys export FILE --replace`. Publication is
  atomic, owner-private and checked by a bounded ciphertext read-back. The
  explicit replacement also checks the previously observed file state.
- Import/export reject final symlinks and non-regular files. Binary inputs and
  outputs are limited to 64 MiB; oversized imports fail before prompting or
  deriving an encryption key. Export does not change the permissions of the
  user-selected parent directory.
- Import accepts owner-held public ciphertext files, but rejects incomplete
  required secrets and duplicate JSON members before any vault mutation.
  Merge import skips existing names; `--replace` remains explicit.

These checks prevent a successful-looking backup from concealing a denied
credential read. They do not turn full-vault compatibility sync into a scoped
sharing protocol.

Project recovery bundles always require a new destination; an existing or
concurrently created file is preserved. They also capture the authority key
needed to authenticate the shared durable mutation journal, including a
standalone schema 2 vault. A restored bundle stays recovery-only until the
separate trusted-history activation checks complete.

## Literal dotenv injection

`keys inject NAME --file FILE --as ENV_NAME [--replace]` supports a portable
single-line literal subset:

- `ENV_NAME` must match `[A-Za-z_][A-Za-z0-9_]*`. It is checked before vault or
  credential access.
- Duplicate active assignments, including whitespace and `export NAME =`
  variants, are rejected before reading a credential. `--replace` permits one
  existing single-line assignment; it does not normalize an ambiguous file.
- Simple values matching `[A-Za-z0-9_./:@%+,-]*` are written bare. Other
  supported literals are enclosed in single quotes.
- Line separators, control characters, apostrophes, backslashes and all `$`
  syntax are rejected. Escaping and interpolation vary between dotenv
  consumers; the CLI does not silently transform such a credential. Empty
  strings remain valid values.

For credentials outside this subset, choose an explicit raw-value file or a
producer for the application's actual configuration format. Do not assume
that dotenv, JSON, YAML and shell escaping have the same rules.

## Template resolution

`keys resolve FILE` preflights all placeholders against one metadata listing
before reading any secret. Unknown entries, unknown fields and invalid
placeholder syntax fail without reading a credential. Each unique primary
secret is read once during that invocation. The first failed provider read
ends the operation; later credentials are not attempted and the target stays
unchanged.

Resolution performs raw substitution, not format encoding. Use it only when
the replacement is valid for the intended sink; a template does not make
arbitrary secrets safe to embed inside JSON strings or shell commands.

Plaintext input/output is bounded to 8 MiB. The shared private-file primitive
opens without following the final link, rejects FIFOs without blocking and
checks bytes/timestamps as well as inode identity before replacement. A newly
appearing target is never overwritten. These are optimistic conflict checks:
an uncooperative writer can still race after the final check, so operations
requiring exclusion must arrange a shared lock.

## Input and operation outcomes

`keys add` validates metadata before reading the selected source. File input
uses bounded no-follow UTF-8/BOM handling; stdin is bounded to 1,048,576 input
characters. Add and edit share port/boolean coercion. Native storage values
must be strings, including legitimate empty strings.

Audit persistence is observational. A committed write stays successful if its
audit event cannot be persisted, and stderr receives a value-free JSON receipt
such as `{"operation":"inject","committed":true,"audit_status":"unavailable"}`.
Resolve events include stable affected entry IDs; `keys audit --name NAME`
uses the current stable ID so batch use and renamed history remain searchable.
Default audit display is newest first; `--tail` displays the last N events in
chronological order.

The same outcome helper covers Keychain policy/ACL changes, catalog changes,
VPS sync, project recovery and personal-sync adapters. Typed errors carrying a
confirmed publication retain `committed:true`; arbitrary provider diagnostics
are never copied into their failure receipts. A successful remote revocation
also keeps that outcome if refreshing the local trust anchor subsequently fails.

If directory durability or read-back cannot be confirmed after backup
publication, the command reports `committed:true` and tells the caller to
inspect the existing backup before retrying. A failure to schedule clipboard
clearing likewise reports that the clipboard was already written. Unexpected
mutation failures use `committed:null` because forward recovery may be needed;
they do not promise rollback or recommend blind automatic retries. Provider
exception text and credential values are excluded from ordinary receipts.

`keys doctor` inspects the metadata-only pending index and enumerates account
presence once. It does not read entry secrets or run recovery. Public notes
do not require a secret account, and reserved runtime/sync accounts are not
reported as orphan entries. Diagnostics use fixed provider-error messages.

`keys doctor --recover` explicitly runs the common durable mutation recovery
for the master profile. It may read and write secrets, and is refused for a
projected or replica profile before accessing its backend. Its value-free JSON
receipt reports status, recovered count, commit outcome and audit status. A
failed recovery can have an unconfirmed outcome; inspect pending state before
retrying. This option does not activate a recovery-only profile.

The synthetic regressions are in `tests/test_cli_secret_contracts.py` and
`tests/test_backend_read_contracts.py`. Recovery diagnostics and durable backup
round trips are covered by `tests/test_cli_doctor_contracts.py` and
`tests/test_project_backup.py`. They use fake providers or an explicitly
isolated encrypted-file backend; they never access the user's vault or
clipboard.
