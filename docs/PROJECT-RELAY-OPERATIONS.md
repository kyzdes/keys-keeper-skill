# Project relay operations

Status: implemented safeguards with synthetic local tests. This runbook is not
production verification or an independent cryptographic audit. The relay stores
signed policies, ciphertext, recipient wraps, token hashes, revocations and
operation history. A relay backup preserves that data; the backup command does
not add another encryption layer. Public policy and routing metadata remain
visible. Store backups on an encrypted, access-controlled volume.

## Consistent backup

Use the installed `keys-keeper-syncd backup` command as the service account, with
read access to the source database and its SQLite WAL files. The destination
parent must already exist. On POSIX it must belong to the invoking user and
have no group/other permissions. On Windows it must have a protected DACL that
grants access only to the process-token user, SYSTEM and Administrators; its
owner must also be one of those principals. Access by privileged Windows system
accounts is part of the local OS trust boundary. An existing destination, including a symlink, is rejected. Parent
symlinks and Windows reparse points (including junctions) are rejected. Each backup has a new filename.

```sh
umask 077
mkdir -m 700 /secure/relay-backups
keys-keeper-syncd --database /var/lib/keys-keeper-syncd/syncd.sqlite3 backup /secure/relay-backups/syncd-20260905-01.sqlite3 --timeout 60
```

For Windows, prepare a **new** backup directory with a protected ACL in PowerShell
before running the command. The example grants no ordinary additional users; it
uses the actual Windows identity SID rather than trusting a username environment
variable. Substitute the source database path if the service uses another path.

```powershell
$relayBackupRoot = Join-Path $env:LOCALAPPDATA 'KeysKeeperRelayBackups'
New-Item -ItemType Directory -Path $relayBackupRoot -ErrorAction Stop | Out-Null
$relayBackupSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$relayBackupAcl = Get-Acl -LiteralPath $relayBackupRoot
$relayBackupAcl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$relayBackupSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", [System.Security.AccessControl.AccessControlSections]::Access)
Set-Acl -LiteralPath $relayBackupRoot -AclObject $relayBackupAcl
keys-keeper-syncd backup (Join-Path $relayBackupRoot 'syncd-20260905-01.sqlite3') --database 'C:\ProgramData\keys-keeper-syncd\syncd.sqlite3'
```

Use an ACL-capable filesystem supporting hard links, such as NTFS. Permission
inspection or hard-link failure aborts; there is no fallback to a public copy.
Windows flushes the completed file before publishing its exclusive hard link.
Python's portable API does not provide Windows directory fsync here, so crash
persistence of the new directory entry depends on Windows and the filesystem.
POSIX additionally fsyncs the parent directory. This distinction does not weaken
the no-overwrite check or permit a permission-validation failure to proceed.

The native validation follows Microsoft's [GetNamedSecurityInfoW contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-getnamedsecurityinfow),
[SetNamedSecurityInfoW contract](https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setnamedsecurityinfow),
[process-token identity API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation)
and [access-allowed ACE layout](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_ace).

`--database` can also follow `backup`. The existing serving command without a
subcommand is unchanged. Backup does not require the HTTP admin token and does
not instantiate or migrate the relay application.

The command opens the source read-only with WAL awareness and uses Python's
`sqlite3.Connection.backup` API. Committed WAL transactions are included;
uncommitted transactions are excluded. It checks the temporary copy with SQLite
`quick_check`, converts it to a self-contained main database, fsyncs it and
publishes it through an atomic no-overwrite hard link. The completed file is mode
0600 on POSIX; on Windows its protected DACL has the same restricted principals
as above. An existing parent DACL is validated and never silently rewritten. Temporary database and sidecars are confined to a private directory and
removed on handled failure. A process kill can leave a private `.relay-backup-*`
directory; inventory it before manual cleanup. Do not copy the live main database
with `cp`, omit its WAL, or independently copy changing main/WAL/SHM files.

The default SQLite processing timeout is 60 seconds; `--timeout` accepts 1–3600.
Busy or continually changing databases can cause an unsuccessful backup, which
must be retried to a fresh destination. A blocked filesystem operation is subject
to OS/storage timeouts. A failure after publishing but during directory fsync can
leave a complete destination while reporting failure; inspect that file before
retrying, and never overwrite it blindly. Reserve enough free space for a full
copy before starting. Backup success alone is not a restore test.

## Isolated restore smoke

Keep production serving its existing database. Restore a selected backup to a
new private directory using the same backup API; this verifies the archive and
prevents overwriting an existing restore target.

```sh
umask 077
mkdir -m 700 /secure/relay-restore-smoke
keys-keeper-syncd backup /secure/relay-restore-smoke/restored.sqlite3 --database /secure/relay-backups/syncd-20260905-01.sqlite3
python3 - /secure/relay-restore-smoke/restored.sqlite3 <<'PY'
import sqlite3
import sys
from pathlib import Path
source = Path(sys.argv[1]).resolve().as_uri() + '?mode=ro'
with sqlite3.connect(source, uri=True) as connection:
    if connection.execute('PRAGMA integrity_check').fetchall() != [('ok',)]:
        raise SystemExit('restore integrity failed')
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if not {'kk3_scopes', 'kk3_policies', 'kk3_snapshots', 'kk3_blocks', 'kk3_operations'} <= tables:
        raise SystemExit('project relay schema missing')
print('restore integrity and schema: ok')
PY
```

For a KK3-enabled archive, start the restored copy on a separate loopback port,
using an independently supplied smoke admin token in the environment. Do not
paste an existing admin token into shell history or reuse the production service
port. In one terminal, with that environment already configured:

```sh
keys-keeper-syncd --database /secure/relay-restore-smoke/restored.sqlite3 --host 127.0.0.1 --port 18787
```

In another terminal:

```sh
curl --fail --silent http://127.0.0.1:18787/healthz
```

Stop the smoke server with Ctrl-C. Health and SQLite integrity only establish that
the restored application opens and serves. For a full synthetic restore drill,
use synthetic project identities to verify signed policy/snapshot continuity,
recipient key unwrap, revocation denial and an idempotent operation retry against
the restored copy. The focused tests provide the WAL/restore portion:

```sh
.venv/bin/python -m pytest -q tests/test_sync_server_cli.py
```

A relay archive contains no master signing private key, inbox private key or
recipient private key. Those require their own tested local recovery procedure.
Restoring an older relay can lose newer records or revocations; clients retaining
newer trusted checkpoints must reject rollback. Do not erase client checkpoints,
local revoke records or grant history to make an old restore appear current.
Production promotion requires an explicitly selected recovery point and a separate
coordinated cutover. This smoke procedure performs no promotion.

## Capacity, control reserve and history

Current `ProjectRelayLimits` defaults are finite logical stored-record budgets:

| Budget | Per scope | Entire relay |
| --- | ---: | ---: |
| Regular records and ciphertext bytes | 512 MiB | 2 GiB |
| Regular record count | 20,000 | 100,000 |
| Additional control reserve bytes | 32 MiB | 128 MiB |
| Additional control reserve records | 2,000 | 10,000 |

Accounting covers scopes, policy/snapshot history, current wraps, durable grant
history, revocations, operation IDs, submissions and receipts. It includes UTF-8
stored values and a fixed per-record allowance. Ordinary writes cannot consume
the control reserve. Revocation records, receipts and publications removing
recipients may use it. The reserve is finite: alert before either normal capacity
or reserve approaches exhaustion. Exhaustion returns `storage_full` and rolls
back the attempted transaction; it does not evict history or erase revocations.
There is no automatic safe history compaction or retention deletion.

Pending creates also have independent bounds: 100 per device, 1,000 and 64 MiB
per scope, with 30 creates per minute per device. Queue reads are bounded by count
and bytes. Defaults allow four simultaneous project handlers, 32 accepted
connections and a 10-second socket inactivity timeout. Request types have separate
body limits. A reverse proxy must provide an absolute request deadline and rate
limits; an inactivity timeout alone does not stop a client sending bytes slowly.

Clients limit each policy or snapshot chain walk to 256 steps, with a combined
64 MiB budget for authenticated records.
A replica beyond that budget stops with checkpoint-refresh-required rather than
silently accepting a relay-provided new trust anchor. Plan a trusted enrollment
or recovery checkpoint refresh for long-offline replicas. Separately, clients
limit snapshot publication to 65,536 per epoch, and the master rotates the scope
key before the next publication. Relay quotas do not substitute for that
cryptographic nonce budget.

Logical quotas are not SQLite physical disk limits. SQLite pages, indexes, WAL,
SHM, filesystem allocation, temporary operations and backups add overhead; an
open reader can retain WAL while writes continue. Place relay data on a dedicated
volume/mount with a separately enforced disk quota, monitor main/WAL sizes and
free space, and put backups on separately budgeted encrypted storage. Apply OS
memory/CPU limits and reverse-proxy limits independently. Do not delete live WAL
or SHM files to recover space. Document capacity increases and backup retention
before applying them; preserve durable grants, blocks, receipts and idempotency
history until a reviewed compaction/recovery protocol exists.
