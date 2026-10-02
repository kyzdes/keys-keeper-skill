# Independent review corrections for 0.12.0

The [independent review](INDEPENDENT-REVIEW-2026-10-02.md) describes the
`96671fd` baseline. The corrections below retain KK1 backup, local admin,
KK2, KK3 and existing entry types. S3 remains removed. They introduce no
runtime dependency, vault migration or new wire format.

## Boundaries and regression evidence

| Finding | Correction | Reproducible regression |
|---|---|---|
| R1: acknowledged revoke was not durable evidence | Persist the exact signed intent before POST. An ACK is unconfirmed; only matching fresh signed evidence promotes pending to permanent trust. | `test_vps_revocation_state.py`: false ACK, lost response, conflicting evidence, preparation/confirmation fsync failure, true process exit before POST and after ACK, restart and resume |
| R2: races and empty HEAD could erase revocations | One bounded reentrant lock per vault serializes all KK2 proof operations across threads, engines and processes. Trust records can omit the complete commit anchor. Fresh revocation evidence survives public status/checkpoint inspection. | Same suite: empty HEAD, stale same/newer HEAD writer, parallel status, independent process timeout, fork ownership, no-op file/timestamp invariance |
| R3: same-second rotation could be overwritten | Snapshot apply requires the prepared presence/value of every written or deleted account. The existing journal compares its recovery preimages before journal begin. A mismatch causes a fresh local read and merge. | `test_mutation_preconditions.py`; `test_snapshot_concurrency.py::test_same_second_api_rotation_survives_stale_sync_apply` invokes the actual API handler with a fixed clock |
| R4: name reuse redirected existing references | Compare each unchanged surviving reference against both histories. Reject bound-to-missing, changed target ID and missing-to-bound before local apply or publication. | `test_snapshot_concurrency.py`: deletion/sync/name reuse/sync, both metadata winners, dangling references and explicit remove/sync/relink |
| R5: full import retained an obsolete optional secret | `SecretInput` defaults to patch; explicit replace removes absent accounts. Empty string remains a value. Secret, passphrase deletion and metadata share existing recovery. | Replacement matrix for schemas 2/3, backend failure and real process-exit recovery in `test_mutation_preconditions.py`, `test_master_journal.py`, plus actual CLI import in `test_snapshot_concurrency.py` |
| R6: installation/status effects were misleading | Installation checks use `--version`. Canonical instructions describe configured personal status unlock reads and conditional KK2 trust writes. All shipped variants are generated from that source. | `test_command_effects.py`, canonical/golden checks and installed-wheel skill generation |
| R7: successful publication appeared as failed audit mutation | Shared normalization emits published/failed/unconfirmed while retaining committed and audit_status. Unknown outcomes do not imply success; audit/confirmation errors do not retry a mutation. Old audit records remain readable. | `test_api_contracts.py`, `test_audit.py`, `test_cli_adapter_outcomes.py`, `test_cli_secret_contracts.py` and real CLI/audit revoke cases |

A retry after HEAD movement changes only the transport CAS precondition.
The original signed cutoff must be in the complete verified chain, and the
target must not have authored a later commit. Otherwise pending remains and
the operation requires recovery. Network operations hold the VPS lock, never
the journal or metadata lock. The lock order is VPS, journal, metadata.

Schema preflight uses the typed schema of the same atomic metadata snapshot
as the payload and revision. It does not parse exception text or race a
separate schema read against catalog migration.

## Independent correction pass

The mutation author reviewed trust/revocation changes; the contract author
reviewed mutation/reference/replacement changes; the trust author reviewed
outcome handling. The integrating reviewer also reviewed shared boundaries.
This pass found and reproduced three additional issues: proof-only entrypoints
forgot new revocations, false ACKs were prematurely classified as published,
and a pre-POST failure differed between CLI and audit. Regression tests now
cover their corrected behavior. A further effects-table correction records
the newly required conditional trust write by KK2 status.

## Release validation

The release gates are the complete local pytest suite, the existing OS/Python
CI matrix and coverage floors, native credential/file integrations, generated
instructions, the installed wheel, native app, Docker and updater checks.
Manual CI runs on a release tag additionally install the Windows package from
that published tag URL. Docker smoke tests enforce 1 CPU, 768 MiB and 64 PIDs.

The release verification manifest records the final source and wheel hashes
and exact CI runs. Platform-specific skips are reported by each job; a passing
platform is not evidence for a skipped native integration on another OS.
Credential access on an operator's computer is not established by synthetic
tests or a version number.

Production rollout requires WAL-aware backups, integrity checks and restored
copies, quota backfill on those copies, and successful startup of each previous
image against the migrated copy. Resource evidence separates process RSS,
cgroup memory, CPU, latency and rejected requests. Limiting concurrency is
not a throughput improvement. Private configurations, credentials and server
inventory are excluded from this repository.

## Linux staging measurement

The installed image built from `cf4586a` matched all 97 package files in the
verified wheel. A separate server container used 1 CPU, 768 MiB, 64 PIDs,
read-only rootfs, non-root user, dropped capabilities and no-new-privileges.
Clients ran in a different cgroup against a new synthetic loopback database.

| Measurement | Observed result |
|---|---|
| Four maximum 16 MiB plaintext KK2 commits against one parent | 1 accepted (201), 1 CAS conflict (409), 2 capacity rejections (429) |
| Server process peak RSS | 317.62 MiB |
| Server cgroup peak memory, including charged page cache | 319.84 MiB of 768 MiB; 58.35% headroom |
| Server CPU / measured load interval | 1.895 CPU seconds / 3.340 wall seconds |
| Accepted / CAS-conflict latency | 3.330 / 2.802 seconds |
| Capacity-rejection latency | 3.13–4.58 milliseconds |
| Active operations / OOM / restarts | 2 / 0 / 0 |
| Full verification of 205 signed commits | 6 HTTP requests, 3 pages, 1 ciphertext |
| Three idle push cycles | 0 changed files, 0 reported changes |
| Quota checks with 1 and 500 records | 2 SELECTs and 32 SQLite VM instructions in both cases |

Request timings include a 150 ms staged-upload barrier to exercise overlapping
large bodies. They are not production TLS latency or successful throughput.
This validates the specified KK2 load and limits, not every possible traffic
mix. The release manifest identifies the final image qualification separately.
