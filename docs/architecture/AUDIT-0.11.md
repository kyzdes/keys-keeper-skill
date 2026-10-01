# Architecture and performance audit — 0.11.0

Date: 2026-10-02. This is an internal source, test and resource-contract audit.
It is not an independent security certification or a physical battery-life
test. Release checks name their tested commit and complete OS/Python matrix.

## Scope and architecture

The starting inventory contains 287 tracked files and 79 Python modules,
native Swift, local Admin/WebVault assets, platform installers, plugin hooks
and generated agent instructions. The audit maps the complete package/test
inventory; deeper adversarial review targets the following authority and
resource boundaries. Inventory does not imply every input was executed.

| Surface | Review and executable evidence |
|---|---|
| Composition, paths, profiles, OS/file backends | Explicit role/selector checks before master access; current-ciphertext authentication; isolated CI stores; stale, replaced and deleted file tests. |
| Catalog, references, importers, sinks | Model validation, linked-entry consent, deep graph traversal, atomic metadata commits, encrypted mutation recovery and clipboard/SSH sink contracts. |
| KK1/KK2/KK3, pairing, project/personal sync | Independent real-crypto interoperability; signed-chain, rollback, membership, lost-response, restart, revocation, outbox and scoped-projection contracts. |
| Admin/WebVault/relay HTTP | Authentication before expensive request work; admission/input/body bounds, strict framing, tenant/session limits and safe public errors. |
| Native app, JS lifecycle, audit displays | Existing Node lifecycle harnesses, executable Swift framing/admission harness, native build, bounded audit readers and incremental summaries. |
| Automatic work, installers, hooks, generated payload | Durable rolling-day claims, process-tree deadlines, platform cancellation, opt-in fallback updates, artifact/version parity and installation smoke tests. |

CLI and authenticated UI requests resolve a profile/access context before
reaching master or replica services. Master services use metadata, the OS/file
secret backend and encrypted mutation recovery; replicas use authenticated
current generations. Daily supervised work invokes the same project/personal
sync services through their explicit scope. The relay has separate authority,
wire and storage bounds. A small shared HTTP resource layer is added; this
release does not rewrite the CLI or change the vault model. The canonical
catalog updater helper remains unchanged.

## Findings corrected

1. Historical recovery repeatedly created managers and derived keys for every
   terminal record. Retained managers now reuse one authenticated terminal
   directory digest only after secure fresh ciphertext reads, canonical names
   and consistent before/after snapshots. Pending/changed/corrupt history is
   reauthenticated.
2. Replica access repeatedly constructed stores and derived the current
   generation key. Runtime retention is bounded to 32 stores; each retains one
   salt/key and authenticates fresh bytes. The personal child runtime remains
   within its existing profile/access boundary.
3. The file backend kept an indefinitely stale plaintext map and rewrote
   identical values. It now retains no plaintext map, reauthenticates fresh
   ciphertext, invalidates keys on errors/profile changes, and skips no-op
   encryption and payload writes.
4. Authenticated state from another profile could be accepted when passwords
   and state record IDs matched. Runtime load/save now validate expected
   scope, vault and master/replica mode.
5. Folder validation revisited every ancestor; references used recursive path
   copies. Both are iterative and linear, including deep chains and back edges.
6. Hostile audit lines, gzip input and whole-log API reads could consume
   unbounded memory/CPU. Lines and total work are capped. Summaries explicitly
   retain incomplete results; searches report exhaustion. Nonblocking
   descriptor opens reject regular-file-to-FIFO/symlink/directory replacement.
7. Successful workers could leave descendants; cancellation could occur during
   spawn. Both normal and exceptional exits reap owned groups. Signal deferral
   covers spawn/reap; Windows binds a kill-on-close Job Object before children.
8. Thread-per-connection services and sliding socket timeouts did not bound
   slow input. Admission precedes thread creation; each request has an absolute
   input deadline. Local shutdown closes owned sockets and cannot deadlock when
   serving has not started.
9. WebVault registry/session/rate maps lacked complete corruption/capacity
   handling. Damaged registries fail closed; deleted sessions cannot inherit
   the operator prefix; expiry/caps reclaim abandoned sessions and throttle
   admission cannot reset active buckets.
10. Metadata, configuration, pointers, generations and legacy S3 anti-rollback
    state had inconsistent read/write limits. Bounds apply before crypto or
    payload writes; malformed existing state is not treated as empty, and
    failed atomic persistence remains a failure.
11. Native stdio and main-thread callbacks could queue indefinitely. Commands,
    reply lines and undelivered replies are capped. Protocol failure uses normal
    TERM/KILL escalation. UI clipboard copies share one sleeping worker; native
    clipboard/Secret Service helpers have deadlines and fixed errors.
12. Personal API construction escaped safe error handling and duplicate JSON
    keys were accepted. Construction is contained, exact schemas reject
    duplicates, and unknown routes fail before manager work.

## Resource contracts

| Boundary | Limit and behavior |
|---|---|
| Automatic sync | One attempt per rolling 86,400 seconds per explicit scope/personal/legacy claim, including failures/restarts; manual Sync immediate. Supervised wall deadline 300 seconds plus bounded cleanup. |
| Daily claim lock | One-second acquisition budget. Transactional storage locks retain blocking semantics to preserve commits. |
| Audit display | 1-MiB logical line, 64-MiB scan, 10,000 Python / 2,000 Admin results. Newest/tail stops when enough rows match. |
| Activity summary | 1-MiB line; shared 64-MiB compressed, decompressed and prefix-verification work. Stable incomplete data is not rescanned. |
| Encrypted file | 64-MiB ciphertext read/write; one current process-local key, no retained plaintext map. |
| Cold journal recovery | 10,000 records / 512 MiB aggregate plus per-record/index limits. Warm terminal checks hash fresh bytes without KDF/writes. |
| HTTP | Admin/WebVault default 16 handlers; finite input/socket budgets and route-specific bodies. Existing relay admission/storage quotas remain enforced. |
| Native IPC | 4,096 command characters; 64-KiB reply line; four pending deliveries; two/four-second TERM/KILL escalation. |
| Keys fallback updater | Opt-in, one attempt per rolling day, bounded commands/private file preflight. Native host update policy is separate. |

These are defensive ceilings. Six scopes can still perform six useful daily
attempts. If every attempt hits the wall deadline, serialized work can occupy
approximately 30 minutes plus cleanup; requested work is not zero-energy.
An HTTP input deadline does not force-interrupt an authenticated application
operation, which retains its own transactional/network limits.

## Measured evidence and test quality

The initial [five-job CI run](https://github.com/kyzdes/keys-keeper-skill/actions/runs/36937886409)
at checkout **12345c509f6b4db364c9aabf3f44a3e2c68eec7c** measured **84.14% lines**
(13,569/16,126) and **69.79% branches** (3,632/5,204), including all 79 Python
modules. Each job had only the unfinished changelog-marker failure; this is
a measured baseline, not a passing release. Final same-commit checks supersede it.

Floors are 84% lines / 69% branches across the complete five-job matrix.
Missing/mixed jobs, omitted modules or missing denominators cannot pass.
JUnit, phase timings, HTML/JSON/XML coverage and test inventory are downloadable.
See [coverage and quality](../TEST-QUALITY-AND-COVERAGE.md) for specific gaps.

Short temporary-data benchmarks used real PBKDF2:

- Four terminal records, three recreated runtimes: 12 KDF / 1.933186 process
  CPU seconds. Retained cold once: four KDF / 0.645746 seconds. Twenty warm
  checks: **zero KDF, zero writes**, 80 fresh reads / 0.006757 seconds.
- A 1,000-row log: twenty unchanged summaries did **zero full parses and zero
  row decodes**, 0.001144 process CPU seconds. Ten appended rows decoded only
  those ten, 0.000662 seconds.

These measure small algorithmic workloads, not battery hours. Regression
assertions use operation counts/resource bounds instead of fragile wall-time
comparisons. The one exact duplicate-body candidate has distinct macOS and
Windows backend fixtures; both stay. Crypto, generated-source and security
contracts stay because execution coverage alone cannot prove their guarantees.

## Remaining limits

- Cold/changed history still derives once per distinct salt; warm history still
  hashes all bytes. File/replica reads decrypt the whole bounded payload.
  Durable trust/deduplication history is not deleted for a benchmark.
- Native OS calls/provider daemons remain OS controlled. Helper deadlines do
  not interrupt arbitrary native framework calls or cap every provider's
  output. Interactive user SSH intentionally has no automatic-work deadline.
- POSIX groups cover ordinary owned descendants; a hostile executable escaping
  its session or an uncatchable kill of the guardian itself is an OS boundary.
  Windows nested-job failure aborts before starting work.
- Clock changes, suspension and scheduling are not a hardware elapsed-time
  proof or a physical battery measurement.
- Python coverage excludes JS/CSS/HTML/Swift. Separate Node/Swift harnesses and
  native builds do not establish browser/OS coverage percentages.
- State binding adds scope/vault/mode, without tightening device/endpoint
  lifecycle semantics. Live relay, TLS/S3 deployment and a full battery
  discharge were not tested.

The supported model is quiet idle operation and bounded useful daily/manual
work. No absolute promise about every possible input or battery life is made.

## Primary references

- [Python socketserver lifecycle](https://docs.python.org/3/library/socketserver.html):
  threaded shutdown semantics informed the lifecycle tests.
- [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects):
  child inheritance/kill-on-close informed the Windows supervisor.
- [Coverage.py branch measurement](https://coverage.readthedocs.io/en/latest/branch.html):
  executed edges are distinguished from assertion quality/interoperability.
