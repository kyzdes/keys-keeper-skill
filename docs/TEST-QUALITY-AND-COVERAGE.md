# Test quality and performance evidence

Audit baseline: source commit `61a081e8466559f544a0f641b1131d0e60f362fa`
(0.10.1). This document distinguishes static inventory, executable regression
contracts, measured CI coverage, and installed application measurements.

## Release matrix and subsequent test correction

The final 0.11.0 release PR [passed all ten checks](https://github.com/kyzdes/keys-keeper-skill/pull/17).
Its five-job matrix measured 14,582/17,140 lines (85.08%) and 3,946/5,518
branches (71.51%) across all 81 Python modules, with zero omitted modules.
The inventory contained 108 test files, 1,095 definitions and 1,450 collected
cases. The release receipt records the tested revision, matrix outcomes and
wheel checksum; these counts precede the additional deterministic case below.

A repeat on merged main exposed a random-order assumption in a journal rename
test. It required another KDF even when the first changed record used the
currently cached salt/key. The implementation still freshly authenticated
ciphertext and rejected the authenticated record/filename identity mismatch.
The corrected contract counts GCM authentication and rejection rather than
requiring unnecessary key derivation. An explicit cached-key-first regression
requires zero KDF, one fresh GCM, `JournalError` and an invalidated terminal
manifest. No runtime code, encryption format or KDF parameter changes for this
correction; the published tag and wheel remain immutable.

## Baseline inventory

Read-only AST inspection found 79 Python source modules, 92 test files and 937
test function definitions. Pytest collection on Python 3.14 found 1,129 cases in
1.37 seconds; parametrization and unittest explain the different counts. These
are baseline counts, not a coverage percentage or proof that every case passes.
The new instrumentation and KK1 contracts add cases after that snapshot.

`scripts/test-quality-inventory.py` reads all test/source ASTs without importing
them. It reports direct test imports, source-reading/membership assertions,
subprocess-language indicators, crypto call sites, and identical normalized
bodies. Its JSON labels those as review indicators, not execution coverage.

Fifteen modules had no direct test import, including dispatchers, page rendering,
pairing server, entry points and canonical prose. Several are deliberately
exercised transitively through CLI/HTTP/render tests. Use the measured missing
lines and branches before calling any of them untested. A useful first review is
the pairing-server failure/lifecycle surface and `webvault.cli`, which have no
dedicated module test file.

One identical-body candidate exists: the macOS and Windows short-value backend
round trips. They exercise different real OS stores through different fixtures;
both are valuable and remain. No test was deleted based on text similarity.

## Measured first matrix baseline and gate

The first complete measurement is CI revision
`12345c509f6b4db364c9aabf3f44a3e2c68eec7c`, retrieved as
`python-coverage-full-matrix` into
`/tmp/keys-keeper-0-11-baseline-coverage`. All five jobs produced coverage and
phase-duration artifacts for the same revision: 79/79 Python source modules,
zero omitted modules, 13,569/16,126 executed lines (84.14%) and 3,632/5,204
executed branches (69.79%). Every job's pytest exit status was 1 because the
release-contract test required a missing 0.11.0 changelog marker. The measurement
is complete; the baseline suite did not pass. Later fixes and new tests require
their own final matrix report.

The combined CI report now requires at least **84% lines and 69% branches**,
using unrounded counts. This is a measured regression floor with room for the
first audit's new error branches, not a claim of full behavioral coverage. The
report keeps `coverage_status` separate from `coverage_gate`: complete data can
fail a threshold, and partial or missing evidence cannot pass one. Missing
matrix jobs, mixed revisions and omitted source modules still fail independently.
Required matrix test jobs must also pass; a coverage gate cannot waive failures.

| Baseline module | Executed lines | Executed branches | Review priority and evidence boundary |
|---|---:|---:|---|
| `api.py` | 298/528 | 61/130 | Request input/error and entry/audit boundaries have substantial missing execution; new API failure contracts should accompany changed handlers |
| `api_personal_sync.py` | 22/52 | 6/30 | Settings adapter dispatch and failed personal-sync outcomes need behavioral HTTP coverage; backend integration alone does not exercise all UI-facing branches |
| `clipboard.py` | 93/151 | 17/42 | Platform call failures and native Windows handle/ownership branches need their specific job; avoid treating matrix union as complete Windows clipboard validation |
| `cli.py` | 694/903 | 156/252 | Dispatch, rejected arguments and backend failure handling dominate missing branches; test outputs and side effects rather than source tokens |
| `sync_vps.py` | 446/565 | 150/242 | Remote/container configuration and failure branches need isolated subprocess results; no live server rollout is implied |
| `project_runtime.py` | 681/775 | 182/258 | Profile identity, concurrent retained state, ciphertext/resource failures and trust paths are performance/security priorities; new retained-runtime contracts complement the baseline |
| `pairing_server.py` | 80/93 | 29/42 | Already exercised transitively despite no direct import; remaining authorization, packet/storage budgets and mailbox lifecycle negatives deserve explicit cases when changed |
| `crypto.py` | 38/38 | 2/2 | Already 100% executed, but the independent KK1 format/vector and tamper tests still add assertion quality and interoperability evidence |

The baseline AST artifact contains 94 test files and 944 definitions after the
first new instrumentation/crypto tests. Its only identical normalized-body group
is `tests/test_backend.py::test_set_and_get_round_trip` and
`tests/test_backend_windows.py::test_roundtrip_short_value`. Different macOS and
Windows backend fixtures make both useful; no deletion is justified. No source
or security contract was removed to raise the percentage. A stricter per-module
floor can follow the final matrix and an explicit contract review; imposing one
now on these newly expanded resource/error paths would be an unmeasured guess.

## Behavioral and source contracts

| Surface | Existing evidence | Gap or next contract |
|---|---|---|
| KK1 exports and encrypted state | Real password round trip, wrong-password rejection, malformed header before KDF; journal ciphertext tamper/cache/profile isolation | Independent 600,000-round PBKDF2-HMAC-SHA256/AES-GCM decode and encode, salt/nonce freshness, modified salt/nonce/body/tag rejection are now covered in `test_crypto_contract.py` |
| KK3 project wire protocol | Independent RFC 5869 vector, signature/context-confusion failures, independent snapshot/wrap decoder, real HTTP+SQLite exchanges | Preserve independent vectors and trust/revocation negative cases through refactors; add behavior tests for any changed branch |
| Journal/state caching | Repeated reads derive once and re-read/authenticate ciphertext; external rewrite, wrong password/profile, restart and durable trust changes | Keep operation/KDF/write-count assertions; line coverage cannot prove an idle loop performs zero costly work |
| Activity statistics | Zero repeated reads/parses after warmup, suffix parsing, rewritten prefix detection, partial tails, rotation, day/timezone, errors, new profiles, 129-file overflow | Full old-prefix hashing on a real append is O(existing bytes); zero parses is not a claim of O(append bytes) IO |
| Settings/personal sync | Real local HTTP isolation, concurrent retained runtime reads, changed ciphertext rejection; Node VM lifecycle/timer harness | DOM/layout/browser focus, installed native visibility/timers, and real user event races require separate runtime evidence |
| Automatic workers | Daily claim/restart/failure tests, deadlines and synthetic process-tree cancellation | Coverage may miss force-killed child paths; keep readiness/identity assertions rather than timing-only sleeps |
| OS backends and clipboard | macOS isolated test keychain, Windows uniquely named test namespace, Linux live Secret Service job with mandatory probe | Platform skips in other jobs are expected; matrix union alone cannot prove a particular platform scenario passed |
| UI and release packaging | Theme contrast calculations, canonical generated CSS equality, safe rendering/source guards, Node behavior, Swift typecheck, wheel verification | Python coverage excludes JS/Swift execution; source tokens/typecheck do not prove native timer shutdown or rendered UI behavior |
| Public threat model | Manifest/version parity, Codex skill-only payload, plaintext exposure and unsupported isolation-claim guards | These source/packaging contracts are intentional; retain them alongside runtime tests |

`test_ui_contract.py` and `test_security_contract.py` contain many membership and
source-reading assertions. Some pin safety requirements such as no unsafe HTML,
version parity or no inherited secret-producing hook. Those should stay.
Selectors, wording and implementation-shape checks should be complemented by
behavior tests when changing the flow; their count should not be reported as
runtime coverage. Node VM tests execute JavaScript but use a synthetic DOM; Swift
typechecking validates compilation, not scheduling or display behavior.

## CI collection and artifacts

The existing five full test jobs remain: macOS/Python 3.12, Windows/Python 3.12,
Ubuntu/Python 3.10, Ubuntu/Python 3.12 with a live isolated Secret Service session,
and Ubuntu/Python 3.14. Full runs happen in CI; this audit did not repeat the full
suite on the laptop.

Each job writes the raw coverage database, line/branch JSON and XML, HTML source
report, JUnit XML, per-test setup/call/teardown durations, CSV, and a manifest.
Artifacts use `python-tests-<os>-py<version>`. An always-run reporting step retains
evidence after failures without capturing fixture values, stderr or traceback
text in the custom metrics JSON. JUnit retains its normal pytest failure report.

The `coverage · full matrix` job combines all five immutable source revisions
and publishes `python-coverage-full-matrix`. Missing/duplicate job artifacts or
mixed revisions produce a partial report and a failing reporting job. Coverage
includes every `.py` under `src/keys_keeper`; omitted modules also fail the report.
No broad omit/exclude rules hide low coverage. The measured 84%/69% package floor
does not replace review of critical missing branches.
Per-job artifacts remain available so the union does not conceal OS-specific
branches or skips. The combined job adds a read-only AST inventory.

CI explicitly installs pytest-cov 7.x and Coverage.py `>=7.10.6,<8`. `.coveragerc`
uses relative file paths and runner-path aliases for macOS/Linux/Windows merging.
The supported subprocess patch follows
[pytest-cov's subprocess migration](https://pytest-cov.readthedocs.io/en/latest/subprocess-support.html)
and [Coverage.py process handling](https://coverage.readthedocs.io/en/latest/subprocess.html).
The `_exit` patch flushes explicit Python `os._exit` calls. SIGKILL and forced
process-tree shutdown can still discard child coverage; no complete killed-child
coverage claim is made. [Coverage.py path remapping](https://coverage.readthedocs.io/en/latest/commands/cmd_combine.html)
explains matrix path normalization.

The opt-in `--test-metrics=PATH` hook only measures pytest phase wall durations
and outcomes. It changes no fixture, password, KDF iteration, runtime cache or
test selection. Durations include coverage overhead and are not CPU benchmarks.

Examples (isolated source checkout, no user vault):

```bash
python scripts/test-quality-inventory.py --output /tmp/test-quality-inventory.json
python -m pytest --collect-only -qq
python -m pytest --cov --cov-report= --test-metrics=/tmp/test-reports/test-metrics.json --junitxml=/tmp/test-reports/junit.xml
python scripts/coverage-report.py job --report-dir /tmp/test-reports --label local --commit "$(git rev-parse HEAD)"
```

For the instrumented example, set `COVERAGE_FILE=/tmp/test-reports/.coverage`
before pytest. Local full-suite execution is optional, not part of the battery
audit workflow. Read measured missing lines/branches and the slowest phase CSV
from CI before choosing another local run.

## PBKDF2 and test cost

Many integration cases create encrypted journals/states with synthetic passwords
and therefore repeat the real KK1 KDF. They test persistence, authentication,
concurrency, restart, trust and failure recovery, so a suite-wide KDF mock or lower
iteration constant would weaken coverage. None was added.

First use CI duration artifacts to rank actual cost. A narrower future split can
use explicit fast KDF fixtures only for unrelated orchestration tests, with the
real crypto, independent interoperability, stale-cache, wrong-key/ciphertext,
trust/revocation and multi-process durability cases kept on the actual KDF. That
change needs an explicit contract review and measured benefit; static call-site
counts alone do not justify it. Reusing immutable synthetic vectors can avoid
redundant encryption setup without sharing mutable state between tests.

The first matrix's slowest macOS case was the CLI project lifecycle at 64.758
seconds; the private desktop-bridge lifecycle took 36.021 seconds. Personal-sync
linked-create/cycle behavior took 15.710 seconds on macOS, and the history-budget
case took 11.379 seconds on Windows. These are instrumented test wall times,
including process/native-store work, not evidence that all time is PBKDF2 CPU.
Retain their persistence, lifecycle, real authentication and trust assertions;
optimize only a measured redundant setup. No KDF iteration or global fixture was
changed in this audit.

Deterministic operation counts are the performance gates: no idle writes, no
repeated KDF after a retained-state warmup, no repeated audit parsing, no idle
Settings requests, one automatic attempt per day, bounded worker lifetime and
bounded response/pagination work. CPU measurements supplement those contracts;
physical battery life remains a separate installed-device observation.

## 0.11 worker and claim contracts

`test_auto_worker.py` now checks descendant cleanup after a successful or failed
supervised command, signal delivery during process creation (TERM/HUP/INT), and
failure to acquire a Windows JobObject before child spawn. Windows CI also runs
a real JobObject descendant test for normal success, failure and hard supervisor
termination. The existing real caller SIGKILL/HUP cases remain. These checks need
their platform job results; Linux success does not validate Windows JobObjects.

`test_auto_schedule.py` checks a busy daily-claim lock against a bounded wait,
preserved attempt marker and zero encrypted-state access; it also verifies that
ordinary storage locks retain their blocking semantics and unsafe claim-lock
targets do not modify an external file. Claims remain scoped. Separate personal
and S3 roots are not asserted to share a single global slot; the live project
launcher serializes its project scopes. Internal worker invocation is an
already-claimed seam. The daily marker uses wall-clock time, so a forward system
clock adjustment is not proof of 24 hours of physically elapsed time.

Additional contracts reject invalid/NaN/negative clocks before a claim or child
spawn; daily-launcher TERM/HUP/INT cancellation reaps a harmless real child tree
while preserving the claim. Updater configuration over 4 MiB or a pipe fails
before parsing or spawning its helper; routing configuration has a 1 MiB cap,
bounded regular-file reads, fixed invalid-UTF-8 errors, and writes that preserve
the old file on overflow. The shared marketplace updater is unchanged: after
Keys Keeper's bounded preflight it rereads configuration once per daily attempt,
so same-OS configuration growth between those reads is not fully bounded. The
project-launcher global queue intentionally serializes scopes without busy CPU;
the 300-second heavy-attempt deadline plus cleanup grace is not a deadline for
the entire queue.

## 0.11 data and WebVault contracts

`test_data_resource_bounds.py` exercises a 3,000-reference chain, shared DAG and
late backedge; a 3,000-folder chain has a deterministic executed-line-count
linear-work contract and a late-cycle negative case. Journal overflow preserves
prior ciphertext/index bytes and rejects before KDF; a full pending index also
rejects before KDF. Oversized replica generation/pointer input rejects before
file IO or password access. These bounded-work checks complement coverage and
avoid machine-speed thresholds.

`test_webvault_resources.py` exercises removed-account tenant/operator isolation
over synthetic real HTTP; corrupt, missing, duplicate or wrong-schema registries
cannot overwrite state or reach S3/backend calls. Additional cases cover
symlink/oversized-before-read input, account capacity and malformed input before
scrypt, bounded IP keys without throttle reset, abandoned-session reclamation
and refresh, and newline key rejection. This is local temporary data with fake
upstream boundaries: no live TLS, S3, vault or installed-device success is implied.

`test_remote_http_resources.py` now tests real local HTTP header/body slow-drip
deadlines, v1 preflight and framing for both sync and WebVault. Journal recovery
tests cover terminal-history cache reuse, new pending records, same-stat corrupt
ciphertext, rename/rotation, mixed same-salt pending work, concurrent directory
updates and resource overflow. Replica tests cover eight concurrent reads with
one KDF and eight fresh GCM authentications, fresh same-salt rewrite/tamper,
trusted identity, at most 32 retained replica stores with one derived key each,
and child runtimes. State-input and
profile-binding tests use temporary synthetic roots; none imply live TLS/S3,
vault or every-platform results before the matrix finishes.

File-backend tests preserve fresh ciphertext reads and GCM authentication without
persistent plaintext caching. Warm unchanged sets and missing deletes have zero
KDF/encryption/write calls; same-stat tamper, external rewrite/deletion and backend
identity changes cannot reuse stale values. Read/write size caps reject before
KDF; cached unlock material cannot be pickled. These tests retain real crypto.

`test_api_personal_contract.py` adds 55 synthetic adapter cases for all GET/POST
routes and exact schemas, malformed/missing/extra/duplicate keys, selectors and
unknown methods/routes before construction or parse, redacted constructor/action
failures, and enable-auto ordering after successful enrollment. Its focused
module measurement is 60/60 lines and 34/34 branches, at
`/tmp/keys-keeper-0.11-personal-api-coverage.json`. This closes the measured adapter
execution gap with fake managers; it does not prove every server, browser or
real enrollment scenario merely because the small module reaches 100%.

## Bounded audit and statistics contracts

`test_audit.py` proves that tail/newest-first search reads backward in bounded
chunks and short-circuits before an irrelevant large remainder; forward search
stops after matching limits. Tail retains physical-line selection and oldest-to-
newest result order, including blank lines, CR/CRLF and UTF-8 across chunk edges.
Zero returns without opening; invalid/negative/boolean/over-10,000 result limits
fail before IO. Audit reads require a regular file, use nonblocking/no-follow
opens and recheck the opened descriptor. FIFO and symlink replacement races are
covered. A logical line over 1 MiB or a scan over 64 MiB raises fixed
`AuditReadLimit`, rather than returning a complete-looking truncated list. The
monthly rotation first-line peek is bounded; archival behavior is preserved.

`test_desktop_stats.py` uses tiny synthetic caps to test line length, combined
compressed/decompressed scan bytes, gzip expansion/header growth, deep malformed
JSON, multi-profile budget exhaustion, exact plain-file EOF and 129-file cache
overflow. Stable unsupported or globally budget-truncated summaries remain
`complete=False` and cause zero rereads while their fingerprint is unchanged.
IO errors retry, file changes recover, and day/timezone/backward-clock/future-event
invalidation remains covered. Nonblocking/no-follow opens and descriptor checks
prevent regular-to-FIFO/symlink/directory replacement from causing an unbounded
wait; plain and gzip replacement/recovery cases are tested. Prefix authentication
on a real append shares the scan budget; cached summaries contain counters and
fingerprints rather than rows.

The small 1,000-row statistics benchmark at
`/tmp/keys-keeper-0-11-desktop-stats-small-benchmark.json` measured 20 warmed
summaries at 0.001144 CPU seconds with zero full scans/parses; appending ten rows
took 0.000662 CPU seconds with ten parsed rows and one prefix hash. This isolated
count contract complements the earlier 100,000-row result; it is not an
installed-device battery observation. The journal evidence at
`/tmp/keys-keeper-0.11-data-performance-evidence.json` measured 20 warmed scans of
four terminal records at 0.006757 CPU seconds, zero KDF, 80 fresh authenticated
reads and zero writes. Warm recovery still reads ciphertext within its aggregate
512 MiB/10,000-record budget; cold records still derive per distinct salt.

## Interpretation

The first CI report measures the named baseline under instrumentation; later
reports must name their commit and matrix. High executed-line coverage does not
prove the assertions would catch a defect. Prioritize missing branches on the hot
paths above, meaningful negative cases, and focused mutation experiments on pure
validators before introducing broad test deletion or runtime changes.
