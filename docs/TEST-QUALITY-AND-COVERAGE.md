# Test quality and performance evidence

Audit baseline: source commit `61a081e8466559f544a0f641b1131d0e60f362fa`
(0.10.1). This document distinguishes static inventory, executable regression
contracts, measured CI coverage, and installed application measurements.

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
No broad omit/exclude rules or arbitrary success threshold hide low coverage.
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

Deterministic operation counts are the performance gates: no idle writes, no
repeated KDF after a retained-state warmup, no repeated audit parsing, no idle
Settings requests, one automatic attempt per day, bounded worker lifetime and
bounded response/pagination work. CPU measurements supplement those contracts;
physical battery life remains a separate installed-device observation.

## Interpretation

No baseline percentage is invented before the matrix runs. The first CI report
after this change measures the current source under instrumentation; later
reports must name their commit and matrix. High executed-line coverage does not
prove the assertions would catch a defect. Prioritize missing branches on the hot
paths above, meaningful negative cases, and focused mutation experiments on pure
validators before introducing broad test deletion or runtime changes.
