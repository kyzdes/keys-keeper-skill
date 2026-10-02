# Release qualification follow-up: macOS worker reaping

The 0.12.0 changes and R1–R7 corrections are documented in
[the independent review corrections](REVIEW-FIXES-0.12.0.md). PR #21 merged
as `c49220f`. Its PR matrix and subsequent published-tag matrix passed, but
the concurrent main-branch macOS run exposed another timing-dependent issue.
The production services and operator software had not been switched.

The unchanged synthetic descendant test reproduced it locally once in 100
iterations. `SIGTERM` succeeded and the parent was reaped with status -15;
a subsequent `killpg(SIGKILL)` returned `EPERM`. The test's later cleanup
observed `ESRCH`. The worker translated the permission error to
`operation_failed`, losing the expected timeout outcome. The empty diagnostic
stderr was insufficient to identify the cause; a separate synthetic trace
recorded each process-group syscall and return status.

The correction handles only `EPERM` with a bounded 200 ms existence check.
It sends no additional destructive signals during that check. An independent
`killpg(pgid, 0)` returning `ESRCH` establishes that the group has disappeared.
A successful existence probe or another `EPERM` does not establish termination;
if the group remains or cannot be verified, the original error is retained.
Other errors propagate immediately. Ordinary successful cleanup is unchanged.

Regression tests exercise disappearance, a surviving group, persistent denied
probes, unrelated errors, bounded waiting, and foreground/direct timeout
outcomes. Real subprocess repetitions and the full platform matrix complement
those deterministic assertions. Exact final results belong in the release
verification manifest.

The already-created `v0.12.0` tag is retained without movement. The corrected
release is 0.12.1; all wheel, image, marketplace and operator installation
checks use its final source commit. The earlier draft is not a published
release. Coverage thresholds remain 84% line and 69% branch coverage, and
no failing regression is disabled or broadened to accept the incorrect result.
