# Project-scoped vaults: implementation evidence

Date: 2026-09-05. Feature branch: `codex/project-scoped-vaults`.
This report separates implementation, synthetic validation, installed artifacts,
CI and real-machine rollout. Only synthetic credentials and dedicated test
backends are used. The user's master vault and VPS have not been migrated.

## Implemented scope

Folders and explicit project/environment assignments; isolated profiles and
scope epoch keys; metadata-only preview; authenticated worker enrollment;
read/create-only worker service and API; local pending sinks; immutable upload,
exactly-once canonical import and publication; durable revocation; restart-safe
mutation/replica state; encrypted backups, recovery-only restore and fresh
authority takeover; background watch; bounded relay and live SQLite backup.

Runbooks: [client](../PROJECT-SCOPED-SYNC.md),
[relay](../PROJECT-RELAY-OPERATIONS.md),
[Russian setup](../PROJECT-SCOPED-SETUP-RU.md).
Review: [wire decision and cross-author evidence](PROJECT-PROTOCOL-INDEPENDENT-REVIEW.md).

## Release 0.9.0 code review

Astra reviewed the protocol/importer, Sol reviewed runtime/recovery, and each
cross-reviewed the other's corrections. Terra verified release contracts,
marketplace descriptions and the setup guide. The integration review also
checked rendered delivery states and device identification. This is an internal
multi-agent review, not an external security certification.

The review reproduced and corrected these defects before release:

- A staged import could resolve a changed alias to a different canonical entry
  after a crash. Commit now checks pinned IDs, current scope/distribution, names
  and cycles under the metadata transaction. Ref-bearing older journals without
  pinned IDs fail closed and clean their matching staged values.
- An empty but previously used master root could enroll as a worker, and direct
  runtime backend access could bypass the normal profile selector. Enrollment
  now requires a fresh root, and worker registries prohibit all master backend
  paths, including cached or injected backends.
- Concurrent restores, or restore racing takeover, could mix state. A shared
  reentrant process/thread lock covers all recovery-root mutation phases.
  Restore resume refuses an already prepared takeover. Activation and completed
  replay verify the exact manifest/marker/activation identity before mutation.
- Broken recovery marker, activation and journal symlinks could yield misleading
  completion; these now fail closed.
- Terminal outbox history could reserve a name forever. Only active requests and
  installed entries reserve names; terminal history is preserved.
- The UI could report stale or unavailable delivery as current and obscure which
  device was being revoked. It now shows pending/error/conflict states and the
  full device ID, including in the scope-specific revoke confirmation. Folder
  moves reject ambiguous names and accept the displayed stable folder ID.

Regressions include encrypted legacy-journal replay, four changed-reference
cases, fresh-root/cached-backend denial, a pause before the first recovery-marker
write, wrong-backup activation, and concurrent takeover/restore. The actual JS
rendering regression executes all delivery states and cancels a revoke while
checking its exact device/scope confirmation. Release publication requires the
complete matrix at the final PR revision to pass; historical results below are
retained as revision-specific evidence.

## Validation record

| Check | Recorded result |
|---|---|
| Full local suite, integration commit `46dc35f`, macOS / Python 3.14.5 | **875 passed, 13 skipped**, 472.11 seconds |
| Wheel at `46dc35f` | Built and installed in clean environments; release artifact verifier passed, including runtime assets, project commands, versions and generated skill hashes |
| Actual installed CLI, separate Python 3.12.11 environment | **1 passed**, 26.90 seconds; native dedicated macOS test Keychain master, independent file-backed worker, HTTP relay, create/use/import and mutation denial |
| Final runtime wheel at `c337b31`, installed Python 3.12.11 | Artifact verifier passed; **14 passed**, 105.57 seconds, running outside the checkout against `site-packages`: CLI lifecycle, enrollment/revoke/retry, recovery guard and fresh-authority takeover |
| Compile, both JS modules, generated UI tokens and both skill bundles | Passed |
| Windows correction: journal/backup/replica/runtime/recovery | **49 targeted tests passed**, plus **24 passed** after narrowing directory-fsync error handling |
| Relay backup portability | **12 passed, 1 Windows-only skipped locally**; actual Windows ACL and backup behavior are covered by CI |

The authoritative platform result for each exact revision is the
[PR #11 checks](https://github.com/kyzdes/keys-keeper-skill/pull/11/checks).
The matrix runs macOS and Windows Python 3.12, Linux Python 3.10/3.12/3.14,
and installed-wheel validation. Linux 3.12 gates on a real Secret Service
store/lookup before running tests, so a missing keyring cannot silently pass.

CI identified Windows portability defects that focused POSIX runs could not
expose. Corrective changes explicitly open raw ciphertext in binary mode,
replace unsupported directory operations, validate native backup DACLs and
accept Windows' intentional connection-abort result in the capacity test.
POSIX I/O and permission errors during directory fsync still propagate; only
unsupported-operation errors are ignored. The crash-test child writes and
fsyncs through the same writable descriptor on every platform. POSIX mode-bit
assertions remain POSIX-specific; secret-absence and actual Windows ACL tests
still run. New Windows functional tests are retained in the matrix rather than
broadly skipped. The latest revision must have successful PR checks before release.

Browser QA used an isolated synthetic Admin server with an intentionally
unavailable secret backend. Projects was inspected at 1280×900 and 390×844 in
both themes. Folder move persisted after reload and preserved a shared key's
three scope assignments. On mobile document width equals content width (390 px).
The final updated page produced no console errors during these actions.

## Acceptance mapping and limits

| Plan IDs | Evidence |
|---|---|
| A01, A02, A04, A07 | `test_project_sync_e2e.py`, `test_project_runtime.py`, `test_cli_project_workflow.py`: independent scopes, local private canary, pending create/use/import and collisions |
| A03, A10 | Projection/catalog/binding tests and two-scope engine lifecycle; desired revision ACK retry; UI shared usage after folder move |
| A05, A06 | Protocol, relay, importer and API adversarial tests; foreign context/wrap/grant, modified writes, invalid signature and canary rejection |
| A08, A09 | Durable journal, importer, replica and takeover interruption tests, plus lost HTTP responses and exact operation retries |
| A11, A12 | Durable local revoke, hidden relay revoke, process exit, rekey, stale outbox dispatch, fresh challenge and active finish replay tests |
| A13, A14 | Chain/checkpoint rejection, recovery-only startup, fresh-authority takeover and interrupted activation; native backend factory forbidden on recovered file profile |
| A15, A16 | Synthetic output canaries, encrypted state/backup, bounded parser, history/queue/global limits, connection/body limits and consistent relay backup tests |
| A17 | Final installed artifact and platform CI results recorded above |

These are bounded automated scenarios, not exhaustive fault injection at every
instruction or a long-duration hostile-network load campaign. The UI fixture
uses synthetic delivery status; real synchronization is checked separately by
HTTP and CLI scenarios. No external cryptographic audit, provider-side key
rotation or functional production verification is claimed.

## Rollout boundary

Installation and schema migration are explicit. Before using real credentials,
select the master, relay endpoint, clean worker and exact allowed entries; make
and verify the encrypted backup, then run the documented fingerprint enrollment.
Existing workers that already held the full vault retain that historic exposure.
Fresh takeover changes authority and scope IDs and requires re-enrollment.

Revocation cannot erase downloaded credentials. Shared credentials expose the
union of their project assignments and provider privileges. The relay may
withhold newer data, and there is no forward secrecy claim for old ciphertext
after relevant private-key compromise. History and storage exhaustion fail
closed and need an operator action; automatic unsafe history deletion is absent.
