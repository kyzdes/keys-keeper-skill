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
[relay](../PROJECT-RELAY-OPERATIONS.md).
Review: [wire decision and cross-author evidence](PROJECT-PROTOCOL-INDEPENDENT-REVIEW.md).

## Validation record

Final integration validation is in progress. Focused suites from the three
implementation agents pass, including real HTTP/SQLite, native Keychain CLI,
subprocess interruption, enrollment/revocation races and recovery takeover.
Final full-suite, artifact and CI results will replace this paragraph before
the implementation handoff.

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
