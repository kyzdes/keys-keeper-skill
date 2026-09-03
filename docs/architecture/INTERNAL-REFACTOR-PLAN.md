# Internal refactor plan

Status: active in the current worktree. This plan covers behavior-preserving
work only; release and product behavior are separate decisions.

## Execution status — 2026-09-03

Implemented in the current worktree:

- compensating writes for the reserved sync credential bundle;
- transaction-local tombstone pruning and O(1) metadata transaction indexes;
- macOS Security.framework ABI and CoreFoundation ownership modules behind the
  existing `MacOSNativeKeychain` facade;
- one generated UI token source for admin and WebVault CSS;
- decomposed HTTP route dispatch and handler composition;
- clean-wheel verification for version parity, runtime assets, command surface,
  and generated skill/reference hashes;
- focused characterization tests and an independent read-only skill forward-test.

Locally verified: 497 tests passed and 13 platform-specific tests skipped. The
wheel smoke test, generated-token check, source-skill validation, JavaScript
syntax checks, compilation, and targeted lint for newly refactored code pass.

Still planned:

- split the mixed historical worktree into reviewable concerns before release;
- run the remote Windows/macOS/Linux CI matrix, including live Secret Service;
- generate the agent command/operation tables from one declarative manifest,
  accepting the change only if every existing target fixture stays byte-identical;
- perform repository-wide mechanical Ruff cleanup in a separate diff. The
  current repository baseline has legacy findings outside this refactor; avoid
  mixing automatic cleanup with security-sensitive changes.

## Boundary

The following are frozen while this plan is executed:

- CLI commands, arguments, exit-code meanings, and ordinary user-facing output;
- metadata, encrypted snapshot, audit, and configuration formats;
- Keychain prompt, bypass, legacy bridge, and one-item preparation semantics;
- admin and WebVault routes, DOM contracts, themes, colors, and interaction;
- the rule that original OS credential records remain the source of truth.

Changing any frozen behavior requires a separate product decision and targeted
migration/compatibility plan. In particular, removing the legacy bridge,
introducing a signed broker, adding structured CLI output, or changing the sync
envelope is out of scope here.

## Phase 0 — baseline and worktree control

1. Keep the current full-suite result as the behavioral baseline.
2. Split the large worktree by architectural concern before release; do not
   publish a package directly from an unreviewed mixed diff.
3. Treat source, packaged plugin, installed plugin, and installed CLI as four
   separately verifiable artifacts.

Acceptance:

- full test suite passes on the current platform;
- `git diff --check` and changed-file lint pass;
- no live secret values are read by validation;
- the worktree contains only intentional files.

## Phase 1 — internal consistency

### Sync credential bundle

Move the three reserved sync credentials through one internal mutation boundary.
On a write or remote-probe failure, restore the previous bundle and leave the
non-secret config unchanged. Preserve the existing CLI and web contracts.

### Tombstone maintenance

Prune tombstones inside one metadata transaction or under an explicit revision
check. A maintenance pass must not replace entries read before a concurrent
mutation.

### Metadata transaction indexes

Build name/id indexes once per transaction and update them with each mutation.
This removes repeated `Entry` reconstruction and quadratic duplicate checks
without changing ordering or persisted JSON.

Acceptance:

- fault injection after every credential write and remote-probe step;
- a concurrent mutation cannot be lost during tombstone pruning;
- persisted bytes remain schema-compatible;
- existing CLI/API tests pass unchanged.

## Phase 2 — native macOS decomposition

Split the native adapter into narrow internal layers:

1. Security.framework/CoreFoundation bindings and constants;
2. owned CoreFoundation references and release helpers;
3. generic-password item operations;
4. ACL inspection and preparation;
5. process-wide interaction policy.

`MacOSNativeKeychain` remains the compatibility facade. No caller outside the
native adapter imports raw ctypes declarations.

Acceptance:

- public Python API and raised domain errors are unchanged;
- existing isolated-Keychain tests pass;
- resource-release paths and interaction restoration have focused tests;
- ordinary native operations still spawn no subprocess.

## Phase 3 — presentation internals

### UI tokens

Keep one canonical token definition for both interfaces and deterministically
render the shipped CSS token blocks. Generated artifacts remain static so the
runtime and WebVault SRI model do not gain a build-time dependency.

### HTTP composition

Replace repeated store/backend/service construction and manual route branching
with internal factories and route tables. Keep paths, status codes, payloads,
headers, authentication, and request limits unchanged.

Acceptance:

- generated CSS is byte-stable when tokens are unchanged;
- SRI checks and UI contract tests pass;
- route contract snapshots are identical;
- complexity is reduced without broad exception swallowing.

## Phase 4 — skill and artifact fidelity

Keep the short skill entrypoint and routed references. Generate source and
packaged copies from the same canonical content, then verify the built wheel and
plugin payload rather than only the checkout.

Move repeated command/operation definitions into one declarative internal
manifest only after characterization fixtures cover every generated target.
Rendered output must remain byte-identical; otherwise treat the difference as a
separate skill-contract change.

Add a clean-environment artifact smoke test that proves:

- package version, plugin manifests, README, changelog, and generated install
  instructions agree;
- the installed CLI exposes the expected command surface;
- installed skill/reference hashes match the source release payload;
- the wheel contains every runtime asset, including generated CSS and SRI inputs.

Version bumping, signing, publishing, and installing over the user's active CLI
remain release actions and are not performed by this internal refactor.

## Phase 5 — verification and integration

1. Run focused tests for each changed boundary.
2. Run the full suite on macOS.
3. Run matrix CI on Windows, macOS, Linux file fallback, and live Secret Service.
4. Build a wheel and install it into a fresh temporary environment.
5. Run an independent skill forward-test in an isolated temporary workspace.
6. Review the final diff by concern before deciding on commits or release.

## Deferred product decisions

The following findings are deliberately not implemented by this plan because
they change user-visible behavior or compatibility:

- strict bypass with the legacy `/usr/bin/security` bridge removed;
- signed broker and per-client authorization policy;
- structured `--json` diagnostics and stable machine-readable error codes;
- durable secret generations and a new crash-recovery journal;
- sync crypto-envelope or metadata-schema changes;
- data-hygiene repair of existing reference cycles or orphaned Keychain items.
