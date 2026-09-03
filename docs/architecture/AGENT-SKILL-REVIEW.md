# Agent experience and skill review

Status: release review for `v0.7.8` of the agent workflows exercised during the
Keychain, sync, admin, and installation work.

## What made agents unreliable

| Friction | Observed effect | Improvement |
|---|---|---|
| A 2,700-word entrypoint loaded every workflow | agents searched a wall of prose and missed the one relevant branch | **Implemented:** a short invariant-first entrypoint with six routed references |
| Trigger text included generic APIs, domains, servers, and configs | the skill activated even when no credential operation was requested | **Implemented:** activation now requires an actual secret action |
| “Metadata-only” described output, not side effects | agents treated `sync status` as local even though it reads credentials and contacts a remote | **Implemented:** command-effects matrix separates value read, network, mutation, and approval |
| Bypass prose did not lead with “original item remains source of truth” | work drifted toward backup/copy workarounds | **Implemented:** the invariant and no-migration rule now lead the bypass reference |
| Interactive and background callers shared one backend construction path | automation could repeatedly trigger macOS authorization dialogs | **Implemented:** explicit `INTERACTIVE` and `UI_FORBIDDEN` contexts |
| Install guidance mixed runtime health with vault-wide warnings | unrelated orphan/reference warnings were mistaken for a broken install | **Implemented:** diagnostics separate install identity, runtime health, data hygiene, and credential validity |
| Generated skill text depended on a hard-coded release | package instructions drifted after releases | **Implemented:** install references render from the package version and are checked in tests |
| Source skill and packaged plugin could diverge silently | one agent followed different policy from another | **Implemented:** generated references are installed and byte-compared in the release contract |
| Bulk preview returned the secret-bearing parser field | UI convenience expanded the browser exposure surface | **Implemented:** preview returns only `has_value`; the UI renders presence, not length or content |
| CLI and API composed metadata/keychain writes independently | agents encountered ambiguous partial-success states | **Implemented first slice:** a shared compensating mutation service |

## Remaining design problems

- Per-client silent policy is unresolved until a broker can authenticate signed
  callers. Process names, PIDs, and environment markers are insufficient.
- The compensating service handles ordinary exceptions but not power loss or
  process death; durable generations and recovery are still required.
- `keys doctor` needs explicit structured receipts for each layer: item
  presence, readable-without-UI, downstream validity, and repair eligibility.
- References should eventually expose stable machine-readable operation
  metadata so an agent does not infer effects from prose.
- The release pipeline still needs artifact provenance, SBOM, signed tags, and
  broker-specific adversarial tests before isolated-mode claims are allowed.

## Recommended skill contract

The entrypoint should remain small and contain only activation, invariants,
routing, and the safe surface. Each reference should answer one user intent and
start with:

1. authority required;
2. whether the command reads a secret;
3. network and mutation effects;
4. success evidence;
5. stop conditions and cleanup.

This keeps normal invocations fast while making sensitive flows deterministic
and reviewable.
