# Security remediation roadmap

Status: active on `security/keys-keeper-hardening`  
Baseline: `df2a9e8`  
Target: truthful compatibility mode in 0.8, isolated broker mode in 1.0

## Product contract

Keys Keeper has two distinct security modes.

### Compatibility mode

Normal commands avoid returning plaintext in tool output and route it to an
explicit local sink. This reduces accidental transcript exposure. It does not
isolate secrets from arbitrary code running as the same OS user. Clipboard,
files, caller-controlled environment gates, direct package imports, and native
credential-store tools remain outside this boundary.

### Isolated mode

The vault broker and the coding agent run under different security principals.
The agent receives scoped operations such as SSH signing or an allowlisted HTTP
request, never a generic reveal primitive. Copy, reveal, and writing a secret to
an agent-readable file are explicit human exposure operations.

## Delivery plan

| Release | Scope | Exit gate |
|---|---|---|
| 0.7.2 | Truthful claims, mutable updates off by default, patched dependency floor | No data migration; tests and runtime dependency audit green |
| 0.8.0 | Input, subprocess, file, audit, web, transaction, and sync hardening | All audit PoCs are regression tests; no open Critical/High |
| 0.9.0 | Opt-in isolated broker preview | Cross-platform sandbox tests; compatibility mode remains available |
| 1.0.0 | High-assurance isolated mode | Independent review and red-team sign-off |

## Workstreams

### SEC-0: release containment

- Remove same-user isolation claims from active product surfaces.
- Disable mutable-HEAD plugin updates unless explicitly opted in.
- Install from a reviewed tag/artifact.
- Require a patched `cryptography` baseline and add locked release inputs.
- Preserve current vault data and command compatibility.

Acceptance:

- SessionStart performs no update network or filesystem work by default.
- Public copy describes the compatibility-mode boundary consistently.
- Package, plugin, and runtime versions match.
- Runtime dependency audit reports no known vulnerability.

### SEC-1: trust-boundary validation

- One schema validator for CLI import, admin import, sync, and WebVault.
- Entry IDs are exactly `kk:<uuid4>`.
- Reject reserved namespaces such as `kk:sync-*`.
- Validate types, sizes, timestamps, refs, host, user, and port.
- Reject control characters and option-shaped SSH destinations.

Acceptance:

- Malformed imports are rejected before any backend mutation.
- Synced metadata cannot become an SSH option or overwrite sync credentials.
- Property/fuzz tests cover every external parser.

### SEC-2: secure local sinks and subprocesses

- Central `SecureFileSink`: no-follow, owner check, mode 0600, atomic replace,
  fsync, and refusal of special files.
- Trusted executable resolution and a minimal environment for every subprocess.
- Replace macOS argv secret handling with a native API.
- Replace Linux `secret-tool search --all` with an attributes-only D-Bus path.
- Pass clipboard-clear state through a pipe or inherited descriptor, not argv.
- Store an executable path, not a complete caller command line, in the audit log.

Acceptance:

- PATH, symlink, argv watcher, permissive umask, and malformed audit-input tests
  cannot recover or redirect a secret.

### SEC-3: transactional secret generations

Logical entry IDs point to versioned physical accounts. A write creates and
verifies a new generation, journals the operation, atomically switches metadata,
then garbage-collects the previous generation. Startup recovery completes or
rolls back interrupted operations.

Apply the same state machine to:

- CLI add/replace/delete;
- local admin and bulk import;
- sync merges;
- Windows chunks;
- paired key/passphrase records;
- encrypted-file backend mutations.

Acceptance:

- Fault injection after every I/O step leaves either the complete old state or
  the complete new state.
- `keys doctor --repair` reconciles interrupted journals and orphan generations.

### SEC-4: authenticated sync and crypto envelope v2

Manifest v2 authenticates vault ID, version, parent hash, snapshot reference,
ciphertext hash, device ID, timestamp, and format profile. Domain-separated
keys are derived for encryption, manifest authentication, and web auth. `HEAD`
is an untrusted cache, not a trust anchor.

Existing clients retain a sealed latest-head anchor. Fresh devices either use a
trusted onboarding checkpoint or explicitly report an unanchored first sync.

The KK2 envelope carries authenticated KDF and algorithm identifiers, resource
limits, salt, nonce, and payload length. The WebVault Argon2 path requires an
audited, vendored implementation; until then it uses an explicit compatibility
profile rather than an implicit fixed KDF.

Acceptance:

- Pointer swap, commit rewrite, version relabel, oversized blob, and rollback
  PoCs fail closed.
- CLI and WebVault produce and verify identical manifests.
- V1 remains readable; V2 is written to a separate remote prefix.

### SEC-5: isolated broker

- Broker is the only process with vault access.
- Agents run under a separate OS account, container, or platform sandbox.
- IPC authenticates the peer and uses scoped, expiring, replay-resistant grants.
- Supported capabilities are specific: SSH signing/connection, allowlisted HTTP
  request/signing, or a fixed trusted launcher profile.
- There is no arbitrary `exec(command, secret_env)` capability.
- Reveal, clipboard, and agent-readable file output are human-only exposure
  operations.

Acceptance:

From the agent sandbox, direct package import, native keychain access, clipboard
read, environment dump, process inspection, socket access, token replay, target
substitution, and binary replacement all fail. Allowed operations work without
returning credential material.

### SEC-6: web and account-state hardening

- DOM APIs instead of untrusted `innerHTML`.
- Nonce/hash CSP and self-hosted assets.
- Body and remote response limits.
- Safe XML parsing.
- Account-state corruption fails closed with explicit recovery.
- Non-loopback WebVault requires TLS unless the user supplies an explicit
  insecure-development flag.

### SEC-7: supply chain and release engineering

- Platform/Python lock inputs with hashes.
- Signed Git tags and release artifacts.
- Wheel/sdist provenance and SBOM.
- GitHub Actions pinned by full SHA.
- CI on supported Python versions and real macOS, Windows, and Linux backends.
- Bandit, Semgrep, dependency audit, secret scan, migration, and downgrade jobs.

## Rollout and rollback

- Every schema or crypto migration starts with an encrypted recovery export.
- V1 and V2 sync prefixes remain separate during the migration window.
- Destructive garbage collection is disabled for at least 30 days.
- Isolated mode is feature-gated through 0.9.
- A tested downgrade command converts the current local V2 state to a V1 export.
- Compatibility mode remains available but never carries the high-assurance
  product claim.

## Definition of done

- Every finding has a regression test and an owner.
- No open Critical/High findings.
- Medium findings are fixed or have an explicit, time-bounded risk acceptance.
- No secret reaches stdout, error text, logs, audit records, or argv outside a
  documented exposure operation.
- Migration, crash recovery, backup restore, and downgrade are tested.
- Public claims match the tested threat model.
- The 1.0 boundary passes an independent security review.
