# Project sync: idle efficiency and daily scheduling

The watcher attempts automatic synchronization once per rolling 24 hours for
each explicitly selected profile. Manual **Sync now** and `project-sync sync`
run immediately. The existing single `--scope` interface is preserved; a
shorter legacy `--interval` does not allow more frequent automatic work.

## Persistence and process memory

Verified trust is saved only when grants or locally observed revocations
change. Authenticated changes remain durable before a later import or
publication can fail. Clean receive/publish cycles write no state journal.

A runtime retains at most 32 state/journal instances by immutable profile
identity. Every load reads the current encrypted file under the existing
locks. Each journal retains only the last successfully read or locally
written salt/key pair. A different salt derives a fresh key; AES-GCM
authenticates every read, including reads using a cached key. Failed decoding
or authentication clears the key cache. Neither keys nor unlocking material
are serialized, logged, or shared between profiles.

The live process already holds unlocking material. This cache deliberately
retains a derived key for that process's lifetime to avoid repeated PBKDF2;
it does not cache mutable plaintext state or change the at-rest threat model.
The KK1 blob format and PBKDF2-HMAC-SHA256 with 600,000 iterations are unchanged.

The watcher records non-secret timing metadata separately from encrypted
project state under `project-watch-schedule/<profile-id>/last-attempt.json`.
It claims the attempt under a profile lock before expensive work. A failed
attempt counts against the daily limit; invalid timing metadata fails closed.
Deferred cycles do not decrypt project state. Manual sync bypasses this
automatic scheduling guard.

Personal-device watchers use the same metadata-only claim without changing
their configured auto-sync setting or recipients. Legacy S3 SessionStart sync
uses a separate claim and an interval of at least 24 hours, even if an older
environment setting requests less. Its explicit `sync auto --force` remains a
manual override and the handoff for an already claimed detached worker. Manual
project/device Sync and S3 push/pull remain immediate.

## macOS one-shot scheduler

`scripts/daily-project-sync.py` is a standard-library launcher usable with an
existing installed package. It runs exactly one scope-specific `project-sync
sync` command. A global POSIX lock serializes different jobs; private durable
timestamps enforce 24 hours between attempts even across launcher restarts.
Errors do not trigger retries, and a child process is bounded to five minutes.
Its output contains only a fixed status, never child output or scope metadata.

Use a separate private scheduling directory, a job ID computed as the SHA-256
hex digest of the existing LaunchAgent label, and these LaunchAgent settings:

- `StartInterval`: 86400
- `RunAtLoad`: false
- no `KeepAlive`
- `ProgramArguments`: Python, launcher, `--state-dir`, scheduling directory,
  `--job-id`, label digest, `--command`, existing keys executable,
  `project-sync`, `sync`, `--scope`, existing scope selector

Initialize each timestamp to the activation time to defer the first automatic
attempt for a day. Back up the original plists privately before replacing them.
Keep each existing scope explicit; never substitute an unscoped watcher that
could also process a separate personal-device profile.

To roll back, boot out the six changed jobs, atomically restore the backed-up
plists, then bootstrap the originals. This restores their previous frequent
watching and CPU cost. Stopping the daily jobs instead preserves manual Sync.

## Reproducible synthetic benchmark

The benchmark creates isolated temporary scopes, a local relay and an empty
backend that rejects secret reads. It measures only receive/publish idle work;
it does not measure live Keychain access, delivery, sleep scheduling or battery
capacity. Choose the code version with `PYTHONPATH` and use the same script:

```sh
PYTHONPATH=/path/to/checkout/src python scripts/benchmark-project-idle.py \
  --scopes 6 --cycles 3 --retain-state
```

Measured on 1 October 2026, six scopes × three idle cycles:

| Implementation | CPU seconds | Wall seconds | KDF derivations | Journal writes | Changed encrypted files |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline `324ee70` | 42.841205 | 43.007272 | 270 | 54 | 6 |
| Changed-only trust persistence | 17.313662 | 17.387930 | 108 | 0 | 0 |
| Combined fix, recreated state per cycle | 3.198274 | 3.225442 | 18 | 0 | 0 |
| Combined fix, retained state, cold start | 1.244087 | 1.261552 | 6 | 0 | 0 |

The combined retained-state measurement starts each journal cold. It derives
once per scope, then reuses that key. All measured cycles remained idle; CPU
fell by approximately 97.1% in this synthetic scenario.

## Core rollout boundary

The source fix and the scheduler are separate deliverables. Deploying the
standalone scheduler does not install the core changes into pipx. Before a
core rollout, review against the installed source: newer installed packages
may contain personal-sync and desktop changes absent from the base commit.
Backport or build from that compatible version, test it in a separate runtime,
retain the old package for rollback, and validate the installed UI and an idle
cycle before enabling unattended execution. Do not replace an installed
package with an older feature worktree wholesale.
