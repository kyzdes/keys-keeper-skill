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
project state under `project-watch-schedule/<scope-id>/last-attempt.json`.
It claims the attempt under a profile lock before expensive work. A failed
attempt counts against the daily limit; invalid timing metadata fails closed.
Deferred cycles do not decrypt project state. Manual sync bypasses this
automatic scheduling guard.

Personal-device watchers use the same metadata-only claim without changing
their configured auto-sync setting or recipients. Legacy S3 SessionStart sync
uses a separate claim and an interval of at least 24 hours, even if an older
environment setting requests less. Its explicit `sync auto --force` remains a
manual override. Detached workers receive an already claimed attempt. Manual
project/device Sync and S3 push/pull remain immediate.

## Working UI and activity summaries

Idle Settings does not issue periodic personal-sync requests. The owner starts
connection polling by adding/joining a computer; polling has an invitation
expiry and stops while the page is hidden or after cancellation/completion.
Local admin requests share a bounded runtime for the server lifetime. Cached
journal keys stay in that process; each encrypted read still authenticates the
current file, preserving external writes and revocations.

The native activity bridge caches counters and file fingerprints in memory.
Unchanged audit files are not reopened or parsed. Appended records update the
counters; replacement, rewrite, rotation, new profiles, read errors, and local
day/timezone changes invalidate the relevant cache. Automatic native refreshes
stop when the activity panel is hidden; explicit refresh stays immediate.
The cache retains at most 128 file entries plus one aggregate fingerprint and
counter set. The aggregate prevents repeated reads when discovered logs exceed
the per-file capacity; errors and concurrent changes invalidate it.

## Automatic worker bounds

Project and personal watchers plus the standalone launcher use the same
scope-based daily claim. A portable supervisor bounds automatic workers to five
minutes and terminates their owned process tree on timeout/cancellation. Manual
operations use their ordinary immediate path. Failed or corrupt configurations
cannot cause a frequent autostart restart loop. HTTP response sizes and S3
pagination are bounded in addition to per-socket timeouts.

The opt-in Keys Keeper fallback updater also claims a daily attempt before
work. Lower interval overrides and failures cannot permit a short retry. The
shared updater templates remain unchanged. Native Claude/Codex update policy
belongs to the host; the hook defers to that policy without changing it.

## macOS one-shot scheduler

`scripts/daily-project-sync.py` is a standard-library launcher usable with an
existing installed package. It runs exactly one scope-specific `project-sync
auto` command. The legacy `sync` input is converted to the automatic entry;
manual CLI `project-sync sync` remains immediate. A global POSIX lock serializes different jobs; private durable
timestamps retain the old daily guard across launcher restarts. The inner
scope-based claim additionally prevents a duplicate/recreated label or a watcher
from gaining another attempt for the same scope.
Errors do not trigger retries, and a child process is bounded to five minutes.
Its output contains only a fixed status, never child output or scope metadata.

Use a separate private scheduling directory, a job ID computed as the SHA-256
hex digest of the existing LaunchAgent label, and these LaunchAgent settings:

- `StartInterval`: 86400
- `RunAtLoad`: false
- no `KeepAlive`
- `ProgramArguments`: Python, launcher, `--state-dir`, scheduling directory,
  `--job-id`, label digest, `--command`, existing keys executable,
  `project-sync`, `auto`, `--scope`, existing scope selector

For a first setup, initialize timestamps to the activation time to defer work
for a day. For an upgrade, preserve the latest old job/profile attempt when
seeding the scope-based marker; never reset it to an earlier time. Back up plists
and scheduling metadata privately before replacing them.
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

The separate `scripts/benchmark-desktop-stats.py` creates a synthetic 100,000-row
audit log. On the same MacBook, three stateless summaries used 0.800136 CPU
seconds and parsed 300,000 rows. After one cache warmup, 100 unchanged refreshes
used 0.004758 CPU seconds with zero file reads or parsed rows. Appending ten rows
used 0.009250 CPU seconds and parsed only those ten rows; a streaming prefix
hash also checked for an interior rewrite. These are synthetic measurements,
not a battery-life estimate.

## Core rollout boundary

The source fix and the scheduler are separate deliverables. Deploying the
standalone scheduler does not install the core changes into pipx. Before a
core rollout, review against the installed source: newer installed packages
may contain personal-sync and desktop changes absent from the base commit.
Backport or build from that compatible version, test it in a separate runtime,
retain the old package for rollback, and validate the installed UI and an idle
cycle before enabling unattended execution. Do not replace an installed
package with an older feature worktree wholesale.
