# macOS legacy credential read correction — 0.11.1

The reported SSH failure was reproduced locally without contacting a server.
The installed 0.11.0 CLI successfully resolved `ssh-universal` into an
owner-only temporary file, but OpenSSH rejected that file as `invalid format`.
Converting that file from hex into a second protected temporary sink produced
a valid OpenSSH key whose public key matched the catalog's public metadata.
Both temporary sinks were removed. This proves the reader changed the value's
representation; it does not prove server authorization or imply key corruption.

Apple's `security find-generic-password -w` prints a bare hex string whenever
the value contains a non-printable byte. Line feeds in private keys trigger
this behavior. The compatibility reader treated this as raw UTF-8. Guessing
whether a string looks hexadecimal would corrupt legitimate hex credentials.

The reader now requests `-g` with all streams captured privately. It validates
the complete tagged `password:` representation from Apple's `print_buffer`:
literal quoted printable bytes, authoritative `0x` hex with the canonical
octal preview, or the empty record. Only authoritative tagged hex is decoded.
Malformed, duplicate, unexpected or non-UTF-8 records fail with fixed errors.
Captured process/decoder failures do not become secret-bearing error chains.

The native reader also discards a failed UTF-8 buffer before raising a fixed
framework error; it retains the original zero/free behavior for the framework
buffer. No secret item, ACL, reference, Keychain policy, encryption format,
PBKDF2 setting, sync scope or scheduling policy is migrated or changed.

The compatibility read still requires an unlocked item that explicitly trusts
`/usr/bin/security`, starts at most one process with the existing five-second
deadline, and is unavailable to strict background/server contexts. Partitioned
items cannot be prepared by weakening their code-signature policy. A metadata
preflight is not proof that an individual value can be read.

Regression tests cover real isolated macOS Keychain round trips, a generated
disposable Ed25519 key parsed by OpenSSH, byte fidelity for LF/CRLF/trailing
newlines/Unicode/quotes/backslashes/empty/literal hex, malformed input,
redacted failures, and retained unknown/locked/strict-context restrictions.
Cross-platform parser tests require no access to an OS credential store.

The agent stop rule now names the failed credential operation: unchanged
authorization retries and repeated dialogs stop, while metadata-only and local
format/configuration diagnostics may continue. Access can be retried after a
confirmed repair or explicit user direction; ACL and secret-ingestion consent
requirements remain in force.

This correction does not introduce periodic work. Large values still depend
on OS-controlled provider behavior and captured helper output; this is not a
new guarantee about arbitrary provider output or physical battery duration.

Primary implementation references:

- [Apple password output](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_find.c)
- [Apple tagged buffer format](https://github.com/apple-oss-distributions/Security/blob/main/SecurityTool/macOS/keychain_utilities.c)
