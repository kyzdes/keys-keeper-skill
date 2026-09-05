# KK3 suite decision and integration review

Date: 2026-09-05. Scope: the implementation in this feature branch and synthetic
fixtures. Protocol implementation: Astra agent; independent integration review
and second wire implementation: root agent; runtime/recovery review: Sol agent.
This is an internal review by separate authors, not an external security audit,
formal proof, or production certification.

## Decision

Keep the explicitly versioned `KK3-projects-v1` suite described in
[the wire contract](PROJECT-PROTOCOL-CONTRACT.md). It combines Ed25519 signatures,
X25519, HKDF-SHA256 and AES-256-GCM using the package's existing `cryptography`
dependency. Scope epoch keys, authority keys, inbox keys and device keys are
independent random values. No worker receives a master seed or VaultKey.

This suite is **not HPKE**. The decision keeps the dependency surface unchanged
and makes the complete byte contract testable by a separate implementation.
It accepts the maintenance cost of a custom composition. Any change to domain
separators, serialization, KDF inputs, key roles or acceptance semantics needs a
versioned compatibility decision and another review. Standard primitives alone
do not establish the security of the application protocol.

HKDF's extract/expand equations and published A.1 test case are the reference for
the independent stdlib HMAC implementation.
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1).
HPKE itself leaves application replay handling to the application; changing the
encryption primitive would not replace grants, durable revocation or checkpoint
verification. [RFC 9180 §9.7](https://www.rfc-editor.org/rfc/rfc9180.html#section-9.7).

## Independent byte checks

`tests/test_project_wire_independent.py` does not call production serializers,
signature-message builders, KDF or encryption helpers for its reference side:

1. Stdlib HMAC extract/expand reproduces RFC 5869 A.1.
2. A separate serializer and Ed25519 verifier validate the signed policy, wrap
   and snapshot fixtures; an independent X25519/KDF/AAD path decrypts the wrap
   and snapshot and checks the complete-record SHA-256.
3. A separately constructed and signed wrap is accepted by the production
   decoder. It uses independent deterministic ephemeral key, salt and nonce
   inputs exclusively for this synthetic test.
4. Changing the message kind breaks signature validation. Changing recipient
   context breaks authenticated decryption.

Both implementations use the same maintained primitive library; this verifies
composition interoperability, not independent implementations of AES or curve
arithmetic. The protocol suite additionally rejects duplicate fields, type
confusion, invalid encodings, forged signatures, wrong scope/policy/grant,
wrong recipient, low-order public keys, tampering, replay and rollback.

## Review findings and resolution evidence

| Finding | Resolution | Regression coverage |
|---|---|---|
| A malicious relay could hide a revoke, leaving an old pending publication eligible for retry | Persist local monotonic revoke before HTTP; invalidate affected pending publication and reconcile an uncertain remote result without retransmitting withdrawn data | `test_project_sync.py`, `test_project_sync_e2e.py` |
| First enrollment could confuse a signed old snapshot with current master approval | Device challenge and signed answer bind request, grant, pin, policy, exact snapshot and wrap; install before active state | `test_project_protocol.py`, `test_project_runtime.py` |
| Queue acknowledgement could erase a later edit | Capture desired revisions and acknowledge only those revisions after accepted publication; resume exact operation on uncertain ACK | `test_project_catalog.py`, `test_project_sync_e2e.py` |
| Two concurrent enrollments could overwrite the grant list | Atomic `add_grant` under the durable job lock | `test_project_sync_e2e.py` |
| Random snapshot nonces lacked a client-owned lifetime budget | Limit each epoch to 65,536 signed snapshots, automatically rotate the independent epoch key, reject same-epoch checkpoint reset | `test_project_protocol.py`, `test_project_sync_e2e.py` |
| Projection could race a partially applied native backend mutation | Encrypted master mutation journal plus projection guard and startup recovery | `test_master_journal.py`, `test_project_projection.py` |
| Restoring a stale authority could resume a second publisher | Recovery-only marker; resumable takeover creates fresh authority, scopes and grants instead of inheriting old trust | `test_project_backup.py`, `test_project_recovery.py` |
| Python module CLI masked command failure with exit status zero | Propagate `main()` through `SystemExit` | `test_cli_project_workflow.py` |

The nonce policy is an application limit enforced independently of relay quotas.
For 2^16 uniformly random 96-bit nonces, the birthday collision probability is
approximately 2.7e-20 per epoch. This calculation covers dispatched snapshots,
not a compromised or rolled-back master deliberately reusing keys. GCM requires
nonce uniqueness for a key; immutable network retries therefore retain the exact
ciphertext. [Cryptography AEAD documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM).

## Boundaries retained in the product

- A compromised worker can use every credential already delivered to any of its
  profiles. OS account compromise is wider than one selected CLI profile.
- A shared credential remains the same credential across projects; effective
  exposure is the union of its assignments and provider permissions.
- Revocation protects future publications after rekey. It cannot erase copies or
  invalidate the credential at its provider. Provider rotation is a separate action.
- A relay can withhold data or present an old valid HEAD. Existing devices retain
  monotonic checkpoints; fresh enrollment obtains a master challenge response.
  There is no offline proof that an unseen later HEAD does not exist.
- There is no forward secrecy claim for previously stored ciphertext after
  compromise of the corresponding long-lived private keys.
- History catch-up has finite record/byte limits. Reaching a limit fails closed;
  it never resets a pin or checkpoint to a relay-supplied value.
- Local state tampering by an attacker controlling the master OS, provider
  credential rotation, external audit and real-machine rollout are outside this
  synthetic validation. See the implementation evidence report for actual checks.
