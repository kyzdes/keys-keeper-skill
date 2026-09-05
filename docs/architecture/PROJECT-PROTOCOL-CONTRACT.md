# KK3 project protocol contract

Status: implemented runtime and synthetic coverage, with
[cross-author internal review and independent byte tests](PROJECT-PROTOCOL-INDEPENDENT-REVIEW.md).
No external security audit or production claim. This is a new format, not a KK2
mode. The durable state and authorization obligations below are part of the format.

## Wire and cryptographic suite

Every record is exactly `{profile,kind,payload,signature}`. `profile` is
`KK3-projects-v1`; kinds are `policy`, `snapshot`, `create`, `receipt`,
`scope-key-wrap`, `revocation`, `invitation`, `enrollment-request`,
`enrollment-answer`. Unknown fields and versions fail closed.
Identifiers are canonical lowercase UUID4. Integers are signed 64-bit JSON values,
with positive epochs/versions/generations, nonnegative checkpoint/revision values.
Floats, duplicate JSON keys, alternate base64 forms and noncanonical byte inputs
are rejected. Dict inputs are defensively copied and validated. Canonical JSON
is UTF-8, sorted keys, no spaces, unescaped Unicode, without floats. Binary values
are URL-safe unpadded base64; hashes are lowercase SHA-256 hex.

Signature is Ed25519 over:
`b"keys-keeper/KK3-projects-v1/signature/" + kind_ascii + b"\0" + canonical(body)`
where body is exactly `{profile,kind,payload}`. `canonical_hash(record)` hashes the
complete canonical record, including signature. Signatures authenticate ciphertext
and every context field before decryption. The master's Ed25519 public key MUST be
pinned from a trusted enrollment channel, not taken from a relay response.

Snapshots use a fresh 96-bit random nonce and AES-256-GCM with an independently
random 32-byte scope epoch key. Every client limits a signed epoch to
`MAX_EPOCH_PUBLICATIONS = 2**16` snapshots, counted as `sequence -
policy.checkpoint_sequence`. At the limit the master generates a new key and
advances the epoch before another publication. A same-epoch policy cannot change
its checkpoint and reset the counter. This gives a random nonce collision bound
of approximately 2.7e-20 per epoch for dispatched snapshots, independent of relay
quotas. Immutable operation retries reuse the exact ciphertext; the application
does not re-encrypt a retry. Local master state rollback or a master that reuses
keys across epochs remains outside this guarantee; there is no forward secrecy
claim. Scope key wraps and create messages use fresh
X25519 ephemeral keys, a fresh 32-byte salt, HKDF-SHA256 and AES-256-GCM.
HKDF input key material is X25519 shared secret. Its info is
`domain + b"kdf/" + kind_ascii + b"\0" + ephemeral_public_bytes + canonical(context)`.
GCM AAD is `domain + b"aead/" + kind_ascii + b"\0" + canonical(context)` where domain
is `b"keys-keeper/KK3-projects-v1/"`. Sealed public-key objects are exactly
`{ephemeral_public_key,salt,nonce,ciphertext}`; snapshots omit the first two fields.
Ciphertext contains the GCM tag. Low-order X25519 shared-secret failures are rejected.

This explicitly named X25519/HKDF-SHA256/AES-256-GCM construction uses maintained
`cryptography` primitives already required by the package. **It is not HPKE** and
makes no RFC 9180 conformance claim. Internal review is recorded in the linked
decision; using standard primitives is not proof that composition or state
transitions are secure, and external security review remains separate.

## Policy

Required payload fields:

- `scope_id`, `vault_id`, `master_device_id`: UUID4.
- `version`, `epoch`: positive monotonically increasing integers.
- `master_public_key`, `inbox_public_key`: Ed25519/X25519 public bytes in base64.
- `master_token_hash`: SHA-256 hex of a high-entropy scoped HTTP bearer token.
- `parent_policy_hash`: null only for version 1; otherwise previous signed policy hash.
- `checkpoint_sequence`, `checkpoint_hash`: latest trusted snapshot before this
  policy's publication. Both zero/null initially; a positive sequence requires a hash.
- `grants`: bounded list of exact objects `{grant_id,generation,device_id,role,
  signing_public_key,agreement_public_key,token_hash}`. Role is reader/contributor.
  Device, grant, signing-key, agreement-key and token identities must be unique.
  Master identity/keys/token may not appear as grants.

`authorize_grant` only accepts `read` and `create`; only contributor has create.
It receives an **already cryptographically verified policy payload**. This helper
is not a signature verifier. Relay token comparisons must be constant-time;
tokens themselves must have at least 256 bits of entropy. Token hashes are public
metadata, not password verifiers or independent end-to-end authorization.

A policy transition must extend the exact prior hash and version, cannot regress
checkpoint or epoch, and can advance epoch only by one. Any grant change requires
an epoch increment. A changed active grant needs a fresh grant UUID and a higher
generation. Inbox key/master device migrations are deliberately rejected because
a safe inbox migration needs retained decryption keys and recovery handling.

## Records and authorization

All non-policy records bind `scope_id,vault_id,epoch,policy_version,policy_hash`.

- Snapshot adds `sequence,parent_hash,sealed`; master signature only. Sequence 1
  has null parent. Supplied minimum sequence is exclusive, and policy checkpoint
  is exclusive. Callers accepting subsequent individual chain records pass the
  expected parent hash and persist the resulting checkpoint atomically. A latest
  full snapshot may skip intervening snapshots only under the explicitly trusted
  master/latest-state policy; a malicious relay can still withhold newer state.
- Scope key wrap adds `device_id,grant_id,generation,recipient_public_key,
  grant_hash,sealed`. Master signs; recipient, agreement key and full grant are
  checked against the signed policy before unwrapping. Only the key for this
  scope/epoch is wrapped; no master seed or full-vault key is accepted implicitly.
- Create adds `device_id,grant_id,generation,request_id,operation,inbox_public_key,
  sealed`. Operation must be `create`. Contributor signs with the device key from
  the pinned-master-signed policy. Encryption targets only the independent master
  inbox key. Plaintext is exactly `{schema_version:1,entry,secret,passphrase}`;
  entry is exactly `{name,type,fields,tags,note,refs}`. ID/backend account/update/
  delete/provenance/distribution/scope assignment fields are not permitted.
  The importer additionally validates complete Entry semantics, reserved names,
  reference boundaries and collision rules before assigning its own new UUID.
- Receipt adds `device_id,grant_id,generation,request_id,submission_hash,status,
  canonical_entry_id,revision`. Master signs; request and complete submission hash
  must match. Accepted/published require an entry UUID and positive revision;
  conflict/rejected/quarantined require null entry ID and revision zero.
- Revocation adds `device_id,grant_id,generation`. Master signature binds the
  exact grant and policy. Relay must durably block this grant immediately and
  finish rekey in a later atomic policy/snapshot/wrap transaction. A revocation
  by itself does not prevent decryption with an already-held epoch key.

- Invitation adds `invite_id,expires_at,endpoint` and has a master signature.
  Verification requires caller-supplied current UTC epoch seconds and rejects
  expiry at or before that time. HTTPS is mandatory except loopback HTTP for tests;
  credentials, query, fragment, whitespace and control characters are rejected.
  The endpoint is signed verbatim. Callers set a short issuance TTL, store active
  one-time invite IDs and consume them transactionally with grant issuance. The
  signature/expiry check alone is not one-time-use enforcement. Device public-key
  response authenticity still requires explicit fingerprint confirmation.

## Public Python API

All records/payloads return plain dicts; all private/public cryptographic key inputs
are 32-byte `bytes`. The base safe exception is `ProtocolError`, with subclasses
`ValidationError`, `AuthenticationError`, `AuthorizationError`, `ReplayError`.
Errors never interpolate caller data or expose key representations.

```python
generate_key() -> bytes
signing_public_key(private_key) -> bytes
agreement_public_key(private_key) -> bytes
encode_key(key) -> str
decode_key(encoded) -> bytes
canonical_bytes(value, *, maximum=MAX_RECORD_SIZE) -> bytes
canonical_hash(value) -> str
parse_record(blob_or_dict, *, maximum=MAX_RECORD_SIZE) -> dict
sign_policy(payload, master_private_key) -> dict
verify_policy(record, pinned_master_public_key, *, expected_scope_id=None,
              expected_vault_id=None, minimum_version=0, minimum_epoch=0) -> dict
validate_policy_transition(old_record, new_record, pinned_master_public_key) -> dict
authorize_grant(verified_policy_payload, device_id, operation, *,
                grant_id=None, generation=None) -> dict
build_snapshot(payload, policy, pinned_key, master_private_key, scope_key, *,
               sequence, parent_hash=None) -> dict
verify_snapshot(record, policy, pinned_key, *, minimum_sequence=0,
                expected_parent_hash=None) -> dict
open_snapshot(record, policy, pinned_key, scope_key, *, minimum_sequence=0,
              expected_parent_hash=None) -> dict
wrap_scope_key(scope_key, policy, pinned_key, master_private_key, device_id) -> dict
verify_scope_key_wrap(record, policy, pinned_key, device_id=None, *,
                      expected_device_id=None) -> dict
unwrap_scope_key(record, policy, pinned_key, device_id, device_private_key) -> bytes
validate_create_payload(payload) -> dict
build_create(payload, policy, pinned_key, device_id, device_private_key, *, request_id) -> dict
verify_create(record, policy, pinned_key, *, current_policy=None) -> dict
open_create(record, policy, pinned_key, inbox_private_key, *, current_policy=None) -> dict
build_receipt(submission, policy, pinned_key, master_private_key, *, status,
              canonical_entry_id=None, revision=0) -> dict
verify_receipt(record, submission, policy, pinned_key) -> dict
build_revocation(policy, pinned_key, master_private_key, *, device_id) -> dict
verify_revocation(record, policy, pinned_key) -> dict
build_invitation(policy, pinned_key, master_private_key, *, invite_id, expires_at, endpoint) -> dict
verify_invitation(record, policy, pinned_key, *, now) -> dict
```

## Durable state obligations and limits

Current policy passed to `verify_create` must already have an authenticated chain
from the submission policy, or a trusted persisted current checkpoint. Matching
IDs or a higher version alone is not proof of chain continuity. Removing then
regranting a device requires a fresh grant UUID and higher persisted generation.
The engine/relay must remember spent grant IDs and generation high-watermarks across
absence, crashes and restore; adjacent policy comparison cannot prove their history.

Create replay is deliberately accepted cryptographically for retry. Store immutable
`(scope,device,grant,request)` plus complete submission hash and durable outcome;
the same identity with different bytes is a conflict. Receipt verification does not
perform imports. Accepted receipt emission occurs only after durable atomic import.

Persist policy, snapshot checkpoint, active grant state and recipient wraps atomically
with CAS. Membership changes, new enrollment and removed distributed entries need
fresh random scope keys and a full snapshot. The crypto layer cannot prove a caller
actually generated a different random key or included the correct entry set. Check
trusted minimum checkpoints on every client path, and compare same-version policy
hashes for equivocation; don't load a stale backup and treat it as current.

Limits: 24 MiB wire record, 16 MiB snapshot plaintext, 1 MiB create plaintext,
256 KiB signed policy, 512 grants, depth 24, 200,000 JSON nodes. Creation entry
names/types are bounded to 256 characters, note to 65,536, each secret/passphrase
to 512 Ki characters (and aggregate UTF-8 JSON size to 1 MiB). No compression.
Relay request/body quotas must run before JSON parsing. These primitives provide
neither denial-of-service isolation against an unbounded HTTP body nor OS-user/root
isolation, secure memory erasure, external credential revocation or rollback-proof
storage. Independent security review and cross-platform integration remain required.


## Relay review corrections and verified integration boundary

The relay's bootstrap retry checks immutable version-1 policy history, so a lost
bootstrap response can be retried after subsequent publications. Publish operations
reserve their IDs and update policies, grant history, wraps and snapshots in one
SQLite transaction. Failed wraps do not leave partial policy/grant state behind.
Historical grant IDs and device generation maxima remain durable across removal.

Immediate revocation retries verify the original historical signed policy and exact
stored block even after a rollover; they never unblock a regranted device. State
returns only blocks still applying to current grants, while historical blocks stay
stored. `rekey=pending` means the blocked grant is still in current policy;
`rekey=complete` means a later validated policy removed it. This says nothing about
external API/SSH credential rotation or copies previously obtained by a recipient.

Receipts progress from accepted to published only for the same canonical UUID with
nondecreasing revision. A late accepted retry cannot regress a published receipt.
An unaccepted queued create cannot receive its first successful receipt after
revocation or loss of create rights. Previously accepted records may finish their
publication after later revocation. Other receipt outcomes remain immutable.

Malformed nested policy/create/receipt objects are bounded and type-checked before
lookup values reach SQLite. Recursive HTTP JSON errors become safe client errors.
Duplicate authentication headers are rejected. ProjectClient adds bounded JSON
shape/type validation around the inherited HTTPS/no-redirect transport.

True HTTP/SQLite tests cover authorization and scope isolation, replay/CAS races,
transaction rollback, enrollment and old-key isolation, historical grant reuse,
immediate revoke/retry/rekey, delayed encrypted creates, receipt transitions,
queue count/byte/rate quotas, hostile inputs, restart and secret-safe persistence.
These are synthetic integration tests; they do not establish independent protocol
review or production deployment. The original pending-only quota gap is addressed by D04 below;
physical SQLite/WAL and backup headroom remain operational requirements.

## D01 local revocation and recoverable dispatch

Local `request_revoke(device_id)` records a master-signed revocation and its source
policy in encrypted state before HTTP, job locks or pending publication replay.
`local_revocations` is monotonic: absence from a relay response never removes a
locally authored or previously authenticated block. An observed signed block is
saved even when pull is then denied or a local backend/install later fails.
Replica outbox retransmission checks the current locally pinned grant and durable
block set before each HTTP dispatch; an already observed revoke stops queued work.

Network jobs use a separate `sync-job` lock. Short state/catalog mutation locks
are released before HTTP; local revocation and outbox creation can proceed while
another job awaits the network. Publication preparation has a durable `attempted`
marker. A revoke can cancel a preparation not yet dispatched. A previously
attempted publication containing a revoked grant is never reissued: the engine
may adopt its already-signed committed HEAD through read-only verification, then
rekey. If its outcome cannot be established, it retains state and reports recovery
required. A relay claiming absence cannot prove an in-flight write never committed.
Revocation cannot unsend an HTTP operation authorized before the durable barrier.

Importer startup calls `recover` against the verified current policy and the latest
local block set before fetching new submissions. Receipt HTTP delivery occurs after
local mutation locks are released. Already durable accepted imports retain their
outcomes; unaccepted revoked work is quarantined. Grant history starts with the
known pinned policy even when an older state file has an empty `used_grants` list.

Replica `trusted_checkpoint` is an authenticated anti-rollback anchor;
`applied_checkpoint` records an installed generation. An enrollment anchor alone
never skips initial installation. The compatibility `checkpoint` mirrors applied
state on replicas and committed state on masters. For an offline replica, the
engine verifies the missing chain and supplies the exact active generation as
`verified_ancestor` when installing the authoritative full snapshot.

## D02 challenge-bound enrollment

`enrollment-request` is signed by the proposed device signing key and binds the
invitation/source context, invitation hash, device UUID, independent signing and
agreement keys, bearer-token hash, requested role, request UUID and a random
32-byte challenge. It is a request, not a grant. The master must compare its device
fingerprint through the approved user enrollment flow.

`enrollment-answer` is master-signed and binds the request hash/challenge, device,
new grant identity, current policy, exact activated snapshot hash/sequence and
recipient wrap hash. The final epoch and policy version must be newer than the
invitation's source; grant keys, token hash and role must match the request. Raw
bearer tokens/private keys are never part of the exchange files. The runtime owns
one-time invite consumption, durable intended-grant allocation and local challenge
matching. Verification is not a substitute for those persistent state checks.

Answer expiration is capped to the original invitation expiration. The MVP requires
finishing enrollment before that deadline. An expired completed grant requires an
explicit revoke/rekey and new invitation; retry must not silently allocate duplicate
identities or leave an unused grant untracked. Root/master unavailability prevents
issuing this fresh enrollment proof; an old signed relay HEAD is not fresh proof.

```python
build_enrollment_request(invitation, source_policy, pin, device_signing_private, *,
    device_id, agreement_public_key, token_hash, role, request_id, challenge, now)
verify_enrollment_request(record, invitation, source_policy, pin, *, now)
build_enrollment_answer(request, invitation, source_policy, current_policy, pin,
    master_private, *, snapshot, wrap, now, expires_at)
verify_enrollment_answer(answer, request, invitation, source_policy, current_policy,
    pin, *, snapshot, wrap, now)
```

## D04 total relay resource bounds

`SyncServerApp(..., project_limits=ProjectRelayLimits(...))` accepts explicit positive
integer budgets. Defaults are 512 MiB/20,000 stored records per scope and 2 GiB/
100,000 records across KK3. Every insert/update checks the totals in the same
SQLite transaction; overflow rolls back and returns `storage_full`. No history,
dedup record or pending key is automatically evicted. Counts include policies,
snapshots, wraps, grants, blocks, operations, submissions/receipts and scope state.
Byte accounting covers stored UTF-8 record fields plus a 256-byte per-row allowance;
it is a logical record budget, not an exact physical SQLite filesystem limit.

A separate bounded reserve (32 MiB/2,000 records per scope; 128 MiB/10,000 globally)
permits immediate blocks, terminal receipts and policies removing recipients when
normal history is full. Exhausting even that reserve fails closed; the master's
local revoke remains effective and rekey remains pending until capacity is restored.

At most 32 accepted connections and four concurrent KK3 handlers run by default.
Sockets receive a ten-second inactivity timeout from acceptance, including header
reads. Excess connections close before worker creation; excess KK3 work returns
`relay_busy`. Authentication precedes request-body allocation, and endpoint body
limits run before body reads. Header/body trickling and adversarial crypto/JSON
work still require reverse-proxy rate limits and an OS process memory/CPU budget
in a production deployment. A timeout is an inactivity deadline, not an absolute
wall-clock deadline for an endlessly trickling connection.

Client history traversal stops after 256 links or 64 MiB of cumulative decoded
records and requires a trusted checkpoint refresh. Retention cannot prune required
ancestry until the separately authenticated refresh procedure is available.
Provision physical database/index/WAL/backup headroom beyond the logical budgets;
KK2 retention is unchanged and is not charged to the KK3 record counters.

## Publication queue and concurrent enrollment

The master captures pending desired revisions before metadata preview and stores
that capture in the encrypted prepared publication. It marks only captured
revisions applied after verifying the remote ACK. That metadata update precedes
clearing the prepared operation, so restart can repeat the same operation and
apply the same capture idempotently. A newer desired revision remains pending.
When metadata preview matches the last acknowledged source revision and membership
is unchanged, the engine reconciles the captured intents without reading secret
values again. Source revision is revalidated under the local mutation boundary
when a new payload does require reading values.

Enrollment uses `ProjectMaster.add_grant(grant)` to merge one grant with current
committed membership under the independent network job lock. Supplying a complete
membership list derived outside that lock can overwrite another concurrent
approval; enrollment must not do so. The same grant is idempotent, differing
identity for an existing device is rejected, and local revoke never waits for
the network job lock.
