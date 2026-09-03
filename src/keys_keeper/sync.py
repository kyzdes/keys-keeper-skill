"""S3 sync engine: snapshots, id-keyed merge, and a git-like version chain.

Layout under the configured prefix:
  versions/NNNNNN.json   immutable commit: {version, parent, device, ts, snapshot, entries_hash}
  snapshots/NNNNNN-<device>.kk   immutable AES-256-GCM blob == a `keys export` blob
  HEAD                   cache: {version, snapshot} (rebuildable by listing versions/)

Concurrency: a push writes its snapshot, then creates versions/<N+1>.json with
If-None-Match:* (create-if-absent). Whoever creates it first wins; the loser
re-pulls, re-merges, and retries. Because version objects are immutable and
counter-addressed, a retry never corrupts state.

Merge is keyed by entry id (UUID), last-write-wins on `updated_at` with a
deterministic content tiebreak (second-resolution timestamps can't order
same-second edits). Deletes propagate via tombstones; a tombstone wins over a
live entry with `updated_at <= deleted_at`. This module NEVER calls cmd_import
(which is name-keyed and tombstone-blind).
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field, replace

from keys_keeper.backend import KeychainBackend, KeychainError
from keys_keeper.crypto import BadPassword, decrypt_blob, encrypt_blob
from keys_keeper.models import (
    Entry,
    ValidationError,
    now_iso,
    validate_snapshot_payload,
)
from keys_keeper.service import ConcurrentMutation, VaultService
from keys_keeper.store import SCHEMA_VERSION, MetadataStore
from keys_keeper.sync_remote import NotFound, PreconditionFailed, TransportError

_MAGIC = b"KK1\x00"
HEAD_KEY = "HEAD"


def vkey(n: int) -> str:
    return f"versions/{n:06d}.json"


def skey(n: int, device: str) -> str:
    return f"snapshots/{n:06d}-{device}.kk"


def _parse_version(key: str) -> int | None:
    # "versions/000042.json" -> 42 ; tolerant of counters that outgrow 6 digits
    # (so listing-based tip discovery never silently drops a version).
    base = key.rsplit("/", 1)[-1]
    if not base.endswith(".json"):
        return None
    stem = base[:-5]
    return int(stem) if stem.isdigit() else None


def _dedupe_tombstones(tombs: list[dict]) -> list[dict]:
    """Keep the latest deletion per id."""
    by_id: dict[str, dict] = {}
    for t in tombs:
        cur = by_id.get(t["id"])
        if cur is None or t["deleted_at"] >= cur["deleted_at"]:
            by_id[t["id"]] = t
    return sorted(by_id.values(), key=lambda t: t["id"])


# ---------------- snapshots ----------------

def _safe_secret(backend: KeychainBackend, account: str) -> str | None:
    try:
        return backend.get(account).unseal()
    except KeychainError:
        return None


def build_snapshot_payload(store: MetadataStore, backend: KeychainBackend) -> dict:
    """Full vault as a plaintext payload (entries + secrets + tombstones).

    Reserved kk:sync-* accounts are never entries, so they're never included.
    """
    entries = []
    for e in store.list():
        rec = e.to_dict()
        rec["_secret"] = _safe_secret(backend, e.id)
        rec["_secret_passphrase"] = _safe_secret(backend, e.id + ":passphrase")
        entries.append(rec)
    return {"schema_version": SCHEMA_VERSION, "entries": entries,
            "tombstones": store.tombstones()}


def encrypt_snapshot(payload: dict, *, passphrase: str) -> bytes:
    blob = encrypt_blob(json.dumps(payload).encode("utf-8"), password=passphrase)
    if blob[:4] != _MAGIC:  # S1: never ship a non-encrypted blob to the remote
        raise RuntimeError("refusing to upload a blob without the KK1 magic header")
    return blob


def decrypt_snapshot(blob: bytes, *, passphrase: str) -> dict:
    raw = decrypt_blob(blob, password=passphrase)  # raises BadPassword (S9)
    payload = json.loads(raw)
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise BadPassword("snapshot payload malformed")
    payload.setdefault("tombstones", [])
    return payload


def content_hash(payload: dict) -> str:
    """Stable hash of vault content (metadata + secret digests, never plaintext).

    Used to detect 'nothing changed vs remote' so push never makes empty commits.
    """
    items = []
    for rec in sorted(payload["entries"], key=lambda r: r["id"]):
        meta = {k: v for k, v in rec.items()
                if k not in ("_secret", "_secret_passphrase")}
        sd = hashlib.sha256((rec.get("_secret") or "").encode()).hexdigest()
        pd = hashlib.sha256((rec.get("_secret_passphrase") or "").encode()).hexdigest()
        items.append({"m": meta, "s": sd, "p": pd})
    body = json.dumps(
        {"entries": items,
         "tombstones": sorted(payload["tombstones"], key=lambda t: t["id"])},
        sort_keys=True,
    )
    return hashlib.sha256(body.encode()).hexdigest()


# ---------------- pure merge ----------------

@dataclass
class MergeResult:
    entries: list[Entry]
    tombstones: list[dict]
    remote_win_ids: set[str] = field(default_factory=set)   # secret comes from remote
    secret_delete_ids: set[str] = field(default_factory=set)  # tombstoned, purge secret
    changed: bool = False


def _sort_key(e: Entry):
    # newer updated_at wins; deterministic content tiebreak for same-second edits.
    return (e.updated_at, json.dumps(e.to_dict(), sort_keys=True))


def _suffix_name(name: str, id_: str) -> str:
    short = id_.split(":")[-1].replace("-", "")[:6] or "dup"
    return f"{name[:56]}-{short}"


def _latest_tombstone(local: dict | None, remote: dict | None) -> dict | None:
    if local and remote:
        return local if local["deleted_at"] >= remote["deleted_at"] else remote
    return local or remote


def _live_winner(
    local: Entry | None,
    remote: Entry | None,
) -> tuple[Entry | None, str | None]:
    if local is None:
        return (remote, "remote") if remote is not None else (None, None)
    if remote is None:
        return local, "local"
    if _sort_key(remote) > _sort_key(local):
        return remote, "remote"
    return local, "local"


def _resolve_entry_state(
    id_: str,
    local_entry: Entry | None,
    remote_entry: Entry | None,
    local_tombstone: dict | None,
    remote_tombstone: dict | None,
) -> tuple[Entry | None, str | None, dict | None]:
    tombstone = _latest_tombstone(local_tombstone, remote_tombstone)
    winner, source = _live_winner(local_entry, remote_entry)
    if winner is not None and (
        tombstone is None or winner.updated_at > tombstone["deleted_at"]
    ):
        return winner, source, None
    if tombstone is None:
        return None, None, None
    name = tombstone.get("name") or (
        local_entry.name
        if local_entry is not None
        else remote_entry.name
        if remote_entry is not None
        else ""
    )
    return None, None, {
        "id": id_,
        "name": name,
        "deleted_at": tombstone["deleted_at"],
    }


def _disambiguate_live_names(
    live: dict[str, tuple[Entry, str]],
) -> dict[str, tuple[Entry, str]]:
    result = dict(live)
    by_name: dict[str, list[str]] = {}
    for id_, (entry, _source) in result.items():
        by_name.setdefault(entry.name, []).append(id_)
    for name, ids in by_name.items():
        if len(ids) <= 1:
            continue
        ids.sort(key=lambda id_: _sort_key(result[id_][0]), reverse=True)
        for loser in ids[1:]:
            entry, source = result[loser]
            result[loser] = (
                replace(entry, name=_suffix_name(name, entry.id)),
                source,
            )
    return result


def _metadata_changed(
    local_entries: list[Entry],
    local_tombstones: list[dict],
    merged_entries: list[Entry],
    merged_tombstones: list[dict],
) -> bool:
    local_entry_records = sorted(
        (entry.to_dict() for entry in local_entries),
        key=lambda record: record["id"],
    )
    merged_entry_records = [entry.to_dict() for entry in merged_entries]
    local_tombstone_records = sorted(local_tombstones, key=lambda item: item["id"])
    return (
        merged_entry_records != local_entry_records
        or merged_tombstones != local_tombstone_records
    )


def merge(local_entries: list[Entry], local_tombs: list[dict],
          remote_entries: list[Entry], remote_tombs: list[dict]) -> MergeResult:
    local_by_id = {e.id: e for e in local_entries}
    remote_by_id = {e.id: e for e in remote_entries}
    ltomb = {t["id"]: t for t in local_tombs}
    rtomb = {t["id"]: t for t in remote_tombs}
    all_ids = set(local_by_id) | set(remote_by_id) | set(ltomb) | set(rtomb)

    live: dict[str, tuple[Entry, str]] = {}   # id -> (entry, 'local'|'remote')
    tombs: dict[str, dict] = {}
    remote_win_ids: set[str] = set()

    for id_ in all_ids:
        winner, source, tombstone = _resolve_entry_state(
            id_,
            local_by_id.get(id_),
            remote_by_id.get(id_),
            ltomb.get(id_),
            rtomb.get(id_),
        )
        if winner is not None and source is not None:
            live[id_] = (winner, source)
            if source == "remote":
                remote_win_ids.add(id_)
        elif tombstone is not None:
            tombs[id_] = tombstone

    # deterministic name disambiguation among live winners (F19)
    live = _disambiguate_live_names(live)

    merged_entries = sorted((entry for entry, _source in live.values()), key=lambda e: e.id)
    merged_tombstones = sorted(tombs.values(), key=lambda item: item["id"])

    # secrets to purge: ids now tombstoned that were live locally
    secret_delete_ids = set(tombs) & set(local_by_id)

    changed = _metadata_changed(
        local_entries,
        local_tombs,
        merged_entries,
        merged_tombstones,
    )

    return MergeResult(merged_entries, merged_tombstones, remote_win_ids,
                       secret_delete_ids, changed)


# ---------------- engine ----------------

@dataclass
class _Tip:
    version: int
    snapshot: str
    entries_hash: str | None


@dataclass
class SyncStatus:
    remote_version: int | None
    local_synced_version: int | None
    dirty: bool


class RollbackDetected(TransportError):
    """A normal pull/push saw a remote tip OLDER than the highest version this
    client has ever adopted. A compromised/MITM bucket can silently repoint HEAD
    (or swap a snapshot pointer) to an older AUTHENTIC commit to resurrect
    deleted entries. We refuse it on the normal path; `keys sync rollback` is the
    one explicit escape hatch.

    Subclasses TransportError so the CLI/web _loud wrappers already surface it as
    a clean error instead of a traceback.
    """


class SnapshotIntegrityError(TransportError):
    """A decrypted snapshot's recomputed content hash did not match the
    entries_hash recorded in the commit object the client fetched. The blob is
    AEAD-authentic on its own, but it is NOT the snapshot this commit promised —
    a swapped/mismatched pointer. Refuse it.
    """


class SnapshotValidationError(TransportError):
    """A decrypted snapshot contains unsafe or unsupported metadata."""


class SyncEngine:
    """Drives push/pull/rollback/gc over a RemoteStore (S3Remote or a fake)."""

    def __init__(self, *, remote, store: MetadataStore, backend: KeychainBackend,
                 device_id: str, retain_snapshots: int = 20, max_retries: int = 5,
                 paths=None, cas_supported: bool = True):
        self.remote = remote
        self.store = store
        self.backend = backend
        self.device_id = device_id
        self.retain_snapshots = retain_snapshots
        self.max_retries = max_retries
        self.paths = paths
        # When the provider honours If-None-Match (verified at setup), the
        # conditional PUT is the serialization point. When it does NOT, we fall
        # back to a read-back-after-write check in _try_commit so a clobbered
        # commit is still detected and retried instead of silently lost.
        self.cas_supported = cas_supported

    # -- remote tip discovery --
    def _list_versions(self) -> list[int]:
        out = []
        for k in self.remote.list_objects("versions/"):
            n = _parse_version(k)
            if n is not None:
                out.append(n)
        return out

    def _tip_version(self) -> int | None:
        try:
            head = json.loads(self.remote.get_object(HEAD_KEY))
            n = int(head["version"])
            return n
        except NotFound:
            pass
        except (ValueError, KeyError, TypeError):
            pass
        ns = self._list_versions()
        return max(ns) if ns else None

    def _current_tip(self) -> _Tip | None:
        n = self._tip_version()
        if n is None:
            return None
        try:
            commit = json.loads(self.remote.get_object(vkey(n)))
        except NotFound:
            # HEAD pointed at a commit that no longer exists (aggressive peer
            # GC, an interrupted push, or read-after-write lag). HEAD is only a
            # cache — self-heal by listing the real versions and retrying.
            ns = [v for v in self._list_versions() if v != n]
            if not ns:
                return None
            n = max(ns)
            commit = json.loads(self.remote.get_object(vkey(n)))
        return _Tip(n, commit["snapshot"], commit.get("entries_hash"))

    # -- snapshot integrity: bind the (authenticated) blob to the commit meta --
    def _decrypt_verified(self, tip: _Tip, passphrase: str) -> dict:
        """Decrypt the snapshot the commit points at, then RECOMPUTE its content
        hash and require it to equal the commit's entries_hash.

        AES-GCM already proves the blob was sealed by someone who knew the
        passphrase, but it does NOT prove THIS blob is the one THIS commit
        promised: a hostile bucket can point a commit at an older authentic
        snapshot. Re-deriving the hash and comparing it to the commit metadata
        the client already fetched closes that gap — with no change to the
        ciphertext/AAD format (the hash is computed client-side over plaintext).
        Legacy commits with no entries_hash (None) can't be checked, so they're
        accepted as before.
        """
        blob = self.remote.get_object(tip.snapshot)
        payload = decrypt_snapshot(blob, passphrase=passphrase)
        try:
            # Validate before content_hash touches attacker-influenced types.
            # The apply path validates again when it consumes the normalized
            # Entry/tombstone objects; keeping this guard here makes malformed
            # authenticated blobs fail with a bounded domain error.
            validate_snapshot_payload(payload)
        except ValidationError as ex:
            raise SnapshotValidationError(
                f"snapshot {tip.version} failed metadata validation: {ex}"
            ) from ex
        if tip.entries_hash is not None:
            actual = content_hash(payload)
            if actual != tip.entries_hash:
                raise SnapshotIntegrityError(
                    f"snapshot content hash mismatch for version {tip.version}: "
                    f"the commit points at a snapshot that is not the one it "
                    f"recorded (possible rollback/pointer-swap); refusing to apply"
                )
        return payload

    # -- apply a remote snapshot into the local vault --
    def _apply_remote(self, tip: _Tip, passphrase: str) -> int:
        payload = self._decrypt_verified(tip, passphrase)
        try:
            remote_entries, remote_tombstones = validate_snapshot_payload(payload)
        except ValidationError as ex:
            raise SnapshotValidationError(
                f"snapshot {tip.version} failed metadata validation: {ex}"
            ) from ex
        remote_secrets = {
            r["id"]: (r.get("_secret"), r.get("_secret_passphrase"))
            for r in payload["entries"]
        }
        for _ in range(self.max_retries):
            local = self.store.snapshot()
            result = merge(local.entries, local.tombstones,
                           remote_entries, remote_tombstones)
            if not result.changed:
                return 0
            try:
                self._apply_merge_result(
                    result,
                    remote_secrets,
                    expected_revision=local.revision,
                )
            except ConcurrentMutation:
                continue
            return len(result.remote_win_ids) + len(result.secret_delete_ids)
        raise TransportError(
            "local vault changed repeatedly while sync was applying; retry the command"
        )

    def _apply_merge_result(
        self,
        result: MergeResult,
        remote_secrets: dict,
        *,
        expected_revision: str,
    ) -> None:
        # Pre-validate (F20/KI-002): every remote-win id must have a secret slot.
        for id_ in result.remote_win_ids:
            if id_ not in remote_secrets:
                raise TransportError(f"remote snapshot missing secret for {id_}")
        writes: dict[str, str] = {}
        for id_ in result.remote_win_ids:
            sec, pf = remote_secrets[id_]
            if sec is not None:
                writes[id_] = sec
            if pf is not None:
                writes[id_ + ":passphrase"] = pf
        deletes: list[str] = []
        for id_ in result.secret_delete_ids:
            deletes.extend((id_, id_ + ":passphrase"))
        VaultService(self.store, self.backend).apply_snapshot(
            result.entries,
            result.tombstones,
            secret_writes=writes,
            secret_deletes=deletes,
            expected_revision=expected_revision,
        )

    # -- anti-rollback watermark (monotonic highest-seen version) --
    def _watermark(self) -> int | None:
        v = self._read_state().get("highest_version")
        return v if isinstance(v, int) else None

    def _guard_not_rolled_back(self, tip: _Tip) -> None:
        """Refuse a remote tip strictly older than the highest version this
        client has ever adopted. First pull (no watermark) is always allowed.
        The explicit `rollback()` path never calls this — it is the one
        sanctioned way to move backwards.
        """
        wm = self._watermark()
        if wm is not None and tip.version < wm:
            raise RollbackDetected(
                f"remote tip is version {tip.version} but this device has already "
                f"adopted version {wm}; refusing a silent rollback. If this is "
                f"intentional, run `keys sync rollback {tip.version}`."
            )

    # -- public ops --
    def pull(self, passphrase: str) -> int:
        tip = self._current_tip()
        if tip is None:
            return 0
        self._guard_not_rolled_back(tip)
        n = self._apply_remote(tip, passphrase)
        self._write_state(version=tip.version)
        return n

    def push(self, passphrase: str) -> int:
        last_err = None
        for _ in range(self.max_retries):
            tip = self._current_tip()
            if tip is not None:
                self._guard_not_rolled_back(tip)
            pulled = self._apply_remote(tip, passphrase) if tip is not None else 0
            payload = build_snapshot_payload(self.store, self.backend)
            if tip is None and not payload["entries"] and not payload["tombstones"]:
                return pulled  # F42: never publish a contentless first version
            if tip is not None and tip.entries_hash == content_hash(payload):
                self._write_state(version=tip.version)
                return pulled  # F42: nothing new locally -> no empty commit
            committed = self._try_commit(payload, tip.version if tip else None,
                                         passphrase)
            if committed is None:
                last_err = "concurrent writer"
                continue  # lost the CAS race; re-pull, re-merge, retry
            return pulled + 1
        raise TransportError(f"push: exceeded {self.max_retries} retries ({last_err})")

    def _try_commit(self, payload: dict, parent: int | None, passphrase: str,
                    *, reset_watermark: bool = False) -> int | None:
        """One CAS attempt: write snapshot, then create the next version object
        with If-None-Match:*. Returns the new version, or None if it lost the
        race (caller retries)."""
        new_version = (parent or 0) + 1
        snap_key = skey(new_version, self.device_id)
        blob = encrypt_snapshot(payload, passphrase=passphrase)
        self.remote.put_object(snap_key, blob)
        commit = {
            "version": new_version, "parent": parent, "device": self.device_id,
            "ts": now_iso(), "snapshot": snap_key, "entries_hash": content_hash(payload),
        }
        try:
            self.remote.put_object(vkey(new_version), json.dumps(commit).encode("utf-8"),
                                   if_none_match="*")
        except PreconditionFailed:
            self.remote.delete_object(snap_key)  # clean our orphan
            return None
        if not self.cas_supported and not self._owns_commit(new_version, commit):
            # Provider ignored If-None-Match and a peer overwrote (or was
            # overwritten by) us — read back and only the true owner proceeds.
            self.remote.delete_object(snap_key)
            return None
        self._write_head(new_version, snap_key)
        self._write_state(version=new_version, reset_watermark=reset_watermark)
        self._gc_quiet()
        return new_version

    def _owns_commit(self, version: int, commit: dict) -> bool:
        try:
            winner = json.loads(self.remote.get_object(vkey(version)))
        except (NotFound, TransportError):
            return False
        return (winner.get("device") == commit["device"]
                and winner.get("ts") == commit["ts"])

    def _commit_payload(self, payload: dict, passphrase: str,
                        *, safe_ids: set[str] | None = None,
                        reset_watermark: bool = False) -> int:
        """Commit a fixed payload as a new version WITHOUT pre-merging the tip
        (used by rollback, which intentionally overrides the current state).

        If a peer wins the race and its new tip introduces live ids we did NOT
        account for (not in `safe_ids`), refuse to overwrite — that would drop
        the peer's change. Surface a loud error so the user re-pulls and retries.
        """
        for _ in range(self.max_retries):
            tip = self._tip_version()
            if safe_ids is not None and tip is not None:
                self._guard_rollback_race(tip, passphrase, safe_ids)
            v = self._try_commit(payload, tip, passphrase,
                                 reset_watermark=reset_watermark)
            if v is not None:
                return v
        raise TransportError("commit: exceeded retries due to concurrent writers")

    def _guard_rollback_race(self, tip: int, passphrase: str, safe_ids: set[str]) -> None:
        try:
            commit = json.loads(self.remote.get_object(vkey(tip)))
            payload = decrypt_snapshot(self.remote.get_object(commit["snapshot"]),
                                       passphrase=passphrase)
        except (NotFound, TransportError, BadPassword):
            return
        try:
            entries, _ = validate_snapshot_payload(payload)
        except ValidationError as ex:
            raise SnapshotValidationError(
                f"snapshot {tip} failed metadata validation: {ex}"
            ) from ex
        unexpected = {entry.id for entry in entries} - safe_ids
        if unexpected:
            raise TransportError(
                f"rollback raced a concurrent change that added {len(unexpected)} "
                f"entr{'y' if len(unexpected) == 1 else 'ies'}; run `keys sync pull` "
                f"and retry the rollback so nothing is lost"
            )

    def rollback(self, version: int, passphrase: str) -> int:
        """Hard-restore the vault to snapshot `version`, then publish that exact
        state as a new commit so peers converge. Entries that exist now but not
        in the target are TOMBSTONED (absence alone wouldn't propagate a
        removal). Older history is left intact for a future rollback.
        """
        commit = json.loads(self.remote.get_object(vkey(version)))
        # Even on the explicit rollback path the snapshot must match its commit's
        # recorded hash — this is the one place we deliberately move backwards, so
        # a swapped pointer here would be the most dangerous. We do NOT apply the
        # watermark guard (rollback is the sanctioned way to go back), only the
        # content-integrity check.
        target_tip = _Tip(version, commit["snapshot"], commit.get("entries_hash"))
        payload = self._decrypt_verified(target_tip, passphrase)
        try:
            target_entries, target_tombstones = validate_snapshot_payload(payload)
        except ValidationError as ex:
            raise SnapshotValidationError(
                f"snapshot {version} failed metadata validation: {ex}"
            ) from ex
        target_secrets = {r["id"]: (r.get("_secret"), r.get("_secret_passphrase"))
                          for r in payload["entries"]}
        target_ids = {e.id for e in target_entries}
        local = self.store.snapshot()
        local_ids = {e.id for e in local.entries}

        now = now_iso()
        removed = [{"id": e.id, "name": e.name, "deleted_at": now}
                   for e in local.entries if e.id not in target_ids]
        tombs = _dedupe_tombstones(list(target_tombstones) + removed)

        writes: dict[str, str] = {}
        for id_ in target_ids:
            sec, pf = target_secrets[id_]
            if sec is not None:
                writes[id_] = sec
            if pf is not None:
                writes[id_ + ":passphrase"] = pf
        deletes: list[str] = []
        for id_ in local_ids - target_ids:
            deletes.extend((id_, id_ + ":passphrase"))
        try:
            VaultService(self.store, self.backend).apply_snapshot(
                target_entries,
                tombs,
                secret_writes=writes,
                secret_deletes=deletes,
                expected_revision=local.revision,
            )
        except ConcurrentMutation as ex:
            raise TransportError(
                "local vault changed during rollback; retry so no local change is lost"
            ) from ex
        # Commit the restored state directly — do NOT pre-merge the current tip,
        # which would re-resurrect exactly what we just rolled away. Guard the
        # commit so a concurrent peer-added entry isn't silently overwritten.
        local_payload = build_snapshot_payload(self.store, self.backend)
        safe_ids = target_ids | {t["id"] for t in tombs}
        # The freshly published commit becomes the new high-water mark; reset it
        # explicitly so a deliberate rollback re-anchors the monotonic guard
        # rather than tripping it on the next pull.
        return self._commit_payload(local_payload, passphrase, safe_ids=safe_ids,
                                    reset_watermark=True)

    def status(self) -> SyncStatus:
        try:
            remote_v = self._tip_version()
        except TransportError:
            remote_v = None
        state = self._read_state()
        return SyncStatus(
            remote_version=remote_v,
            local_synced_version=state.get("last_version"),
            dirty=self._is_dirty(remote_v),
        )

    def _is_dirty(self, remote_v: int | None) -> bool:
        if remote_v is None:
            return bool(self.store.list())
        try:
            commit = json.loads(self.remote.get_object(vkey(remote_v)))
        except (NotFound, TransportError):
            return True
        local_hash = content_hash(build_snapshot_payload(self.store, self.backend))
        return commit.get("entries_hash") != local_hash

    def gc(self) -> int:
        """Keep the newest `retain_snapshots` versions; delete older snapshot
        blobs + commit objects. Never touches the newest (HEAD-reachable) tip."""
        ns = sorted(self._list_versions())
        if len(ns) <= self.retain_snapshots:
            return 0
        doomed = ns[:-self.retain_snapshots]
        # tombstone GC horizon = oldest RETAINED commit ts (F13)
        oldest_kept_ts = None
        kept = ns[-self.retain_snapshots:]
        if kept:
            try:
                oldest_kept_ts = json.loads(
                    self.remote.get_object(vkey(kept[0]))).get("ts")
            except (NotFound, TransportError):
                oldest_kept_ts = None
        for n in doomed:
            try:
                commit = json.loads(self.remote.get_object(vkey(n)))
                self.remote.delete_object(commit["snapshot"])
            except (NotFound, TransportError):
                pass
            self.remote.delete_object(vkey(n))
        if oldest_kept_ts:
            self._gc_local_tombstones(oldest_kept_ts)
        return len(doomed)

    def _gc_local_tombstones(self, horizon_ts: str) -> None:
        self.store.prune_tombstones_before(horizon_ts)

    def _gc_quiet(self) -> None:
        try:
            self.gc()
        except TransportError:
            pass

    # -- HEAD cache + local state sidecar (no secrets) --
    def _write_head(self, version: int, snapshot: str) -> None:
        try:
            self.remote.put_object(
                HEAD_KEY,
                json.dumps({"version": version, "snapshot": snapshot}).encode("utf-8"),
            )
        except TransportError:
            pass  # HEAD is only a cache; lineage is recoverable by listing

    def _read_state(self) -> dict:
        if self.paths is None or not self.paths.sync_state_json.exists():
            return {}
        try:
            return json.loads(self.paths.sync_state_json.read_text())
        except (ValueError, OSError):
            return {}

    def _write_state(self, *, version: int | None = None,
                     reset_watermark: bool = False, **extra) -> None:
        if self.paths is None:
            return
        state = self._read_state()
        if version is not None:
            state["last_version"] = version
            # Monotonic anti-rollback watermark: only ever moves UP on the normal
            # path, so a later silent repoint to an older commit is detectable.
            # `reset_watermark` (set only by the explicit rollback) lets the user
            # deliberately move it back DOWN to the version they restored to.
            cur = state.get("highest_version")
            if reset_watermark:
                state["highest_version"] = version
            elif not isinstance(cur, int) or version > cur:
                state["highest_version"] = version
        state["last_sync_at"] = now_iso()
        state.update(extra)
        self.paths.ensure()
        try:
            self.paths.sync_state_json.write_text(json.dumps(state))
            try:
                os.chmod(self.paths.sync_state_json, 0o600)  # S11 (no-op on Windows)
            except OSError:
                pass
        except OSError:
            pass
