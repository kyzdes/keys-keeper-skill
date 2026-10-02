"""Legacy vault snapshots and deterministic merge shared by export and VPS sync.

Snapshots include secrets only for schema-v1/v2 vaults. Catalog schema v3 uses
its separate project protocol and cannot be serialized as a full-vault snapshot.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace

from keys_keeper.backend import KeychainBackend, KeychainError
from keys_keeper.crypto import BadPassword, decrypt_blob, encrypt_blob
from keys_keeper.models import Entry, ValidationError, entry_requires_secret, validate_name
from keys_keeper.store import SCHEMA_VERSION, MetadataStore

_MAGIC = b"KK1\x00"
MAX_SNAPSHOT_BLOB_BYTES = 64 * 1024 * 1024


class LegacyCatalogSyncError(RuntimeError):
    """Legacy full-vault snapshots must never serialize catalog schema v3."""


class SnapshotReadError(KeychainError):
    """A complete snapshot could not be read; no partial backup is publishable."""


class MergeReferenceConflict(ValidationError):
    """A surviving name-based reference would silently change its binding."""


def build_snapshot_payload(store: MetadataStore, backend: KeychainBackend) -> dict:
    return prepare_snapshot_payload(store, backend)[0]


def prepare_snapshot_payload(
    store: MetadataStore, backend: KeychainBackend,
) -> tuple[dict, str]:
    """Read one complete legacy snapshot and its revision under the profile guard."""
    from keys_keeper.master_journal import projection_guard
    with projection_guard(store.paths):
        return _prepare_snapshot_payload(store, backend)


def _prepare_snapshot_payload(
    store: MetadataStore, backend: KeychainBackend,
) -> tuple[dict, str]:
    """Full vault as a plaintext payload (entries + secrets + tombstones).

    Reserved service accounts are never entries, so they are never included.
    """
    # Bind the schema to the same metadata read as the payload and revision,
    # before opening any secret account. Schema v3 uses the project protocol;
    # a separate schema preflight could race an explicit catalog migration.
    # Serializing catalog data as a legacy snapshot would discard metadata and
    # disclose the entire master vault.
    snapshot = store.snapshot()
    if snapshot.schema_version >= 3:
        raise LegacyCatalogSyncError(
            "legacy full-vault snapshots are disabled for catalog schema v3; use the project protocol"
        )
    try:
        # Presence is metadata. Enumerate once before any credential read so
        # optional absence stays distinct from denied/unavailable access.
        accounts = set(backend.list_ids()) if snapshot.entries else set()
    except Exception:
        raise SnapshotReadError("cannot verify snapshot secret accounts") from None
    if any(entry_requires_secret(e) and e.id not in accounts for e in snapshot.entries):
        raise SnapshotReadError("required snapshot secret is missing")
    entries = []
    for e in snapshot.entries:
        rec = e.to_dict()
        passphrase_id = e.id + ":passphrase"
        try:
            rec["_secret"] = backend.get(e.id).unseal() if e.id in accounts else None
            rec["_secret_passphrase"] = (
                backend.get(passphrase_id).unseal() if passphrase_id in accounts else None
            )
        except Exception:
            # Include optional accounts when present, but never treat a
            # failed read (including a concurrent disappearance) as absence.
            raise SnapshotReadError("snapshot secret access failed") from None
        entries.append(rec)
    payload = {"schema_version": SCHEMA_VERSION, "entries": entries,
               "tombstones": snapshot.tombstones}
    return payload, snapshot.revision


def encrypt_snapshot(payload: dict, *, passphrase: str) -> bytes:
    raw = bytearray()
    for part in json.JSONEncoder().iterencode(payload):
        encoded = part.encode("utf-8")
        if len(raw) + len(encoded) > MAX_SNAPSHOT_BLOB_BYTES - 48:
            raise SnapshotReadError("snapshot exceeds the supported backup size limit")
        raw.extend(encoded)
    blob = encrypt_blob(bytes(raw), password=passphrase)
    if blob[:4] != _MAGIC:
        raise RuntimeError("refusing a snapshot without the KK1 magic header")
    return blob


def decrypt_snapshot(blob: bytes, *, passphrase: str) -> dict:
    if len(blob) > MAX_SNAPSHOT_BLOB_BYTES:
        raise BadPassword("snapshot exceeds the supported backup size limit")
    raw = decrypt_blob(blob, password=passphrase)
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate member")
            result[key] = value
        return result
    try:
        payload = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError, RecursionError):
        raise BadPassword("snapshot payload malformed") from None
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise BadPassword("snapshot payload malformed")
    payload.setdefault("tombstones", [])
    return payload


def content_hash(payload: dict) -> str:
    """Stable hash of vault content (metadata + secret digests, never plaintext).

    Used to compare snapshots without including plaintext secret values.
    """
    items = []
    for rec in sorted(payload["entries"], key=lambda r: r["id"]):
        meta = {k: v for k, v in rec.items()
                if k not in ("_secret", "_secret_passphrase")}
        secret_pair = json.dumps(
            [rec.get("_secret"), rec.get("_secret_passphrase")],
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        items.append({"m": meta, "s": hashlib.sha256(secret_pair).hexdigest()})
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


def _unique_suffix_name(name: str, id_: str, occupied: set[str], total: int) -> str:
    candidate = _suffix_name(name, id_)
    if candidate not in occupied:
        validate_name(candidate)
        return candidate
    short = id_.split(":")[-1].replace("-", "")[:6] or "dup"
    # There are fewer occupied names than live entries while a loser remains
    # unassigned. At most `total` distinct suffixes therefore finds a free name.
    for number in range(1, total + 1):
        suffix = f"-{short}-{number}"
        candidate = name[:64 - len(suffix)] + suffix
        if candidate not in occupied:
            validate_name(candidate)
            return candidate
    raise RuntimeError("cannot disambiguate entry names")


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
    occupied = set(by_name)
    for name in sorted(by_name):
        ids = by_name[name]
        if len(ids) <= 1:
            continue
        ids.sort(key=lambda id_: _sort_key(result[id_][0]), reverse=True)
        for loser in ids[1:]:
            entry, source = result[loser]
            unique_name = _unique_suffix_name(name, entry.id, occupied, len(result))
            occupied.add(unique_name)
            result[loser] = (
                replace(entry, name=unique_name),
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


def _require_reference_bindings(
    live: dict[str, tuple[Entry, str]],
    local_entries: list[Entry],
    remote_entries: list[Entry],
) -> None:
    sources = [({entry.id: entry for entry in entries},
                {entry.name: entry.id for entry in entries})
               for entries in (local_entries, remote_entries)]
    merged_targets = {entry.name: entry.id for entry, _source in live.values()}
    for entry, _source in live.values():
        histories = [
            (targets, {(ref["role"], ref["name"]) for ref in original.refs})
            for entries, targets in sources
            if (original := entries.get(entry.id)) is not None
        ]
        for reference in entry.refs:
            name = reference.get("name")
            merged_id = merged_targets.get(name)
            # Check both histories, not only the metadata winner: an unrelated
            # edit or a newer timestamp is not permission to rebind a reference
            # that survived unchanged on the other peer. A missing target is a
            # binding state too; it must not silently acquire a new credential.
            for source_targets, original_refs in histories:
                if (reference["role"], name) not in original_refs:
                    continue
                original_id = source_targets.get(name)
                if original_id != merged_id:
                    raise MergeReferenceConflict(
                        f"vault merge would change reference {name!r} on "
                        f"{entry.name!r} ({entry.id}) from "
                        f"{original_id or 'missing'} to {merged_id or 'missing'}; "
                        "remove the old reference and sync before explicitly relinking"
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
    _require_reference_bindings(live, local_entries, remote_entries)

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
