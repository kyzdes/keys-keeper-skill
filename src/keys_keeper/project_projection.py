"""Build a least-privilege snapshot before reading any secret backend account."""
from __future__ import annotations

from keys_keeper.backend import KeychainError
from keys_keeper.models import Entry, EntryType, ValidationError
from keys_keeper.project_models import CatalogState, ScopeEntry
from keys_keeper import project_protocol as protocol


class ProjectionError(RuntimeError):
    """A scope cannot be published without losing data or expanding access."""


_ESSENTIAL_FIELDS = {
    EntryType.API_KEY: set(), EntryType.SSH_KEY: {"public_key"},
    EntryType.SERVER: {"host", "user", "auth", "port"},
    EntryType.DOMAIN: {"host"}, EntryType.NOTE: {"secret_body"},
}


def _needs_secret(entry: Entry) -> bool:
    return entry.type in (EntryType.API_KEY, EntryType.SSH_KEY) or (
        entry.type == EntryType.NOTE and bool(entry.fields.get("secret_body"))
    ) or (entry.type == EntryType.SERVER and entry.fields.get("auth") == "password")


def _prepare(tx, scope_id: str, *, personal: bool = False):
    entries = tx.list()
    catalog = CatalogState.from_dict(tx.catalog_state(), entry_ids={e.id for e in entries})
    if scope_id not in {scope.id for scope in catalog.scopes}:
        raise ProjectionError("unknown project scope")
    bindings = sorted((b for b in catalog.bindings if b.scope_id == scope_id), key=lambda b: b.entry_id)
    if personal:
        # Only the encrypted master authority opts into personal replication.
        # Never change distribution/bindings of ordinary project recipients.
        bindings = [ScopeEntry(scope_id, e.id, e.name,
                    {"fields": list(e.fields), "note": True, "refs": True, "tags": True},
                    protocol.canonical_hash({"personal_entry": e.id}))
                    for e in sorted(entries, key=lambda e: e.id)]
    by_id = {e.id: e for e in entries}
    by_name = {e.name: e for e in entries}
    aliases = {b.entry_id: b.local_name for b in bindings}
    if len(set(aliases.values())) != len(aliases):
        raise ProjectionError("scope contains ambiguous local entry aliases")
    records, source = [], []
    for binding in bindings:
        entry = by_id[binding.entry_id]
        if not personal and entry.distribution != "project_allowed":
            raise ProjectionError("scope contains a local-only entry")
        field_names = set(binding.export["fields"]) | _ESSENTIAL_FIELDS[entry.type]
        fields = {k: v for k, v in entry.fields.items() if k in field_names}
        refs = []
        required_ref = entry.type == EntryType.SERVER and entry.fields.get("auth") == "ssh_key"
        for ref in entry.refs:
            required = required_ref and ref["role"] == "ssh_key"
            if not required and not binding.export["refs"]:
                continue
            target = by_name.get(ref["name"])
            if target is None or target.id not in aliases:
                if required:
                    raise ProjectionError("scope reference requires an explicitly included entry")
                # Optional references do not cause a global lookup or widen the
                # projection; omit them when their target is outside this scope.
                continue
            if required and target.type != EntryType.SSH_KEY:
                raise ProjectionError("server reference is not an SSH key")
            refs.append({"role": ref["role"], "name": aliases[target.id]})
        if required_ref and len([r for r in refs if r["role"] == "ssh_key"]) != 1:
            raise ProjectionError("server requires exactly one included SSH key")
        record = {"id": entry.id, "name": binding.local_name, "type": entry.type.value,
                  "fields": fields, "tags": entry.tags if binding.export["tags"] else [],
                  "note": entry.note if binding.export["note"] else "", "refs": refs,
                  "created_at": entry.created_at, "updated_at": entry.updated_at}
        try:
            Entry.from_untrusted_dict(record)
        except ValidationError:
            raise ProjectionError("project metadata projection is invalid") from None
        records.append((entry, record))
        source.append({"id": entry.id, "content_revision": entry.content_revision,
                       "record": record, "binding": binding.to_dict()})
    # Scoped delivery requires an acyclic graph. A personal copy preserves the
    # owner's informational links, which may legitimately point both ways.
    from keys_keeper.refs import detect_cycles, RefCycleError
    try:
        if not personal:
            detect_cycles([Entry.from_dict(record) for _, record in records])
    except RefCycleError:
        raise ProjectionError("project reference cycle") from None
    return records, protocol.canonical_hash(source)


def preview_scope(store, scope_id: str, *, personal: bool = False) -> dict:
    """Metadata-only preview; this function has no backend argument."""
    with store.transaction() as tx:
        records, revision = _prepare(tx, scope_id, personal=personal)
        return {"scope_id": scope_id, "source_revision": revision,
                "catalog_revision": tx.revision(), "count": len(records),
                "entries": [record for _, record in records]}


def build_project_payload(store, backend, scope_id: str, *, expected_revision: str | None = None, personal: bool = False) -> dict:
    from keys_keeper.master_journal import projection_guard
    with projection_guard(store.paths):
        return _build_project_payload(store, backend, scope_id, expected_revision=expected_revision, personal=personal)


def _build_project_payload(store, backend, scope_id: str, *, expected_revision: str | None = None, personal: bool = False) -> dict:
    with store.transaction() as tx:
        records, revision = _prepare(tx, scope_id, personal=personal)
        if expected_revision is not None and expected_revision != revision:
            raise ProjectionError("project preview is stale")
        # Presence is metadata. A missing account and a permission error must
        # never both collapse to a successful null secret.
        accounts = set(backend.list_ids()) if records else set()
        for entry, _ in records:
            if _needs_secret(entry) and entry.id not in accounts:
                raise ProjectionError("required project secret is unavailable")
        payload_records = []
        for entry, record in records:
            try:
                secret = backend.get(entry.id).unseal() if entry.id in accounts else None
                passphrase_id = entry.id + ":passphrase"
                passphrase = backend.get(passphrase_id).unseal() if (
                    entry.type == EntryType.SSH_KEY and passphrase_id in accounts
                ) else None
            except KeychainError:
                raise ProjectionError("project secret access failed") from None
            payload_records.append({**record, "secret": secret, "passphrase": passphrase})
        return {"schema_version": 2 if personal else 1, "scope_id": scope_id,
                "source_revision": revision, "entries": payload_records}
