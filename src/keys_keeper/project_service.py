"""Catalog-only folder and project operations.

This service never opens a secret backend.  It deliberately does not infer a
scope assignment from a folder, tag, project slug, or name: only ``assign``
creates a scope-entry binding.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any

from keys_keeper.models import Entry
from keys_keeper.project_models import (
    CatalogState,
    Folder,
    Project,
    Scope,
    ScopeEntry,
    default_export_config,
    new_catalog_id,
)
from keys_keeper.store import MetadataStore, NotFound, StoreError


class ProjectCatalogError(StoreError):
    pass


class ProjectAmbiguousError(ProjectCatalogError):
    pass


class LocalOnlyError(ProjectCatalogError):
    pass


class BindingConflict(ProjectCatalogError):
    pass


class ArchivedProjectError(ProjectCatalogError):
    pass


class ProjectService:
    """Mutate catalog entities atomically with the metadata store."""

    def __init__(self, store: MetadataStore):
        self.store = store

    def create_folder(self, name: str, *, parent_id: str | None = None, position: int | None = None) -> Folder:
        with self.store.transaction() as tx:
            state = self._state(tx)
            siblings = [folder for folder in state.folders if folder.parent_id == parent_id]
            folder = Folder(id=new_catalog_id(), name=name, parent_id=parent_id, position=len(siblings) if position is None else position)
            state.folders.append(folder)
            self._save(tx, state)
            return folder

    def move_folder(self, folder_id: str, *, parent_id: str | None, position: int | None = None) -> Folder:
        """Move catalog navigation only; scope bindings are intentionally untouched."""
        with self.store.transaction() as tx:
            state = self._state(tx)
            folder = self._folder(state, folder_id)
            siblings = [item for item in state.folders if item.parent_id == parent_id and item.id != folder_id]
            moved = replace(folder, parent_id=parent_id, position=len(siblings) if position is None else position)
            state = replace(state, folders=[moved if item.id == folder_id else item for item in state.folders])
            self._save(tx, state)
            return moved

    def rename_folder(self, folder_id: str, name: str) -> Folder:
        with self.store.transaction() as tx:
            state = self._state(tx)
            folder = self._folder(state, folder_id)
            renamed = replace(folder, name=name)
            state = replace(state, folders=[renamed if item.id == folder_id else item for item in state.folders])
            self._save(tx, state)
            return renamed

    def set_entry_folder(self, entry_id: str, folder_id: str | None) -> Entry:
        """Move local organization only; bindings and delivery remain unchanged."""
        with self.store.transaction() as tx:
            state = self._state(tx)
            entry = tx.get_by_id(entry_id)
            if entry is None:
                raise NotFound(f"no entry with id {entry_id}")
            if folder_id is not None:
                self._folder(state, folder_id)
            entry.folder_id = folder_id
            tx.update(entry)
            return entry

    def delete_folder(self, folder_id: str, *, destination_id: str | None = None) -> Folder:
        """Delete only catalog navigation; never delete entries or scope bindings."""
        with self.store.transaction() as tx:
            state = self._state(tx)
            folder = self._folder(state, folder_id)
            children = [item for item in state.folders if item.parent_id == folder_id]
            entries = [item for item in tx.list() if item.folder_id == folder_id]
            if (children or entries) and destination_id is None:
                raise ProjectCatalogError("nonempty folder requires an explicit destination_id")
            if destination_id == folder_id:
                raise ProjectCatalogError("folder destination cannot be the deleted folder")
            if destination_id is not None:
                self._folder(state, destination_id)
                if self._is_descendant(state, destination_id, folder_id):
                    raise ProjectCatalogError("folder destination cannot be inside the deleted folder")
                for entry in entries:
                    entry.folder_id = destination_id
                    tx.update(entry)
            moved_children = [replace(item, parent_id=destination_id) if item.parent_id == folder_id else item for item in state.folders]
            state = replace(state, folders=[item for item in moved_children if item.id != folder_id])
            self._save(tx, state)
            return folder

    def create_project(self, slug: str, name: str, *, state: str = "active") -> Project:
        with self.store.transaction() as tx:
            catalog = self._state(tx)
            project = Project(id=new_catalog_id(), slug=slug, name=name, state=state)
            catalog.projects.append(project)
            self._save(tx, catalog)
            return project

    def create_scope(
        self,
        project_id: str,
        environment: str = "default",
        *,
        vault_id: str | None = None,
        epoch: int = 1,
        policy_version: int = 1,
    ) -> Scope:
        with self.store.transaction() as tx:
            catalog = self._state(tx)
            project = self._project(catalog, project_id)
            if project.state != "active":
                raise ArchivedProjectError("cannot create a scope for an archived project")
            scope = Scope(id=new_catalog_id(), project_id=project_id, environment=environment, vault_id=vault_id or new_catalog_id(), epoch=epoch, policy_version=policy_version)
            catalog.scopes.append(scope)
            self._save(tx, catalog)
            return scope

    def rename_project(self, project_id: str, name: str, *, slug: str | None = None) -> Project:
        with self.store.transaction() as tx:
            state = self._state(tx)
            project = self._project(state, project_id)
            renamed = replace(project, name=name, slug=project.slug if slug is None else slug)
            state = replace(state, projects=[renamed if item.id == project_id else item for item in state.projects])
            self._save(tx, state)
            return renamed

    def archive_project(self, project_id: str) -> Project:
        """Stop new catalog assignments; this is not a cryptographic revocation."""
        with self.store.transaction() as tx:
            state = self._state(tx)
            project = self._project(state, project_id)
            archived = replace(project, state="archived")
            state = replace(state, projects=[archived if item.id == project_id else item for item in state.projects])
            self._save(tx, state)
            return archived

    def get_scope(
        self,
        scope_id: str | None = None,
        *,
        project_slug: str | None = None,
        environment: str | None = None,
    ) -> Scope:
        """Resolve a stable scope ID, or an unambiguous project slug + environment."""
        state = self._read_state()
        if scope_id is not None:
            return self._scope(state, scope_id)
        if project_slug is None or environment is None:
            raise ProjectCatalogError("pass scope_id or project_slug and environment")
        projects = [project for project in state.projects if project.slug == project_slug]
        if not projects:
            raise NotFound(f"no project with slug {project_slug!r}")
        matches = [scope for scope in state.scopes if scope.environment == environment and scope.project_id in {p.id for p in projects}]
        if not matches:
            raise NotFound(f"no scope for project slug {project_slug!r} and environment {environment!r}")
        if len(matches) != 1:
            raise ProjectAmbiguousError("project slug and environment resolve to multiple scopes; use scope_id")
        return matches[0]

    def assign(
        self,
        scope_id: str,
        entry_id: str,
        *,
        local_name: str | None = None,
        export: dict[str, Any] | None = None,
    ) -> ScopeEntry:
        with self.store.transaction() as tx:
            state = self._state(tx)
            scope = self._scope(state, scope_id)
            if self._project(state, scope.project_id).state != "active":
                raise ArchivedProjectError("cannot assign entries to an archived project")
            entry = tx.get_by_id(entry_id)
            if entry is None:
                raise NotFound(f"no entry with id {entry_id}")
            if entry.distribution != "project_allowed":
                raise LocalOnlyError("entry is local_only and must be explicitly made project_allowed first")
            if any(item.scope_id == scope_id and item.entry_id == entry_id for item in state.bindings):
                raise BindingConflict("entry is already assigned to this scope")
            config = default_export_config()
            if export is not None:
                config.update(export)
            binding = ScopeEntry(
                scope_id=scope_id,
                entry_id=entry_id,
                local_name=local_name or entry.name,
                export=config,
                approval_revision=tx.revision(),
            )
            # Parse now so API callers receive the same strict validation as
            # persisted data. No global metadata is copied into a binding.
            binding = ScopeEntry.from_dict(binding.to_dict())
            state.bindings.append(binding)
            self._append_publication_intent(state, scope_id, entry_id, "entry_assigned")
            self._save(tx, state)
            return binding

    def set_entry_distribution(self, entry_id: str, distribution: str) -> Entry:
        """Explicitly opt an entry in or out of later project assignment.

        Changing this flag does not create, remove, or infer any bindings.
        """
        if distribution not in {"local_only", "project_allowed"}:
            raise ProjectCatalogError("distribution must be local_only or project_allowed")
        with self.store.transaction() as tx:
            state = self._state(tx)  # Require migrated metadata before changing access intent.
            entry = tx.get_by_id(entry_id)
            if entry is None:
                raise NotFound(f"no entry with id {entry_id}")
            if entry.distribution == distribution:
                return entry
            entry.distribution = distribution
            tx.update(entry)
            for binding in state.bindings:
                if binding.entry_id == entry_id:
                    self._append_publication_intent(state, binding.scope_id, entry_id, "distribution_changed")
            self._save(tx, state)
            return entry

    def unassign(self, scope_id: str, entry_id: str) -> ScopeEntry:
        with self.store.transaction() as tx:
            state = self._state(tx)
            self._scope(state, scope_id)
            matches = [item for item in state.bindings if item.scope_id == scope_id and item.entry_id == entry_id]
            if not matches:
                raise NotFound("entry is not assigned to this scope")
            binding = matches[0]
            state = replace(state, bindings=[item for item in state.bindings if item is not binding])
            self._append_publication_intent(state, scope_id, entry_id, "entry_unassigned")
            self._save(tx, state)
            return binding

    def list_folders(self) -> list[Folder]:
        return list(self._read_state().folders)

    def list_projects(self) -> list[Project]:
        return list(self._read_state().projects)

    def list_scopes(self, *, project_id: str | None = None) -> list[Scope]:
        scopes = self._read_state().scopes
        return [scope for scope in scopes if project_id is None or scope.project_id == project_id]

    def list_bindings(self, *, scope_id: str | None = None, entry_id: str | None = None) -> list[ScopeEntry]:
        bindings = self._read_state().bindings
        return [item for item in bindings if (scope_id is None or item.scope_id == scope_id) and (entry_id is None or item.entry_id == entry_id)]

    def effective_shared_usages(self) -> dict[str, list[dict[str, str]]]:
        """Return explicit scope assignments keyed by canonical entry ID.

        This is catalog metadata, not a recipient or delivery graph: a binding
        states only that the master intends a scope to include the entry.  The
        project runtime owns grants and per-device delivery state.
        """
        state = self._read_state()
        projects = {project.id: project for project in state.projects}
        scopes = {scope.id: scope for scope in state.scopes}
        usages: dict[str, list[dict[str, str]]] = {}
        for binding in state.bindings:
            scope = scopes[binding.scope_id]
            project = projects[scope.project_id]
            usages.setdefault(binding.entry_id, []).append({
                "scope_id": scope.id,
                "project_id": project.id,
                "project_slug": project.slug,
                "project_name": project.name,
                "project_state": project.state,
                "environment": scope.environment,
                "local_name": binding.local_name,
            })
        for assigned in usages.values():
            assigned.sort(key=lambda item: (
                item["project_slug"], item["project_id"], item["environment"], item["scope_id"]
            ))
        return dict(sorted(usages.items()))

    def publication_intents(self, *, scope_id: str | None = None) -> list[dict[str, Any]]:
        """Read compact desired/applied publication state without persisting it.

        Old draft records are normalized when an operation next captures or
        mutates them; ordinary status reads remain side-effect free.
        """
        state = self._read_state()
        intents, _ = self._compact_publication_intents(state)
        return [dict(item) for item in intents if scope_id is None or item["scope_id"] == scope_id]

    def capture_publications(self, scope_id: str) -> dict[str, int]:
        """Atomically compact and capture desired revisions for one publish job."""
        with self.store.transaction() as tx:
            state = self._state(tx)
            self._scope(state, scope_id)
            intents, changed = self._compact_publication_intents(state)
            if changed:
                state = replace(state, publication_intents=intents)
                self._save(tx, state)
            return {
                item["entry_id"]: item["desired_revision"]
                for item in intents
                if item["scope_id"] == scope_id and item["desired_revision"] > item["applied_revision"]
            }

    def mark_publications_applied(self, scope_id: str, captured: dict[str, int]) -> None:
        """Advance only revisions acknowledged by the remote publication.

        A fresh local change can land after capture. Its higher desired
        revision is preserved, so the next job still publishes it.
        """
        if not isinstance(captured, dict) or any(
            not isinstance(entry_id, str) or type(revision) is not int or revision < 0
            for entry_id, revision in captured.items()
        ):
            raise ProjectCatalogError("captured publication revisions are invalid")
        with self.store.transaction() as tx:
            state = self._state(tx)
            self._scope(state, scope_id)
            intents, _ = self._compact_publication_intents(state)
            updated = []
            for item in intents:
                record = dict(item)
                captured_revision = captured.get(record["entry_id"])
                if record["scope_id"] == scope_id and captured_revision is not None:
                    acknowledged = min(captured_revision, record["desired_revision"])
                    record["applied_revision"] = max(record["applied_revision"], acknowledged)
                updated.append(record)
            self._save(tx, replace(state, publication_intents=updated))

    def _read_state(self) -> CatalogState:
        data = self.store.catalog_state()
        return CatalogState.from_dict(data, entry_ids={entry.id for entry in self.store.list()})

    @staticmethod
    def _state(tx) -> CatalogState:
        return CatalogState.from_dict(tx.catalog_state(), entry_ids={entry.id for entry in tx.list()})

    @staticmethod
    def _save(tx, state: CatalogState) -> None:
        tx.set_catalog_state(state.to_dict())

    @staticmethod
    def _append_publication_intent(
        state: CatalogState, scope_id: str, entry_id: str, reason: str
    ) -> None:
        """Maintain exactly one desired-state marker per scope and entry."""
        intents, _ = ProjectService._compact_publication_intents(state)
        revision = ProjectService._next_desired_revision(state, intents=intents)
        replacement = {"scope_id": scope_id, "entry_id": entry_id, "reason": reason,
                       "desired_revision": revision, "applied_revision": 0}
        for index, item in enumerate(intents):
            if item["scope_id"] == scope_id and item["entry_id"] == entry_id:
                replacement["applied_revision"] = item["applied_revision"]
                intents[index] = replacement
                state.publication_intents[:] = intents
                return
        state.publication_intents[:] = [*intents, replacement]

    @staticmethod
    def _next_desired_revision(state: CatalogState, *, intents: list[dict[str, Any]] | None = None) -> int:
        values = [0]
        for record in [*state.dedup, *(intents if intents is not None else state.publication_intents)]:
            revision = record.get("desired_revision", record.get("revision"))
            if type(revision) is int and revision >= 0:
                values.append(revision)
        return max(values) + 1

    @staticmethod
    def _compact_publication_intents(state: CatalogState) -> tuple[list[dict[str, Any]], bool]:
        """Normalize legacy drafts into one monotonic desired/applied record.

        The global high-water mark is retained by keeping every assigned
        revision; no compaction can make a later desired revision go backwards.
        """
        source = state.publication_intents
        highwater = 0
        for record in [*state.dedup, *source]:
            revision = record.get("desired_revision", record.get("revision"))
            if type(revision) is int and revision >= 0:
                highwater = max(highwater, revision)
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for raw in source:
            scope_id, entry_id = raw.get("scope_id"), raw.get("entry_id")
            if not isinstance(scope_id, str) or not isinstance(entry_id, str):
                raise ProjectCatalogError("publication intent requires scope_id and entry_id")
            desired = raw.get("desired_revision")
            if type(desired) is not int or desired < 0:
                # Legacy writers did not have a desired revision. Treat every
                # such record as a fresh desired state: an unnecessary replay
                # is safe, whereas collapsing a later secret/content update
                # into an already-applied revision would lose publication
                # accounting.
                highwater += 1
                desired = highwater
            applied = raw.get("applied_revision", 0)
            if type(applied) is not int or applied < 0:
                applied = 0
            record = {"scope_id": scope_id, "entry_id": entry_id,
                      "reason": raw.get("reason") if isinstance(raw.get("reason"), str) else "catalog_changed",
                      "desired_revision": desired, "applied_revision": min(applied, desired)}
            if isinstance(raw.get("desired_content_revision"), str):
                record["desired_content_revision"] = raw["desired_content_revision"]
            key = (scope_id, entry_id)
            existing = groups.get(key)
            if existing is None or record["desired_revision"] >= existing["desired_revision"]:
                if existing is not None:
                    record["applied_revision"] = max(record["applied_revision"], min(existing["applied_revision"], record["desired_revision"]))
                groups[key] = record
            else:
                existing["applied_revision"] = max(existing["applied_revision"], min(record["applied_revision"], existing["desired_revision"]))
                # Preserve the newest semantic reason/content marker even
                # when a legacy record was assigned the greater sequence.
                existing["reason"] = record["reason"]
                if "desired_content_revision" in record:
                    existing["desired_content_revision"] = record["desired_content_revision"]
        compacted = [groups[key] for key in sorted(groups)]
        return compacted, compacted != source

    @staticmethod
    def _folder(state: CatalogState, folder_id: str) -> Folder:
        for folder in state.folders:
            if folder.id == folder_id:
                return folder
        raise NotFound(f"no folder with id {folder_id}")

    @staticmethod
    def _is_descendant(state: CatalogState, candidate_id: str, ancestor_id: str) -> bool:
        parents = {folder.id: folder.parent_id for folder in state.folders}
        current = parents.get(candidate_id)
        while current is not None:
            if current == ancestor_id:
                return True
            current = parents.get(current)
        return False

    @staticmethod
    def _project(state: CatalogState, project_id: str) -> Project:
        for project in state.projects:
            if project.id == project_id:
                return project
        raise NotFound(f"no project with id {project_id}")

    @staticmethod
    def _scope(state: CatalogState, scope_id: str) -> Scope:
        for scope in state.scopes:
            if scope.id == scope_id:
                return scope
        raise NotFound(f"no scope with id {scope_id}")
