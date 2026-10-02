"""Local-only CLI commands for the project catalog."""
from __future__ import annotations

import argparse
import json
import sys

from keys_keeper.audit import AuditLog
from keys_keeper.paths import Paths
from keys_keeper.project_service import ProjectCatalogError, ProjectService
from keys_keeper.store import MetadataStore, NotFound, StoreError


def _emit(value, *, as_json: bool) -> None:
    if as_json:
        if isinstance(value, list):
            value = [item.to_dict() for item in value]
        else:
            value = value.to_dict() if hasattr(value, "to_dict") else value
        print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    elif isinstance(value, list):
        for item in value:
            print("  ".join(str(part) for part in item))
    elif hasattr(value, "to_dict"):
        for key, item in value.to_dict().items():
            print(f"{key}: {item}")


def _service() -> ProjectService:
    return ProjectService(MetadataStore(Paths()))


def _finish_catalog(operation: str, value, *, as_json: bool, mutating: bool) -> int:
    from keys_keeper.cli import _audit_outcome, _operation_failure
    status = "unknown"
    if mutating:
        status = _audit_outcome(AuditLog(Paths()), op=operation, name="<catalog>",
                                id_=getattr(value, "id", "-"))
    try:
        _emit(value, as_json=as_json)
    except Exception as ex:
        return _operation_failure(operation, ex, committed=mutating, audit_status=status)
    return 0


def _catalog_failure(operation: str, error: Exception, *, mutating: bool) -> int:
    from keys_keeper.cli import _audit_outcome, _operation_failure
    committed = None if mutating and not isinstance(error, (ProjectCatalogError, ValueError)) else False
    if getattr(error, "committed", None) is True:
        committed = True
    status = _audit_outcome(AuditLog(Paths()), op=operation, name="<catalog>", id_="-",
                            success=committed is True, committed=committed) if mutating else "unknown"
    sys.stderr.write("error: catalog request is unavailable or invalid; catalog use requires explicit schema-v3 migration with `keys project-sync migrate`\n")
    return _operation_failure(operation, error, committed=committed, audit_status=status)


def cmd_folders(args: argparse.Namespace) -> int:
    command = args.folders_command
    mutating = command != "list"
    try:
        service = _service()
        if command == "list":
            folders = service.list_folders()
            value = folders if args.json else [(item.id, item.parent_id or "-", item.name) for item in folders]
        elif command == "create":
            value = service.create_folder(args.name, parent_id=args.parent, position=args.position)
        elif command == "move":
            value = service.move_folder(args.folder_id, parent_id=args.parent, position=args.position)
        elif command == "rename":
            value = service.rename_folder(args.folder_id, args.name)
        elif command == "delete":
            value = service.delete_folder(args.folder_id, destination_id=args.destination)
        else:  # assign-entry
            entry = service.store.get_by_id(args.entry_id) or service.store.get_by_name(args.entry_id)
            if entry is None:
                raise NotFound("entry is unavailable")
            value = service.set_entry_folder(entry.id, args.folder_id)
        return _finish_catalog("folders." + command, value, as_json=args.json, mutating=mutating)
    except Exception as ex:
        return _catalog_failure("folders." + command, ex, mutating=mutating)


def cmd_projects(args: argparse.Namespace) -> int:
    command = args.projects_command
    mutating = command not in {"list", "init"} and (command != "scopes" or args.create)
    try:
        service = _service()
        if command == "init":
            raise ProjectCatalogError(
                "catalog migration requires a verified recovery backup; run "
                "`keys project-sync migrate --out BACKUP --password-file FILE`"
            )
        elif command == "list":
            projects = service.list_projects()
            value = projects if args.json else [(item.id, item.slug, item.name, item.state) for item in projects]
        elif command == "create":
            value = service.create_project(args.slug, args.name, state=args.state)
        elif command == "rename":
            value = service.rename_project(args.project_id, args.name, slug=args.slug)
        elif command == "archive":
            value = service.archive_project(args.project_id)
        elif command == "scopes":
            if args.create:
                value = service.create_scope(args.project_id, args.environment)
            else:
                value = service.list_scopes(project_id=args.project_id)
        elif command == "add":
            scope = service.get_scope(args.scope_id, project_slug=args.project, environment=args.environment)
            value = service.assign(scope.id, args.entry_id, local_name=args.local_name)
        elif command == "remove":
            scope = service.get_scope(args.scope_id, project_slug=args.project, environment=args.environment)
            value = service.unassign(scope.id, args.entry_id)
        else:  # distribution
            value = service.set_entry_distribution(args.entry_id, args.distribution)
        return _finish_catalog("projects." + command, value, as_json=args.json, mutating=mutating)
    except Exception as ex:
        return _catalog_failure("projects." + command, ex, mutating=mutating)


def register_catalog(sub: argparse._SubParsersAction) -> None:
    folders = sub.add_parser("folders", help="organize local catalog folders")
    folders_sub = folders.add_subparsers(dest="folders_command", required=True)
    folder_list = folders_sub.add_parser("list", help="list folders")
    folder_list.add_argument("--json", action="store_true")
    folder_list.set_defaults(func=cmd_folders)
    folder_create = folders_sub.add_parser("create", help="create a folder")
    folder_create.add_argument("name")
    folder_create.add_argument("--parent")
    folder_create.add_argument("--position", type=int)
    folder_create.add_argument("--json", action="store_true")
    folder_create.set_defaults(func=cmd_folders)
    folder_move = folders_sub.add_parser("move", help="move a folder")
    folder_move.add_argument("folder_id")
    folder_move.add_argument("--parent")
    folder_move.add_argument("--position", type=int)
    folder_move.add_argument("--json", action="store_true")
    folder_move.set_defaults(func=cmd_folders)
    folder_rename = folders_sub.add_parser("rename", help="rename a folder")
    folder_rename.add_argument("folder_id")
    folder_rename.add_argument("name")
    folder_rename.add_argument("--json", action="store_true")
    folder_rename.set_defaults(func=cmd_folders)
    folder_delete = folders_sub.add_parser("delete", help="delete an empty folder or move its contents explicitly")
    folder_delete.add_argument("folder_id")
    folder_delete.add_argument("--destination")
    folder_delete.add_argument("--json", action="store_true")
    folder_delete.set_defaults(func=cmd_folders)
    folder_assign = folders_sub.add_parser("assign-entry", help="move an entry into a folder")
    folder_assign.add_argument("entry_id")
    folder_assign.add_argument("--folder", dest="folder_id", required=True)
    folder_assign.add_argument("--json", action="store_true")
    folder_assign.set_defaults(func=cmd_folders)

    projects = sub.add_parser("projects", help="manage explicit local project scopes")
    projects_sub = projects.add_subparsers(dest="projects_command", required=True)
    project_init = projects_sub.add_parser("init", help="explicitly migrate local metadata to catalog schema v3")
    project_init.add_argument("--json", action="store_true")
    project_init.set_defaults(func=cmd_projects)
    project_list = projects_sub.add_parser("list", help="list projects")
    project_list.add_argument("--json", action="store_true")
    project_list.set_defaults(func=cmd_projects)
    project_create = projects_sub.add_parser("create", help="create a project")
    project_create.add_argument("slug")
    project_create.add_argument("name")
    project_create.add_argument("--state", choices=["active", "archived"], default="active")
    project_create.add_argument("--json", action="store_true")
    project_create.set_defaults(func=cmd_projects)
    project_rename = projects_sub.add_parser("rename", help="rename a project")
    project_rename.add_argument("project_id")
    project_rename.add_argument("name")
    project_rename.add_argument("--slug")
    project_rename.add_argument("--json", action="store_true")
    project_rename.set_defaults(func=cmd_projects)
    project_archive = projects_sub.add_parser("archive", help="archive a project; this does not revoke delivered secrets")
    project_archive.add_argument("project_id")
    project_archive.add_argument("--json", action="store_true")
    project_archive.set_defaults(func=cmd_projects)
    scopes = projects_sub.add_parser("scopes", help="list or create project environments")
    scopes.add_argument("project_id")
    scopes.add_argument("--create", action="store_true")
    scopes.add_argument("--environment", default="default")
    scopes.add_argument("--json", action="store_true")
    scopes.set_defaults(func=cmd_projects)
    for name, help_text in (("add", "explicitly add an entry to a scope"), ("remove", "remove an entry from a scope")):
        parser = projects_sub.add_parser(name, help=help_text)
        parser.add_argument("entry_id")
        resolver = parser.add_mutually_exclusive_group(required=True)
        resolver.add_argument("--scope-id")
        resolver.add_argument("--project")
        parser.add_argument("--environment", default="default")
        parser.add_argument("--local-name") if name == "add" else None
        parser.add_argument("--json", action="store_true")
        parser.set_defaults(func=cmd_projects)
    distribution = projects_sub.add_parser("distribution", help="explicitly set project assignment eligibility")
    distribution.add_argument("entry_id")
    distribution.add_argument("--distribution", choices=["local_only", "project_allowed"], required=True)
    distribution.add_argument("--json", action="store_true")
    distribution.set_defaults(func=cmd_projects)
