"""Explicit project profiles, enrollment and application composition.

The registry contains routing metadata only. Master authority lives in encrypted
state unlocked through the master backend; replica profiles have independent
local unlock material and never construct a master backend.
"""
from __future__ import annotations

import copy
import hashlib
import json
import secrets
import time
from contextlib import ExitStack
from dataclasses import asdict
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID, uuid4

from keys_keeper import project_protocol as wire
from keys_keeper.audit import AuditLog
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.composition import AccessContext, build_backend
from keys_keeper.models import Entry, now_iso
from keys_keeper.operation_journal import JournalError, OperationJournal, _atomic_write_bytes, _secure_read, profile_lock
from keys_keeper.paths import Paths
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_projection import build_project_payload, preview_scope
from keys_keeper.project_replica import NoReplicaGeneration, ReplicaReadOnlyError, ReplicaStore
from keys_keeper.project_service import ProjectService
from keys_keeper.project_sync import ProjectMaster, ProjectReplica, ProjectState, new_master_state
from keys_keeper.profiles import ProfileContext
from keys_keeper.store import MetadataStore


class RuntimeErrorSafe(RuntimeError):
    pass


_MASTER_KEY = "kk:project-runtime-key"
_REGISTRY_FIELDS = {"schema_version", "default_profile", "profiles"}
_PROFILE_FIELDS = {"id", "kind", "scope_id", "vault_id", "project", "environment", "endpoint", "device_id", "status"}
_MAX_BUNDLE = 32 * 1024 * 1024
_MAX_REGISTRY = 1024 * 1024


def _uuid(value):
    if not isinstance(value, str):
        raise RuntimeErrorSafe("canonical profile identity is required")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError):
        raise RuntimeErrorSafe("invalid profile identity") from None
    if str(parsed) != value or parsed.version != 4:
        raise RuntimeErrorSafe("invalid profile identity")
    return value


def _json_read(path: Path, maximum=_MAX_BUNDLE):
    try:
        blob = _secure_read(path, max_bytes=maximum)
    except JournalError:
        raise RuntimeErrorSafe("cannot safely read project file") from None
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RuntimeErrorSafe("duplicate project field")
            result[key] = value
        return result
    try:
        return json.loads(blob, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError):
        raise RuntimeErrorSafe("invalid project file") from None


def _public_label(value, label, *, maximum=256):
    if not isinstance(value, str) or not 1 <= len(value) <= maximum:
        raise RuntimeErrorSafe(f"invalid {label}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuntimeErrorSafe(f"invalid {label}")
    return value


def write_bundle(path: Path, value: dict):
    """Write public enrollment material, never raw credentials, owner-only."""
    blob = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(blob) > _MAX_BUNDLE:
        raise RuntimeErrorSafe("project bundle exceeds size limit")
    if path.exists() or path.is_symlink():
        raise RuntimeErrorSafe("project output already exists")
    _atomic_write_bytes(path, blob)


def _assert_fresh_worker_root(paths: Paths) -> None:
    """Require a first replica enrollment to claim an otherwise empty root.

    The two allowed directories are created by the role and scope locks held
    by ``join`` before this check.  Everything else represents a pre-existing
    vault, runtime, or interrupted operation and must not be reclassified as a
    worker root.
    """
    allowed_lock_dirs = {"project-runtime-role", "project-join"}
    try:
        children = list(paths.root.iterdir())
    except OSError as ex:
        raise RuntimeErrorSafe("cannot verify a clean Keys Keeper root") from ex
    for child in children:
        if (
            child.name not in allowed_lock_dirs
            or child.is_symlink()
            or not child.is_dir()
        ):
            raise RuntimeErrorSafe("enroll replicas in a clean Keys Keeper root")


class ProfileRegistry:
    def __init__(self, paths: Paths):
        self.paths = paths
        self.path = paths.root / "profile-registry.json"
        self.lock_paths = Paths(paths.root / "registry-lock")

    def read(self):
        try:
            data = _json_read(self.path, _MAX_REGISTRY)
        except FileNotFoundError:
            return {"schema_version": 1, "default_profile": "master", "profiles": []}
        return self._validate(data)

    @staticmethod
    def _validate(data):
        if not isinstance(data, dict) or set(data) != _REGISTRY_FIELDS or data["schema_version"] != 1:
            raise RuntimeErrorSafe("invalid profile registry")
        if not isinstance(data["profiles"], list) or len(data["profiles"]) > 1000:
            raise RuntimeErrorSafe("invalid profile registry")
        seen = set()
        seen_scopes = set()
        for item in data["profiles"]:
            if not isinstance(item, dict) or set(item) != _PROFILE_FIELDS:
                raise RuntimeErrorSafe("invalid profile registry record")
            for field in ("id", "scope_id", "vault_id", "device_id"):
                _uuid(item[field])
            if item["id"] in seen or item["kind"] not in {"master_scope", "replica"}:
                raise RuntimeErrorSafe("invalid profile registry identity")
            seen.add(item["id"])
            if item["scope_id"] in seen_scopes:
                raise RuntimeErrorSafe("duplicate project scope profile")
            seen_scopes.add(item["scope_id"])
            if (
                (item["kind"] == "master_scope" and item["id"] != item["scope_id"])
                or (item["kind"] == "replica" and item["id"] == item["scope_id"])
            ):
                raise RuntimeErrorSafe("invalid profile registry identity")
            if item["status"] not in {"pending", "active", "recovery_required"}:
                raise RuntimeErrorSafe("invalid profile registry status")
            _public_label(item["project"], "profile project")
            _public_label(item["environment"], "profile environment")
            _public_label(item["endpoint"], "profile endpoint", maximum=2048)
            ProjectClient(base_url=item["endpoint"])
        if data["default_profile"] != "master" and data["default_profile"] not in seen:
            raise RuntimeErrorSafe("default project profile is missing")
        return data

    def list(self):
        return copy.deepcopy(self.read()["profiles"])

    def resolve(self, selector=None):
        data = self.read()
        if selector is None:
            selector = data["default_profile"]
        if not isinstance(selector, str) or not selector:
            raise RuntimeErrorSafe("invalid project profile selector")
        if selector == "master":
            return None
        matches = [item for item in data["profiles"] if selector in {
            item["id"], item["scope_id"], item["project"] + "/" + item["environment"]}]
        if len(matches) != 1:
            raise RuntimeErrorSafe("project profile is unknown or ambiguous; use its UUID")
        return copy.deepcopy(matches[0])

    def put(self, item, *, make_default=False):
        with profile_lock(self.lock_paths):
            data = self.read()
            previous = next((p for p in data["profiles"] if p["id"] == item["id"]), None)
            if previous and any(previous[k] != item[k] for k in ("id", "scope_id", "vault_id", "kind", "device_id", "endpoint")):
                raise RuntimeErrorSafe("profile identity cannot be replaced")
            data["profiles"] = [p for p in data["profiles"] if p["id"] != item["id"]] + [copy.deepcopy(item)]
            if make_default:
                data["default_profile"] = item["id"]
            self._validate(data)
            _atomic_write_bytes(self.path, json.dumps(data, sort_keys=True).encode())

    def set_default(self, selector):
        item = self.resolve(selector)
        with profile_lock(self.lock_paths):
            data = self.read()
            data["default_profile"] = item["id"] if item else "master"
            self._validate(data)
            _atomic_write_bytes(self.path, json.dumps(data, sort_keys=True).encode())


class _ReadView:
    def __init__(self, runtime, item):
        self.runtime, self.item = runtime, item

    def _read(self, *, include_values=True):
        if self.item["kind"] == "master_scope":
            payload = (build_project_payload(self.runtime.master_store, self.runtime.master_backend, self.item["scope_id"])
                       if include_values else preview_scope(self.runtime.master_store, self.item["scope_id"]))
            raw_entries = payload["entries"]
            pending = []
        else:
            try:
                payload, _ = self.runtime.replica_store(self.item).load()
                raw_entries = payload["entries"]
            except NoReplicaGeneration:
                raw_entries = []
            state = self.runtime.state(self.item).load()
            pending = [i for i in state.get("outbox", []) if i["status"] in {"local_pending", "uploaded", "accepted"}]
        entries, values = [], {}
        allowed = {"id", "name", "type", "fields", "tags", "note", "refs", "created_at", "updated_at"}
        for raw in raw_entries:
            entry = Entry.from_untrusted_dict({k: raw[k] for k in allowed})
            entries.append(entry)
            for field, suffix in (("secret", ""), ("passphrase", ":passphrase")):
                if raw.get(field) is not None:
                    values[entry.id + suffix] = raw[field]
        names = {e.name for e in entries}
        for item in pending:
            body = item["payload"]
            if body["entry"]["name"] in names:
                continue
            stamp = item.get("created_at", "1970-01-01T00:00:00+00:00")
            entry = Entry.from_untrusted_dict({**body["entry"], "id": "kk:" + item["request_id"], "created_at": stamp, "updated_at": stamp})
            entries.append(entry)
            names.add(entry.name)
            for field, suffix in (("secret", ""), ("passphrase", ":passphrase")):
                if body[field] is not None:
                    values[entry.id + suffix] = body[field]
        return entries, values

    def list(self):
        return self._read(include_values=False)[0]

    def get_by_name(self, name):
        return next((e for e in self.list() if e.name == name), None)

    def get_by_id(self, id_):
        return next((e for e in self.list() if e.id == id_), None)

    def _deny(self, *args, **kwargs):
        raise ReplicaReadOnlyError("project catalog is read-only; changes belong on the master")

    add = update = replace_by_name = delete_by_name = replace_all = transaction = _deny


class _ReadBackend(KeychainBackend):
    def __init__(self, view):
        self.view = view

    def list_ids(self):
        return list(self.view._read()[1])

    def get(self, account):
        values = self.view._read()[1]
        if account not in values:
            raise KeychainError("secret is unavailable in the selected profile")
        return Sealed(values[account])

    def set(self, *args, **kwargs):
        raise ReplicaReadOnlyError("project secrets are read-only")

    delete = set


class _ReplicaService:
    def __init__(self, context):
        self.context = context

    def create_entry(self, entry, *, secrets=None, replace=False):
        if replace:
            raise ReplicaReadOnlyError("replica cannot replace existing entries")
        body = {k: entry.to_dict()[k] for k in ("name", "type", "fields", "tags", "note", "refs")}
        value = secrets.value if secrets else None
        passphrase = secrets.passphrase if secrets else None
        result = self.context.runtime.replica(self.context.item).create({
            "schema_version": 1, "entry": body, "secret": value, "passphrase": passphrase})
        # Pending identity belongs to the request; it is never an upstream UUID.
        return self.context.store.get_by_id("kk:" + result["request_id"])

    def _deny(self, *args, **kwargs):
        raise ReplicaReadOnlyError("replica can create entries but cannot edit or delete them")

    update_entry = delete_entry = replace_secret = _deny


@dataclass
class RuntimeContext:
    runtime: "ProjectRuntime"
    item: dict | None

    @property
    def kind(self):
        return self.item["kind"] if self.item else "master"

    @property
    def profile_id(self):
        return self.item["id"] if self.item else "master"

    @property
    def scope_id(self):
        return self.item["scope_id"] if self.item else None

    @property
    def paths(self):
        if self.kind == "replica":
            return self.runtime.paths.for_profile(self.item["id"])
        return self.runtime.paths

    @property
    def store(self):
        if not self.item:
            return self.runtime.master_store
        return _ReadView(self.runtime, self.item)

    @property
    def backend(self):
        return self.runtime.master_backend if not self.item else _ReadBackend(self.store)

    @property
    def audit(self):
        return AuditLog(self.paths)

    @property
    def service(self):
        if self.kind == "replica":
            return _ReplicaService(self)
        if self.kind == "master_scope":
            raise ReplicaReadOnlyError("select the master profile to edit the canonical catalog")
        from keys_keeper.service import VaultService
        if self.store._read().get("schema_version", 2) < 3:
            return VaultService(self.store, self.backend)
        manager = self.runtime.mutations()
        manager.recover()
        return VaultService(self.store, self.backend, master_mutations=manager)


class ProjectRuntime:
    def __init__(self, paths: Paths, backend=None, *, access=AccessContext.UI_FORBIDDEN, backend_factory=None):
        self.paths = paths
        self.registry = ProfileRegistry(paths)
        self.access = access
        self._backend = backend
        self._backend_factory = backend_factory
        self.master_store = MetadataStore(paths)

    def assert_available(self) -> None:
        marker = self.paths.root / "recovery-only"
        if marker.exists() or marker.is_symlink():
            raise RuntimeErrorSafe("restored profile requires recovery before activation")

    @property
    def master_backend(self):
        self.assert_available()
        # A replica registry fixes this root's role.  Check it before touching
        # either a configured factory or an already injected/cached backend so
        # no caller can bypass ``context()`` and fall back to master secrets.
        if any(item["kind"] == "replica" for item in self.registry.list()):
            raise RuntimeErrorSafe("master backend is unavailable in a worker root")
        if self._backend is None:
            settings_path = self.paths.root / "runtime-backend.json"
            if settings_path.exists() or settings_path.is_symlink():
                settings = _json_read(settings_path, 4096)
                if settings != {"schema_version": 1, "backend": "encrypted_file"}:
                    raise RuntimeErrorSafe("invalid recovered backend configuration")
                from keys_keeper.backend_file import EncryptedFileBackend
                self._backend = EncryptedFileBackend(paths=self.paths, password_file=self.paths.backend_password_file,
                    allow_env_password=False, service="keys-keeper")
            else:
                self._backend = self._backend_factory() if self._backend_factory else build_backend(paths=self.paths, access=self.access)
        return self._backend

    def context(self, selector=None):
        self.assert_available()
        item = self.registry.resolve(selector)
        if item is None and any(p["kind"] == "replica" for p in self.registry.list()):
            raise RuntimeErrorSafe("master profile is unavailable in a worker root")
        if item and item["status"] != "active":
            raise RuntimeErrorSafe("project enrollment or recovery must finish first")
        return RuntimeContext(self, item)

    def _master_password(self, *, create=False):
        with profile_lock(self.registry.lock_paths):
            backend = self.master_backend
            if _MASTER_KEY not in backend.list_ids():
                if not create:
                    raise RuntimeErrorSafe("master project runtime is not initialized")
                backend.set(_MASTER_KEY, wire.encode_key(wire.generate_key()))
            raw = backend.get(_MASTER_KEY).unseal()
            wire.decode_key(raw)
            return raw

    def mutations(self):
        self.assert_available()
        from keys_keeper.master_journal import MasterMutationManager
        journal = OperationJournal(paths=self.paths,
                                   password_provider=lambda: self._master_password(create=True))
        return MasterMutationManager(self.master_store, self.master_backend, journal)

    def _profile_password(self, item):
        self.assert_available()
        if item["kind"] == "master_scope":
            return self._master_password()
        path = self.paths.for_profile(item["id"]).backend_password_file
        blob = _secure_read(path)
        if len(blob) != 43:
            raise RuntimeErrorSafe("invalid replica unlock material")
        value = blob.decode("ascii")
        wire.decode_key(value)
        return value

    def state(self, item):
        self.assert_available()
        root = (self.paths.root / "project-sync" / item["scope_id"] if item["kind"] == "master_scope"
                else self.paths.for_profile(item["id"]).root)
        return ProjectState(Paths(root / "state"), lambda: self._profile_password(item))

    def replica_store(self, item):
        self.assert_available()
        if item["kind"] != "replica":
            raise RuntimeErrorSafe("replica profile required")
        root = self.paths.for_profile(item["id"]).root
        return ReplicaStore(paths=Paths(root / "replica"), password_provider=lambda: self._profile_password(item))

    def master(self, item):
        self.assert_available()
        if item["kind"] != "master_scope":
            raise RuntimeErrorSafe("master scope required")
        manager = self.mutations()
        manager.recover()
        manager.assert_projection_ready()
        return ProjectMaster(self.state(item), self.master_store, self.master_backend)

    def replica(self, item):
        self.assert_available()
        if item["kind"] != "replica" or item["status"] != "active":
            raise RuntimeErrorSafe("active replica profile required")
        return ProjectReplica(self.state(item), self.replica_store(item))

    def initialize(self, scope_id, endpoint, *, admin_token: Sealed):
        self.assert_available()
        if not isinstance(admin_token, Sealed):
            raise TypeError("admin_token must be sealed")
        _uuid(scope_id)
        # Establishing the root role is global. Without this lock, the first
        # master initialization and first replica enrollment can both observe
        # an empty registry and create incompatible local identities.
        with profile_lock(Paths(self.paths.root / "project-runtime-role")):
            if any(p["kind"] == "replica" for p in self.registry.list()):
                raise RuntimeErrorSafe("initialize a master scope in a separate root")
            with profile_lock(Paths(self.paths.root / "project-init" / scope_id)):
                return self._initialize(scope_id, endpoint, admin_token=admin_token)

    def _initialize(self, scope_id, endpoint, *, admin_token: Sealed):
        scope = ProjectService(self.master_store).get_scope(scope_id)
        project = next(p for p in ProjectService(self.master_store).list_projects() if p.id == scope.project_id)
        self._master_password(create=True)
        item = next((p for p in self.registry.list() if p["kind"] == "master_scope" and p["scope_id"] == scope.id), None)
        if item is None:
            state = new_master_state(scope.id, scope.vault_id, endpoint)
            item = {"id": scope.id, "kind": "master_scope", "scope_id": scope.id, "vault_id": scope.vault_id,
                    "project": project.slug, "environment": scope.environment, "endpoint": endpoint,
                    "device_id": state["device_id"], "status": "pending"}
            local = self.state(item)
            if local.exists():
                state = local.load()
                if state["endpoint"] != endpoint or state["vault_id"] != scope.vault_id:
                    raise RuntimeErrorSafe("interrupted initialization has a different identity")
                item["device_id"] = state["device_id"]
            else:
                local.save(state)
            self.registry.put(item)
        elif item["endpoint"] != endpoint:
            raise RuntimeErrorSafe("configured endpoint cannot be replaced")
        data = self.state(item).load()
        if item["status"] != "active":
            response = ProjectClient(base_url=endpoint, token=admin_token).create_scope(data["policy"])
            if not isinstance(response, dict) or response.get("scope_id") != scope.id:
                raise RuntimeErrorSafe("relay initialization acknowledgement mismatch")
        item["status"] = "active"
        self.registry.put(item)
        return {"profile_id": item["id"], "scope_id": item["scope_id"], "fingerprint": hashlib.sha256(wire.decode_key(data["pin"])).hexdigest()}

    def status(self, selector=None):
        self.assert_available()
        item = self.registry.resolve(selector)
        if item is None:
            return {"kind": "master", "profiles": self.registry.list()}
        result = {**item, "pending": 0, "delivery": "pending"}
        try:
            data = self.state(item).load()
            policy = wire.verify_policy(data["policy"], wire.decode_key(data["pin"]), expected_scope_id=item["scope_id"])
            result.update(epoch=policy["epoch"], policy_version=policy["version"],
                          checkpoint=data.get("applied_checkpoint") or data.get("checkpoint"),
                          fingerprint=hashlib.sha256(wire.decode_key(data["pin"])).hexdigest(),
                          recipients=[{"device_id": g["device_id"], "role": g["role"], "grant_id": g["grant_id"]} for g in policy["grants"]],
                          pending=sum(i["status"] not in {"published", "conflict", "rejected", "quarantined"} for i in data.get("outbox", [])),
                          outbox=[{"request_id": i["request_id"], "status": i["status"]} for i in data.get("outbox", [])],
                          delivery="pending" if data.get("pending") else "idle")
        except Exception:
            result["delivery"] = "unavailable"
            result.pop("checkpoint", None)
            result.pop("recipients", None)
            result.pop("outbox", None)
        return result

    def sync(self, selector=None):
        self.assert_available()
        item = self.registry.resolve(selector)
        if not item or item["status"] != "active":
            raise RuntimeErrorSafe("active project profile required")
        if item["kind"] == "master_scope":
            master = self.master(item)
            accepted = master.receive()
            published = master.publish()
            return {"receive": accepted, "publish": published}
        replica = self.replica(item)
        pulled = replica.pull()
        sent = replica.submit()
        return {"pull": pulled, "submit": sent}

    def preview(self, selector):
        self.assert_available()
        item = self.registry.resolve(selector)
        if not item or item["kind"] != "master_scope":
            raise RuntimeErrorSafe("master scope required")
        result = preview_scope(self.master_store, item["scope_id"])
        state = self.state(item).load()
        policy = wire.verify_policy(state["policy"], wire.decode_key(state["pin"]))
        result.update(policy_hash=wire.canonical_hash(state["policy"]),
                      recipients=[{"device_id": g["device_id"], "role": g["role"]} for g in policy["grants"]])
        return result

    def backup(self, selector, destination: Path, password):
        self.assert_available()
        from keys_keeper.project_backup import create_master_backup, create_replica_backup, inspect_backup
        item = self.registry.resolve(selector)
        if item and item["kind"] == "replica":
            state = self.state(item)
            # Replica state and generation are independently locked by their
            # owners; capture verifies the generation did not change meanwhile.
            manifest = create_replica_backup(self.replica_store(item), destination=destination,
                password=password, project_state_provider=lambda: {"registry": self.registry.read(), "state": state.load()})
            if inspect_backup(destination, password=password) != manifest:
                raise RuntimeErrorSafe("recovery bundle verification failed")
            return asdict(manifest)
        self._master_password(create=True)
        manager = self.mutations()
        manager.recover()
        profiles = [i for i in self.registry.list() if i["kind"] == "master_scope"]
        states = {i["scope_id"]: self.state(i) for i in sorted(profiles, key=lambda i: i["scope_id"])}
        with ExitStack() as stack:
            for state in states.values():
                stack.enter_context(state.locked())
            captured = {scope_id: state.load() for scope_id, state in states.items()}
            if any(s.get("pending") for s in captured.values()):
                raise RuntimeErrorSafe("finish pending project publications before backup")
            manifest = create_master_backup(self.master_store, self.master_backend, journal=manager.journal,
                destination=destination, password=password,
                project_state={"registry": self.registry.read(), "states": captured}, service_accounts=(_MASTER_KEY,))
            if inspect_backup(destination, password=password) != manifest:
                raise RuntimeErrorSafe("recovery bundle verification failed")
            proof = {"schema_version": 1, "content_hash": manifest.content_hash,
                "metadata_revision": manifest.metadata_revision,
                "scopes": {scope: {"pin": data["pin"],
                    "inbox_public_key": wire.verify_policy(data["policy"], wire.decode_key(data["pin"]))["inbox_public_key"]}
                    for scope, data in captured.items()}}
            _atomic_write_bytes(self.paths.root / "project-recovery-proof.json", json.dumps(proof, sort_keys=True).encode())
            _atomic_write_bytes(self.paths.root / "catalog-migration-ready.json", json.dumps({
                "schema_version": 1, "metadata_revision": manifest.metadata_revision, "content_hash": manifest.content_hash}, sort_keys=True).encode())
        return asdict(manifest)

    def _require_recovery(self, data):
        try:
            proof = _json_read(self.paths.root / "project-recovery-proof.json", 1024 * 1024)
            if (
                not isinstance(proof, dict)
                or set(proof) != {"schema_version", "content_hash", "metadata_revision", "scopes"}
                or proof["schema_version"] != 1
                or not isinstance(proof["scopes"], dict)
            ):
                raise RuntimeErrorSafe("invalid master recovery proof")
            for field in ("content_hash", "metadata_revision"):
                digest = proof[field]
                if not isinstance(digest, str) or len(digest) != 64 or any(
                    character not in "0123456789abcdef" for character in digest
                ):
                    raise RuntimeErrorSafe("invalid master recovery proof")
            if proof["metadata_revision"] != self.master_store.snapshot().revision:
                raise RuntimeErrorSafe("master recovery backup is stale")
            scope = proof["scopes"][data["scope_id"]]
            if not isinstance(scope, dict) or set(scope) != {"pin", "inbox_public_key"}:
                raise RuntimeErrorSafe("invalid master recovery proof")
        except (FileNotFoundError, KeyError, TypeError):
            raise RuntimeErrorSafe("create and verify a master project backup before inviting devices") from None
        policy = wire.verify_policy(data["policy"], wire.decode_key(data["pin"]))
        if scope != {"pin": data["pin"], "inbox_public_key": policy["inbox_public_key"]}:
            raise RuntimeErrorSafe("master recovery bundle does not cover this project authority")
        return proof

    def watch(self, selector, *, interval=60, cycles=0, report=lambda result: None, sleep=time.sleep):
        """One bounded job per cycle; durable queues survive stopping this process."""
        if self.access != AccessContext.UI_FORBIDDEN:
            raise RuntimeErrorSafe("background synchronization requires noninteractive backend access")
        self.assert_available()
        cycle = 0
        while cycles == 0 or cycle < cycles:
            cycle += 1
            items = [self.registry.resolve(selector)] if selector else self.registry.list()
            results = []
            for item in items:
                if not item or item["status"] != "active":
                    continue
                result = {"profile_id": item["id"], "status": "pending"}
                for attempt in range(5):
                    try:
                        result.update(status="synced", result=self.sync(item["id"]))
                        break
                    except Exception:
                        # Persist only one stable code, never types or payloads.
                        result.update(status="pending", error="operation_failed")
                        if attempt < 4:
                            sleep(min(2 ** attempt, 8))
                results.append(result)
            report({"cycle": cycle, "profiles": results})
            if cycles == 0 or cycle < cycles:
                sleep(interval + secrets.randbelow(max(2, interval // 10)))
        return {"cycles": cycle}

    def invite(self, selector, *, ttl=900):
        self.assert_available()
        item = self.registry.resolve(selector)
        if not item or item["kind"] != "master_scope" or not 60 <= ttl <= 3600:
            raise RuntimeErrorSafe("master scope and bounded invitation TTL required")
        state = self.state(item)
        with state.locked():
            data = state.load()
            proof = self._require_recovery(data)
            invite_id, now = str(uuid4()), int(time.time())
            invitation = wire.build_invitation(data["policy"], wire.decode_key(data["pin"]),
                wire.decode_key(data["signing_private"]), invite_id=invite_id, expires_at=now + ttl, endpoint=data["endpoint"])
            data.setdefault("invites", []).append({"invite_id": invite_id, "invitation": invitation,
                "source_policy": data["policy"], "recovery_hash": proof["content_hash"],
                "request_hash": None, "grant": None, "bundle": None})
            state.save(data)
            return {"schema_version": 1, "invitation": invitation, "source_policy": data["policy"],
                    "pin": data["pin"], "endpoint": data["endpoint"], "project": item["project"], "environment": item["environment"]}

    def join(self, bundle, *, fingerprint, role="contributor"):
        self.assert_available()
        expected = {"schema_version", "invitation", "source_policy", "pin", "endpoint", "project", "environment"}
        if not isinstance(bundle, dict) or set(bundle) != expected or bundle["schema_version"] != 1:
            raise RuntimeErrorSafe("invalid invitation bundle")
        if role not in {"reader", "contributor"}:
            raise RuntimeErrorSafe("invalid project role")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise RuntimeErrorSafe("invalid master fingerprint")
        _public_label(bundle["project"], "invitation project")
        _public_label(bundle["environment"], "invitation environment")
        _public_label(bundle["endpoint"], "invitation endpoint", maximum=2048)
        pin = wire.decode_key(bundle["pin"])
        if not secrets.compare_digest(hashlib.sha256(pin).hexdigest(), fingerprint):
            raise RuntimeErrorSafe("master fingerprint does not match")
        source = wire.verify_policy(bundle["source_policy"], pin)
        checked = wire.verify_invitation(bundle["invitation"], bundle["source_policy"], pin, now=int(time.time()))
        if checked["endpoint"] != bundle["endpoint"]:
            raise RuntimeErrorSafe("invitation endpoint does not match")
        scope_id = source["scope_id"]
        bundle_hash = wire.canonical_hash(bundle)
        reservation_path = self.paths.pending_dir / "joins" / f"{scope_id}.json"
        with profile_lock(Paths(self.paths.root / "project-runtime-role")), profile_lock(
            Paths(self.paths.root / "project-join" / scope_id)
        ):
            registry = self.registry.read()
            # data.json is a master metadata identity even when it contains no
            # live entries (for example, after deleting the last key).
            if (
                self.paths.data_json.exists()
                or self.paths.data_json.is_symlink()
                or any(p["kind"] == "master_scope" for p in registry["profiles"])
            ):
                raise RuntimeErrorSafe("enroll replicas in a clean Keys Keeper root")
            try:
                reservation = _json_read(reservation_path, 4096)
            except FileNotFoundError:
                reservation = None
            if reservation is None:
                if not registry["profiles"]:
                    _assert_fresh_worker_root(self.paths)
                if any(p["scope_id"] == scope_id for p in registry["profiles"]):
                    raise RuntimeErrorSafe("scope already has a local profile")
                profile_id = str(uuid4())
                reservation = {
                    "schema_version": 1,
                    "scope_id": scope_id,
                    "bundle_hash": bundle_hash,
                    "profile_id": profile_id,
                }
                _atomic_write_bytes(reservation_path, json.dumps(
                    reservation, sort_keys=True, separators=(",", ":")
                ).encode())
            elif (
                not isinstance(reservation, dict)
                or set(reservation) != {"schema_version", "scope_id", "bundle_hash", "profile_id"}
                or reservation["schema_version"] != 1
                or reservation["scope_id"] != scope_id
                or reservation["bundle_hash"] != bundle_hash
            ):
                raise RuntimeErrorSafe("scope enrollment reservation conflicts")
            profile_id = _uuid(reservation["profile_id"])
            shell = {
                "id": profile_id, "kind": "replica", "scope_id": scope_id,
                "vault_id": source["vault_id"], "project": bundle["project"],
                "environment": bundle["environment"], "endpoint": bundle["endpoint"],
                "device_id": str(uuid4()), "status": "pending",
            }
            local = self.state(shell)
            if local.exists():
                state = local.load()
                enrollment = state.get("enrollment")
                if (
                    not isinstance(enrollment, dict)
                    or any(enrollment.get(key) != bundle[key] for key in expected)
                    or state.get("scope_id") != scope_id
                    or state.get("vault_id") != source["vault_id"]
                ):
                    raise RuntimeErrorSafe("stored scope enrollment conflicts")
                request = enrollment.get("request")
                if not isinstance(request, dict):
                    raise RuntimeErrorSafe("stored scope enrollment is incomplete")
                shell["device_id"] = _uuid(state.get("device_id"))
            else:
                device = shell["device_id"]
                signing, agreement = wire.generate_key(), wire.generate_key()
                token = secrets.token_urlsafe(48)
                request = wire.build_enrollment_request(
                    bundle["invitation"], bundle["source_policy"], pin, signing,
                    device_id=device,
                    agreement_public_key=wire.agreement_public_key(agreement),
                    token_hash=hashlib.sha256(token.encode()).hexdigest(),
                    role=role, request_id=str(uuid4()), challenge=wire.generate_key(),
                    now=int(time.time()),
                )
                unlock_path = self.paths.for_profile(profile_id).backend_password_file
                _atomic_write_bytes(
                    unlock_path, wire.encode_key(wire.generate_key()).encode()
                )
                state = {
                    "mode": "replica", "scope_id": scope_id,
                    "vault_id": source["vault_id"], "endpoint": bundle["endpoint"],
                    "device_id": device, "token": token, "pin": bundle["pin"],
                    "signing_private": wire.encode_key(signing),
                    "agreement_private": wire.encode_key(agreement),
                    "policy": bundle["source_policy"], "checkpoint": None,
                    "applied_checkpoint": None, "trusted_checkpoint": None,
                    "used_grants": [], "outbox": [],
                    "enrollment": {**bundle, "request": request},
                }
                local.save(state)
            existing = next((p for p in registry["profiles"] if p["id"] == profile_id), None)
            if existing is not None and any(
                existing[key] != shell[key]
                for key in ("id", "kind", "scope_id", "vault_id", "endpoint", "device_id")
            ):
                raise RuntimeErrorSafe("stored scope enrollment identity conflicts")
            if existing is not None and existing["status"] == "active":
                raise RuntimeErrorSafe("scope already has an active local profile")
            self.registry.put(shell, make_default=not registry["profiles"])
            return {"profile_id": profile_id, "request_bundle": {**bundle, "request": request}}

    def approve(self, request_bundle, *, fingerprint):
        self.assert_available()
        expected = {
            "schema_version", "invitation", "source_policy", "pin", "endpoint",
            "project", "environment", "request",
        }
        if (
            not isinstance(request_bundle, dict)
            or set(request_bundle) != expected
            or request_bundle["schema_version"] != 1
        ):
            raise RuntimeErrorSafe("invalid enrollment request bundle")
        if not isinstance(fingerprint, str) or len(fingerprint) != 64:
            raise RuntimeErrorSafe("invalid device request fingerprint")
        _public_label(request_bundle["project"], "request project")
        _public_label(request_bundle["environment"], "request environment")
        _public_label(request_bundle["endpoint"], "request endpoint", maximum=2048)
        pin = wire.decode_key(request_bundle["pin"])
        scope_id = wire.verify_policy(
            request_bundle["source_policy"], pin
        )["scope_id"]
        with profile_lock(Paths(self.paths.root / "project-enrollment" / scope_id)):
            return self._approve_serialized(request_bundle, fingerprint=fingerprint)

    def _approve_serialized(self, request_bundle, *, fingerprint):
        source, invitation, request = (request_bundle[k] for k in ("source_policy", "invitation", "request"))
        pin = wire.decode_key(request_bundle["pin"])
        body = wire.verify_enrollment_request(request, invitation, source, pin, now=int(time.time()))
        # Confirmation binds both device keys and bearer-token hash via the request.
        if not secrets.compare_digest(wire.canonical_hash(request), fingerprint):
            raise RuntimeErrorSafe("device request fingerprint does not match")
        scope_id = wire.verify_policy(source, pin)["scope_id"]
        item = self.registry.resolve(scope_id)
        if not item or item["kind"] != "master_scope":
            raise RuntimeErrorSafe("master scope is not configured")
        state = self.state(item)
        with state.locked():
            data = state.load()
            if data["pin"] != request_bundle["pin"] or data["endpoint"] != request_bundle["endpoint"]:
                raise RuntimeErrorSafe("enrollment authority does not match")
            invite = next((i for i in data["invites"] if wire.canonical_hash(i["invitation"]) == wire.canonical_hash(invitation)), None)
            digest = wire.canonical_hash(request)
            if invite is None or invite["source_policy"] != source:
                raise RuntimeErrorSafe("invitation is unknown")
            if invite["request_hash"] not in {None, digest}:
                raise RuntimeErrorSafe("invitation has already been consumed")
            if invite["bundle"]:
                current = wire.verify_policy(data["policy"], pin)
                blocked = {
                    item["record"]["payload"]["grant_id"]
                    for item in data.get("local_revocations", [])
                }
                if (
                    invite["grant"] is None
                    or invite["grant"]["grant_id"] in blocked
                    or not any(
                        grant == invite["grant"] for grant in current["grants"]
                    )
                ):
                    raise RuntimeErrorSafe("enrollment grant is no longer active")
                return invite["bundle"]
            recovery_hash = invite.get("recovery_hash")
            if (
                not isinstance(recovery_hash, str)
                or len(recovery_hash) != 64
                or any(character not in "0123456789abcdef" for character in recovery_hash)
            ):
                raise RuntimeErrorSafe("enrollment invitation has no recovery proof")
            if invite["grant"] is None:
                grant = {k: body[k] for k in ("device_id", "role", "signing_public_key", "agreement_public_key", "token_hash")}
                grant.update(grant_id=str(uuid4()), generation=1)
                invite.update(request_hash=digest, grant=grant)
                state.save(data)
            grant = invite["grant"]
        self.master(item).add_grant(grant)
        data = state.load()
        client = ProjectClient(base_url=data["endpoint"], token=Sealed(data["token"]), device_id=data["device_id"])
        snapshot = client.snapshot(scope_id, data["checkpoint"]["snapshot_hash"])["record"]
        wrap = wire.wrap_scope_key(wire.decode_key(data["scope_key"]), data["policy"], pin,
                                  wire.decode_key(data["signing_private"]), grant["device_id"])
        now = int(time.time())
        answer = wire.build_enrollment_answer(request, invitation, source, data["policy"], pin,
            wire.decode_key(data["signing_private"]), snapshot=snapshot, wrap=wrap, now=now, expires_at=now + 900)
        result = {"schema_version": 1, "invitation": invitation, "source_policy": source,
            "request": request, "policy": data["policy"], "snapshot": snapshot, "wrap": wrap,
            "answer": answer, "pin": data["pin"], "endpoint": data["endpoint"]}
        with state.locked():
            data = state.load()
            invite = next(i for i in data["invites"] if i["request_hash"] == digest)
            current = wire.verify_policy(data["policy"], pin)
            blocked = {
                item["record"]["payload"]["grant_id"]
                for item in data.get("local_revocations", [])
            }
            checkpoint = data.get("checkpoint")
            if (
                grant["grant_id"] in blocked
                or not any(candidate == grant for candidate in current["grants"])
                or data["policy"] != result["policy"]
                or not isinstance(checkpoint, dict)
                or checkpoint.get("snapshot_hash") != wire.canonical_hash(snapshot)
            ):
                raise RuntimeErrorSafe("enrollment changed while preparing its response; retry")
            invite["bundle"] = result
            state.save(data)
        return result

    def finish(self, selector, bundle):
        self.assert_available()
        item = self.registry.resolve(selector)
        if not item or item["kind"] != "replica":
            raise RuntimeErrorSafe("replica enrollment profile required")
        expected = {
            "schema_version", "invitation", "source_policy", "request", "policy",
            "snapshot", "wrap", "answer", "pin", "endpoint",
        }
        if (
            not isinstance(bundle, dict)
            or set(bundle) != expected
            or bundle["schema_version"] != 1
        ):
            raise RuntimeErrorSafe("invalid enrollment response bundle")
        with profile_lock(Paths(self.paths.root / "project-join" / item["scope_id"])):
            return self._finish_serialized(item, bundle)

    def _finish_serialized(self, item, bundle):
        state = self.state(item)
        digest = wire.canonical_hash(bundle)
        with state.locked():
            data = state.load()
            original = data.get("enrollment")
            if not isinstance(original, dict) or not isinstance(original.get("request"), dict):
                raise RuntimeErrorSafe("local enrollment state is incomplete")
            if (
                bundle["pin"] != data["pin"]
                or bundle["endpoint"] != data["endpoint"]
                or bundle["request"] != original["request"]
            ):
                raise RuntimeErrorSafe("enrollment response does not match the local request")
            previous_digest = data.get("enrollment_result_hash")
            if previous_digest is not None and previous_digest != digest:
                raise RuntimeErrorSafe("enrollment response conflicts with installed generation")
            if previous_digest == digest:
                payload, _checkpoint_value = self.replica_store(item).load()
                if item["status"] != "active":
                    item["status"] = "active"
                    self.registry.put(item)
                reservation = self.paths.pending_dir / "joins" / f"{item['scope_id']}.json"
                try:
                    reservation.unlink()
                except FileNotFoundError:
                    pass
                return {
                    "profile_id": item["id"], "status": "active",
                    "count": len(payload["entries"]),
                }
            pin = wire.decode_key(data["pin"])
            wire.verify_enrollment_answer(
                bundle["answer"], original["request"], original["invitation"],
                original["source_policy"], bundle["policy"], pin,
                snapshot=bundle["snapshot"], wrap=bundle["wrap"], now=int(time.time()),
            )
            key = wire.unwrap_scope_key(
                bundle["wrap"], bundle["policy"], pin, data["device_id"],
                wire.decode_key(data["agreement_private"]),
            )
            payload = wire.open_snapshot(
                bundle["snapshot"], bundle["policy"], pin, key
            )
            from keys_keeper.project_sync import _checkpoint
            checkpoint = _checkpoint(bundle["snapshot"])
            self.replica_store(item).install(payload, checkpoint)
            data.update(
                policy=bundle["policy"], trusted_checkpoint=checkpoint,
                applied_checkpoint=checkpoint, checkpoint=checkpoint,
                used_grants=wire.verify_policy(bundle["policy"], pin)["grants"],
                enrollment_result_hash=digest,
            )
            state.save(data)
            item["status"] = "active"
            self.registry.put(item)
        reservation = self.paths.pending_dir / "joins" / f"{item['scope_id']}.json"
        try:
            reservation.unlink()
        except FileNotFoundError:
            pass
        return {
            "profile_id": item["id"], "status": "active",
            "count": len(payload["entries"]),
        }
