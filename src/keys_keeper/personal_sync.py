"""Personal all-entry replication over KK3, with UI-managed enrollment.

The only all-entry authorization is an explicit bit in encrypted master state.
The public settings file selects this authority; it cannot widen another scope.
"""
from __future__ import annotations

import hashlib
import json
import platform
import secrets
import time
from pathlib import Path
from uuid import uuid4

from keys_keeper import pairing, project_protocol as wire
from keys_keeper.backend import Sealed
from keys_keeper.composition import AccessContext
from keys_keeper.models import EntryType, now_iso
from keys_keeper.operation_journal import _atomic_write_bytes, profile_lock
from keys_keeper.paths import Paths
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_runtime import ProjectRuntime, RuntimeErrorSafe, _json_read, _public_label, _uuid
from keys_keeper.project_service import ProjectService

RECOVERY_ACCOUNT = "kk:personal-recovery-key"
SETTINGS = "personal-sync.json"


def read_settings(paths):
    try:
        value = _json_read(paths.root / SETTINGS, 8192)
    except FileNotFoundError:
        return None
    expected = {"version", "role", "scope_id", "endpoint", "auto", "name", "replica_id"}
    if not isinstance(value, dict) or set(value) != expected or value["version"] != 1 or value["role"] not in {"master", "replica"} or type(value["auto"]) is not bool:
        raise RuntimeErrorSafe("Invalid personal sync settings")
    _uuid(value["scope_id"])
    if value["role"] == "replica":
        _uuid(value["replica_id"])
    elif value["replica_id"] is not None:
        raise RuntimeErrorSafe("Invalid personal master settings")
    _public_label(value["name"], "computer name", maximum=80)
    ProjectClient(base_url=value["endpoint"])
    return value


def worker_paths(paths):
    settings = read_settings(paths)
    return Paths(paths.root / "personal-replicas" / settings["replica_id"]) if settings and settings["role"] == "replica" else None


def _save_settings(paths, value):
    _atomic_write_bytes(paths.root / SETTINGS, json.dumps(value, sort_keys=True).encode())


def _client(runtime, item):
    data = runtime.state(item).load()
    return ProjectClient(base_url=data["endpoint"], token=Sealed(data["token"]), device_id=data["device_id"])


class PersonalSync:
    def __init__(self, paths, runtime=None):
        self.paths = paths
        self.root = runtime or ProjectRuntime(paths, access=AccessContext.UI_FORBIDDEN)

    def runtime(self):
        child = worker_paths(self.paths)
        return ProjectRuntime(child, access=AccessContext.UI_FORBIDDEN) if child else self.root

    def _configured(self, *, master=False):
        settings = read_settings(self.paths)
        if settings is None or (master and settings["role"] != "master"):
            raise RuntimeErrorSafe("Set up personal sync on your main computer first")
        runtime = self.runtime()
        item = runtime.registry.resolve(settings["scope_id"])
        if item is None:
            raise RuntimeErrorSafe("Personal sync setup is incomplete; retry setup")
        if master and runtime.state(item).load().get("personal_vault") is not True:
            raise RuntimeErrorSafe("This scope does not authorize all-key replication")
        return settings, runtime, item

    def options(self):
        profiles = self.root.registry.list()
        endpoints = sorted({i["endpoint"] for i in profiles if i["kind"] == "master_scope"})
        entries = self.root.master_store.list() if not worker_paths(self.paths) else []
        tokens = [e.name for e in entries if e.type == EntryType.API_KEY]
        preferred = "keys-keeper-kk3-prime-admin"
        return {"endpoint": endpoints[0] if len(endpoints) == 1 else "",
                "admin_token_entry": preferred if preferred in tokens else "",
                "token_entries": sorted(tokens), "count": len(entries),
                "name": platform.node()[:80] or "My computer"}

    def _backup(self):
        backend = self.root.master_backend
        if RECOVERY_ACCOUNT not in backend.list_ids():
            backend.set(RECOVERY_ACCOUNT, secrets.token_urlsafe(48))
        destination = self.paths.root / "recovery" / f"personal-{uuid4()}.kk3"
        self.root.backup("master", destination, backend.get(RECOVERY_ACCOUNT).unseal())
        return str(destination)

    def setup(self, *, endpoint, admin_token_entry, name, all_keys=False):
        if all_keys is not True:
            raise RuntimeErrorSafe("Confirm synchronization of all existing and future keys")
        _public_label(name, "computer name", maximum=80)
        transport = ProjectClient(base_url=endpoint)
        if transport._request("GET", "/v2/capabilities", auth=False).get("personal_pairing") != 1:
            raise RuntimeErrorSafe("Update the VPS relay to enable computer pairing")
        if worker_paths(self.paths) or any(i["kind"] == "replica" for i in self.root.registry.list()):
            raise RuntimeErrorSafe("This computer is already a replica")
        entry = self.root.master_store.get_by_name(admin_token_entry)
        if entry is None or entry.type != EntryType.API_KEY:
            raise RuntimeErrorSafe("Choose the saved VPS administrator credential")
        with profile_lock(Paths(self.paths.root / "personal-setup")):
            settings = read_settings(self.paths)
            if settings is not None and settings["endpoint"] != endpoint:
                raise RuntimeErrorSafe("The configured VPS cannot be replaced during setup")
            if settings is None:
                # Backup also establishes the verified migration proof for old catalogs.
                self._backup()
                if self.root.master_store._read().get("schema_version", 2) < 3:
                    self.root.master_store.migrate_catalog_v3()
                catalog = ProjectService(self.root.master_store)
                project = catalog.create_project("my-computers-" + uuid4().hex[:8], "My computers")
                scope = catalog.create_scope(project.id, "personal")
                settings = {"version": 1, "role": "master", "scope_id": scope.id,
                            "endpoint": endpoint, "auto": True, "name": name, "replica_id": None}
                _save_settings(self.paths, settings)
            self.root.initialize(settings["scope_id"], endpoint,
                                 admin_token=self.root.master_backend.get(entry.id))
            item = self.root.registry.resolve(settings["scope_id"])
            state = self.root.state(item)
            with state.locked():
                data = state.load()
                if not data.get("personal_vault") and (data.get("checkpoint") or data["policy"]["payload"]["grants"]):
                    raise RuntimeErrorSafe("Cannot convert an existing delivery scope to personal access")
                data["personal_vault"] = True
                data["personal_name"] = name
                state.save(data)
            self._backup()
        self.sync()
        return self.status()

    def status(self):
        settings = read_settings(self.paths)
        if settings is None:
            return {"configured": False, "options": self.options()}
        runtime = self.runtime()
        try:
            item = runtime.registry.resolve(settings["scope_id"])
        except RuntimeErrorSafe:
            item = None
        result = {"configured": True, **settings, "state": "setup_incomplete", "devices": []}
        if item is not None:
            state = runtime.state(item).load()
            profile = runtime.status(item["id"])
            result.update(state=item["status"], pending=profile.get("pending", 0),
                          scope_id=item["scope_id"], profile_id=item["id"],
                          count=len(runtime.master_store.list()) if settings["role"] == "master" else len(runtime.context().store.list()) if item["status"] == "active" else 0)
            names = state.get("personal_device_names", {})
            result["devices"] = [{"device_id": d["device_id"], "name": names.get(d["device_id"], "Connected computer"), "role": d["role"]}
                                 for d in profile.get("recipients", [])]
            if item["status"] == "pending" and state.get("personal_pairing"):
                request_hash = wire.canonical_hash(state["enrollment"]["request"])
                result["comparison_code"] = pairing.comparison(request_hash)
        try:
            result["last_sync"] = _json_read(self.paths.root / "personal-sync-status.json", 8192)
        except FileNotFoundError:
            result["last_sync"] = None
        try:
            result["background"] = _json_read(self.paths.root / "personal-sync-startup.json", 4096)
        except FileNotFoundError:
            result["background"] = None
        return result

    def sync(self):
        settings, runtime, item = self._configured()
        try:
            if item["status"] == "pending" and settings["role"] == "replica":
                result = self.poll_worker()
            else:
                if settings["role"] == "master":
                    self._flush_responses(runtime, item)
                result = runtime.sync(item["id"])
            status = {"at": now_iso(), "status": "waiting_for_approval" if result.get("status") == "pending" else "synced"}
            _atomic_write_bytes(self.paths.root / "personal-sync-status.json", json.dumps(status).encode())
            return result
        except Exception:
            status = {"at": now_iso(), "status": "pending", "error": "Synchronization could not complete. Changes are saved locally."}
            _atomic_write_bytes(self.paths.root / "personal-sync-status.json", json.dumps(status).encode())
            raise

    def invite(self):
        settings, runtime, item = self._configured(master=True)
        self._backup()
        bundle = runtime.invite(item["id"], ttl=600)
        pair_id, key = str(uuid4()), secrets.token_bytes(32)
        expires = int(time.time()) + 600
        packet = pairing.seal(key, pair_id, "invitation", bundle)
        record = {"pair_id": pair_id, "key": wire.encode_key(key), "expires_at": expires,
                  "invitation_packet": packet, "response_packet": None}
        local = runtime.state(item)
        with local.locked():
            data = local.load()
            records = [r for r in data.get("personal_pairings", []) if r["expires_at"] > time.time()]
            if len(records) >= 8:
                raise RuntimeErrorSafe("Finish an existing connection or wait for its code to expire")
            data["personal_pairings"] = records + [record]
            local.save(data)
        self._upload_invite(runtime, item, record)
        fingerprint = hashlib.sha256(wire.decode_key(bundle["pin"])).hexdigest()
        return {"code": pairing.make_code(settings["endpoint"], item["scope_id"], pair_id, key, fingerprint),
                "pair_id": pair_id, "expires_at": expires}

    @staticmethod
    def _upload_invite(runtime, item, record):
        key = wire.decode_key(record["key"])
        return _client(runtime, item)._request("POST", pairing.route(item["scope_id"]), payload={
            "pair_id": record["pair_id"], "token_hash": hashlib.sha256(pairing.token(key).encode()).hexdigest(),
            "expires_at": record["expires_at"], "invitation": record["invitation_packet"]}, expected_statuses=(200, 201))

    def join(self, *, code, name):
        with profile_lock(Paths(self.paths.root / "personal-setup")):
            return self._join(code=code, name=name)

    def _join(self, *, code, name):
        _public_label(name, "computer name", maximum=80)
        value = pairing.parse_code(code)
        settings = read_settings(self.paths)
        if settings and (settings["role"] != "replica" or settings["scope_id"] != value["scope_id"]):
            raise RuntimeErrorSafe("This computer is already connected to another vault")
        # Preserve pre-existing vaults; do not silently change their role/default.
        if not settings and (self.root.master_store.list() or self.root.registry.list()):
            raise RuntimeErrorSafe("Connect from an empty Keys Keeper installation; existing keys were preserved")
        key = wire.decode_key(value["key"])
        transport = pairing.client(value["endpoint"], key)
        mailbox = transport._request("GET", pairing.route(value["scope_id"], value["pair_id"]))
        bundle = pairing.open_packet(key, value["pair_id"], "invitation", mailbox["invitation"])
        if bundle.get("endpoint") != value["endpoint"] or bundle.get("source_policy", {}).get("payload", {}).get("scope_id") != value["scope_id"]:
            raise RuntimeErrorSafe("The connection code does not match this invitation")
        replica_id = settings["replica_id"] if settings else str(uuid4())
        runtime = ProjectRuntime(Paths(self.paths.root / "personal-replicas" / replica_id), access=AccessContext.UI_FORBIDDEN)
        joined = runtime.join(bundle, fingerprint=value["fingerprint"], role="contributor")
        item = runtime.registry.resolve(joined["profile_id"])
        local = runtime.state(item)
        with local.locked():
            data = local.load()
            previous = data.get("personal_pairing")
            if previous and previous["pair_id"] != value["pair_id"]:
                raise RuntimeErrorSafe("Another connection is already pending")
            if not previous:
                data["personal_pairing"] = {**value, "name": name, "request_packet": pairing.seal(key, value["pair_id"], "request", {"bundle": joined["request_bundle"], "name": name})}
                local.save(data)
        _save_settings(self.paths, {"version": 1, "role": "replica", "scope_id": item["scope_id"],
                                   "endpoint": value["endpoint"], "auto": True, "name": name, "replica_id": replica_id})
        self._upload_request(runtime, item)
        return {"status": "pending", "comparison_code": pairing.comparison(wire.canonical_hash(joined["request_bundle"]["request"]))}

    @staticmethod
    def _upload_request(runtime, item):
        record = runtime.state(item).load()["personal_pairing"]
        return pairing.client(record["endpoint"], wire.decode_key(record["key"]))._request(
            "POST", pairing.route(item["scope_id"], record["pair_id"], "request"),
            payload={"packet": record["request_packet"]}, expected_statuses=(200, 201))

    def _request(self, runtime, item, record):
        self._upload_invite(runtime, item, record)
        mailbox = _client(runtime, item)._request("GET", pairing.route(item["scope_id"], record["pair_id"]))
        if mailbox["request"] is None:
            return None
        value = pairing.open_packet(wire.decode_key(record["key"]), record["pair_id"], "request", mailbox["request"])
        if set(value) != {"bundle", "name"}:
            raise RuntimeErrorSafe("Invalid computer request")
        _public_label(value["name"], "computer name", maximum=80)
        bundle = value["bundle"]
        original = pairing.open_packet(wire.decode_key(record["key"]), record["pair_id"], "invitation", record["invitation_packet"])
        if set(bundle) != set(original) | {"request"} or any(bundle[k] != v for k, v in original.items()):
            raise RuntimeErrorSafe("The computer request belongs to another invitation")
        body = wire.verify_enrollment_request(bundle["request"], bundle["invitation"], bundle["source_policy"], wire.decode_key(bundle["pin"]), now=int(time.time()))
        if body["role"] != "contributor":
            raise RuntimeErrorSafe("Personal computers require read and create access")
        return value

    def pending(self):
        settings, runtime, item = self._configured(master=True)
        records = runtime.state(item).load().get("personal_pairings", [])
        result = []
        for record in records:
            if record["expires_at"] <= time.time() or record.get("response_packet"):
                continue
            request = self._request(runtime, item, record)
            if request:
                fingerprint = wire.canonical_hash(request["bundle"]["request"])
                result.append({"pair_id": record["pair_id"], "name": request["name"], "fingerprint": fingerprint,
                               "comparison_code": pairing.comparison(fingerprint)})
        return result

    def approve(self, *, pair_id, fingerprint):
        settings, runtime, item = self._configured(master=True)
        local = runtime.state(item)
        record = next((r for r in local.load().get("personal_pairings", []) if r["pair_id"] == pair_id and r["expires_at"] > time.time()), None)
        if record is None:
            raise RuntimeErrorSafe("This connection code has expired")
        request = self._request(runtime, item, record)
        if request is None:
            raise RuntimeErrorSafe("The other computer has not requested access yet")
        answer = runtime.approve(request["bundle"], fingerprint=fingerprint)
        with local.locked():
            data = local.load()
            stored = next(r for r in data["personal_pairings"] if r["pair_id"] == pair_id)
            if not stored["response_packet"]:
                stored["response_packet"] = pairing.seal(wire.decode_key(stored["key"]), pair_id, "response", answer)
                stored["response_device"] = answer["request"]["payload"]["device_id"]
            data.setdefault("personal_device_names", {})[answer["request"]["payload"]["device_id"]] = request["name"]
            local.save(data)
        self._flush_responses(runtime, item)
        return {"status": "approved"}

    @staticmethod
    def _flush_responses(runtime, item):
        local = runtime.state(item)
        data = local.load()
        policy = wire.verify_policy(data["policy"], wire.decode_key(data["pin"]))
        blocked = {r["record"]["payload"]["grant_id"] for r in data.get("local_revocations", [])}
        allowed = {g["device_id"] for g in policy["grants"] if g["grant_id"] not in blocked}
        for record in data.get("personal_pairings", []):
            if not record.get("response_packet") or record.get("response_sent") or record["expires_at"] <= time.time() or record.get("response_device") not in allowed:
                continue
            _client(runtime, item)._request("POST", pairing.route(item["scope_id"], record["pair_id"], "response"),
                payload={"packet": record["response_packet"]}, expected_statuses=(200, 201))
            with local.locked():
                current = local.load()
                next(r for r in current["personal_pairings"] if r["pair_id"] == record["pair_id"])["response_sent"] = True
                local.save(current)

    def poll_worker(self):
        with profile_lock(Paths(self.paths.root / "personal-setup")):
            return self._poll_worker()

    def _poll_worker(self):
        settings, runtime, item = self._configured()
        if settings["role"] != "replica":
            raise RuntimeErrorSafe("This is the main computer")
        if item["status"] == "active":
            return {"status": "active"}
        record = runtime.state(item).load()["personal_pairing"]
        self._upload_request(runtime, item)
        mailbox = pairing.client(record["endpoint"], wire.decode_key(record["key"]))._request("GET", pairing.route(item["scope_id"], record["pair_id"]))
        if mailbox["response"] is None:
            return {"status": "pending"}
        answer = pairing.open_packet(wire.decode_key(record["key"]), record["pair_id"], "response", mailbox["response"])
        return runtime.finish(item["id"], answer)

    def revoke(self, device_id):
        settings, runtime, item = self._configured(master=True)
        _uuid(device_id)
        return runtime.master(item).revoke(device_id)

    def cancel_pending(self):
        with profile_lock(Paths(self.paths.root / "personal-setup")):
            return self._cancel_pending()

    def _cancel_pending(self):
        settings, runtime, item = self._configured()
        if settings["role"] != "replica" or item["status"] != "pending":
            raise RuntimeErrorSafe("Only an unfinished connection can be cancelled")
        with profile_lock(Paths(runtime.paths.root / "project-join" / item["scope_id"])):
            data = runtime.state(item).load()
            current = runtime.registry.resolve(item["id"])
            if current["status"] != "pending" or data.get("checkpoint") or data.get("outbox") or data.get("enrollment_result_hash"):
                raise RuntimeErrorSafe("This connection already received data and cannot be reset")
            # Preserve the abandoned private identity instead of deleting files.
            # A main-computer grant, if approved concurrently, is disconnected
            # separately in its own device list.
            self.paths.root.joinpath(SETTINGS).unlink()
        # A later attempt gets a fresh UUID root. In-flight readers and Windows
        # file locks can finish without renaming or deleting private state.
        return {"status": "cancelled"}

    def set_auto(self, enabled):
        if type(enabled) is not bool:
            raise RuntimeErrorSafe("Choose whether automatic sync is enabled")
        settings = read_settings(self.paths)
        if settings is None:
            raise RuntimeErrorSafe("Set up personal sync first")
        settings["auto"] = enabled
        _save_settings(self.paths, settings)
        from keys_keeper.sync_autostart import configure
        try:
            result = configure(self.paths, enabled)
        except Exception:
            result = {"autostart": False, "error": "Could not configure background sync; use Retry background sync"}
        _atomic_write_bytes(self.paths.root / "personal-sync-startup.json", json.dumps(result).encode())
        return result

    def watch(self, *, interval=60, cycles=0, sleep=time.sleep):
        if not 5 <= interval <= 3600 or cycles < 0:
            raise RuntimeErrorSafe("Invalid synchronization interval")
        cycle = 0
        while cycles == 0 or cycle < cycles:
            settings = read_settings(self.paths)
            if settings is None or not settings["auto"]:
                break
            try:
                self.sync()
            except Exception:
                pass  # sync persists a fixed public error; never print payloads.
            cycle += 1
            if cycles == 0 or cycle < cycles:
                sleep(interval)
        return {"cycles": cycle}
