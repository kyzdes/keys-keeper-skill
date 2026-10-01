#!/usr/bin/env python3
"""Measure isolated idle project sync; never access a user's vault or Keychain.

Select the implementation using PYTHONPATH=/path/to/checkout/src. All scopes,
keys, relay data and encrypted journals are generated under TemporaryDirectory.
--retain-state models a watcher retaining each scope's process-local journal.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import threading
import time

from keys_keeper import crypto
from keys_keeper.backend import Sealed
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.project_client import ProjectClient
from keys_keeper.project_service import ProjectService
from keys_keeper.project_sync import ProjectMaster, ProjectState, new_master_state
from keys_keeper.store import MetadataStore
from keys_keeper.sync_server import SyncServerApp, create_http_server


class EmptyBackend:
    def get(self, account):
        raise AssertionError("idle benchmark must not read a secret")


@contextmanager
def relay(root):
    app = SyncServerApp(root / "relay.sqlite3", "synthetic-benchmark-bootstrap")
    server = create_http_server(app)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        host, port = server.server_address[:2]
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


def run(scopes: int, cycles: int, retain_state: bool) -> dict:
    with tempfile.TemporaryDirectory(prefix="keys-idle-benchmark-") as directory:
        root = Path(directory)
        store = MetadataStore(Paths(root / "catalog"))
        store.migrate_catalog_v3()
        catalog = ProjectService(store)
        backend = EmptyBackend()
        with relay(root) as endpoint:
            admin = ProjectClient(base_url=endpoint, token=Sealed("synthetic-benchmark-bootstrap"))
            states = []
            for number in range(scopes):
                project = catalog.create_project(f"fixture-{number}", f"Fixture {number}")
                scope = catalog.create_scope(project.id, "synthetic")
                state = ProjectState(Paths(root / f"profile-{number}"), lambda: b"fixture-journal-key" * 2)
                initial = new_master_state(scope.id, scope.vault_id, endpoint)
                state.save(initial)
                admin.create_scope(initial["policy"])
                ProjectMaster(state, store, backend).publish()
                # Start each measured worker cold, as after a process restart.
                states.append(ProjectState(state.paths, lambda: b"fixture-journal-key" * 2))
            files = {path: path.read_bytes() for state in states for path in state.paths.operations_dir.glob("*.enc")}
            counts = {"kdf_derivations": 0, "journal_record_writes": 0}
            derive, write = crypto._derive_key, OperationJournal._write_unlocked

            def counted_derive(*args, **kwargs):
                counts["kdf_derivations"] += 1
                return derive(*args, **kwargs)

            def counted_write(*args, **kwargs):
                counts["journal_record_writes"] += 1
                return write(*args, **kwargs)

            crypto._derive_key = counted_derive
            OperationJournal._write_unlocked = counted_write
            cpu_start, wall_start = time.process_time(), time.perf_counter()
            try:
                for _ in range(cycles):
                    for retained in states:
                        state = retained if retain_state else ProjectState(retained.paths, lambda: b"fixture-journal-key" * 2)
                        master = ProjectMaster(state, store, backend)
                        assert master.receive() == {"processed": 0, "outcomes": {}}
                        assert master.publish() == {"status": "unchanged", "sequence": 1}
                cpu, wall = time.process_time() - cpu_start, time.perf_counter() - wall_start
            finally:
                crypto._derive_key = derive
                OperationJournal._write_unlocked = write
            return {
                "scopes": scopes, "cycles": cycles, "scope_cycles": scopes * cycles,
                "retain_state": retain_state, "all_results_idle": True,
                "cpu_seconds": round(cpu, 6), "wall_seconds": round(wall, 6),
                "encrypted_files_changed": sum(path.read_bytes() != before for path, before in files.items()),
                **counts,
            }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scopes", type=int, default=6)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--retain-state", action="store_true")
    arguments = parser.parse_args()
    if arguments.scopes < 1 or arguments.cycles < 1:
        parser.error("scopes and cycles must be positive")
    print(json.dumps(run(arguments.scopes, arguments.cycles, arguments.retain_state), sort_keys=True))
