"""Assert known defects in the reviewed source using synthetic fixtures only.

No production source, OS vault or clipboard is changed. The results file and
temporary fixtures are written only beside this script.
"""
from __future__ import annotations

import argparse
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from keys_keeper import cli, api
from keys_keeper.backend import KeychainBackend, KeychainError, Sealed
from keys_keeper.crypto import decrypt_blob
from keys_keeper.master_journal import MasterMutationManager
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal
from keys_keeper.paths import Paths
from keys_keeper.refs import RefMissingError, resolve_chain
from keys_keeper.secure_io import read_secure_text, replace_secure_text
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore
from keys_keeper.sync import build_snapshot_payload

REPORTS: list[dict] = []
SOURCE_COMMIT = "36df576ba403437d6352add265232bc01601cbae"


def assert_source_commit():
    source_root = Path(cli.__file__).resolve().parents[2]
    actual = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=source_root, text=True
    ).strip()
    if actual != SOURCE_COMMIT:
        raise SystemExit("review probes require source commit " + SOURCE_COMMIT)


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values = {}
        self.denied = set()
        self.reads = []

    def get(self, account):
        self.reads.append(account)
        if account in self.denied:
            raise KeychainError("synthetic access denied")
        if account not in self.values:
            raise KeychainError("synthetic account absent")
        return Sealed(self.values[account])

    def set(self, account, value):
        self.values[account] = value

    def delete(self, account):
        self.values.pop(account, None)

    def list_ids(self):
        return list(self.values)


class MemoryAudit:
    def __init__(self):
        self.events = []

    def record(self, **kwargs):
        self.events.append(kwargs)

    def search(self, *, name=None, limit=1000, newest_first=False, **kwargs):
        rows = [r for r in self.events if name is None or r.get("name") == name]
        return iter((list(reversed(rows)) if newest_first else rows)[:limit])


def fixture(root, label, *, catalog=False):
    paths = Paths(root / label)
    paths.ensure()
    store = MetadataStore(paths)
    backend = MemoryBackend()
    if catalog:
        store.migrate_catalog_v3()
        journal = OperationJournal(paths=paths, password_provider=lambda: b"synthetic-review-journal-key-only")
        service = VaultService(store, backend, master_mutations=MasterMutationManager(store, backend, journal))
    else:
        service = VaultService(store, backend)
    return SimpleNamespace(paths=paths, store=store, backend=backend, audit=MemoryAudit(), service=service, kind="master")


def add(ctx, name, value="synthetic-review-value", **kwargs):
    entry = Entry.new(name=name, type=kwargs.pop("type", EntryType.API_KEY), **kwargs)
    ctx.service.create_entry(entry, secrets=SecretInput(value=value))
    return entry


def invoke(ctx, command):
    out, err = io.StringIO(), io.StringIO()
    with patch.object(cli, "_context_or_error", return_value=ctx), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        result = cli.build_parser().parse_args(command).func(cli.build_parser().parse_args(command))
    return result, out.getvalue(), err.getvalue()


def record(name, **evidence):
    REPORTS.append({"probe": name, **evidence})


def probes(root):
    ctx = fixture(root, "legacy-null")
    entry = add(ctx, "denied-entry")
    ctx.backend.denied.add(entry.id)
    payload = build_snapshot_payload(ctx.store, ctx.backend)
    assert payload["entries"][0]["_secret"] is None
    record("legacy_snapshot_silently_omits_denied_secret", accepted=True, required_secret_is_null=True)

    backup = root / "legacy-backup.enc"
    with patch.object(cli.getpass, "getpass", return_value="synthetic-export-password"):
        result, out, err = invoke(ctx, ["export", str(backup)])
    exported = json.loads(decrypt_blob(backup.read_bytes(), password="synthetic-export-password"))
    assert result == 0 and not err and exported["entries"][0]["_secret"] is None
    record("legacy_export_reports_success_with_denied_secret", exit_code=result, required_secret_is_null=True, success_receipt=True)

    victim = root / "existing-file"
    victim.write_bytes(b"SYNTHETIC-UNRELATED-CONTENTS")
    link = root / "backup-symlink"
    link.symlink_to(victim)
    with patch.object(cli.getpass, "getpass", return_value="synthetic-export-password"):
        result, out, err = invoke(ctx, ["export", str(link)])
    assert result == 0 and victim.read_bytes().startswith(b"KK1\x00")
    record("legacy_export_follows_symlink_and_overwrites_target", exit_code=result, target_overwritten=True, target_mode=oct(victim.stat().st_mode & 0o777))

    for catalog in (False, True):
        ctx = fixture(root, "rename-v3" if catalog else "rename-v2", catalog=catalog)
        parent = add(ctx, "old-key", type=EntryType.SSH_KEY, fields={"public_key": "synthetic-public-key"})
        child = add(ctx, "linked-server", type=EntryType.SERVER, fields={"host": "example.invalid", "user": "root", "auth": "ssh_key"}, refs=[{"role": "ssh_key", "name": parent.name}])
        updated = ctx.store.get_by_id(parent.id)
        updated.name = "new-key"
        ctx.service.update_entry(updated)
        try:
            resolve_chain(ctx.store.list(), child.name, "ssh_key")
        except RefMissingError:
            pass
        else:
            raise AssertionError("expected dangling reference")
        assert ctx.store.get_by_id(child.id).refs[0]["name"] == "old-key"
        record("rename_leaves_dangling_reference", schema=3 if catalog else 2, rename_committed=True, dependent_uses_old_name=True, resolution_failed=True)
        replacement = add(ctx, "old-key", "synthetic-different-value", type=EntryType.SSH_KEY, fields={"public_key": "synthetic-different-public-key"})
        assert resolve_chain(ctx.store.list(), child.name, "ssh_key").id == replacement.id != parent.id
        record("reusing_old_name_silently_rebinds_reference", schema=3 if catalog else 2, dependent_unchanged=True, resolved_to_different_entry=True)

    ctx = fixture(root, "resolve-denied")
    blocked = add(ctx, "blocked-entry")
    later = add(ctx, "later-entry")
    ctx.backend.denied.add(blocked.id)
    ctx.backend.reads.clear()
    target = root / "resolve-denied.env"
    target.write_text("A=__KEYS:blocked-entry__\nB=__KEYS:blocked-entry__\nC=__KEYS:later-entry__\n")
    result, out, err = invoke(ctx, ["resolve", str(target)])
    assert result == 1 and ctx.backend.reads == [blocked.id, blocked.id, later.id]
    assert not ctx.audit.events
    record("resolve_continues_after_authorization_failure", exit_code=result, denied_read_attempts=2, later_secret_read=True, audit_events=0)

    ctx = fixture(root, "env-sinks")
    entry = add(ctx, "env-entry", "synthetic-new-value")
    target = root / "duplicate.env"
    target.write_text("MY_KEY=synthetic-old-one\nMY_KEY=synthetic-old-two\n")
    result, out, err = invoke(ctx, ["inject", entry.name, "--file", str(target), "--as", "MY_KEY", "--replace"])
    lines = target.read_text().splitlines()
    assert result == 0 and lines[-1] == "MY_KEY=synthetic-old-two"
    record("inject_replace_only_updates_first_duplicate", exit_code=result, duplicate_assignments=2, last_assignment_still_old=True)

    target = root / "bad-env-name.env"
    result, out, err = invoke(ctx, ["inject", entry.name, "--file", str(target), "--as", "SAFE=first\nUNRELATED"])
    assert result == 0 and len(target.read_text().splitlines()) == 2
    record("inject_accepts_newline_in_env_name", exit_code=result, assignments_written=2)

    ctx.backend.values[entry.id] = "synthetic-line-one\nUNRELATED=synthetic-line-two"
    target = root / "multiline.env"
    result, out, err = invoke(ctx, ["inject", entry.name, "--file", str(target), "--as", "MY_KEY"])
    assert result == 0 and len(target.read_text().splitlines()) == 2
    record("inject_multiline_value_creates_second_assignment", exit_code=result, assignments_written=2)

    target = root / "concurrent-edit.env"
    target.write_text("BEFORE=synthetic-one\n")
    state = read_secure_text(target, missing_ok=False)
    with target.open("w") as stream:
        stream.write("CONCURRENT=synthetic-two\n")
    assert target.stat().st_ino == state.identity[1]
    replace_secure_text(state, state.text + "INJECTED=synthetic-three\n")
    assert "CONCURRENT=" not in target.read_text()
    record("secure_sink_accepts_in_place_concurrent_edit", same_inode=True, concurrent_edit_lost=True)

    ctx = fixture(root, "audit-after-write")
    entry = add(ctx, "audit-entry")
    target = root / "audit-after-write.env"
    with patch.object(ctx.audit, "record", side_effect=OSError("synthetic audit disk failure")):
        try:
            invoke(ctx, ["inject", entry.name, "--file", str(target), "--as", "MY_KEY"])
        except OSError:
            pass
        else:
            raise AssertionError("expected audit exception")
    assert target.exists() and "MY_KEY=" in target.read_text()
    record("audit_failure_escapes_after_successful_sink", sink_committed=True, command_raises=True, receipt_missing=True)

    ctx.audit.events = [{"name": entry.name, "index": i} for i in range(7)]
    class Handler:
        _kk_context = ctx
        def _send_json(self, status, payload):
            self.status, self.payload = status, payload
    handler = Handler()
    api._entry_detail(handler, ctx.paths, entry.id)
    assert [r["index"] for r in handler.payload["recent_events"]] == [0, 1, 2, 3, 4]
    record("entry_recent_events_returns_oldest_five", returned_indices=[0, 1, 2, 3, 4], expected_indices=[6, 5, 4, 3, 2])

    ctx = fixture(root, "ui-api-contract")
    class ApiHandler:
        _kk_context = ctx
        def _send_json(self, status, payload):
            self.status, self.payload = status, payload
    handler = ApiHandler()
    api._create_entry(handler, ctx.paths, json.dumps({"name": "ui-note", "type": "note", "fields": {"body": "synthetic-public-note"}}).encode())
    assert handler.status == 400 and ctx.store.get_by_name("ui-note") is None
    record("ui_note_payload_is_rejected_by_domain_model", status=handler.status, missing_required_secret_body=True)

    entry = add(ctx, "before-ui-rename")
    api._patch_entry(handler, ctx.paths, entry.id, json.dumps({"name": "after-ui-rename"}).encode())
    assert handler.status == 200 and ctx.store.get_by_id(entry.id).name == "before-ui-rename"
    record("api_patch_accepts_unsupported_name_field", status=handler.status, name_unchanged=True, edit_form_is_readonly=True)

    ctx_empty = fixture(root, "empty-existing-metadata")
    existing = add(ctx_empty, "existing-entry")
    ctx_empty.paths.data_json.write_bytes(b"")
    assert ctx_empty.store.list() == [] and existing.id in ctx_empty.backend.values
    record("existing_empty_metadata_is_treated_as_fresh_vault", metadata_entries=0, backend_entry_still_present=True, read_error=False)

    import keys_keeper.operation_journal as journal_module
    from keys_keeper.operation_journal import JournalError
    ctx_history = fixture(root, "completed-history", catalog=True)
    for i in range(4):
        add(ctx_history, "completed-entry-" + str(i))
    manager = ctx_history.service.master_mutations
    journal = manager.journal
    records = list(ctx_history.paths.operations_dir.glob("*.enc"))
    assert len(records) == 4 and all(journal.read(p.stem).finished for p in records)
    assert not journal.pending_refs()
    with patch.object(journal_module, "_MAX_RECOVERY_RECORDS", 3):
        try:
            manager.recover()
        except JournalError:
            pass
        else:
            raise AssertionError("expected completed-history resource limit")
    record("completed_history_counts_towards_recovery_limit", completed_records=4, pending_records=0, modeled_record_limit=3, recovery_rejected=True, production_record_limit=10000)

    from keys_keeper import crypto
    for i in range(4, 8):
        add(ctx_history, "completed-entry-" + str(i))
    # A new journal instance makes the first scan genuinely cold: no key from
    # fixture creation remains in its single-record derivation cache.
    fresh_journal = OperationJournal(
        paths=ctx_history.paths,
        password_provider=lambda: b"synthetic-review-journal-key-only",
    )
    manager = MasterMutationManager(ctx_history.store, ctx_history.backend, fresh_journal)
    ctx_history.service.master_mutations = manager
    real_kdf = crypto._derive_key
    counts = {"cold": 0, "warm": 0, "mutation": 0, "after_mutation": 0}
    phase = "cold"
    def counted_kdf(*args, **kwargs):
        counts[phase] += 1
        return real_kdf(*args, **kwargs)
    with patch.object(crypto, "_derive_key", side_effect=counted_kdf):
        started = time.perf_counter()
        manager.recover()
        cold_seconds = time.perf_counter() - started
        phase = "warm"
        manager.recover()
        assert counts["warm"] == 0
        phase = "mutation"
        add(ctx_history, "completed-entry-8")
        phase = "after_mutation"
        started = time.perf_counter()
        manager.recover()
        after_seconds = time.perf_counter() - started
    record("completed_history_reauthenticated_after_every_mutation", completed_records_before=8, completed_records_after=9,
           cold_kdf_count=counts["cold"], warm_unchanged_kdf_count=counts["warm"], after_mutation_kdf_count=counts["after_mutation"],
           cold_wall_seconds=round(cold_seconds, 6), after_mutation_wall_seconds=round(after_seconds, 6))

    from keys_keeper.server import AdminServer
    runtime = SimpleNamespace(context=lambda _selector=None: ctx)
    server = AdminServer(paths=ctx.paths, port=0, idle_timeout_sec=30, project_runtime=runtime)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connection = http.client.HTTPConnection("127.0.0.1", server.bound_port, timeout=2)
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            connection.request("POST", "/api/entries", body=b"{", headers={"Sec-Keys-Token": server.token, "Content-Type": "application/json"})
            try:
                connection.getresponse()
            except http.client.RemoteDisconnected:
                record("authenticated_admin_malformed_json_closes_connection", disconnected=True, structured_400=False)
            else:
                raise AssertionError("expected unhandled JSON error")
    finally:
        connection.close()
        server.stop()
        thread.join(timeout=3)


def fifo_child(root):
    import keys_keeper.secure_io as secure_io
    target = root / "fifo-race-target"
    target.write_text("SYNTHETIC=1")
    real_open = os.open
    def raced_open(path, flags, *args, **kwargs):
        if Path(path) == target:
            target.unlink()
            os.mkfifo(target)
        return real_open(path, flags, *args, **kwargs)
    with patch.object(secure_io.os, "open", side_effect=raced_open):
        read_secure_text(target, missing_ok=False)


def legacy_crash_child(root):
    from keys_keeper.backend_file import EncryptedFileBackend
    paths = Paths(root)
    backend = EncryptedFileBackend(paths=paths, password_file=root / "synthetic-password", allow_env_password=False)
    store = MetadataStore(paths)
    changed = store.get_by_name("crash-entry")
    changed.note = "synthetic-new-note"
    real_set = backend.set
    def crashing_set(account, value):
        real_set(account, value)
        os._exit(77)
    with patch.object(backend, "set", side_effect=crashing_set):
        VaultService(store, backend).update_entry(changed, secrets=SecretInput(value="synthetic-new-value"))


def process_probes(root):
    try:
        subprocess.run([sys.executable, __file__, "--fifo-child", str(root)], capture_output=True, timeout=1)
    except subprocess.TimeoutExpired:
        record("secure_sink_blocks_on_fifo_open_race", child_exceeded_seconds=1, child_killed_by_probe=True)
    else:
        raise AssertionError("expected blocking FIFO open")
    from keys_keeper.backend_file import EncryptedFileBackend
    paths = Paths(root / "legacy-crash")
    paths.ensure()
    password = paths.root / "synthetic-password"
    password.write_bytes(b"synthetic-unlock-password")
    password.chmod(0o600)
    backend = EncryptedFileBackend(paths=paths, password_file=password, allow_env_password=False)
    store = MetadataStore(paths)
    entry = Entry.new(name="crash-entry", type=EntryType.API_KEY, note="synthetic-old-note")
    VaultService(store, backend).create_entry(entry, secrets=SecretInput(value="synthetic-old-value"))
    result = subprocess.run([sys.executable, __file__, "--legacy-crash-child", str(paths.root)], capture_output=True, timeout=10)
    assert result.returncode == 77
    assert backend.get(entry.id).unseal() == "synthetic-new-value"
    assert store.get_by_id(entry.id).note == "synthetic-old-note"
    record("legacy_mutation_crash_leaves_mismatched_state", child_exit=77, backend_has_new_value=True, metadata_has_old_note=True)


if __name__ == "__main__":
    assert_source_commit()
    parser = argparse.ArgumentParser()
    parser.add_argument("--fifo-child", type=Path)
    parser.add_argument("--legacy-crash-child", type=Path)
    args = parser.parse_args()
    if args.fifo_child:
        fifo_child(args.fifo_child)
    elif args.legacy_crash_child:
        legacy_crash_child(args.legacy_crash_child)
    else:
        with tempfile.TemporaryDirectory(prefix="synthetic-probes-", dir=Path(__file__).parent) as scratch:
            root = Path(scratch)
            probes(root)
            process_probes(root)
        result = {"source_commit": SOURCE_COMMIT, "synthetic_data_only": True, "probes": REPORTS}
        Path(__file__).with_name("probe-results.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
