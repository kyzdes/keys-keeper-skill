"""Credential/sink contracts using synthetic, platform-independent providers."""
from __future__ import annotations

import json
import os
import shlex
import stat
from io import StringIO
from types import SimpleNamespace

import pytest

from keys_keeper import cli, crypto, vault_snapshot
from keys_keeper.backend import (
    KeychainBackend, KeychainError, Sealed,
    SecretAccessDenied, SecretNotFound, SecretUnavailable,
)
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.service import VaultService
from keys_keeper.store import MetadataStore
from keys_keeper.vault_snapshot import SnapshotReadError, build_snapshot_payload


SENTINEL = "synthetic-secret-that-must-not-appear-in-receipts"


class MemoryBackend(KeychainBackend):
    def __init__(self):
        self.values: dict[str, str] = {}
        self.reads: list[str] = []
        self.failures: dict[str, Exception] = {}
        self.enumeration_failure: Exception | None = None

    def get(self, account):
        self.reads.append(account)
        if account in self.failures:
            raise self.failures[account]
        if account not in self.values:
            raise SecretNotFound("secret missing")
        return Sealed(self.values[account])

    def list_ids(self):
        if self.enumeration_failure:
            raise self.enumeration_failure
        return list(self.values)

    def set(self, account, value):
        self.values[account] = value

    def delete(self, account):
        self.values.pop(account, None)


class MemoryAudit:
    def __init__(self):
        self.events = []
        self.unavailable = False

    def record(self, **event):
        if self.unavailable:
            raise OSError(SENTINEL)
        self.events.append(event)


@pytest.fixture
def context(tmp_path, monkeypatch):
    paths = Paths(root=tmp_path / "isolated-vault")
    store, backend, audit = MetadataStore(paths), MemoryBackend(), MemoryAudit()
    ctx = SimpleNamespace(paths=paths, store=store, backend=backend, audit=audit,
                          kind="master", service=VaultService(store, backend))
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args, **_kwargs: ctx)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_args: "synthetic-backup-password")
    return ctx


def add(ctx, name="test-key", value=SENTINEL, *, type_=EntryType.API_KEY, fields=None):
    entry = Entry.new(name=name, type=type_, fields=fields or {})
    ctx.store.add(entry)
    if value is not None:
        ctx.backend.values[entry.id] = value
    return entry


@pytest.mark.parametrize("failure", [
    SecretAccessDenied(SENTINEL), SecretUnavailable(SENTINEL),
    KeychainError(SENTINEL), RuntimeError(SENTINEL),
])
def test_denied_snapshot_export_leaves_existing_backup_unchanged(context, tmp_path, capsys, failure):
    entry = add(context)
    context.backend.failures[entry.id] = failure
    target = tmp_path / "existing.kk"
    target.write_bytes(b"previous-backup")
    assert cli.main(["export", str(target), "--replace"]) == 1
    assert target.read_bytes() == b"previous-backup"
    assert context.backend.reads == [entry.id]
    assert context.audit.events[-1]["success"] is False
    assert SENTINEL not in capsys.readouterr().err


def test_snapshot_presence_preflight_fails_before_any_secret_read(context):
    add(context, "available-key")
    add(context, "missing-key", value=None)
    with pytest.raises(SnapshotReadError, match="required.*missing"):
        build_snapshot_payload(context.store, context.backend)
    assert context.backend.reads == []


def test_snapshot_optional_absence_is_valid_but_present_passphrase_denial_is_not(context):
    entry = add(context, type_=EntryType.SSH_KEY, fields={"public_key": "ssh-ed25519 synthetic"})
    payload = build_snapshot_payload(context.store, context.backend)
    assert payload["entries"][0]["_secret_passphrase"] is None
    assert context.backend.reads == [entry.id]
    context.backend.values[entry.id + ":passphrase"] = "synthetic-passphrase"
    context.backend.failures[entry.id + ":passphrase"] = SecretAccessDenied(SENTINEL)
    with pytest.raises(SnapshotReadError, match="access failed"):
        build_snapshot_payload(context.store, context.backend)


def test_snapshot_metadata_only_entry_and_empty_secret_round_trip(context):
    domain = add(context, "test-domain", value=None, type_=EntryType.DOMAIN, fields={"host": "example.test"})
    entry = add(context, value="")
    payload = build_snapshot_payload(context.store, context.backend)
    assert {r["id"]: r["_secret"] for r in payload["entries"]} == {domain.id: None, entry.id: ""}
    assert context.backend.reads == [entry.id]


def test_snapshot_account_enumeration_failure_never_reads_or_publishes(context, tmp_path):
    add(context)
    context.backend.enumeration_failure = SecretUnavailable(SENTINEL)
    target = tmp_path / "backup.kk"
    assert cli.main(["export", str(target)]) == 1
    assert not target.exists()
    assert context.backend.reads == []


def test_export_is_private_verified_and_does_not_chmod_parent(context, tmp_path):
    entry = add(context)
    target = tmp_path / "backup.kk"
    original_mode = stat.S_IMODE(tmp_path.stat().st_mode)
    assert cli.main(["export", str(target)]) == 0
    payload = vault_snapshot.decrypt_snapshot(target.read_bytes(), passphrase="synthetic-backup-password")
    assert payload["entries"][0]["id"] == entry.id
    assert payload["entries"][0]["_secret"] == SENTINEL
    assert stat.S_IMODE(tmp_path.stat().st_mode) == original_mode
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_export_existing_backup_requires_explicit_replace_before_prompt(context, tmp_path, monkeypatch):
    add(context)
    target = tmp_path / "backup.kk"
    target.write_bytes(b"existing-backup")
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_args: pytest.fail("unexpected password prompt"))
    assert cli.main(["export", str(target)]) == 1
    assert target.read_bytes() == b"existing-backup"
    assert context.backend.reads == []


@pytest.mark.skipif(os.name != "posix", reason="requires unprivileged symlinks")
def test_export_and_import_refuse_symlink_without_touching_target(context, tmp_path, monkeypatch):
    add(context)
    target = tmp_path / "victim"
    target.write_bytes(b"unrelated-content")
    link = tmp_path / "backup.kk"
    link.symlink_to(target)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_args: pytest.fail("unexpected password prompt"))
    assert cli.main(["export", str(link), "--replace"]) == 1
    assert cli.main(["import", str(link)]) == 1
    assert target.read_bytes() == b"unrelated-content"
    assert context.backend.reads == []


def test_import_limit_precedes_password_prompt_and_kdf(context, tmp_path, monkeypatch):
    target = tmp_path / "oversized.kk"
    target.write_bytes(b"KK1\x00" + b"x" * 125)
    monkeypatch.setattr(vault_snapshot, "MAX_SNAPSHOT_BLOB_BYTES", 128)
    monkeypatch.setattr(cli.getpass, "getpass", lambda *_args: pytest.fail("unexpected password prompt"))
    monkeypatch.setattr(vault_snapshot, "decrypt_blob", lambda *_args, **_kwargs: pytest.fail("unexpected KDF"))
    assert cli.main(["import", str(target)]) == 1
    assert context.store.list() == []


def test_snapshot_limits_before_encrypt_or_decrypt_kdf(monkeypatch):
    monkeypatch.setattr(vault_snapshot, "MAX_SNAPSHOT_BLOB_BYTES", 128)
    monkeypatch.setattr(vault_snapshot, "encrypt_blob", lambda *_args, **_kwargs: pytest.fail("unexpected KDF"))
    monkeypatch.setattr(vault_snapshot, "decrypt_blob", lambda *_args, **_kwargs: pytest.fail("unexpected KDF"))
    with pytest.raises(SnapshotReadError, match="size limit"):
        vault_snapshot.encrypt_snapshot({"entries": [{"value": "x" * 129}]}, passphrase="pw")
    with pytest.raises(crypto.BadPassword, match="size limit"):
        vault_snapshot.decrypt_snapshot(b"KK1\x00" + b"x" * 125, passphrase="pw")


def test_import_rejects_incomplete_required_secret_before_mutation(context, tmp_path):
    entry = Entry.new(name="incomplete-key", type=EntryType.API_KEY)
    payload = {"schema_version": 2, "entries": [{**entry.to_dict(), "_secret": None}]}
    target = tmp_path / "incomplete.kk"
    target.write_bytes(crypto.encrypt_blob(json.dumps(payload).encode(), password="synthetic-backup-password"))
    assert cli.main(["import", str(target)]) == 1
    assert context.store.list() == []
    assert context.backend.values == {}


def test_import_rejects_duplicate_json_members_before_mutation(context, tmp_path):
    target = tmp_path / "duplicate-json.kk"
    target.write_bytes(crypto.encrypt_blob(b'{"schema_version":1,"entries":[],"entries":[]}',
                                          password="synthetic-backup-password"))
    assert cli.main(["import", str(target)]) == 1
    assert context.store.list() == []


@pytest.mark.parametrize("identifier", ["GOOD\nOTHER", "GOOD=FIRST", "1INVALID", "BAD-NAME", ""])
def test_inject_invalid_identifier_precedes_context_and_secret_reads(monkeypatch, tmp_path, identifier):
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args: pytest.fail("unexpected vault access"))
    assert cli.main(["inject", "test-key", "--file", str(tmp_path / ".env"), "--as", identifier]) == 2


def test_inject_rejects_duplicate_or_multiline_assignment_before_read(context, tmp_path):
    add(context)
    target = tmp_path / ".env"
    for original in ["MY_KEY=first\n export MY_KEY = second\n", "MY_KEY='first\nsecond'\n"]:
        target.write_text(original)
        assert cli.main(["inject", "test-key", "--file", str(target), "--as", "MY_KEY", "--replace"]) == 1
        assert target.read_text() == original
    assert context.backend.reads == []


@pytest.mark.parametrize("value", [SENTINEL + suffix for suffix in ["\nOTHER=value", "\r", "\x00", "'apostrophe", "\\escape", "${OTHER}", "$OTHER", "\u2028OTHER=value"]])
def test_inject_unsupported_values_leave_file_unchanged_and_never_expose(context, tmp_path, capsys, value):
    entry = add(context, value=value)
    target = tmp_path / ".env"
    target.write_text("OTHER=keep\n")
    assert cli.main(["inject", "test-key", "--file", str(target), "--as", "MY_KEY"]) == 1
    assert target.read_text() == "OTHER=keep\n"
    assert context.backend.reads == [entry.id]
    assert SENTINEL not in capsys.readouterr().err


@pytest.mark.parametrize("value", ["simple-token/@host:443", "space and #comment", "literal=with\"quotes", "не ASCII"])
def test_inject_supported_literals_round_trip_without_interpolation(context, tmp_path, value):
    add(context, value=value)
    target = tmp_path / ".env"
    assert cli.main(["inject", "test-key", "--file", str(target), "--as", "MY_KEY"]) == 0
    # Standard shell lexical parsing verifies the literal subset independently
    # of the serializer (no shell process or environment evaluation is run).
    assert shlex.split(target.read_text(encoding="utf-8"), comments=True) == ["MY_KEY=" + value]


def test_inject_success_with_audit_failure_reports_committed(context, tmp_path, capsys):
    add(context)
    context.audit.unavailable = True
    target = tmp_path / ".env"
    assert cli.main(["inject", "test-key", "--file", str(target), "--as", "MY_KEY"]) == 0
    assert SENTINEL in target.read_text()
    receipt = json.loads(capsys.readouterr().err)
    assert receipt == {"operation": "inject", "committed": True, "outcome": "published",
                       "audit_status": "unavailable"}


@pytest.mark.parametrize("published", [True, None])
def test_cli_mutation_audit_matches_known_or_unknown_outcome(context, monkeypatch, capsys, published):
    class Failure(RuntimeError):
        committed = published
    create = context.service.create_entry
    def fail(entry, **kwargs):
        if published:
            create(entry, **kwargs)
        raise Failure(SENTINEL)
    monkeypatch.setattr(context.service, "create_entry", fail)
    monkeypatch.setattr(cli.sys, "stdin", StringIO("synthetic-stored-value"))
    assert cli.main(["add", "receipt-key", "--stdin"]) == 1
    output = capsys.readouterr()
    receipt = json.loads(output.err.splitlines()[0])
    event = context.audit.events[-1]
    assert receipt["committed"] is published
    assert receipt["outcome"] == event["outcome"] == ("published" if published else "unconfirmed")
    assert event["committed"] is published and event["success"] is (published is True)
    assert (context.store.get_by_name("receipt-key") is not None) is (published is True)
    assert SENTINEL not in output.out + output.err


def test_resolve_metadata_errors_preflight_all_placeholders_before_any_read(context, tmp_path):
    add(context)
    target = tmp_path / "config"
    for original in ["__KEYS:test-key__ __KEYS:missing-key__", "__KEYS:test-key__ __KEYS:test-key:absent__", "__KEYS:test-key__ __KEYS:INVALID__"]:
        target.write_text(original)
        assert cli.main(["resolve", str(target)]) == 1
        assert target.read_text() == original
    assert context.backend.reads == []


def test_resolve_stops_after_one_denied_read_and_records_one_safe_failure(context, tmp_path, capsys):
    blocked = add(context, "blocked-key")
    add(context, "later-key")
    context.backend.failures[blocked.id] = SecretAccessDenied(SENTINEL)
    original = "__KEYS:blocked-key__ __KEYS:blocked-key__ __KEYS:later-key__"
    target = tmp_path / "config"
    target.write_text(original)
    assert cli.main(["resolve", str(target)]) == 1
    assert target.read_text() == original
    assert context.backend.reads == [blocked.id]
    assert len(context.audit.events) == 1
    assert context.audit.events[0]["success"] is False
    assert SENTINEL not in str(context.audit.events)
    assert SENTINEL not in capsys.readouterr().err


def test_resolve_repeated_keys_are_read_once_and_audit_has_stable_ids(context, tmp_path):
    first = add(context, "first-key", value="first", fields={"service": "metadata"})
    second = add(context, "second-key", value="second")
    target = tmp_path / "config"
    target.write_text("__KEYS:first-key__ __KEYS:first-key__ __KEYS:first-key:service__ __KEYS:second-key__")
    assert cli.main(["resolve", str(target)]) == 0
    assert target.read_text() == "first first metadata second"
    assert context.backend.reads == [first.id, second.id]
    assert context.audit.events[-1]["affected_entry_ids"] == [first.id, second.id]


def test_export_postpublication_directory_failure_reports_committed(context, tmp_path, monkeypatch, capsys):
    from keys_keeper import private_files
    add(context)
    target = tmp_path / "backup.kk"
    def fail_sync(_parent):
        raise OSError(SENTINEL)
    monkeypatch.setattr(private_files, "fsync_parent", fail_sync)
    assert cli.main(["export", str(target)]) == 1
    assert target.read_bytes().startswith(b"KK1\x00")
    error = capsys.readouterr().err
    assert '"committed":true' in error
    assert SENTINEL not in error
    assert context.audit.events[-1]["success"] is True


def test_export_postpublication_readback_failure_reports_committed(context, tmp_path, monkeypatch, capsys):
    from keys_keeper import private_files
    add(context)
    target = tmp_path / "backup.kk"
    real_read = private_files.secure_read
    def fail_read(path, **kwargs):
        if path == target:
            raise private_files.PrivateFileError(SENTINEL)
        return real_read(path, **kwargs)
    monkeypatch.setattr(private_files, "secure_read", fail_read)
    assert cli.main(["export", str(target)]) == 1
    assert target.read_bytes().startswith(b"KK1\x00")
    error = capsys.readouterr().err
    assert '"committed":true' in error
    assert SENTINEL not in error


def test_invalid_entry_precedes_secret_source_read(context, monkeypatch):
    monkeypatch.setattr(cli, "_read_input", lambda *_args: pytest.fail("unexpected secret input read"))
    assert cli.main(["add", "INVALID", "--stdin"]) == 2
    assert context.store.list() == []


def test_add_stdin_limit_rejects_without_truncation_or_mutation(context, monkeypatch):
    monkeypatch.setattr(cli, "_MAX_INPUT_CHARS", 8)
    monkeypatch.setattr(cli.sys, "stdin", StringIO("first-eight-then-extra"))
    assert cli.main(["add", "test-key", "--stdin"]) == 2
    assert context.store.list() == []
    assert context.backend.values == {}


def test_add_file_invalid_encoding_never_discloses_decoder_material(context, tmp_path, capsys):
    source = tmp_path / "secret-source"
    source.write_bytes(SENTINEL.encode() + b"\xff")
    assert cli.main(["add", "test-key", "--from-file", str(source)]) == 2
    assert context.store.list() == []
    error = capsys.readouterr().err
    assert SENTINEL not in error
    assert "\\xff" not in error


def test_add_edit_share_note_boolean_and_port_coercion(context):
    note = add(context, "public-note", value=None, type_=EntryType.NOTE,
               fields={"secret_body": False, "body": "before"})
    assert cli.main(["edit", note.name, "--field", "secret_body=false", "--field", "body=after"]) == 0
    assert context.store.get_by_name(note.name).fields == {"secret_body": False, "body": "after"}
    assert cli.main(["edit", note.name, "--field", "secret_body=not-a-bool"]) == 2
    assert context.store.get_by_name(note.name).fields["secret_body"] is False
    assert cli.main(["add", "test-server", "--type", "server", "--field", "host=example.test",
                     "--field", "user=owner", "--field", "auth=none", "--field", "port=2200"]) == 0
    assert cli.main(["edit", "test-server", "--field", "port=2222"]) == 0
    assert context.store.get_by_name("test-server").fields["port"] == 2222


def test_clipboard_schedule_failure_reports_written_value_without_raw_error(context, monkeypatch, capsys):
    add(context)
    written = []
    monkeypatch.setattr(cli.clipboard, "write", lambda value: written.append(value) or True)
    def failed_schedule(*_args):
        raise OSError(SENTINEL)
    monkeypatch.setattr(cli.clipboard, "spawn_clear_after", failed_schedule)
    assert cli.main(["copy", "test-key"]) == 1
    assert written == [SENTINEL]
    error = capsys.readouterr().err
    assert '"committed":true' in error
    assert SENTINEL not in error


def test_last_resort_cli_failure_hides_raw_provider_error(context, monkeypatch, capsys):
    monkeypatch.setattr(cli, "cmd_list", lambda *_args: (_ for _ in ()).throw(RuntimeError(SENTINEL)))
    assert cli.main(["list"]) == 1
    error = capsys.readouterr().err
    assert '"committed":null' in error
    assert SENTINEL not in error


def test_cli_audit_name_includes_batch_use_and_renamed_history(context, capsys):
    from keys_keeper.audit import AuditLog
    entry = add(context, "current-key")
    context.audit = AuditLog(context.paths)
    context.audit.record(op="copy", name="previous-key", id_=entry.id)
    context.audit.record(op="resolve", name="<file>", id_="synthetic-target", affected_entry_ids=[entry.id])
    assert cli.main(["audit", "--name", "current-key"]) == 0
    output = capsys.readouterr().out
    assert "previous-key" in output
    assert "<file>" in output
    assert output.index("resolve") < output.index("copy")
    assert context.backend.reads == []


def test_cli_audit_tail_uses_last_events_not_first(context, capsys):
    from keys_keeper.audit import AuditLog
    context.audit = AuditLog(context.paths)
    for i in range(7):
        context.audit.record(op="copy", name=f"event-{i}", id_="synthetic")
    assert cli.main(["audit", "--tail", "--limit", "2"]) == 0
    output = capsys.readouterr().out
    assert "event-5" in output and "event-6" in output
    assert "event-0" not in output
    assert output.index("event-5") < output.index("event-6")
