"""Value-free diagnostics and explicit master recovery with isolated providers."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from keys_keeper import cli
from keys_keeper.backend import KeychainBackend, Sealed, SecretAccessDenied
from keys_keeper.master_journal import MASTER_MUTATION_KIND
from keys_keeper.models import Entry, EntryType
from keys_keeper.operation_journal import OperationJournal, pending_operation_refs
from keys_keeper.paths import Paths
from keys_keeper.service import SecretInput, VaultService
from keys_keeper.store import MetadataStore


SENTINEL = "synthetic-provider-diagnostic-must-stay-hidden"


class Backend(KeychainBackend):
    def __init__(self):
        self.values = {}
        self.reads = []
        self.enumerations = 0
        self.failure = None

    def get(self, account):
        self.reads.append(account)
        return Sealed(self.values[account])

    def set(self, account, value):
        self.values[account] = value

    def delete(self, account):
        self.values.pop(account, None)

    def list_ids(self):
        self.enumerations += 1
        if self.failure:
            raise self.failure
        return list(self.values)


class Audit:
    def __init__(self):
        self.events = []
        self.failure = False

    def record(self, **event):
        if self.failure:
            raise OSError(SENTINEL)
        self.events.append(event)


@pytest.fixture
def context(tmp_path, monkeypatch):
    paths = Paths(tmp_path / "isolated")
    ctx = SimpleNamespace(kind="master", paths=paths, store=MetadataStore(paths),
                          backend=Backend(), audit=Audit())
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args, **_kwargs: ctx)
    return ctx


def receipts(output):
    return [json.loads(line) for line in output.splitlines() if line.startswith("{")]


def test_default_doctor_is_presence_only_and_excludes_reserved_accounts(context, capsys):
    note = Entry.new(name="public-note", type=EntryType.NOTE,
                     fields={"secret_body": False, "body": "public metadata"})
    context.store.add(note)
    context.backend.values.update({"kk:project-runtime-key": SENTINEL,
                                   "kk:personal-recovery-key": SENTINEL,
                                   "kk:sync-passphrase": SENTINEL})
    assert cli.main(["doctor"]) == 0
    output = capsys.readouterr().out
    assert "in sync with metadata" in output
    assert "no pending mutations" in output
    assert context.backend.enumerations == 1
    assert context.backend.reads == []
    assert context.audit.events == []
    assert SENTINEL not in output


def test_doctor_uses_required_secret_predicate_for_sensitive_notes(context, capsys):
    context.store.add(Entry.new(name="private-note", type=EntryType.NOTE,
                               fields={"secret_body": True}))
    assert cli.main(["doctor"]) == 0
    assert "1 metadata entry/entries missing keychain blobs" in capsys.readouterr().out
    assert context.backend.reads == []


def test_default_doctor_reports_pending_without_reading_or_recovering(context, capsys):
    journal = OperationJournal(paths=context.paths, password_provider=lambda: "isolated-key")
    journal.begin(MASTER_MUTATION_KIND, state={"synthetic": SENTINEL})
    assert cli.main(["doctor"]) == 0
    output = capsys.readouterr().out
    assert "1 pending mutation(s)" in output and "doctor --recover" in output
    assert len(pending_operation_refs(context.paths, kind=MASTER_MUTATION_KIND)) == 1
    assert context.backend.reads == []
    assert context.backend.values == {}
    assert SENTINEL not in output


@pytest.mark.parametrize("failure", [SecretAccessDenied(SENTINEL), RuntimeError(SENTINEL)])
def test_doctor_provider_errors_are_fixed_and_enumeration_is_not_retried(context, capsys, failure):
    context.backend.failure = failure
    assert cli.main(["doctor"]) == 0
    captured = capsys.readouterr()
    assert SENTINEL not in captured.out + captured.err
    assert "secret access denied" in captured.out or "secret read failed" in captured.out
    assert context.backend.enumerations == 1
    assert context.backend.reads == []


def test_doctor_metadata_errors_never_print_source_exception(context, capsys, monkeypatch):
    monkeypatch.setattr(context.store, "list", lambda: (_ for _ in ()).throw(RuntimeError(SENTINEL)))
    assert cli.main(["doctor"]) == 0
    captured = capsys.readouterr()
    assert "metadata is unavailable or invalid" in captured.out
    assert SENTINEL not in captured.out + captured.err


@pytest.mark.parametrize("kind", ["master_scope", "replica"])
def test_doctor_recover_refuses_projected_profiles_before_backend_or_file_access(
    context, capsys, monkeypatch, kind,
):
    class ForbiddenContext:
        @property
        def backend(self):
            raise AssertionError("backend must not be accessed")

        @property
        def paths(self):
            raise AssertionError("profile files must not be accessed")
    ctx = ForbiddenContext()
    ctx.kind = kind
    monkeypatch.setattr(cli, "_context_or_error", lambda *_args, **_kwargs: ctx)
    assert cli.main(["doctor", "--recover"]) == 1
    assert "only to the master profile" in capsys.readouterr().err
    assert not context.paths.root.exists()


def test_doctor_recover_completes_committed_mutation_and_keeps_values_private(
    context, capsys, monkeypatch,
):
    service = VaultService(context.store, context.backend)
    original = Entry.new(name="original-entry", type=EntryType.API_KEY)
    service.create_entry(original, secrets=SecretInput(value=SENTINEL))
    manager = service.master_mutations
    second = Entry.new(name="interrupted-entry", type=EntryType.API_KEY)
    with monkeypatch.context() as fault:
        fault.setattr(manager.journal, "finish",
                      lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(SENTINEL)))
        with pytest.raises(OSError):
            service.create_entry(second, secrets=SecretInput(value=SENTINEL))
    assert manager.has_pending
    assert context.store.get_by_id(second.id) is not None
    context.backend.reads.clear()
    assert cli.main(["doctor", "--recover"]) == 0
    captured = capsys.readouterr()
    receipt = receipts(captured.out)[0]
    assert receipt == {"operation": "recover", "status": "completed", "committed": True,
                       "recovered_count": 1, "pending_count": 0, "audit_status": "recorded",
                       "outcome": "published"}
    assert not manager.has_pending
    assert context.backend.values[second.id] == SENTINEL
    assert context.audit.events[-1]["op"] == "recover"
    assert SENTINEL not in captured.out + captured.err


def test_doctor_recover_failed_provider_reports_unknown_outcome(context, capsys):
    context.backend.failure = SecretAccessDenied(SENTINEL)
    # With an existing encrypted terminal receipt, explicit recovery needs its
    # authority key; enumeration denial cannot mean "nothing to recover".
    journal = OperationJournal(paths=context.paths, password_provider=lambda: "isolated-key")
    operation = journal.begin(MASTER_MUTATION_KIND, state={"synthetic": True})
    assert cli.main(["doctor", "--recover"]) == 1
    captured = capsys.readouterr()
    assert receipts(captured.out)[0]["committed"] is None
    assert receipts(captured.out)[0]["status"] == "unconfirmed"
    assert len(pending_operation_refs(context.paths, kind=MASTER_MUTATION_KIND)) == 1
    assert SENTINEL not in captured.out + captured.err
    journal.fail(operation.operation_id, error_code="test_finished")


def test_doctor_recover_audit_failure_preserves_completed_receipt(context, capsys):
    context.audit.failure = True
    assert cli.main(["doctor", "--recover"]) == 0
    captured = capsys.readouterr()
    assert receipts(captured.out)[0]["committed"] is True
    assert receipts(captured.out)[0]["audit_status"] == "unavailable"
    assert SENTINEL not in captured.out + captured.err


def test_quickstart_states_explicit_sink_contract(context, capsys):
    assert cli.main(["quickstart"]) == 0
    output = capsys.readouterr().out
    assert "routes secrets to explicit sinks" in output
    assert "never read" not in output
    assert context.backend.reads == [] and context.backend.enumerations == 0


def test_doctor_diagnoses_retired_s3_config_without_reading_or_deleting_credentials(context, capsys):
    context.paths.ensure()
    original = ("[sync]\nmode='auto'\nendpoint='https://retired.example.test'\n"
                "secret='" + SENTINEL + "'\n").encode()
    context.paths.config_toml.write_bytes(original)
    context.backend.values["kk:sync-passphrase"] = SENTINEL
    assert cli.main(["doctor"]) == 0
    captured = capsys.readouterr()
    assert "legacy S3 config retained" in captured.out
    assert "S3 synchronization has been removed" in captured.out
    assert SENTINEL not in captured.out + captured.err
    assert context.backend.reads == []
    assert context.backend.values == {"kk:sync-passphrase": SENTINEL}
    assert context.paths.config_toml.read_bytes() == original
