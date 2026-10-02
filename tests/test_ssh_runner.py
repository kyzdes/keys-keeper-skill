from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from keys_keeper.ssh_runner import SSHRunnerError, _validated_executable
from keys_keeper import ssh_runner
from keys_keeper.backend import Sealed
from keys_keeper.models import Entry, EntryType
from keys_keeper.paths import Paths
from keys_keeper.store import MetadataStore


@pytest.fixture
def synthetic_ssh(tmp_path, monkeypatch):
    store = MetadataStore(Paths(tmp_path / "vault"))
    key = Entry.new(name="synthetic-key", type=EntryType.SSH_KEY,
                    fields={"public_key": "ssh-ed25519 synthetic-public"})
    server = Entry.new(name="synthetic-server", type=EntryType.SERVER,
                       fields={"host": "example.invalid", "user": "test", "port": 22, "auth": "ssh_key"},
                       refs=[{"role": "ssh_key", "name": key.name}])
    store.add(key)
    store.add(server)
    backend = SimpleNamespace(get=lambda _: Sealed("SYNTHETIC-PRIVATE-KEY-CANARY"))
    monkeypatch.setattr(ssh_runner, "_resolve_ssh_executable", lambda: str(tmp_path / "ssh"))
    monkeypatch.setattr(ssh_runner, "_ssh_tempdir", lambda: str(tmp_path))
    return store, backend


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable mode policy")
def test_validated_executable_rejects_group_world_writable_file(tmp_path):
    executable = tmp_path / "ssh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o777)

    with pytest.raises(SSHRunnerError, match="group/world writable"):
        _validated_executable(str(executable), "ssh")


@pytest.mark.skipif(os.name != "posix", reason="POSIX executable mode policy")
def test_validated_executable_returns_canonical_absolute_path(tmp_path):
    executable = tmp_path / "ssh"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)

    assert _validated_executable(str(executable), "ssh") == str(executable.resolve())


@pytest.mark.parametrize("fails", [False, True])
def test_ssh_uses_private_file_before_exec_and_always_removes_it(synthetic_ssh, monkeypatch, fails):
    store, backend = synthetic_ssh
    captured = []

    def execute(argv):
        path = Path(argv[argv.index("-i") + 1])
        captured.append(path)
        if os.name == "nt":
            from keys_keeper.windows_file_security import validate_path
            validate_path(path, require_protected=True)
        else:
            assert path.stat().st_mode & 0o777 == 0o600
        assert path.read_bytes() == b"SYNTHETIC-PRIVATE-KEY-CANARY\n"
        if fails:
            raise OSError("synthetic exec failure")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(ssh_runner.subprocess, "run", execute)
    if fails:
        with pytest.raises(OSError, match="synthetic exec failure"):
            ssh_runner.run_ssh(store=store, backend=backend, server_name="synthetic-server")
    else:
        assert ssh_runner.run_ssh(store=store, backend=backend, server_name="synthetic-server") == 0
    assert len(captured) == 1
    assert not captured[0].exists()


def test_ssh_private_creation_failure_never_executes(synthetic_ssh, monkeypatch):
    store, backend = synthetic_ssh
    monkeypatch.setattr(ssh_runner, "create_private_temp",
                        lambda *a, **kw: (_ for _ in ()).throw(SSHRunnerError("synthetic creation failure")))
    monkeypatch.setattr(ssh_runner.subprocess, "run", lambda *a: pytest.fail("ssh must not execute"))
    with pytest.raises(SSHRunnerError, match="creation failure"):
        ssh_runner.run_ssh(store=store, backend=backend, server_name="synthetic-server")
