from __future__ import annotations

import os

import pytest

from keys_keeper.ssh_runner import SSHRunnerError, _validated_executable


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
