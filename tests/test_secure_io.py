import os

import pytest

from keys_keeper.secure_io import (
    SecureFileError,
    read_secure_text,
    replace_secure_text,
)


def test_replace_rejects_target_changed_after_read(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("OLD=1\n")
    state = read_secure_text(target, missing_ok=False)

    replacement = tmp_path / "replacement"
    replacement.write_text("ATTACKER=1\n")
    os.replace(replacement, target)

    with pytest.raises(SecureFileError, match="changed"):
        replace_secure_text(state, "SECRET=must-not-land\n")
    assert target.read_text() == "ATTACKER=1\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_replace_preserves_stricter_owner_mode(tmp_path):
    target = tmp_path / "secret.env"
    target.write_text("OLD=1\n")
    target.chmod(0o400)
    state = read_secure_text(target, missing_ok=False)
    replace_secure_text(state, "NEW=1\n")
    assert target.read_text() == "NEW=1\n"
    assert target.stat().st_mode & 0o777 == 0o400
