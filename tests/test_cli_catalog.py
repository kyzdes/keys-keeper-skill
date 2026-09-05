import json

from keys_keeper import cli


def test_catalog_cli_requires_recovery_backed_migration(kk_home, capsys):
    assert cli.main(["projects", "list", "--json"]) == 1
    assert "explicit" in capsys.readouterr().err

    assert cli.main(["projects", "init", "--json"]) == 1
    assert "project-sync migrate" in capsys.readouterr().err
    assert not (kk_home / "data.json").exists()
