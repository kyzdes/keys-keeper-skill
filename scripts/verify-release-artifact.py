"""Verify a built wheel against the repository release payload.

This deliberately uses only metadata and generated instruction files. It never
opens the user's Keys Keeper configuration or credential backend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

EXPECTED_WHEEL_PATHS = {
    "keys_keeper/__init__.py",
    "keys_keeper/cli.py",
    "keys_keeper/macos_keychain.py",
    "keys_keeper/macos_keychain_abi.py",
    "keys_keeper/macos_keychain_cf.py",
    "keys_keeper/service.py",
    "keys_keeper/static/app.css",
    "keys_keeper/static/theme.js",
    "keys_keeper/templates/base.html",
    "keys_keeper/project_runtime.py",
    "keys_keeper/project_protocol.py",
    "keys_keeper/project_recovery.py",
    "keys_keeper/static/projects.js",
    "keys_keeper/templates/projects.html",
    "keys_keeper/webvault/static/app.css",
    "keys_keeper/webvault/static/theme.js",
    "keys_keeper/webvault/static/vault.css",
    "keys_keeper/webvault/static/vault.mjs",
}

GENERATED_SKILL_PATHS = (
    Path("SKILL.md"),
    Path("references/diagnostics.md"),
    Path("references/install.md"),
    Path("references/keychain-bypass.md"),
    Path("references/save-and-route.md"),
    Path("references/sync.md"),
    Path("references/temporary-sinks.md"),
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _single_match(pattern: str, text: str, source: Path) -> str:
    match = re.search(pattern, text, flags=re.MULTILINE)
    if match is None:
        raise SystemExit(f"could not determine version from {source}")
    return match.group(1)


def _verify_version_contract(root: Path, names: set[str], wheel: Path) -> str:
    pyproject = root / "pyproject.toml"
    project_version = _single_match(
        r'^version\s*=\s*"([^"]+)"$', pyproject.read_text(), pyproject
    )
    expected = {
        "src/keys_keeper/__init__.py": _single_match(
            r'^__version__\s*=\s*"([^"]+)"$',
            (root / "src/keys_keeper/__init__.py").read_text(),
            root / "src/keys_keeper/__init__.py",
        ),
        ".claude-plugin/plugin.json": json.loads(
            (root / ".claude-plugin/plugin.json").read_text()
        )["version"],
        "plugins/keys-keeper/.codex-plugin/plugin.json": json.loads(
            (root / "plugins/keys-keeper/.codex-plugin/plugin.json").read_text()
        )["version"],
    }
    mismatches = [
        f"{path}={version}"
        for path, version in expected.items()
        if version != project_version
    ]
    if mismatches:
        raise SystemExit(
            f"release version {project_version} disagrees with " + ", ".join(mismatches)
        )

    metadata_paths = [name for name in names if name.endswith(".dist-info/METADATA")]
    if len(metadata_paths) != 1:
        raise SystemExit(
            f"expected one wheel METADATA file in {wheel}, got {metadata_paths}"
        )
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read(metadata_paths[0]).decode("utf-8")
    wheel_version = _single_match(r"^Version: (\S+)$", metadata, wheel)
    if wheel_version != project_version:
        raise SystemExit(
            f"wheel version {wheel_version} disagrees with project version {project_version}"
        )

    required_markers = {
        root / "README.md": (
            f"**Status:** v{project_version}",
            f"keys-keeper-skill.git@v{project_version}",
        ),
        root / "CHANGELOG.md": (f"## [{project_version}]",),
        root / "skills/keys-keeper/references/install.md": (
            f"keys-keeper-skill.git@v{project_version}",
        ),
    }
    for path, markers in required_markers.items():
        text = path.read_text()
        for marker in markers:
            if marker not in text:
                raise SystemExit(f"{path} is missing release marker {marker!r}")
    return project_version


def _verify_wheel_contents(root: Path, names: set[str]) -> None:
    missing = sorted(EXPECTED_WHEEL_PATHS - names)
    if missing:
        raise SystemExit("wheel is missing expected files: " + ", ".join(missing))

    source_package = root / "src" / "keys_keeper"
    source_runtime_paths = {
        path.relative_to(root / "src").as_posix()
        for path in source_package.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    }
    missing_source_files = sorted(source_runtime_paths - names)
    if missing_source_files:
        raise SystemExit(
            "wheel is missing source runtime files: " + ", ".join(missing_source_files)
        )


def _run_from_installed_artifact(
    python: Path,
    cwd: Path,
    *args: str,
) -> subprocess.CompletedProcess[str]:
    command = [str(python), "-m", "keys_keeper", *args]
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.CalledProcessError as ex:
        detail = ex.stderr.strip() or ex.stdout.strip() or "no command output"
        raise SystemExit(
            f"installed-artifact command failed ({' '.join(args)}): {detail}"
        ) from ex


def verify(wheel: Path, root: Path) -> None:
    if not wheel.is_file():
        raise SystemExit(f"wheel does not exist: {wheel}")

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    _verify_wheel_contents(root, names)
    project_version = _verify_version_contract(root, names, wheel)

    with tempfile.TemporaryDirectory(prefix="keys-keeper-artifact-") as raw_tmp:
        temporary = Path(raw_tmp)
        environment = temporary / "venv"
        subprocess.run(
            [sys.executable, "-m", "venv", str(environment)],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        # Exercise the wheel as an installable artifact and include its declared
        # runtime dependencies. Direct extraction can accidentally pass on a
        # developer machine while failing in a clean release environment.
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                str(wheel),
            ],
            cwd=temporary,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

        origin = subprocess.run(
            [
                str(python),
                "-c",
                "import keys_keeper; print(keys_keeper.__file__)",
            ],
            cwd=temporary,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.strip()
        if not Path(origin).resolve().is_relative_to(environment.resolve()):
            raise SystemExit(f"artifact smoke imported keys_keeper from {origin}")

        version = _run_from_installed_artifact(python, temporary, "--version").stdout
        if version.strip() != f"keys-keeper {project_version}":
            raise SystemExit(
                "installed wheel version output disagrees with the release contract"
            )

        keychain_help = _run_from_installed_artifact(
            python, temporary, "keychain", "--help"
        ).stdout
        for command in ("status", "bypass", "prompt", "prepare"):
            if command not in keychain_help:
                raise SystemExit(
                    f"installed wheel keychain command is missing {command!r}"
                )

        vps_help = _run_from_installed_artifact(
            python, temporary, "sync", "vps", "--help"
        ).stdout
        for command in (
            "init", "push", "pull", "status", "devices",
            "invite", "join", "approve", "finish", "revoke",
        ):
            if command not in vps_help:
                raise SystemExit(
                    f"installed wheel VPS sync command is missing {command!r}"
                )

        project_help = _run_from_installed_artifact(
            python, temporary, "project-sync", "--help"
        ).stdout
        for command in (
            "profiles", "use", "status", "preview", "init", "invite", "join",
            "approve", "finish", "sync", "watch", "revoke", "backup", "migrate",
            "restore", "recover-takeover",
        ):
            if command not in project_help:
                raise SystemExit(f"installed wheel project sync is missing {command!r}")

        syncd_help = subprocess.run(
            [str(python), "-m", "keys_keeper.sync_server_cli", "--help"],
            cwd=temporary,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout
        if "keys-keeper-syncd" not in syncd_help or "--database" not in syncd_help:
            raise SystemExit("installed wheel is missing the syncd service entrypoint")

        _run_from_installed_artifact(
            python,
            temporary,
            "init",
            "claude",
            "--out",
            "skills/keys-keeper/SKILL.md",
            "--force",
        )
        generated_root = temporary / "skills" / "keys-keeper"
        source_root = root / "skills" / "keys-keeper"
        for relative in GENERATED_SKILL_PATHS:
            generated = generated_root / relative
            source = source_root / relative
            if not generated.is_file():
                raise SystemExit(f"wheel did not generate {relative}")
            if _digest(generated) != _digest(source):
                raise SystemExit(
                    f"wheel-generated {relative} differs from the source payload"
                )

        # The Codex-specific target is part of the installed CLI, not merely a
        # source-checkout convenience. An explicit path keeps this release
        # test isolated from the operator's real Codex home.
        _run_from_installed_artifact(
            python,
            temporary,
            "init",
            "codex-skill",
            "--out",
            "codex-home/skills/keys-keeper/SKILL.md",
            "--force",
        )
        if not (
            temporary / "codex-home" / "skills" / "keys-keeper" / "SKILL.md"
        ).is_file():
            raise SystemExit("wheel did not expose the codex-skill init target")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
    )
    args = parser.parse_args()
    verify(args.wheel.resolve(), args.root.resolve())
    print("release artifact verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
