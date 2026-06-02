"""Filesystem paths for keys-keeper config + data."""
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path


def _default_root() -> Path:
    if env := os.environ.get("KEYS_KEEPER_HOME"):
        return Path(env)
    if sys.platform == "win32":
        # %APPDATA% is the standard per-user roaming config location on Windows.
        # We deliberately skip XDG even if the env var is set (e.g. under
        # WSL/Cygwin shells) to avoid surprising the user with two different
        # config dirs depending on which shell launched `keys`.
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(appdata) / "keys-keeper"
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(xdg) / "keys-keeper"


@dataclass
class Paths:
    root: Path = field(default_factory=_default_root)

    @property
    def data_json(self) -> Path:
        return self.root / "data.json"

    @property
    def data_json_bak(self) -> Path:
        return self.root / "data.json.bak"

    @property
    def audit_jsonl(self) -> Path:
        return self.root / "audit.jsonl"

    @property
    def config_toml(self) -> Path:
        return self.root / "config.toml"

    @property
    def serve_url_file(self) -> Path:
        # Live admin URL (with session token) of a running `keys serve`, so the
        # macOS quick-launch app can re-open the tab. Written on start, removed
        # on shutdown. See cli._write_serve_url and the macos_app launcher.
        return self.root / "serve-url"

    @property
    def secrets_enc(self) -> Path:
        # Encrypted secret blob for the Linux headless (no-keyring) backend.
        # AES-256-GCM, unlocked by KEYS_KEEPER_MASTER_KEY. See backend_file.py.
        return self.root / "secrets.enc"

    def audit_archive(self, year_month: str) -> Path:
        return self.root / f"audit.{year_month}.jsonl.gz"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
