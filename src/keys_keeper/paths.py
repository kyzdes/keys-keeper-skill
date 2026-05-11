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

    def audit_archive(self, year_month: str) -> Path:
        return self.root / f"audit.{year_month}.jsonl.gz"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
