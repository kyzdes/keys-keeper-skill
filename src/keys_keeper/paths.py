"""Filesystem paths for keys-keeper config + data."""
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID


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


@dataclass(frozen=True)
class Paths:
    root: Path = field(default_factory=_default_root)

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))

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
    def keychain_toml(self) -> Path:
        # Non-secret macOS interaction policy: prompt | bypass.
        return self.root / "keychain.toml"

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

    @property
    def sync_state_json(self) -> Path:
        # Non-secret sync bookkeeping (last-synced version, last-sync/auto times)
        # for `keys sync status` + the auto-hook debounce. Never holds secrets.
        return self.root / "sync-state.json"

    @property
    def profiles_dir(self) -> Path:
        """Replica profiles, addressed only by canonical UUID."""
        return self.root / "profiles"

    @property
    def locks_dir(self) -> Path:
        return self.root / "locks"

    @property
    def pending_dir(self) -> Path:
        return self.root / "pending"

    @property
    def service_keys_dir(self) -> Path:
        return self.root / "service-keys"

    @property
    def backend_password_file(self) -> Path:
        """Profile-local unlock source for the encrypted file backend."""
        return self.service_keys_dir / "file-backend-password"

    @property
    def operations_dir(self) -> Path:
        return self.root / "operations"

    @property
    def generations_dir(self) -> Path:
        return self.root / "generations"

    @property
    def active_generation(self) -> Path:
        return self.root / "active-generation"

    def for_profile(self, profile_id: UUID | str) -> "Paths":
        """Return isolated paths for one replica UUID.

        Strings must use the canonical lowercase, hyphenated UUID spelling.
        Refusing aliases here keeps untrusted slugs and traversal components out
        of filesystem selection.
        """
        parsed = _canonical_uuid(profile_id, field_name="profile_id")
        return Paths(root=self.profiles_dir / str(parsed))

    def audit_archive(self, year_month: str) -> Path:
        return self.root / f"audit.{year_month}.jsonl.gz"

    def ensure(self) -> None:
        ensure_private_dir(self.root)


def ensure_private_dir(directory: Path) -> None:
    """Create ``directory`` (and parents) with 0700 on POSIX.

    ``mkdir(mode=...)`` is masked by the process umask, so it cannot be
    relied on to produce 0700 — we mkdir, then explicitly chmod to 0o700.
    On Windows POSIX mode bits are meaningless; we skip the chmod there so
    we don't break the platform. On POSIX a chmod failure is surfaced
    (not swallowed) because a world-accessible config dir would leak the
    audit log and other per-user state.
    """
    directory.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(directory, 0o700)


def _canonical_uuid(value: UUID | str, *, field_name: str) -> UUID:
    if isinstance(value, UUID):
        return value
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a canonical UUID")
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as ex:
        raise ValueError(f"{field_name} must be a canonical UUID") from ex
    if value != str(parsed):
        raise ValueError(f"{field_name} must be a canonical UUID")
    return parsed
