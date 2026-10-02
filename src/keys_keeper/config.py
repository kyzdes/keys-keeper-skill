"""Non-secret sync settings, persisted to `config.toml`.

Only the `[sync]` table is used. Values are all scalars (str / int / bool),
so we hand-roll a tiny flat-TOML reader+writer rather than depend on `tomllib`
(stdlib only from Python 3.11; the project floor is 3.10) or add a writer dep.

SECRETS NEVER LIVE HERE. The S3 access key id, S3 secret key, and the backup
passphrase are stored in the OS keychain via `build_backend()` under reserved
`kk:sync-*` accounts. This module only ever touches non-secret configuration.
"""
from __future__ import annotations

import socket
import json
import uuid
from dataclasses import dataclass, replace
from urllib.parse import urlparse

from keys_keeper.paths import Paths
from keys_keeper.private_files import PrivateFileCommitError, PrivateFileError, atomic_write_bytes, secure_read


class SyncConfigError(ValueError):
    """Invalid or unsafe sync configuration."""


class SyncConfigCommitError(SyncConfigError):
    """Configuration was published; its directory durability is uncertain."""
    committed = True


VALID_MODES = ("off", "manual", "auto")
VALID_ADDRESSING = ("path", "virtual")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}
MAX_CONFIG_BYTES = 1024 * 1024


@dataclass(frozen=True)
class SyncConfig:
    mode: str = "off"                # off | manual | auto
    endpoint: str = ""               # e.g. https://<acct>.r2.cloudflarestorage.com
    bucket: str = ""
    region: str = "us-east-1"        # R2 uses "auto"
    prefix: str = ""                 # object-key namespace, e.g. "keys-keeper"
    device_id: str = ""
    addressing: str = "path"         # path | virtual
    retain_snapshots: int = 20
    insecure: bool = False           # allow plain http for a non-loopback endpoint
    cas_supported: bool = True       # provider honours If-None-Match (probed at setup)
    proxy: str = "direct"            # direct | system | http(s)://host:port — S3 transport proxy

    def validate(self) -> None:
        for field, annotation in SyncConfig.__annotations__.items():
            expected = {"str": str, "int": int, "bool": bool}[annotation]
            if type(getattr(self, field)) is not expected:
                raise SyncConfigError(f"sync {field} has an invalid scalar type")
        if self.mode not in VALID_MODES:
            raise SyncConfigError(f"mode must be one of {VALID_MODES}, got {self.mode!r}")
        if self.addressing not in VALID_ADDRESSING:
            raise SyncConfigError(
                f"addressing must be one of {VALID_ADDRESSING}, got {self.addressing!r}"
            )
        if not isinstance(self.retain_snapshots, int) or self.retain_snapshots < 1:
            raise SyncConfigError("retain_snapshots must be an int >= 1")
        # proxy policy for the S3 transport (sync_remote._opener_for): a flaky
        # local/VPN proxy must not be silently inherited for secret backups.
        if self.proxy not in ("direct", "system") and not self.proxy.startswith(
            ("http://", "https://")
        ):
            raise SyncConfigError(
                "sync proxy must be 'direct', 'system', or an http(s):// proxy URL, "
                f"got {self.proxy!r}"
            )
        # device_id ends up inside S3 object keys — keep it to a canonical charset
        # so a hand-edited config can't produce keys needing odd encoding.
        if self.device_id and not all(c.isalnum() or c in "._-" for c in self.device_id):
            raise SyncConfigError("device_id may only contain [A-Za-z0-9._-]")
        # prefix must stay inside its namespace (S10): no traversal, no absolute key.
        if self.prefix.startswith("/") or ".." in self.prefix.split("/"):
            raise SyncConfigError(f"unsafe prefix {self.prefix!r}: no leading '/' or '..'")
        if self.mode != "off" or self.endpoint:
            self._validate_endpoint()

    def _validate_endpoint(self) -> None:
        if not self.endpoint:
            if self.mode != "off":
                raise SyncConfigError("endpoint is required when sync is enabled")
            return
        u = urlparse(self.endpoint)
        if u.scheme not in ("http", "https"):
            raise SyncConfigError(f"endpoint must be http(s): {self.endpoint!r}")
        host = (u.hostname or "").lower()
        is_loopback = host in _LOOPBACK_HOSTS
        if u.scheme == "http" and not is_loopback and not self.insecure:
            raise SyncConfigError(
                "refusing a plaintext http:// endpoint for a non-loopback host "
                "(secrets would traverse it unencrypted at the TLS layer). "
                "Use https://, or set insecure=true to override."
            )

    def with_device_id(self) -> "SyncConfig":
        """Return a copy guaranteed to have a stable, sanitized device_id."""
        if self.device_id:
            return self
        host = "".join(c for c in socket.gethostname().split(".")[0] if c.isalnum()) or "host"
        return replace(self, device_id=f"{host[:24]}-{uuid.uuid4().hex[:8]}")


# ---------------- flat-TOML I/O (only the [sync] table) ----------------

def _parse_scalar(raw: str) -> object:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        try:
            return json.loads(raw)
        except ValueError:
            raise SyncConfigError("invalid quoted sync configuration value") from None
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1]
    low = raw.lower()
    if low in ("true", "false"):
        return low == "true"
    try:
        return int(raw)
    except ValueError:
        return raw  # bare string fallback


def _strip_comment(line: str) -> str:
    out, in_str, q = [], False, ""
    escaped = False
    for ch in line:
        if in_str:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\" and q == '"':
                escaped = True
            elif ch == q:
                in_str = False
        elif ch in ("'", '"'):
            in_str = True
            q = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out)


_FIELD_TYPES = {f: t for f, t in SyncConfig.__annotations__.items()}


def _read_sync_table(text: str) -> dict:
    out: dict = {}
    section = None
    for line in text.splitlines():
        s = _strip_comment(line).strip()
        if not s:
            continue
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip()
            continue
        if section != "sync" or "=" not in s:
            continue
        key, _, val = s.partition("=")
        key = key.strip()
        if key in _FIELD_TYPES:
            out[key] = _parse_scalar(val)
    return out


def _emit(text_key: str, value: object) -> str:
    # This flat scalar subset shares JSON string/bool/int syntax with TOML.
    return f"{text_key} = {json.dumps(value, ensure_ascii=False)}"


def load_sync_config(paths: Paths | None = None) -> SyncConfig:
    paths = paths or Paths()
    try:
        blob = secure_read(paths.config_toml, max_bytes=MAX_CONFIG_BYTES,
                           require_private=False)
    except FileNotFoundError:
        return SyncConfig()
    except (PrivateFileError, OSError):
        raise SyncConfigError("invalid sync configuration file or size limit exceeded") from None
    try:
        text = blob.decode("utf-8")
    except UnicodeError:
        raise SyncConfigError("invalid sync configuration encoding") from None
    raw = _read_sync_table(text)
    cfg = SyncConfig(**{k: v for k, v in raw.items() if k in _FIELD_TYPES})
    cfg.validate()
    return cfg


def save_sync_config(cfg: SyncConfig, paths: Paths | None = None) -> None:
    cfg.validate()
    paths = paths or Paths()
    paths.ensure()
    lines = ["# keys-keeper sync configuration. NO SECRETS HERE — those live in the",
             "# OS keychain under kk:sync-* accounts. Safe to back up / commit-ignore.",
             "", "[sync]"]
    for fname in SyncConfig.__annotations__:
        lines.append(_emit(fname, getattr(cfg, fname)))
    text = "\n".join(lines) + "\n"
    if len(text.encode("utf-8")) > MAX_CONFIG_BYTES:
        raise SyncConfigError("sync configuration exceeds size limit")
    try:
        atomic_write_bytes(paths.config_toml, text.encode("utf-8"))
    except PrivateFileCommitError:
        raise SyncConfigCommitError(
            "sync configuration was published but durability is uncertain; inspect before retrying"
        ) from None
    except (PrivateFileError, OSError):
        raise SyncConfigError("cannot safely publish sync configuration") from None


def set_mode(mode: str, paths: Paths | None = None) -> SyncConfig:
    paths = paths or Paths()
    cfg = replace(load_sync_config(paths), mode=mode)
    cfg.validate()
    save_sync_config(cfg, paths)
    return cfg
