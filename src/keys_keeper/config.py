"""Non-secret sync settings, persisted to `config.toml`.

Only the `[sync]` table is used. Values are all scalars (str / int / bool),
so we hand-roll a tiny flat-TOML reader+writer rather than depend on `tomllib`
(stdlib only from Python 3.11; the project floor is 3.10) or add a writer dep.

SECRETS NEVER LIVE HERE. The S3 access key id, S3 secret key, and the backup
passphrase are stored in the OS keychain via `build_backend()` under reserved
`kk:sync-*` accounts. This module only ever touches non-secret configuration.
"""
from __future__ import annotations

import os
import socket
import uuid
from dataclasses import dataclass, replace
from urllib.parse import urlparse

from keys_keeper.paths import Paths


class SyncConfigError(ValueError):
    """Invalid or unsafe sync configuration."""


VALID_MODES = ("off", "manual", "auto")
VALID_ADDRESSING = ("path", "virtual")
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


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

    def validate(self) -> None:
        if self.mode not in VALID_MODES:
            raise SyncConfigError(f"mode must be one of {VALID_MODES}, got {self.mode!r}")
        if self.addressing not in VALID_ADDRESSING:
            raise SyncConfigError(
                f"addressing must be one of {VALID_ADDRESSING}, got {self.addressing!r}"
            )
        if not isinstance(self.retain_snapshots, int) or self.retain_snapshots < 1:
            raise SyncConfigError("retain_snapshots must be an int >= 1")
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
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
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
    for ch in line:
        if in_str:
            out.append(ch)
            if ch == q:
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
    if isinstance(value, bool):
        return f"{text_key} = {'true' if value else 'false'}"
    if isinstance(value, int):
        return f"{text_key} = {value}"
    esc = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'{text_key} = "{esc}"'


def load_sync_config(paths: Paths | None = None) -> SyncConfig:
    paths = paths or Paths()
    if not paths.config_toml.exists():
        return SyncConfig()
    raw = _read_sync_table(paths.config_toml.read_text(encoding="utf-8"))
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
    tmp = paths.config_toml.with_suffix(".toml.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)  # S11: no group/other access (POSIX; no-op on Windows)
    except OSError:
        pass
    os.replace(tmp, paths.config_toml)


def set_mode(mode: str, paths: Paths | None = None) -> SyncConfig:
    paths = paths or Paths()
    cfg = replace(load_sync_config(paths), mode=mode)
    cfg.validate()
    save_sync_config(cfg, paths)
    return cfg
