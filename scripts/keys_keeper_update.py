"""Daily guard for the explicitly opted-in Keys Keeper fallback updater.

This is independent of native host updates and manual plugin-update commands.
Only a private attempt timestamp is persisted, before the reviewed helper runs.
Failures, concurrent sessions and clock rollback cannot authorize a short retry.
"""
from __future__ import annotations

import importlib.util
import json
import math
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

DAY = 86_400
_spec = importlib.util.spec_from_file_location("keys_keeper_shared_updater", Path(__file__).with_name("auto_update.py"))
shared = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shared)


def _private(info):
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("invalid update marker")
    if os.name == "posix" and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("update marker must be private")


def _unique(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate update timestamp")
        result[key] = value
    return result


def _last(path):
    try:
        if path.is_symlink():
            raise ValueError("invalid update marker")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        _private(info)
        if info.st_size > 256:
            raise ValueError("invalid update timestamp")
        data = json.loads(stream.read(257), object_pairs_hook=_unique)
    if not isinstance(data, dict) or set(data) != {"last_attempt"}:
        raise ValueError("invalid update timestamp")
    value = data["last_attempt"]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("invalid update timestamp")
    return value


def _write(path, now):
    fd, temporary = tempfile.mkstemp(prefix=".keys-update-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump({"last_attempt": now}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if Path(temporary).exists():
            Path(temporary).unlink()


def update_daily(root=None, env=None, *, clock=time.time):
    env = os.environ if env is None else env
    if ("PLUGIN_DATA" in env or env.get("KKZ_NO_AUTOUPDATE") or env.get("KEYS_KEEPER_NO_AUTOUPDATE")
            or env.get("KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE") != "1"):
        return "disabled"
    root = Path(__file__).resolve().parent.parent if root is None else Path(root)
    if json.loads((root / ".claude-plugin/plugin.json").read_text())["name"] != "keys-keeper":
        return "disabled"
    config = Path(env.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))
    installed = json.loads((config / "plugins/installed_plugins.json").read_text())
    if "keys-keeper@claude-skills" not in installed.get("plugins", {}):
        return "disabled"
    known = config / "plugins/known_marketplaces.json"
    if known.exists() and json.loads(known.read_text()).get("claude-skills", {}).get("autoUpdate") is True:
        return "native"
    if not shutil.which("claude"):
        return "disabled"
    cache = shared.cache_directory(config, env)
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = cache.lstat()
    if not stat.S_ISDIR(info.st_mode) or (os.name == "posix" and
            (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077)):
        raise ValueError("update cache must be private")
    lock_path = cache / "keys-keeper.daily.lock"
    if lock_path.is_symlink():
        raise ValueError("invalid update lock")
    if lock_path.exists():
        _private(lock_path.lstat())
    # No wait/retry loop on SessionStart. The OS releases this lock on exit.
    with shared.locked(lock_path, 0) as handle:
        if handle is None:
            return "busy"
        # The shared helper opens these paths. Preflight them without following
        # links so a stale/unsafe cache cannot chmod or overwrite another file.
        for name in ("claude.lock", "keys-keeper.log", "catalog.success", "catalog.failed"):
            try:
                helper_info = (cache / name).lstat()
            except FileNotFoundError:
                continue
            _private(helper_info)
            if helper_info.st_size > 65_536:
                raise ValueError("invalid update helper metadata")
        marker = cache / "keys-keeper.daily.json"
        previous = _last(marker)
        # Retain the most recent old success/failure through this migration.
        for suffix in ("success", "failed"):
            legacy = cache / ("keys-keeper." + suffix)
            try:
                legacy_info = legacy.lstat()
            except FileNotFoundError:
                continue
            _private(legacy_info)
            previous = max(previous or 0, legacy_info.st_mtime)
        now = clock()
        if isinstance(now, bool) or not math.isfinite(now) or now < 0:
            raise ValueError("invalid update clock")
        if previous is not None and now - previous < DAY:
            return "deferred"
        _write(marker, now)
        options = dict(env)
        options["KKZ_AUTO_UPDATE_INTERVAL_SEC"] = str(max(DAY, shared.number(env, "KKZ_AUTO_UPDATE_INTERVAL_SEC", DAY, 2_592_000)))
        # Two helper commands are capped at 120 s each; don't add a 180 s lock wait.
        options["KKZ_UPDATE_LOCK_WAIT_SEC"] = "0"
        shared.update(root, options)
        return "attempted"


if __name__ == "__main__":
    try:
        update_daily()
    except Exception:
        pass  # Never block a session or echo local metadata/helper exception text.
