"""Exercise the shipped Keys Keeper hook guard without a real CLI or network."""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import threading

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("daily_keys_update", ROOT / "scripts/keys_keeper_update.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture
def install(tmp_path, monkeypatch):
    plugin = tmp_path / "plugin"
    (plugin / ".claude-plugin").mkdir(parents=True)
    (plugin / ".claude-plugin/plugin.json").write_text(json.dumps({"name": "keys-keeper"}))
    config = tmp_path / "claude"
    (config / "plugins").mkdir(parents=True)
    (config / "plugins/installed_plugins.json").write_text(json.dumps({"plugins": {"keys-keeper@claude-skills": [{}]}}))
    env = {"CLAUDE_CONFIG_DIR": str(config), "KKZ_PLUGIN_CACHE_ROOT": str(tmp_path / "cache"),
           "KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE": "1", "KKZ_AUTO_UPDATE_INTERVAL_SEC": "0"}
    monkeypatch.setattr(module.shutil, "which", lambda _: "/fake/claude")
    calls = []
    monkeypatch.setattr(module.shared, "update", lambda root, options: calls.append(options))
    return plugin, config, env, calls


def test_actual_hook_uses_daily_wrapper():
    groups = json.loads((ROOT / "hooks/hooks.json").read_text())["hooks"]["SessionStart"]
    updates = [hook for group in groups for hook in group["hooks"] if "auto-update" in hook["command"]]
    assert len(updates) == 1
    assert "/scripts/keys-keeper-auto-update.sh" in updates[0]["command"]
    assert updates[0]["timeout"] == 300


def test_zero_interval_failure_restart_and_rollback_cannot_repeat(install, monkeypatch):
    plugin, config, env, calls = install
    def failed(root, options):
        calls.append(options)
        raise RuntimeError("synthetic failed update")
    monkeypatch.setattr(module.shared, "update", failed)
    with pytest.raises(RuntimeError):
        module.update_daily(plugin, env, clock=lambda: 100_000)
    assert len(calls) == 1
    assert calls[0]["KKZ_AUTO_UPDATE_INTERVAL_SEC"] == "86400"
    assert calls[0]["KKZ_UPDATE_LOCK_WAIT_SEC"] == "0"
    # A fresh invocation uses only the durable timestamp, not Python memory.
    for now in (100_000, 99_000, 186_399):
        assert module.update_daily(plugin, dict(env), clock=lambda: now) == "deferred"
    assert len(calls) == 1
    monkeypatch.setattr(module.shared, "update", lambda root, options: calls.append(options))
    assert module.update_daily(plugin, env, clock=lambda: 186_400) == "attempted"
    assert len(calls) == 2


def test_legacy_attempt_and_new_plugin_directory_preserve_limit(install):
    plugin, config, env, calls = install
    cache = module.shared.cache_directory(config, env)
    cache.mkdir(parents=True, mode=0o700)
    legacy = cache / "keys-keeper.failed"
    legacy.write_text("100000")
    legacy.chmod(0o600)
    os.utime(legacy, (100_000, 100_000))
    assert module.update_daily(plugin, env, clock=lambda: 100_060) == "deferred"
    other = plugin.parent / "new-version"
    (other / ".claude-plugin").mkdir(parents=True)
    (other / ".claude-plugin/plugin.json").write_text(json.dumps({"name": "keys-keeper"}))
    assert module.update_daily(other, env, clock=lambda: 186_400) == "attempted"
    assert module.update_daily(plugin, env, clock=lambda: 186_401) == "deferred"
    assert len(calls) == 1


@pytest.mark.parametrize("changes", [{"KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE": "0"},
    {"KEYS_KEEPER_NO_AUTOUPDATE": "1"}, {"KKZ_NO_AUTOUPDATE": "1"}, {"PLUGIN_DATA": "present"}])
def test_disabled_does_not_create_cache(install, changes):
    plugin, config, env, calls = install
    env.update(changes)
    assert module.update_daily(plugin, env) == "disabled"
    assert not module.shared.cache_directory(config, env).exists()
    assert not calls


def test_native_host_policy_is_preserved_without_fallback_attempt(install):
    plugin, config, env, calls = install
    (config / "plugins/known_marketplaces.json").write_text(json.dumps({"claude-skills": {"autoUpdate": True}}))
    assert module.update_daily(plugin, env) == "native"
    assert not module.shared.cache_directory(config, env).exists()
    assert not calls


@pytest.mark.parametrize("body", ['{"last_attempt":true}', '{"last_attempt":NaN}',
    '{"last_attempt":0,"last_attempt":1}', '{"last_attempt":100000}' + ' ' * 256, '{}'])
def test_invalid_marker_blocks_work(install, body):
    plugin, config, env, calls = install
    cache = module.shared.cache_directory(config, env)
    cache.mkdir(parents=True, mode=0o700)
    marker = cache / "keys-keeper.daily.json"
    marker.write_text(body)
    marker.chmod(0o600)
    with pytest.raises(ValueError):
        module.update_daily(plugin, env, clock=lambda: 200_000)
    assert not calls
    assert marker.read_text() == body


@pytest.mark.skipif(os.name != "posix", reason="symlink setup needs POSIX")
@pytest.mark.parametrize("name", ["keys-keeper.daily.lock", "keys-keeper.daily.json", "keys-keeper.success",
    "keys-keeper.failed", "claude.lock", "keys-keeper.log", "catalog.success", "catalog.failed"])
def test_unsafe_cache_symlinks_do_not_modify_targets(install, name):
    plugin, config, env, calls = install
    cache = module.shared.cache_directory(config, env)
    cache.mkdir(parents=True, mode=0o700)
    target = plugin.parent / "outside"
    target.write_text("synthetic outside metadata")
    target.chmod(0o644)
    (cache / name).symlink_to(target)
    with pytest.raises(ValueError):
        module.update_daily(plugin, env, clock=lambda: 200_000)
    assert target.read_text() == "synthetic outside metadata"
    assert target.stat().st_mode & 0o777 == 0o644
    assert not calls
    assert not (cache / "keys-keeper.daily.json").is_file() or name == "keys-keeper.daily.json"


def test_concurrent_sessions_only_start_one_helper(install, monkeypatch):
    plugin, config, env, calls = install
    entered, finish = threading.Event(), threading.Event()
    def work(root, options):
        calls.append(options)
        entered.set()
        assert finish.wait(5)
    monkeypatch.setattr(module.shared, "update", work)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(module.update_daily, plugin, env, clock=lambda: 100_000)
        assert entered.wait(5)
        try:
            assert pool.submit(module.update_daily, plugin, env, clock=lambda: 100_000).result(timeout=5) == "busy"
        finally:
            finish.set()
        assert first.result(timeout=5) == "attempted"
    assert len(calls) == 1


@pytest.mark.parametrize("which", ["plugin", "installed", "known"])
def test_oversized_public_configuration_fails_before_parsing_or_helper(install, monkeypatch, which):
    plugin, config, env, calls = install
    paths = {"plugin": plugin / ".claude-plugin/plugin.json",
             "installed": config / "plugins/installed_plugins.json",
             "known": config / "plugins/known_marketplaces.json"}
    with paths[which].open("wb") as stream:
        stream.truncate(module.MAX_CONFIG_BYTES + 1)
    with pytest.raises(ValueError, match="updater configuration"):
        module.update_daily(plugin, env, clock=lambda: 100_000)
    assert not calls
    assert not module.shared.cache_directory(config, env).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe fixture")
def test_configuration_pipe_never_blocks_or_starts_helper(install):
    plugin, config, env, calls = install
    installed = config / "plugins/installed_plugins.json"
    installed.unlink()
    os.mkfifo(installed)
    with pytest.raises(ValueError, match="updater configuration"):
        module.update_daily(plugin, env, clock=lambda: 100_000)
    assert not calls
    assert not module.shared.cache_directory(config, env).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX pipe fixture")
def test_updater_timestamp_pipe_never_blocks_or_starts_helper(install):
    plugin, config, env, calls = install
    cache = module.shared.cache_directory(config, env)
    cache.mkdir(parents=True, mode=0o700)
    os.mkfifo(cache / "keys-keeper.daily.json", 0o600)
    with pytest.raises(ValueError, match="update marker"):
        module.update_daily(plugin, env, clock=lambda: 100_000)
    assert not calls
