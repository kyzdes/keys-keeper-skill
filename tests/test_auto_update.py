"""Behavioral regressions; no network, real client, or real user config."""
import importlib.util
import json
import multiprocessing
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HELPER = Path(__file__).resolve().parent.parent / "scripts/auto_update.py"
if not HELPER.exists():
    HELPER = Path(__file__).with_name("auto_update.py")
spec = importlib.util.spec_from_file_location("plugin_update", HELPER)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
REAL_COMMAND = module.run_command


def worker(root, env, events):
    def command(args, timeout, lock_fd=None):
        # macOS Python 3.9 monotonic clocks are not shared across processes.
        events.put((time.time_ns(), "start", args[1:]))
        time.sleep(0.1)
        events.put((time.time_ns(), "end", args[1:]))
        return 0
    with patch.object(module.shutil, "which", return_value="/fake/claude"), patch.object(module, "run_command", side_effect=command):
        module.update(root, env)


def crash_while_locked(lock_path, ready):
    with module.locked(Path(lock_path), 0) as handle:
        ready.put(handle is not None)
        ready.close()
        ready.join_thread()
        os._exit(13)


def command_with_lock(lock_path, marker):
    try:
        with module.locked(Path(lock_path), 0) as handle:
            if handle is None:
                raise RuntimeError("could not acquire test lock")
            REAL_COMMAND([sys.executable, "-c", "from pathlib import Path; import sys,time; Path(sys.argv[1]).write_text('ready'); time.sleep(20)", str(marker)], 1.5, handle.fileno())
    except KeyboardInterrupt:
        pass


def drain_events(events):
    result = []
    while True:
        try:
            result.append(events.get(timeout=0.2))
        except queue.Empty:
            return [(phase, args) for _, phase, args in sorted(result)]


class UpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.plugin = self.make_plugin("clarity")
        self.config = self.make_config("config")
        self.cache_base = self.root / "cache"
        self.env = {"CLAUDE_CONFIG_DIR": str(self.config), "KKZ_PLUGIN_CACHE_ROOT": str(self.cache_base)}
        self.cache = module.cache_directory(self.config, self.env)
        self.calls = []
        self.codes = []
        for patcher in [patch.object(module.shutil, "which", return_value="/fake/claude"),
                        patch.object(module, "run_command", side_effect=self.command)]:
            patcher.start()
            self.addCleanup(patcher.stop)

    def make_plugin(self, name):
        plugin = self.root / (name + " plugin with spaces")
        (plugin / ".claude-plugin").mkdir(parents=True)
        (plugin / ".claude-plugin/plugin.json").write_text(json.dumps({"name": name}))
        return plugin

    def make_config(self, name):
        config = self.root / name
        (config / "plugins").mkdir(parents=True)
        (config / "plugins/installed_plugins.json").write_text(json.dumps({"plugins": {n + "@claude-skills": [{}] for n in ["clarity", "deck-copy", "keys-keeper", "agentix"]}}))
        return config

    def command(self, args, timeout, lock_fd=None):
        self.calls.append(args[1:])
        return self.codes.pop(0) if self.codes else 0

    def assert_no_side_effects(self):
        self.assertFalse(self.cache_base.exists())
        self.assertEqual(self.calls, [])

    def test_only_own_plugin_and_success_cooldown(self):
        self.env.update(KEYS_KEEPER_NO_AUTOUPDATE="1", AGENTIX_PLUGIN_AUTO_UPDATE="0")
        module.update(self.plugin, self.env)
        module.update(self.plugin, self.env)
        self.assertEqual(self.calls, [["plugin", "marketplace", "update", "claude-skills"], ["plugin", "update", "clarity@claude-skills"]])

    def test_global_optout_is_side_effect_free_even_without_manifest(self):
        self.env["KKZ_NO_AUTOUPDATE"] = "1"
        module.update(self.root / "missing-plugin", self.env)
        self.assert_no_side_effects()

    def test_keys_keeper_default_and_optout(self):
        plugin = self.make_plugin("keys-keeper")
        module.update(plugin, self.env)
        self.env.update(KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE="1", KEYS_KEEPER_NO_AUTOUPDATE="1")
        module.update(plugin, self.env)
        self.assert_no_side_effects()

    def test_keys_keeper_optin_updates_itself(self):
        plugin = self.make_plugin("keys-keeper")
        self.env["KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE"] = "1"
        module.update(plugin, self.env)
        self.assertEqual(self.calls[-1], ["plugin", "update", "keys-keeper@claude-skills"])

    def test_global_optout_wins_over_keys_keeper_optin(self):
        plugin = self.make_plugin("keys-keeper")
        self.env.update(KEYS_KEEPER_ENABLE_MUTABLE_AUTOUPDATE="1", KKZ_NO_AUTOUPDATE="1")
        module.update(plugin, self.env)
        self.assert_no_side_effects()

    def test_native_updater_owns_policy(self):
        (self.config / "plugins/known_marketplaces.json").write_text(json.dumps({"claude-skills": {"autoUpdate": True}}))
        module.update(self.plugin, self.env)
        self.assert_no_side_effects()

    def test_disabled_native_updater_allows_fallback(self):
        (self.config / "plugins/known_marketplaces.json").write_text(json.dumps({"claude-skills": {"autoUpdate": False}}))
        module.update(self.plugin, self.env)
        self.assertEqual(len(self.calls), 2)

    def test_codex_never_updates_claude_even_with_empty_plugin_data(self):
        for value in ["codex-data", ""]:
            with self.subTest(value=value):
                self.env["PLUGIN_DATA"] = value
                module.update(self.plugin, self.env)
                self.assert_no_side_effects()

    def test_uninstalled_plugin_is_side_effect_free(self):
        module.update(self.make_plugin("not-installed"), self.env)
        self.assert_no_side_effects()

    def test_missing_client_is_side_effect_free(self):
        with patch.object(module.shutil, "which", return_value=None):
            module.update(self.plugin, self.env)
        self.assert_no_side_effects()

    def test_failure_does_not_start_success_cooldown(self):
        self.codes = [0, 1]
        module.update(self.plugin, self.env)
        self.assertFalse((self.cache / "clarity.success").exists())
        self.assertTrue((self.cache / "clarity.failed").exists())
        module.update(self.plugin, self.env)
        self.assertEqual(len(self.calls), 2)
        os.utime(self.cache / "clarity.failed", (0, 0))
        module.update(self.plugin, self.env)
        self.assertTrue((self.cache / "clarity.success").exists())
        self.assertFalse((self.cache / "clarity.failed").exists())
        self.assertEqual(len(self.calls), 3)

    def test_catalog_failure_is_shared_without_success_cooldown(self):
        self.codes = [1]
        module.update(self.plugin, self.env)
        module.update(self.make_plugin("deck-copy"), self.env)
        self.assertEqual(len(self.calls), 1)
        self.assertFalse((self.cache / "catalog.success").exists())
        self.assertFalse((self.cache / "clarity.success").exists())
        os.utime(self.cache / "clarity.failed", (0, 0))
        os.utime(self.cache / "catalog.failed", (0, 0))
        module.update(self.plugin, self.env)
        self.assertTrue((self.cache / "catalog.success").exists())
        self.assertFalse((self.cache / "catalog.failed").exists())
        self.assertEqual(len(self.calls), 3)

    def test_failed_plugin_does_not_suppress_other_plugin(self):
        self.codes = [0, 1]
        module.update(self.plugin, self.env)
        module.update(self.make_plugin("deck-copy"), self.env)
        self.assertEqual(self.calls[-1], ["plugin", "update", "deck-copy@claude-skills"])
        self.assertTrue((self.cache / "deck-copy.success").exists())

    def test_different_configs_have_independent_cooldowns(self):
        other = self.make_config("other-config")
        other_env = dict(self.env, CLAUDE_CONFIG_DIR=str(other))
        module.update(self.plugin, self.env)
        module.update(self.plugin, other_env)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(len(list(self.cache_base.glob("*/clarity.success"))), 2)
        # Alternate spellings of the same path use the same policy state.
        module.update(self.plugin, dict(self.env, CLAUDE_CONFIG_DIR=str(self.config / ".." / "config")))
        self.assertEqual(len(self.calls), 4)

    def spawn_workers(self, roots):
        ctx = multiprocessing.get_context("spawn")
        events = ctx.Queue()
        children = [ctx.Process(target=worker, args=(root, self.env, events)) for root in roots]
        try:
            for child in children:
                child.start()
            for child in children:
                child.join(15)
                self.assertEqual(child.exitcode, 0)
            return drain_events(events)
        finally:
            for child in children:
                if child.is_alive():
                    child.terminate()
                    child.join(5)
            events.close()

    def test_processes_share_lock_and_recheck_cooldown(self):
        events = self.spawn_workers([self.plugin] * 3)
        self.assertEqual(events, [
            ("start", ["plugin", "marketplace", "update", "claude-skills"]),
            ("end", ["plugin", "marketplace", "update", "claude-skills"]),
            ("start", ["plugin", "update", "clarity@claude-skills"]),
            ("end", ["plugin", "update", "clarity@claude-skills"]),
        ])

    def test_different_plugins_serialize_and_share_catalog(self):
        events = self.spawn_workers([self.plugin, self.make_plugin("deck-copy")])
        self.assertEqual(len(events), 6)
        for start, end in zip(events[::2], events[1::2]):
            self.assertEqual(start[0], "start")
            self.assertEqual(end, ("end", start[1]))
        commands = [event[1] for event in events[::2]]
        self.assertEqual(commands[0], ["plugin", "marketplace", "update", "claude-skills"])
        self.assertCountEqual(commands[1:], [["plugin", "update", "clarity@claude-skills"], ["plugin", "update", "deck-copy@claude-skills"]])

    def test_lock_is_released_after_crash_without_child(self):
        self.cache.mkdir(parents=True)
        lock_path = self.cache / "claude.lock"
        ctx = multiprocessing.get_context("spawn")
        ready = ctx.Queue()
        child = ctx.Process(target=crash_while_locked, args=(lock_path, ready))
        child.start()
        self.assertTrue(ready.get(timeout=5))
        child.join(5)
        self.assertEqual(child.exitcode, 13)
        with module.locked(lock_path, 0) as handle:
            self.assertIsNotNone(handle)
        ready.close()

    @unittest.skipIf(os.name == "nt", "POSIX flock inheritance; Windows timeout is tested separately")
    def test_updater_exit_keeps_lock_until_child_timeout(self):
        self.cache.mkdir(parents=True)
        lock_path = self.cache / "claude.lock"
        ctx = multiprocessing.get_context("spawn")
        for interruption in ["kill", "interrupt"]:
            with self.subTest(interruption=interruption):
                marker = self.root / ("command-started-" + interruption)
                child = ctx.Process(target=command_with_lock, args=(lock_path, marker))
                child.start()
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.02)
                    self.assertTrue(marker.exists())
                    if interruption == "kill":
                        child.kill()
                    else:
                        os.kill(child.pid, signal.SIGINT)
                    child.join(5)
                    self.assertEqual(child.exitcode, -signal.SIGKILL if interruption == "kill" else 0)
                    with module.locked(lock_path, 0) as handle:
                        self.assertIsNone(handle)
                    start = time.monotonic()
                    with module.locked(lock_path, 5) as handle:
                        self.assertIsNotNone(handle)
                    self.assertLess(time.monotonic() - start, 4)
                finally:
                    if child.is_alive():
                        child.terminate()
                        child.join(5)

    def test_lock_wait_is_bounded_without_success_stamp(self):
        self.cache.mkdir(parents=True)
        with module.locked(self.cache / "claude.lock", 0) as handle:
            self.assertIsNotNone(handle)
            module.update(self.plugin, dict(self.env, KKZ_UPDATE_LOCK_WAIT_SEC="0"))
        self.assertEqual(self.calls, [])
        self.assertFalse((self.cache / "clarity.success").exists())

    def test_timeout_is_bounded(self):
        start = time.monotonic()
        code = REAL_COMMAND([sys.executable, "-c", "import time; time.sleep(20)"], 0.1)
        self.assertEqual(code, 124)
        self.assertLess(time.monotonic() - start, 5)

    def test_timeout_stops_descendant_process(self):
        marker = self.root / "descendant-survived"
        descendant = "from pathlib import Path; import sys,time; time.sleep(1.5); Path(sys.argv[1]).write_text('alive')"
        parent = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); time.sleep(20)"
        code = REAL_COMMAND([sys.executable, "-c", parent, descendant, str(marker)], 0.3)
        self.assertEqual(code, 124)
        time.sleep(1.6)
        self.assertFalse(marker.exists())

    def test_missing_binary_reports_failure(self):
        self.assertEqual(REAL_COMMAND([str(self.root / "no-such-client")], 0.1), 127)

    def test_supervised_command_propagates_failure(self):
        self.cache.mkdir(parents=True)
        with module.locked(self.cache / "claude.lock", 0) as handle:
            code = REAL_COMMAND([sys.executable, "-c", "import sys; sys.exit(7)"], 1, handle.fileno())
        self.assertEqual(code, 7)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem permissions")
    def test_private_state_permissions_and_metadata_only_log(self):
        module.update(self.plugin, self.env)
        self.assertEqual(self.cache.stat().st_mode & 0o777, 0o700)
        for name in ["claude.lock", "clarity.log", "clarity.success", "catalog.success"]:
            self.assertEqual((self.cache / name).stat().st_mode & 0o777, 0o600)
        log = (self.cache / "clarity.log").read_text()
        self.assertIn("clarity@claude-skills exit=0", log)
        self.assertNotIn(str(self.root), log)

    @unittest.skipIf(os.name == "nt", "bash hook is POSIX-only")
    def test_shell_hook_with_spaces_and_optout_has_no_writes(self):
        # Use only a temporary manifest/config/PATH; never the real Claude CLI.
        scripts = self.plugin / "scripts"
        scripts.mkdir()
        (scripts / "auto_update.py").write_text(HELPER.read_text())
        wrapper = HELPER.with_name("auto-update.sh")
        (scripts / wrapper.name).write_text(wrapper.read_text())
        env = {"PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"]), "HOME": str(self.root), "CLAUDE_CONFIG_DIR": str(self.config), "KKZ_PLUGIN_CACHE_ROOT": str(self.cache_base), "KKZ_NO_AUTOUPDATE": "1"}
        proc = subprocess.run(["/bin/bash", str(scripts / wrapper.name)], env=env, capture_output=True, timeout=5)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout + proc.stderr, b"")
        self.assert_no_side_effects()

    @unittest.skipIf(os.name == "nt", "bash hook is POSIX-only")
    def test_shell_hook_updates_only_itself_using_fake_client(self):
        scripts = self.plugin / "scripts"
        scripts.mkdir()
        (scripts / "auto_update.py").write_text(HELPER.read_text())
        wrapper = HELPER.with_name("auto-update.sh")
        (scripts / wrapper.name).write_text(wrapper.read_text())
        binaries = self.root / "bin"
        binaries.mkdir()
        (binaries / "python3").symlink_to(sys.executable)
        client = binaries / "claude"
        client.write_text("#!" + sys.executable + "\nimport json,os,sys\nwith open(os.environ['TEST_UPDATE_CALLS'], 'a') as log:\n    log.write(json.dumps(sys.argv[1:]) + '\\n')\n")
        client.chmod(0o700)
        calls = self.root / "calls.jsonl"
        env = {"PATH": os.pathsep.join([str(binaries), "/usr/bin", "/bin"]), "HOME": str(self.root), "CLAUDE_CONFIG_DIR": str(self.config), "KKZ_PLUGIN_CACHE_ROOT": str(self.cache_base), "TEST_UPDATE_CALLS": str(calls), "KEYS_KEEPER_NO_AUTOUPDATE": "1", "AGENTIX_PLUGIN_AUTO_UPDATE": "0"}
        proc = subprocess.run(["/bin/bash", str(scripts / wrapper.name)], env=env, capture_output=True, timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout + proc.stderr, b"")
        self.assertEqual([json.loads(line) for line in calls.read_text().splitlines()], [
            ["plugin", "marketplace", "update", "claude-skills"],
            ["plugin", "update", "clarity@claude-skills"],
        ])


if __name__ == "__main__":
    unittest.main()
