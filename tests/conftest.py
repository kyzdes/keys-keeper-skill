"""Shared pytest fixtures for keys-keeper."""
import os
import json
import subprocess
import sys
import time
from pathlib import Path
import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--regen",
        action="store_true",
        default=False,
        help="rewrite golden fixtures (tests/fixtures/rules/*) from current render output",
    )
    parser.addoption(
        "--test-metrics",
        metavar="PATH",
        default=None,
        help="write test phase durations/outcomes as JSON without captured output",
    )


class TestMetricsReporter:
    """Opt-in measurement only; does not change fixtures or crypto parameters."""

    def __init__(self, path):
        self.path = Path(path)
        self.started = None
        self.tests = {}
        self.collection_failures = []

    def pytest_sessionstart(self, session):
        self.started = time.perf_counter()

    def pytest_collectreport(self, report):
        if report.failed:
            self.collection_failures.append(report.nodeid)

    def pytest_runtest_logreport(self, report):
        phases = self.tests.setdefault(report.nodeid, {})
        phases[report.when] = {
            "seconds": round(report.duration, 6),
            "outcome": report.outcome,
        }

    def pytest_sessionfinish(self, session, exitstatus):
        rows = []
        for nodeid, phases in self.tests.items():
            outcomes = {phase["outcome"] for phase in phases.values()}
            outcome = "failed" if "failed" in outcomes else (
                "skipped" if "skipped" in outcomes else "passed")
            rows.append({"nodeid": nodeid, "outcome": outcome, "phases": phases,
                         "seconds": round(sum(p["seconds"] for p in phases.values()), 6)})
        rows.sort(key=lambda row: (-row["seconds"], row["nodeid"]))
        data = {"schema_version": 1, "exit_status": int(exitstatus),
                "session_seconds": round(time.perf_counter() - self.started, 6),
                "collection_failures": self.collection_failures, "tests": rows}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def pytest_configure(config):
    config.addinivalue_line("markers", "macos: requires macOS (keychain, pbcopy, etc.)")
    config.addinivalue_line("markers", "windows: requires Windows (Credential Manager, etc.)")
    config.addinivalue_line("markers", "linux: requires Linux (Secret Service, xclip, etc.)")
    if metrics_path := config.getoption("--test-metrics"):
        config.pluginmanager.register(TestMetricsReporter(metrics_path), "test-metrics")


def pytest_collection_modifyitems(config, items):
    plat = sys.platform
    skip_macos = pytest.mark.skip(reason="macOS-only test")
    skip_windows = pytest.mark.skip(reason="Windows-only test")
    skip_linux = pytest.mark.skip(reason="Linux-only test")
    for item in items:
        if "macos" in item.keywords and plat != "darwin":
            item.add_marker(skip_macos)
        if "windows" in item.keywords and plat != "win32":
            item.add_marker(skip_windows)
        if "linux" in item.keywords and not plat.startswith("linux"):
            item.add_marker(skip_linux)


@pytest.fixture
def kk_home(tmp_path, monkeypatch):
    """Isolated KEYS_KEEPER_HOME for each test."""
    home = tmp_path / "kk-home"
    monkeypatch.setenv("KEYS_KEEPER_HOME", str(home))
    return home


@pytest.fixture
def test_keychain(tmp_path):
    """Create an isolated macOS keychain for testing.

    Returns the keychain path. Caller is responsible for setting
    `KEYS_KEEPER_TEST_KEYCHAIN` env var if the backend reads it,
    or for passing it explicitly to the backend constructor.
    """
    if sys.platform != "darwin":
        pytest.skip("macOS keychain tests require Darwin")
    kc_path = tmp_path / "test.keychain-db"
    pwd = "test-pwd"
    subprocess.run(
        ["security", "create-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "unlock-keychain", "-p", pwd, str(kc_path)],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["security", "set-keychain-settings", "-u", str(kc_path)],
        check=True, capture_output=True,
    )
    yield kc_path
    subprocess.run(["security", "delete-keychain", str(kc_path)], capture_output=True)
