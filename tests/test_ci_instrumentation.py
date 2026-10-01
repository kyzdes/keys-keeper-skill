"""Synthetic checks for reporting failures/partial coverage accurately."""
import importlib.util
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_metrics_preserve_teardown_failure_and_phase_durations_without_output(tmp_path):
    shared = load_script("_metrics_contract", ROOT / "tests/conftest.py")
    destination = tmp_path / "test-metrics.json"
    reporter = shared.TestMetricsReporter(destination)
    reporter.started = time.perf_counter()
    for phase, outcome, seconds in [("setup", "passed", 0.1), ("call", "passed", 0.2), ("teardown", "failed", 0.3)]:
        reporter.pytest_runtest_logreport(SimpleNamespace(nodeid="test_synthetic.py::test_example", when=phase,
                                                        outcome=outcome, duration=seconds,
                                                        longrepr="SYNTHETIC-PRIVATE-CAPTURE"))
    reporter.pytest_collectreport(SimpleNamespace(failed=True, nodeid="test_broken.py"))
    reporter.pytest_sessionfinish(None, 1)
    raw = destination.read_text()
    data = json.loads(raw)
    assert data["tests"][0]["outcome"] == "failed"
    assert data["tests"][0]["seconds"] == 0.6
    assert data["tests"][0]["phases"]["call"]["seconds"] == 0.2
    assert data["collection_failures"] == ["test_broken.py"]
    assert data["exit_status"] == 1
    assert "SYNTHETIC-PRIVATE-CAPTURE" not in raw


def test_missing_matrix_job_cannot_be_reported_as_complete(tmp_path, monkeypatch):
    report = load_script("_coverage_contract", ROOT / "scripts/coverage-report.py")
    root = tmp_path / "inputs"
    job = root / "one-job"
    job.mkdir(parents=True)
    (job / "manifest.json").write_text(json.dumps({"jobs": ["linux-py3.12"], "commit": "a" * 40,
                                                   "pytest_exit_status": 0, "coverage_status": "complete"}))
    recorded = {}
    def save(_out, files, manifest, _metrics):
        recorded.update(manifest)
        assert files == []
        return 1 if manifest["errors"] else 0
    monkeypatch.setattr(report, "save_reports", save)
    assert report.merge(root, tmp_path / "out", 5) == 1
    assert recorded["errors"] == ["expected 5 matrix jobs, received 1"]


def test_identical_test_bodies_are_candidates_not_coverage_claims(tmp_path):
    audit = load_script("_inventory_contract", ROOT / "scripts/test-quality-inventory.py")
    tests = tmp_path / "tests"
    package = tmp_path / "src/keys_keeper"
    tests.mkdir(); package.mkdir(parents=True)
    (package / "direct.py").write_text("def entry():\n    return 1\n")
    (package / "transitive.py").write_text("def helper():\n    return 2\n")
    (tests / "test_one.py").write_text("from keys_keeper.direct import entry\ndef test_first():\n    assert entry() == 1\n")
    (tests / "test_two.py").write_text("from keys_keeper.direct import entry\ndef test_second():\n    assert entry() == 1\n")
    data = audit.inventory(tmp_path)
    assert data["summary"]["modules_without_direct_test_import"] == 1
    assert data["summary"]["exact_body_duplicate_groups"] == 1
    assert data["modules"][1]["directly_importing_tests"] == []
    assert "not measure" in data["limitations"][-1]
