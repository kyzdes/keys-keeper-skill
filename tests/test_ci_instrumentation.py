"""Synthetic checks for reporting failures/partial coverage accurately."""
import importlib.util
import argparse
import json
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import pytest


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
    def save(_out, files, manifest, _metrics, **_floors):
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


def test_coverage_floor_uses_raw_counts_and_preserves_complete_evidence_status():
    report = load_script("_coverage_floor_contract", ROOT / "scripts/coverage-report.py")
    manifest = {"errors": [], "coverage_status": "complete", "totals": {
        "covered_lines": 16_799, "lines": 20_000,
        "covered_branches": 69, "branches": 100,
    }}
    # 83.995 displays as 84.0; rounding must not let it pass the 84% gate.
    assert report.percentage(16_799, 20_000) == 84.0
    gate = report.evaluate_gate(manifest, min_line=84, min_branch=69)
    assert gate["status"] == "failed"
    assert gate["errors"] == ["line coverage is below the 84% floor"]
    assert manifest["coverage_status"] == "complete"
    manifest["totals"]["covered_lines"] = 16_800
    assert report.evaluate_gate(manifest, min_line=84, min_branch=69)["status"] == "passed"


def test_missing_or_partial_measurement_never_passes_coverage_floor():
    report = load_script("_coverage_partial_floor_contract", ROOT / "scripts/coverage-report.py")
    for manifest in ({"errors": ["missing matrix job"], "totals": {"covered_lines": 100, "lines": 100}},
                     {"errors": []}):
        gate = report.evaluate_gate(manifest, min_line=84)
        assert gate["status"] == "not-evaluated"
        assert gate["errors"] == ["coverage evidence is incomplete"]
    empty = {"errors": [], "totals": {"covered_lines": 0, "lines": 0, "covered_branches": 0, "branches": 0}}
    assert report.evaluate_gate(empty, min_line=84, min_branch=69)["status"] == "failed"


@pytest.mark.parametrize("bad", ["-1", "101", "nan", "inf", "-inf"])
def test_invalid_coverage_floor_is_rejected(bad):
    report = load_script("_coverage_invalid_floor_contract", ROOT / "scripts/coverage-report.py")
    with pytest.raises(argparse.ArgumentTypeError, match="finite percentage"):
        report.valid_floor(bad)


def test_merge_passes_floors_to_reporting_without_hiding_failed_tests(tmp_path, monkeypatch):
    report = load_script("_coverage_merge_floor_contract", ROOT / "scripts/coverage-report.py")
    job = tmp_path / "inputs" / "job"
    job.mkdir(parents=True)
    (job / "manifest.json").write_text(json.dumps({"jobs": ["linux-py3.12"], "commit": "b" * 40,
                                                   "pytest_exit_status": 1, "coverage_status": "complete"}))
    def save(_out, _files, manifest, _metrics, **floors):
        assert manifest["matrix"][0]["pytest_exit_status"] == 1
        assert floors == {"min_line": 84, "min_branch": 69}
        return 1
    monkeypatch.setattr(report, "save_reports", save)
    assert report.merge(tmp_path / "inputs", tmp_path / "out", 1, min_line=84, min_branch=69) == 1
