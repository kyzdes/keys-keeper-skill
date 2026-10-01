#!/usr/bin/env python3
"""Report measured Python coverage and pytest phase durations from CI artifacts.

No source/test execution, vault access, captured output or traceback extraction.
Matrix union describes executed Python branches; it is not a JS/Swift, mutation,
security-audit, installed-app or battery-life measurement.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
from pathlib import Path
import platform
import sys


ROOT = Path(__file__).resolve().parents[1]
LIMITATIONS = (
    "Python package only: JavaScript/CSS/HTML and native Swift are not instrumented.",
    "Subprocess coverage includes normal Python exits and patched os._exit; "
    "SIGKILL/forced process-tree termination may lose child data.",
    "Line/branch execution does not prove assertions, all input combinations, "
    "live deployment, OS integration, or battery life.",
    "Test phase durations are wall time under coverage, not uninstrumented CPU benchmarks.",
)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_metrics(path):
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1 or not isinstance(data.get("tests"), list):
        raise ValueError("unsupported test metrics schema")
    return data


def percentage(covered, total):
    return round(100 * covered / total, 2) if total else None


def coverage_totals(totals):
    lines, branches = totals["num_statements"], totals.get("num_branches", 0)
    return {"covered_lines": totals["covered_lines"], "lines": lines,
            "line_percent": percentage(totals["covered_lines"], lines),
            "covered_branches": totals.get("covered_branches", 0), "branches": branches,
            "branch_percent": percentage(totals.get("covered_branches", 0), branches)}


def valid_floor(value):
    floor = float(value)
    if not math.isfinite(floor) or not 0 <= floor <= 100:
        raise argparse.ArgumentTypeError("coverage floor must be a finite percentage from 0 to 100")
    return floor


def evaluate_gate(manifest, min_line=None, min_branch=None):
    """Compare raw counts, never rounded display percentages."""
    gate = {"status": "not-configured", "min_line": min_line, "min_branch": min_branch, "errors": []}
    if min_line is None and min_branch is None:
        return gate
    if manifest["errors"] or not manifest.get("totals"):
        gate["status"] = "not-evaluated"
        gate["errors"].append("coverage evidence is incomplete")
        return gate
    for kind, floor, covered, total in (
        ("line", min_line, "covered_lines", "lines"),
        ("branch", min_branch, "covered_branches", "branches"),
    ):
        if floor is None:
            continue
        totals = manifest["totals"]
        if totals[total] == 0:
            gate["errors"].append(f"no {kind} coverage denominator")
        elif 100 * totals[covered] < floor * totals[total]:
            gate["errors"].append(f"{kind} coverage is below the {floor:g}% floor")
    gate["status"] = "failed" if gate["errors"] else "passed"
    return gate


def render_summary(manifest, coverage_data, metrics_by_job):
    lines = ["# Python test evidence", "", f"Coverage status: **{manifest['coverage_status']}**.",
             "", "## Coverage", ""]
    gate = manifest["coverage_gate"]
    if gate["status"] != "not-configured":
        floors = ", ".join(f"{kind} >= {gate['min_' + kind]:g}%" for kind in ("line", "branch")
                           if gate['min_' + kind] is not None)
        lines.extend([f"Measured coverage gate: **{gate['status']}** ({floors}).", ""])
        lines.extend([f"- {error}" for error in gate["errors"]])
        if gate["errors"]:
            lines.append("")
    if coverage_data:
        totals = coverage_totals(coverage_data["totals"])
        lines.extend([f"Lines: {totals['covered_lines']}/{totals['lines']} "
                      f"({totals['line_percent']}%). Branches: {totals['covered_branches']}/"
                      f"{totals['branches']} ({totals['branch_percent']}%).", "",
                      "Missing lines/branches are in coverage.json, coverage.xml and html/index.html.", "",
                      "| Module | Missing lines | Missing branches |", "|---|---:|---:|"])
        files = sorted(coverage_data["files"].items(), key=lambda pair: (
            -pair[1]["summary"].get("missing_branches", 0),
            -pair[1]["summary"]["missing_lines"], pair[0]))
        for path, data in files[:20]:
            summary = data["summary"]
            lines.append(f"| {path} | {summary['missing_lines']} | {summary.get('missing_branches', 0)} |")
    else:
        lines.append("No usable coverage data was produced.")
    lines.extend(["", "## Test durations", "",
                  "| Matrix job | Test outcomes | Session seconds |", "|---|---|---:|"])
    slow = []
    for label, data in sorted(metrics_by_job.items()):
        counts = {kind: sum(row["outcome"] == kind for row in data["tests"])
                  for kind in ("passed", "failed", "skipped")}
        outcomes = ", ".join(f"{count} {kind}" for kind, count in counts.items())
        lines.append(f"| {label} | {outcomes} | {data['session_seconds']} |")
        slow.extend((row["seconds"], label, row["nodeid"]) for row in data["tests"])
    lines.extend(["", "Slowest individual cases (setup + call + teardown):", "",
                  "| Job | Test | Seconds |", "|---|---|---:|"])
    for seconds, label, nodeid in sorted(slow, reverse=True)[:20]:
        lines.append(f"| {label} | {nodeid.replace('|', '&#124;')} | {seconds} |")
    if manifest["errors"]:
        lines.extend(["", "## Incomplete evidence", ""] + [f"- {error}" for error in manifest["errors"]])
    lines.extend(["", "## Limits", ""] + [f"- {item}" for item in LIMITATIONS])
    return "\n".join(lines) + "\n"


def write_durations(path, metrics_by_job):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["job", "test", "outcome", "setup_seconds", "call_seconds", "teardown_seconds", "total_seconds"])
        for label, data in sorted(metrics_by_job.items()):
            for row in data["tests"]:
                phases = row["phases"]
                writer.writerow([label, row["nodeid"], row["outcome"],
                                 *(phases.get(phase, {}).get("seconds", 0)
                                   for phase in ("setup", "call", "teardown")), row["seconds"]])


def save_reports(report_dir, coverage_files, manifest, metrics_by_job, *, min_line=None, min_branch=None):
    import coverage

    report_dir.mkdir(parents=True, exist_ok=True)
    data = None
    target = report_dir / ".coverage"
    cov = coverage.Coverage(data_file=str(target), config_file=str(ROOT / ".coveragerc"))
    if coverage_files:
        # Explicit filenames combine canonical per-job .coverage files too.
        # keep=True preserves input evidence if a later report step fails.
        cov.combine(data_paths=[str(path) for path in coverage_files], keep=True)
        cov.save()
        cov.load()
        cov.json_report(outfile=str(report_dir / "coverage.json"))
        cov.xml_report(outfile=str(report_dir / "coverage.xml"))
        cov.html_report(directory=str(report_dir / "html"))
        data = json.loads((report_dir / "coverage.json").read_text(encoding="utf-8"))
        manifest["totals"] = coverage_totals(data["totals"])
        measured = {name.replace("\\", "/") for name in data["files"]}
        expected = {path.relative_to(ROOT).as_posix()
                    for path in (ROOT / "src/keys_keeper").rglob("*.py")}
        omitted = sorted(path for path in expected
                         if not any(name == path or name.endswith("/" + path) for name in measured))
        manifest["source_modules"] = len(expected)
        manifest["omitted_source_modules"] = omitted
        if omitted:
            manifest["errors"].append(f"coverage omitted {len(omitted)} Python source modules")
    else:
        manifest["errors"].append("no usable coverage files")
    manifest["coverage_status"] = "partial" if manifest["errors"] else "complete"
    manifest["coverage_gate"] = evaluate_gate(manifest, min_line, min_branch)
    manifest["coverage_tool_version"] = coverage.__version__
    manifest["limitations"] = list(LIMITATIONS)
    write_json(report_dir / "manifest.json", manifest)
    write_durations(report_dir / "test-durations.csv", metrics_by_job)
    summary = render_summary(manifest, data, metrics_by_job)
    (report_dir / "summary.md").write_text(summary, encoding="utf-8")
    if summary_path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary_path, "a", encoding="utf-8") as stream:
            stream.write(summary)
    print(json.dumps({"coverage_status": manifest["coverage_status"], "jobs": manifest["jobs"],
                      "totals": manifest.get("totals"), "coverage_gate": manifest["coverage_gate"],
                      "errors": manifest["errors"]}))
    return 1 if manifest["errors"] or manifest["coverage_gate"]["errors"] else 0


def job(report_dir, label, commit):
    metrics = load_metrics(report_dir / "test-metrics.json")
    errors = []
    if metrics is None:
        errors.append("pytest did not produce phase metrics")
    manifest = {"schema_version": 1, "jobs": [label], "commit": commit,
                "python": platform.python_version(), "platform": sys.platform, "errors": errors,
                "pytest_exit_status": None if metrics is None else metrics["exit_status"]}
    files = sorted(report_dir.glob(".coverage*"))
    # Always use a different output directory when combining; .coverage is then
    # copied back as the canonical downloadable file after reports finish.
    output = report_dir / "generated"
    code = save_reports(output, files, manifest, {} if metrics is None else {label: metrics})
    for path in output.iterdir():
        target = report_dir / path.name
        if path.is_file():
            target.write_bytes(path.read_bytes())
        elif path.name == "html":
            import shutil
            shutil.copytree(path, target, dirs_exist_ok=True)
    import shutil
    shutil.rmtree(output)
    return code


def merge(input_dir, report_dir, expected_jobs, *, min_line=None, min_branch=None):
    rows, metrics_by_job, files, errors = [], {}, [], []
    for manifest_path in sorted(input_dir.glob("*/manifest.json")):
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        label, = data["jobs"]
        if label in metrics_by_job or any(row["label"] == label for row in rows):
            errors.append("duplicate matrix job: " + label)
            continue
        rows.append({"label": label, "commit": data["commit"], "pytest_exit_status": data["pytest_exit_status"]})
        if data["coverage_status"] != "complete":
            errors.append("incomplete coverage artifact: " + label)
        metrics = load_metrics(manifest_path.parent / "test-metrics.json")
        if metrics is not None:
            metrics_by_job[label] = metrics
        coverage_file = manifest_path.parent / ".coverage"
        if coverage_file.is_file():
            files.append(coverage_file)
    if len(rows) != expected_jobs:
        errors.append(f"expected {expected_jobs} matrix jobs, received {len(rows)}")
    commits = {row["commit"] for row in rows}
    if len(commits) != 1:
        errors.append("matrix artifacts have missing or differing source commits")
    manifest = {"schema_version": 1, "jobs": [row["label"] for row in rows],
                "commit": next(iter(commits)) if len(commits) == 1 else None,
                "matrix": rows, "expected_jobs": expected_jobs, "errors": errors}
    return save_reports(report_dir, files, manifest, metrics_by_job, min_line=min_line, min_branch=min_branch)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    single = commands.add_parser("job")
    single.add_argument("--report-dir", type=Path, required=True)
    single.add_argument("--label", required=True)
    single.add_argument("--commit", required=True)
    combined = commands.add_parser("merge")
    combined.add_argument("--input-dir", type=Path, required=True)
    combined.add_argument("--report-dir", type=Path, required=True)
    combined.add_argument("--expected-jobs", type=int, required=True)
    combined.add_argument("--min-line", type=valid_floor)
    combined.add_argument("--min-branch", type=valid_floor)
    args = parser.parse_args()
    if args.command == "job":
        return job(args.report_dir, args.label, args.commit)
    return merge(args.input_dir, args.report_dir, args.expected_jobs,
                 min_line=args.min_line, min_branch=args.min_branch)


if __name__ == "__main__":
    raise SystemExit(main())
