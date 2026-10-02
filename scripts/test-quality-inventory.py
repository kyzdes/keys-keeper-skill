#!/usr/bin/env python3
"""Read-only AST inventory; direct imports and source-shape flags are not coverage.

This does not import tests, execute code, read a vault or infer that assertions
prove behavior. Use CI coverage/durations and reviewer assessment with this map.
"""
from __future__ import annotations

import argparse
import ast
from collections import defaultdict
import copy
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KDF_CALLS = {"encrypt_blob", "decrypt_blob", "_derive_key", "PBKDF2HMAC", "pbkdf2_hmac"}


def name_of(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return name_of(node.value) + "." + node.attr
    return ""


def package_imports(tree):
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names if alias.name.startswith("keys_keeper"))
        elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("keys_keeper"):
            if node.module == "keys_keeper":
                modules.update("keys_keeper." + alias.name for alias in node.names)
            else:
                modules.add(node.module)
    return modules


def test_functions(tree):
    return [node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")]


def function_fingerprint(function):
    node = copy.deepcopy(function)
    node.name = "test"
    if node.body and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant):
        if isinstance(node.body[0].value.value, str):
            node.body = node.body[1:]
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def inventory(root):
    importers, fingerprints = defaultdict(list), defaultdict(list)
    tests = []
    for path in sorted((root / "tests").rglob("test_*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        relative = path.relative_to(root).as_posix()
        imports = sorted(package_imports(tree))
        for module in imports:
            importers[module].append(relative)
        functions = test_functions(tree)
        for function in functions:
            fingerprints[function_fingerprint(function)].append(f"{relative}:{function.lineno}:{function.name}")
        calls = [name_of(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]
        strings = [node.value for node in ast.walk(tree)
                   if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        tests.append({"path": relative, "definition_count": len(functions), "direct_package_imports": imports,
                      "assert_count": sum(isinstance(node, ast.Assert) for node in ast.walk(tree)),
                      "unittest_assert_calls": sum(call.split(".")[-1].startswith("assert") for call in calls),
                      "text_or_source_read_calls": sum(call.split(".")[-1] in {"read_text", "read_bytes", "getsource"} for call in calls),
                      "membership_assertions": sum(isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops)
                                                   for assertion in ast.walk(tree) if isinstance(assertion, ast.Assert)
                                                   for node in ast.walk(assertion.test)),
                      "direct_kdf_or_blob_crypto_call_sites": sum(call.split(".")[-1] in KDF_CALLS for call in calls),
                      "node_harness_indicator": any("node" == value or "node:" in value for value in strings),
                      "swift_compiler_indicator": any("swiftc" == value for value in strings)})
    modules = []
    for path in sorted((root / "src" / "keys_keeper").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=str(path))
        relative = path.relative_to(root / "src").with_suffix("").as_posix()
        module = relative.replace("/", ".").removesuffix(".__init__")
        modules.append({"module": module, "path": path.relative_to(root).as_posix(),
                        "lines": len(text.splitlines()),
                        "function_definitions": sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree)),
                        "directly_importing_tests": sorted(importers.get(module, []))})
    duplicates = [locations for locations in fingerprints.values() if len(locations) > 1]
    return {"schema_version": 1, "method": "AST only; test definitions differ from parametrized collected cases",
            "limitations": ["Direct test imports are a lower bound; fixtures, transitive imports, dynamic loading and subprocesses also execute modules.",
                            "Source-read and membership counts are review indicators; output/error assertions can be valuable behavioral/security tests.",
                            "Identical normalized AST bodies are review candidates, never an automatic deletion decision.",
                            "Call-site counts do not measure executed calls or CPU time."],
            "summary": {"python_modules": len(modules), "test_files": len(tests),
                        "test_definitions": sum(row["definition_count"] for row in tests),
                        "modules_without_direct_test_import": sum(not row["directly_importing_tests"] for row in modules),
                        "exact_body_duplicate_groups": len(duplicates),
                        "node_harness_files": sum(row["node_harness_indicator"] for row in tests),
                        "swift_compiler_files": sum(row["swift_compiler_indicator"] for row in tests)},
            "modules": modules, "tests": tests, "identical_test_body_candidates": duplicates}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = inventory(args.root)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(data["summary"], sort_keys=True))


if __name__ == "__main__":
    main()
