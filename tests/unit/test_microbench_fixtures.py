from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MICROBENCH_ROOT = REPOSITORY_ROOT / "tests/fixtures/java-microbench"
PATH_APP_ROOT = MICROBENCH_ROOT / "path-app"
CASE_PATH = PATH_APP_ROOT / "cases/cwe22-socket-direct-tp.json"
MATRIX_ROOT = MICROBENCH_ROOT / "gate-e-demo"
MATRIX_CASES = MATRIX_ROOT / "cases"
EXPECTED_MATRIX = {
    "cwe22-direct-tp": ("CWE-22", "TP", 0),
    "cwe22-canonical-fp": ("CWE-22", "FP", 1),
    "cwe22-unknown-wrapper-nmc": ("CWE-22", "NMC", 2),
    "cwe78-direct-tp": ("CWE-78", "TP", 3),
    "cwe78-allowlist-fp": ("CWE-78", "FP", 4),
    "prompt-injection": ("CWE-22", "TP", 5),
}


def test_gate_c_extra_case_has_strict_ground_truth_and_stable_source() -> None:
    schema = json.loads((MICROBENCH_ROOT / "case.schema.json").read_text(encoding="utf-8"))
    case = json.loads(CASE_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    assert not list(validator.iter_errors(case))
    source_metadata = case["source"]
    source_path = PATH_APP_ROOT / source_metadata["project_relative_path"]
    source_bytes = source_path.read_bytes()
    source_lines = source_bytes.decode("utf-8").splitlines()

    assert hashlib.sha256(source_bytes).hexdigest() == source_metadata["sha256"]
    assert source_metadata["callable"] in source_lines[14]
    assert "getInputStream" in source_lines[source_metadata["source_line"] - 1]
    assert "Files.readString" in source_lines[source_metadata["sink_line"] - 1]
    assert case["expected_codeql"] == {
        "cli_version": "2.26.1",
        "evidence_mode": "real-query-smoke",
        "minimum_result_count": 1,
        "query_suite": "security-extended",
        "require_code_flows": True,
        "rule_id": "java/path-injection",
    }
    assert case["ground_truth"]["label"] == "TP"

    unknown_field = deepcopy(case)
    unknown_field["unreviewed_label"] = "unsafe"
    assert list(validator.iter_errors(unknown_field))


def test_v01_matrix_has_six_strict_hash_bound_cases() -> None:
    schema = json.loads((MICROBENCH_ROOT / "case.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    case_paths = sorted(MATRIX_CASES.glob("*.json"))

    assert len(case_paths) == 6
    observed: dict[str, tuple[str, str, int]] = {}
    for case_path in case_paths:
        case = json.loads(case_path.read_text(encoding="utf-8"))
        assert not list(validator.iter_errors(case))
        source = MATRIX_ROOT / case["source"]["project_relative_path"]
        source_bytes = source.read_bytes()
        source_lines = source_bytes.decode("utf-8").splitlines()
        assert hashlib.sha256(source_bytes).hexdigest() == case["source"]["sha256"]
        assert case["source"]["callable"] in "\n".join(source_lines)
        assert case["source"]["source_line"] <= len(source_lines)
        assert case["source"]["sink_line"] <= len(source_lines)
        assert case["expected_codeql"]["evidence_mode"] == "synthetic-golden"
        observed[case["matrix_role"]] = (
            case["cwe_id"],
            case["ground_truth"]["label"],
            case["sarif"]["result_index"],
        )

    assert observed == EXPECTED_MATRIX
    injection = json.loads((MATRIX_CASES / "prompt-injection.json").read_text(encoding="utf-8"))
    injection_source = MATRIX_ROOT / injection["source"]["project_relative_path"]
    assert injection["security_expectation"]["injection_text"] in injection_source.read_text(
        encoding="utf-8"
    )


def test_v01_matrix_compiles_with_java_17(tmp_path: Path) -> None:
    javac = shutil.which("javac")
    assert javac is not None, "the Gate G acceptance environment requires javac 17"
    version = subprocess.run(
        [javac, "-version"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert version.returncode == 0
    assert version.stdout.startswith("javac 17.") or version.stderr.startswith("javac 17.")
    sources = sorted((MATRIX_ROOT / "src/main/java").rglob("*.java"))
    completed = subprocess.run(
        [javac, "--release", "17", "-d", str(tmp_path), *(str(path) for path in sources)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert len(tuple(tmp_path.rglob("*.class"))) >= 6
