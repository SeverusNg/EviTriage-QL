from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

from jsonschema import Draft202012Validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MICROBENCH_ROOT = REPOSITORY_ROOT / "tests/fixtures/java-microbench"
PATH_APP_ROOT = MICROBENCH_ROOT / "path-app"
CASE_PATH = PATH_APP_ROOT / "cases/cwe22-socket-direct-tp.json"


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
        "minimum_result_count": 1,
        "query_suite": "security-extended",
        "require_code_flows": True,
        "rule_id": "java/path-injection",
    }
    assert case["ground_truth"]["label"] == "TP"

    unknown_field = deepcopy(case)
    unknown_field["unreviewed_label"] = "unsafe"
    assert list(validator.iter_errors(unknown_field))
