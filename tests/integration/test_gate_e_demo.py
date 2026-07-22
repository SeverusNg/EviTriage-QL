from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from evitriage.config import load_llm_profile
from evitriage.domain.report import AlertReport
from evitriage.domain.run import RunManifest, WorkflowState
from evitriage.domain.triage import TriageRunSummary

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
BUNDLES_ROOT = REPOSITORY_ROOT / "tests/fixtures/replay-bundles"
BUNDLE_ROOT = BUNDLES_ROOT / "gate-e-three-label-v0.1"
BUNDLE_SCHEMA = REPOSITORY_ROOT / "tests/fixtures/replay-bundles/bundle.schema.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_state(root: Path) -> dict[str, tuple[str, int, str | None]]:
    state: dict[str, tuple[str, int, str | None]] = {}
    for path in sorted((root, *root.rglob("*"))):
        relative = "." if path == root else path.relative_to(root).as_posix()
        metadata = path.lstat()
        if stat.S_ISDIR(metadata.st_mode):
            state[relative] = ("directory", stat.S_IMODE(metadata.st_mode), None)
        elif stat.S_ISREG(metadata.st_mode):
            state[relative] = ("file", stat.S_IMODE(metadata.st_mode), _sha256(path))
        else:
            raise AssertionError(f"unexpected fixture entry type: {relative}")
    return state


def test_gate_e_replay_bundle_manifest_closes_over_checked_in_inputs() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "EVITRIAGE_COMMAND ?= uv run --offline evitriage" in makefile
    schema = json.loads(BUNDLE_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    bundle_roots = sorted(path.parent for path in BUNDLES_ROOT.glob("*/bundle-manifest.json"))
    assert {path.name for path in bundle_roots} == {
        "gate-e-nmc-v0.1",
        "gate-e-three-label-v0.1",
    }
    for bundle_root in bundle_roots:
        bundle = json.loads((bundle_root / "bundle-manifest.json").read_text(encoding="utf-8"))
        assert not list(validator.iter_errors(bundle))
        entries = bundle["entries"]
        expected_response_files: set[str] = set()
        roles_by_result: dict[int, list[str]] = {}
        for entry in entries:
            roles_by_result.setdefault(entry["result_index"], []).append(entry["agent_role"])
            response_file = entry["response_file"]
            assert response_file == f"{entry['request_sha256']}.json"
            response_path = bundle_root / response_file
            assert response_path.is_file()
            assert not response_path.is_symlink()
            assert _sha256(response_path) == entry["response_sha256"]
            expected_response_files.add(response_file)
        assert all(roles == ["analyst", "rebuttal", "judge"] for roles in roles_by_result.values())
        actual_response_files = {
            path.name for path in bundle_root.glob("*.json") if path.name != "bundle-manifest.json"
        }
        assert actual_response_files == expected_response_files

        project_config = REPOSITORY_ROOT / bundle["project"]["path"]
        sarif = REPOSITORY_ROOT / bundle["sarif"]["path"]
        profile_path = REPOSITORY_ROOT / bundle["profile"]["path"]
        assert _sha256(project_config) == bundle["project"]["config_sha256"]
        assert _sha256(sarif) == bundle["sarif"]["sha256"]
        if "supplement" in bundle:
            supplement = REPOSITORY_ROOT / bundle["supplement"]["path"]
            assert _sha256(supplement) == bundle["supplement"]["sha256"]
        counts = bundle["expected_result"]["label_counts"]
        assert sum(counts.values()) == bundle["expected_result"]["alert_count"]
        profile = load_llm_profile(profile_path)
        assert profile.provider == "replay"
        assert profile.data_policy == "offline_only"
        assert profile.digest == bundle["profile"]["digest"]


@pytest.mark.integration
def test_make_demo_replays_complete_pipeline_in_an_isolated_checkout(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "evitriage-ql"\n', encoding="utf-8"
    )
    bundle = json.loads((BUNDLE_ROOT / "bundle-manifest.json").read_text(encoding="utf-8"))
    for relative_path in (
        bundle["project"]["path"],
        bundle["profile"]["path"],
        bundle["sarif"]["path"],
        bundle["supplement"]["path"],
    ):
        source = REPOSITORY_ROOT / relative_path
        destination = repository / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    source_root = repository / "tests/fixtures/java-microbench"
    shutil.copytree(
        REPOSITORY_ROOT / "tests/fixtures/java-microbench",
        source_root,
        copy_function=shutil.copy2,
    )
    shutil.copytree(BUNDLE_ROOT, repository / BUNDLE_ROOT.relative_to(REPOSITORY_ROOT))
    source_before = _source_state(source_root)

    environment = os.environ.copy()
    environment["EVITRIAGE_PROJECT_ROOT"] = str(repository)
    environment.pop("DEEPSEEK_API_KEY", None)
    make = shutil.which("make")
    assert make is not None
    completed = subprocess.run(
        [
            make,
            "--no-print-directory",
            "--file",
            str(REPOSITORY_ROOT / "Makefile"),
            "demo",
            f"EVITRIAGE_COMMAND={sys.executable} -m evitriage.cli",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert completed.returncode == 0, completed.stderr
    assert len(completed.stdout.splitlines()) == 1
    summary = TriageRunSummary.model_validate_json(completed.stdout, strict=True)
    assert summary.state == "JUDGED"
    assert summary.real_codeql is False
    assert summary.analysis_identity == bundle["analysis_identity"]
    assert summary.snapshot_identity == bundle["project"]["source_tree_sha256"]
    assert summary.alert_count == 3
    assert summary.tp_count == summary.fp_count == summary.nmc_count == 1
    assert summary.invocation_count == 9
    assert summary.tool_versions["llm-provider"] == "replay"
    assert summary.tool_versions["report-renderer"] == "1.0"

    run_root = Path(summary.artifact_run_root)
    assert run_root.is_relative_to(repository / "artifacts")
    manifest_path = run_root / "run-manifest.json"
    event_log_path = run_root / "workflow-events.jsonl"
    manifest = RunManifest.model_validate_json(manifest_path.read_bytes(), strict=True)
    assert manifest.status == "completed"
    assert manifest.state is WorkflowState.JUDGED
    registered = {record.relative_path: record for record in manifest.artifacts}
    assert {
        "input/source.sarif",
        "input/evidence-supplement.json",
        "normalized/alerts.json",
        "context/index.json",
        "context/slices/run-000000-result-000000.json",
        "context/slices/run-000000-result-000001.json",
        "context/slices/run-000000-result-000002.json",
        "evidence/registry.json",
        "triage/analyst.json",
        "triage/rebuttal.json",
        "triage/judged.json",
        "reports/decisions.jsonl",
        "reports/index.html",
    }.issubset(registered)
    for record in manifest.artifacts:
        artifact = run_root / record.relative_path
        assert artifact.is_file()
        assert not artifact.is_symlink()
        assert artifact.stat().st_size == record.size_bytes
        assert _sha256(artifact) == record.sha256
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o400
    for audit_path in (manifest_path, event_log_path):
        assert stat.S_IMODE(audit_path.stat().st_mode) == 0o400

    report_lines = (run_root / "reports/decisions.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(report_lines) == 3
    reports = tuple(AlertReport.model_validate_json(line, strict=True) for line in report_lines)
    assert [report.triage.final_decision.label for report in reports] == ["TP", "FP", "NMC"]
    assert all(report.triage.final_decision.auto_dismiss is False for report in reports)
    assert all(report.verification.status == "not_performed" for report in reports)
    assert "judge_label_accepted" in reports[0].triage.final_decision.policy_flags
    assert "fp_decisive_rebuttal_present" in reports[1].triage.final_decision.policy_flags
    assert "judge_requested_nmc" in reports[2].triage.final_decision.policy_flags
    html_report = (run_root / "reports/index.html").read_text(encoding="utf-8")
    assert "EviTriage offline triage report" in html_report
    assert "No alert was automatically dismissed" in html_report
    assert "Alerts: 3; TP: 1; FP: 1; NMC: 1." in html_report
    assert "<script" not in html_report.lower()
    assert _source_state(source_root) == source_before
