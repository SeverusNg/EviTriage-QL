from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evitriage.cli import app
from evitriage.codeql import CodeQLVersionMismatchError
from evitriage.errors import FeatureNotAvailableError
from evitriage.pipeline import run_codeql_scan, run_sarif_ingest
from evitriage.sarif import InvalidSarifError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sarif"
runner = CliRunner()


def _gate_b_repository(tmp_path: Path) -> tuple[Path, Path, bytes]:
    repository = tmp_path / "repository"
    source = repository / "fixture"
    config = repository / "configs" / "projects" / "fixture.yaml"
    source_file = source / "src/main/java/org/evitriage/fixture/PathReader.java"
    source_file.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "evitriage-ql"\n', encoding="utf-8"
    )
    source_bytes = (
        Path(__file__).parents[1]
        / "fixtures/java-microbench/path-app/src/main/java/org/evitriage/fixture/PathReader.java"
    ).read_bytes()
    source_file.write_bytes(source_bytes)
    wrapper = source / "mvnw"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o700)
    wrapper_properties = source / ".mvn" / "wrapper" / "maven-wrapper.properties"
    wrapper_properties.parent.mkdir(parents=True)
    wrapper_properties.write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/"
        "apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n"
        "distributionSha256Sum="
        "4ec3f26fb1a692473aea0235c300bd20f0f9fe741947c82c1234cefd76ac3a3c\n",
        encoding="utf-8",
    )
    config.write_text(
        """\
schema_version: "1.0"
project:
  id: gate-b-fixture
  display_name: Gate B Fixture
  language: java
  license_hint: Apache-2.0
source:
  type: local
  path: fixture
  snapshot_mode: copy
  require_clean_git: false
  submodules: false
build:
  adapter: maven
  jdk: "17"
  working_directory: "."
  command: ["./mvnw", "--offline", "-q", "package"]
  timeout_seconds: 60
  network_policy: disabled
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: [security-extended]
  query_packs: []
  model_packs: []
  include_query_help: true
analysis:
  target_cwes: [CWE-22]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
security:
  source_upload_policy: offline_only
  allow_build_network: false
  allow_submodules: false
  allow_generated_shell: false
storage:
  workspace_root: workspaces
  artifact_root: artifacts
""",
        encoding="utf-8",
    )
    return repository, config, source_bytes


@pytest.mark.integration
def test_ingest_and_normalize_cli_share_one_auditable_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, source_bytes = _gate_b_repository(tmp_path)
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository))
    sarif = FIXTURES / "single-path.sarif"

    ingested = runner.invoke(
        app,
        [
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(sarif),
            "--json",
        ],
    )
    normalized = runner.invoke(
        app,
        [
            "normalize",
            "--project-config",
            str(config),
            "--sarif",
            str(sarif),
            "--json",
        ],
    )

    assert ingested.exit_code == 0, ingested.output
    assert normalized.exit_code == 0, normalized.output
    first = json.loads(ingested.stdout)
    second = json.loads(normalized.stdout)
    assert first["status"] == second["status"] == "ok"
    assert first["command"] == "ingest-sarif"
    assert second["command"] == "normalize"
    assert first["real_codeql"] is second["real_codeql"] is False
    assert first["alert_count"] == second["alert_count"] == 1
    assert first["path_count"] == second["path_count"] == 1
    assert first["state"] == second["state"] == "CONTEXT_READY"
    assert first["complete_context_count"] == second["complete_context_count"] == 1
    assert first["partial_context_count"] == second["partial_context_count"] == 0
    assert first["evidence_count"] >= 3
    assert first["claim_count"] == 0
    assert first["run_id"] != second["run_id"]

    first_root = Path(first["artifact_run_root"])
    copied_raw = first_root / first["raw_sarif"]["relative_path"]
    assert copied_raw.read_bytes() == sarif.read_bytes()
    assert first["raw_sarif"]["sha256"] == hashlib.sha256(sarif.read_bytes()).hexdigest()
    first_alert = json.loads(
        (first_root / first["normalized_bundle"]["relative_path"]).read_text(encoding="utf-8")
    )["alerts"][0]
    second_alert = json.loads(
        (
            Path(second["artifact_run_root"]) / second["normalized_bundle"]["relative_path"]
        ).read_text(encoding="utf-8")
    )["alerts"][0]
    assert first_alert["alert_fingerprint"] == second_alert["alert_fingerprint"]
    assert (
        repository / "fixture/src/main/java/org/evitriage/fixture/PathReader.java"
    ).read_bytes() == source_bytes

    manifest = json.loads((first_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["state"] == "CONTEXT_READY"
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "SARIF_INGESTED",
        "NORMALIZED",
        "CONTEXT_READY",
    ]
    registered = {artifact["relative_path"]: artifact for artifact in manifest["artifacts"]}
    assert {
        "context/index.json",
        "context/slices/run-000000-result-000000.json",
        "context/source-map.html",
        "evidence/graph.dot",
        "evidence/registry.json",
    }.issubset(registered)
    evidence = json.loads((first_root / "evidence/registry.json").read_text(encoding="utf-8"))
    assert evidence["claims"] == []
    assert {item["origin"] for item in evidence["items"]} == {"codeql", "repository"}
    assert all(
        item["artifact_sha256"]
        in {artifact["artifact_sha256"] for artifact in evidence["artifacts"]}
        for item in evidence["items"]
    )


@pytest.mark.integration
def test_invalid_sarif_and_missing_codeql_are_structured_failed_runs(tmp_path: Path) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    environment = os.environ.copy()
    environment["EVITRIAGE_PROJECT_ROOT"] = str(repository)
    environment["PATH"] = "/usr/bin:/bin"

    invalid = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(FIXTURES / "malicious-uri.sarif"),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert invalid.returncode == 3
    invalid_error = json.loads(invalid.stderr)["error"]
    assert invalid_error["code"] == "UNSAFE_SARIF_URI"
    invalid_manifest = json.loads(
        (Path(invalid_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert invalid_manifest["status"] == "failed"
    assert invalid_manifest["state"] == "INVALID_SARIF"
    invalid_artifacts = {artifact["relative_path"] for artifact in invalid_manifest["artifacts"]}
    assert "metadata/error.json" in invalid_artifacts
    assert invalid_manifest["events"][-1]["output_sha256"] is not None

    malformed_document = json.loads((FIXTURES / "single-path.sarif").read_text(encoding="utf-8"))
    malformed_document["runs"][0]["artifacts"][0]["location"]["uri"] = "src/%FF.java"
    malformed_sarif = repository / "malformed-uri.sarif"
    malformed_sarif.write_text(json.dumps(malformed_document), encoding="utf-8")
    malformed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(malformed_sarif),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert malformed.returncode == 3
    malformed_error = json.loads(malformed.stderr)["error"]
    assert malformed_error["code"] == "UNSAFE_SARIF_URI"
    malformed_manifest = json.loads(
        (Path(malformed_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert malformed_manifest["status"] == "failed"
    assert malformed_manifest["state"] == "INVALID_SARIF"

    scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "scan",
            "--project-config",
            str(config),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert scan.returncode == 7
    scan_error = json.loads(scan.stderr)["error"]
    assert scan_error["code"] == "CODEQL_TOOL_UNAVAILABLE"
    assert scan_error["details"]["tool"] == "codeql"
    scan_manifest = json.loads(
        (Path(scan_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert scan_manifest["status"] == "failed"
    assert scan_manifest["state"] == "CODEQL_FAILED"
    scan_artifacts = {artifact["relative_path"] for artifact in scan_manifest["artifacts"]}
    assert "metadata/error.json" in scan_artifacts


@pytest.mark.integration
def test_unsupported_context_policy_records_context_incomplete(tmp_path: Path) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["analysis"]["context_policy"] = "adaptive_slice"
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(FeatureNotAvailableError, match="adaptive_slice") as raised:
        run_sarif_ingest(
            repository,
            project_config=config,
            sarif_path=FIXTURES / "single-path.sarif",
        )

    run_root = Path(str(raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["state"] == "CONTEXT_INCOMPLETE"
    assert manifest["events"][-2]["to_state"] == "NORMALIZED"
    assert manifest["events"][-1]["error_code"] == "FEATURE_NOT_AVAILABLE"
    artifacts = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert "normalized/alerts.json" in artifacts
    assert "metadata/error.json" in artifacts
    assert "evidence/registry.json" not in artifacts


@pytest.mark.integration
def test_scan_converges_on_the_same_normalizer_after_a_real_runner_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)

    def which(value: str) -> str | None:
        return {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value)

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["shell"] is False
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="",
                stderr='openjdk version "17.0.10"\n',
            )
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
        if arguments[1:3] == ["database", "create"]:
            Path(arguments[3]).mkdir()
            return subprocess.CompletedProcess(arguments, 0, stdout="created\n", stderr="")
        if arguments[1:3] == ["database", "analyze"]:
            output = next(item for item in arguments if item.startswith("--output="))
            Path(output.removeprefix("--output=")).write_bytes(
                (FIXTURES / "single-path.sarif").read_bytes()
            )
            return subprocess.CompletedProcess(arguments, 0, stdout="analyzed\n", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr("evitriage.codeql.runner.shutil.which", which)
    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", fake_run)

    summary = run_codeql_scan(repository, project_config=config)

    assert summary.status == "ok"
    assert summary.command == "scan"
    assert summary.source_kind == "scan"
    assert summary.real_codeql is True
    assert summary.alert_count == 1
    assert summary.path_count == 1
    assert summary.tool_versions["codeql"] == "2.26.1"
    assert summary.tool_versions["maven-distribution-pin"] == "3.9.9"
    root = Path(summary.artifact_run_root)
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "BUILD_READY",
        "CODEQL_DB_READY",
        "SCANNED",
        "NORMALIZED",
        "CONTEXT_READY",
    ]
    artifact_paths = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert {
        "codeql/results.sarif",
        "codeql/run.json",
        "codeql/database-create.command.json",
        "normalized/alerts.json",
    } <= artifact_paths


@pytest.mark.integration
def test_failed_runner_indexes_partial_logs_and_structured_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    monkeypatch.setattr(
        "evitriage.codeql.runner.shutil.which",
        lambda value: {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value),
    )
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(
            arguments, 0, stdout="2.25.0\n", stderr=""
        ),
    )

    with pytest.raises(CodeQLVersionMismatchError) as raised:
        run_codeql_scan(repository, project_config=config)

    root = Path(str(raised.value.details["artifact_run_root"]))
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    artifact_paths = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert {
        "codeql/codeql-version.stdout.log",
        "codeql/codeql-version.stderr.log",
        "codeql/codeql-version.command.json",
        "metadata/error.json",
    } <= artifact_paths
    assert manifest["state"] == "CODEQL_FAILED"
    assert manifest["events"][-1]["output_sha256"] is not None
    assert all(
        (root / relative_path).stat().st_mode & 0o222 == 0 for relative_path in artifact_paths
    )

    invalid_repository, invalid_config, _ = _gate_b_repository(tmp_path / "invalid-output")

    def invalid_output(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(
                arguments, 0, stdout="", stderr='openjdk version "17.0.10"\n'
            )
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
        if arguments[1:3] == ["database", "create"]:
            Path(arguments[3]).mkdir()
            return subprocess.CompletedProcess(arguments, 0, stdout="created\n", stderr="")
        output = next(item for item in arguments if item.startswith("--output="))
        Path(output.removeprefix("--output=")).write_text(
            '{"version":"2.0.0","runs":[]}\n', encoding="utf-8"
        )
        return subprocess.CompletedProcess(arguments, 0, stdout="analyzed\n", stderr="")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", invalid_output)
    with pytest.raises(InvalidSarifError) as invalid:
        run_codeql_scan(invalid_repository, project_config=invalid_config)

    invalid_root = Path(str(invalid.value.details["artifact_run_root"]))
    invalid_manifest = json.loads((invalid_root / "run-manifest.json").read_text(encoding="utf-8"))
    invalid_artifacts = {artifact["relative_path"] for artifact in invalid_manifest["artifacts"]}
    assert "codeql/results.sarif" in invalid_artifacts
    assert (invalid_root / "codeql/results.sarif").stat().st_mode & 0o222 == 0
