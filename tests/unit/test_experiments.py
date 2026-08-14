from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest
from pydantic import BaseModel

from evitriage.domain.experiment import (
    ExistingSarifExperimentManifest,
    resolve_manifest_path,
)
from evitriage.errors import ModelError, PathSafetyError, PolicyRejectedError
from evitriage.experiments import preflight_existing_sarif_experiment, run_existing_sarif_experiment
from evitriage.llm import InvocationContext


def _git_source(root: Path) -> str:
    git = shutil.which("git")
    assert git is not None
    root.mkdir()
    subprocess.run((git, "init", "-q"), cwd=root, check=True)
    subprocess.run((git, "config", "user.email", "fixture@example.invalid"), cwd=root, check=True)
    subprocess.run((git, "config", "user.name", "Fixture"), cwd=root, check=True)
    (root / "Resource.java").write_text("class Resource {}\n", encoding="utf-8")
    subprocess.run((git, "add", "Resource.java"), cwd=root, check=True)
    subprocess.run((git, "commit", "-q", "-m", "fixture"), cwd=root, check=True)
    return subprocess.run(
        (git, "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _manifest(tmp_path: Path, *, sha: str) -> ExistingSarifExperimentManifest:
    source = tmp_path / "source"
    commit = _git_source(source)
    project = tmp_path / "project.yaml"
    project.write_text(
        f"""schema_version: "1.0"
project:
  id: experiment-test
  display_name: Experiment Test
  language: java
source:
  type: local
  path: {source}
  snapshot_mode: copy
  require_clean_git: true
  submodules: false
build:
  adapter: maven
  jdk: "17"
  command: ["./mvnw", "--offline", "package"]
  network_policy: disabled
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: [security-and-quality]
  query_packs: []
  model_packs: []
  include_query_help: true
analysis:
  target_cwes: [CWE-404]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
security:
  source_upload_policy: offline_only
  allow_build_network: false
  allow_submodules: false
  allow_generated_shell: false
storage:
  workspace_root: {tmp_path / "workspaces"}
  artifact_root: {tmp_path / "artifacts/runs"}
""",
        encoding="utf-8",
    )
    sarif = tmp_path / "zero.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "columnKind": "unicodeCodePoints",
                        "tool": {"driver": {"name": "CodeQL", "rules": []}},
                        "results": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    value = {
        "schema_version": "1.0",
        "experiment_id": "zero-result-test",
        "llm_profile": "configs/llm/replay-v0.1.yaml",
        "artifact_root": str(tmp_path / "artifacts"),
        "run_artifact_root": str(tmp_path / "artifacts/runs"),
        "workspace_root": str(tmp_path / "workspaces"),
        "cases": (
            {
                "id": "zero-database",
                "source_root": str(source),
                "source_commit": commit,
                "sarif_path": str(sarif),
                "sarif_sha256": sha,
                "expected_query_family": "resource_database",
                "expected_result_count": 0,
                "mode": "triage",
                "project_spec": str(project),
            },
        ),
    }
    return ExistingSarifExperimentManifest.model_validate(value, strict=True)


def test_zero_result_preflight_and_dry_run_do_not_create_model_adapter(tmp_path: Path) -> None:
    # _manifest creates the same canonical compact JSON after the hash argument,
    # so first build once with a placeholder and then bind the observed bytes.
    placeholder = "0" * 64
    draft = _manifest(tmp_path, sha=placeholder)
    observed = hashlib.sha256(Path(draft.cases[0].sarif_path).read_bytes()).hexdigest()
    manifest = draft.model_copy(
        update={"cases": (draft.cases[0].model_copy(update={"sarif_sha256": observed}),)}
    )

    preflight = preflight_existing_sarif_experiment(Path.cwd(), manifest)
    result = run_existing_sarif_experiment(Path.cwd(), manifest, llm=None, dry_run=True)

    assert preflight.triage_alert_count == 0
    assert result.status == "dry_run"
    assert result.cases[0].alert_count == 0


def test_zero_result_triage_completes_without_a_model_call(tmp_path: Path) -> None:
    draft = _manifest(tmp_path, sha="0" * 64)
    observed = hashlib.sha256(Path(draft.cases[0].sarif_path).read_bytes()).hexdigest()
    manifest = draft.model_copy(
        update={"cases": (draft.cases[0].model_copy(update={"sarif_sha256": observed}),)}
    )

    result = run_existing_sarif_experiment(Path.cwd(), manifest, llm=_FailingLLM(), dry_run=False)

    assert result.status == "completed"
    assert result.decided_alert_count == 0
    assert result.invocation_count == 0
    assert result.cases[0].status == "completed"
    assert result.cases[0].run_id is not None
    assert result.cases[0].decisions_sha256 == hashlib.sha256(b"").hexdigest()


def test_preflight_rejects_sha_before_any_model_call(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, sha="f" * 64)
    with pytest.raises(PolicyRejectedError, match="SHA-256"):
        preflight_existing_sarif_experiment(Path.cwd(), manifest)


def test_manifest_relative_path_rejects_parent_traversal(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError, match="traverse"):
        resolve_manifest_path(tmp_path, "../outside.sarif")


def test_preflight_rejects_output_root_overlapping_source(tmp_path: Path) -> None:
    draft = _manifest(tmp_path, sha="0" * 64)
    observed = hashlib.sha256(Path(draft.cases[0].sarif_path).read_bytes()).hexdigest()
    source = Path(draft.cases[0].source_root)
    project = Path(draft.cases[0].project_spec)
    content = project.read_text(encoding="utf-8")
    content = content.replace(
        f"workspace_root: {tmp_path / 'workspaces'}",
        f"workspace_root: {source / 'workspaces'}",
    ).replace(
        f"artifact_root: {tmp_path / 'artifacts/runs'}",
        f"artifact_root: {source / 'artifacts/runs'}",
    )
    project.write_text(content, encoding="utf-8")
    manifest = draft.model_copy(
        update={
            "artifact_root": str(source / "artifacts"),
            "run_artifact_root": str(source / "artifacts/runs"),
            "workspace_root": str(source / "workspaces"),
            "cases": (draft.cases[0].model_copy(update={"sarif_sha256": observed}),),
        }
    )

    with pytest.raises(PathSafetyError, match="source root"):
        preflight_existing_sarif_experiment(Path.cwd(), manifest)


def test_preflight_rejects_symlinked_output_root(tmp_path: Path) -> None:
    draft = _manifest(tmp_path, sha="0" * 64)
    observed = hashlib.sha256(Path(draft.cases[0].sarif_path).read_bytes()).hexdigest()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked-artifacts"
    link.symlink_to(outside, target_is_directory=True)
    project = Path(draft.cases[0].project_spec)
    content = project.read_text(encoding="utf-8").replace(
        f"artifact_root: {tmp_path / 'artifacts/runs'}",
        f"artifact_root: {link / 'runs'}",
    )
    project.write_text(content, encoding="utf-8")
    manifest = draft.model_copy(
        update={
            "artifact_root": str(link),
            "run_artifact_root": str(link / "runs"),
            "cases": (draft.cases[0].model_copy(update={"sarif_sha256": observed}),),
        }
    )

    with pytest.raises(PathSafetyError, match=r"symbolic[- ]link"):
        preflight_existing_sarif_experiment(Path.cwd(), manifest)


class _FailingLLM:
    def complete[ResponseT: BaseModel](
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[ResponseT],
        invocation_context: InvocationContext,
    ) -> ResponseT:
        del system_prompt, user_payload, response_model, invocation_context
        raise ModelError("synthetic network failure")


def test_model_failure_marks_batch_incomplete_and_never_fabricates_nmc(tmp_path: Path) -> None:
    draft = _manifest(tmp_path, sha="0" * 64)
    sarif = Path(draft.cases[0].sarif_path)
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "columnKind": "unicodeCodePoints",
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [{"id": "java/database-resource-leak"}],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "java/database-resource-leak",
                                "message": {"text": "Resource may leak"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "Resource.java"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    observed = hashlib.sha256(sarif.read_bytes()).hexdigest()
    case = draft.cases[0].model_copy(update={"sarif_sha256": observed, "expected_result_count": 1})
    manifest = draft.model_copy(update={"cases": (case,)})

    summary = run_existing_sarif_experiment(Path.cwd(), manifest, llm=_FailingLLM(), dry_run=False)

    assert summary.status == "incomplete"
    assert summary.decided_alert_count == 0
    assert summary.cases[0].status == "failed"
    assert summary.cases[0].nmc_count == 0
    assert summary.cases[0].error_code == "MODEL_FAILED"
