from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

import pytest
from pydantic import ValidationError

from evitriage.domain.run import RunManifest, WorkflowState
from evitriage.domain.workspace import WorkspaceAllocation
from evitriage.errors import PathSafetyError, WorkflowError, WorkspaceConflictError
from evitriage.run_artifacts import RunJournal
from evitriage.workspace import WorkspaceManager


def _allocation(tmp_path: Path, run_id: str = "run-one") -> WorkspaceAllocation:
    source = tmp_path / "source"
    source.mkdir(exist_ok=True)
    (source / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    return manager.prepare(source, "project-one", '{"project":"one"}\n', run_id)


def test_run_journal_persists_artifacts_events_and_final_manifest(tmp_path: Path) -> None:
    allocation = _allocation(tmp_path)
    journal = RunJournal(allocation, input_mode="sarif")
    raw = b'{"version":"2.1.0","runs":[]}\n'

    journal.transition(WorkflowState.PROJECT_VALIDATED, event_type="project_validated")
    journal.transition(WorkflowState.WORKSPACE_READY, event_type="workspace_ready")
    journal.transition(WorkflowState.SOURCE_READY, event_type="source_ready")
    raw_record = journal.write_artifact(
        "input/source.sarif",
        raw,
        role="input",
        media_type="application/sarif+json",
    )
    journal.transition(
        WorkflowState.SARIF_INGESTED,
        event_type="sarif_ingested",
        input_sha256=raw_record.sha256,
        output_sha256=raw_record.sha256,
    )
    normalized_record = journal.write_artifact(
        "normalized/alerts.json",
        b'{"alerts":[]}\n',
        role="normalized",
        media_type="application/json",
    )
    journal.add_tool_versions({"sarif-normalizer": "1.0"})
    journal.transition(
        WorkflowState.NORMALIZED,
        event_type="sarif_normalized",
        input_sha256=raw_record.sha256,
        output_sha256=normalized_record.sha256,
    )
    manifest = journal.complete()

    assert manifest.status == "completed"
    assert manifest.state is WorkflowState.NORMALIZED
    assert [event.sequence for event in manifest.events] == list(range(6))
    assert [artifact.relative_path for artifact in manifest.artifacts] == [
        ".evitriage-workspace.json",
        "project-spec.resolved.yaml",
        "input/source.sarif",
        "normalized/alerts.json",
    ]
    assert raw_record.sha256 == hashlib.sha256(raw).hexdigest()
    run_root = allocation.workspace.artifact_run_root
    persisted = RunManifest.model_validate_json((run_root / "run-manifest.json").read_bytes())
    assert persisted == manifest
    event_lines = (run_root / "workflow-events.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(line)["sequence"] for line in event_lines] == list(range(6))
    assert stat.S_IMODE((run_root / "run-manifest.json").stat().st_mode) == 0o400
    assert stat.S_IMODE((run_root / "workflow-events.jsonl").stat().st_mode) == 0o400
    assert stat.S_IMODE((run_root / "input/source.sarif").stat().st_mode) == 0o400
    for artifact in manifest.artifacts:
        assert stat.S_IMODE((run_root / artifact.relative_path).stat().st_mode) == 0o400

    with pytest.raises(WorkflowError, match="finalized"):
        journal.write_artifact(
            "normalized/late.json",
            b"{}",
            role="normalized",
            media_type="application/json",
        )

    inconsistent = manifest.model_dump(mode="python")
    inconsistent["state"] = WorkflowState.CREATED
    with pytest.raises(ValidationError, match="final event state"):
        RunManifest.model_validate(inconsistent, strict=True)


def test_run_journal_rejects_invalid_transition_and_records_failure(tmp_path: Path) -> None:
    allocation = _allocation(tmp_path, "failed-run")
    journal = RunJournal(allocation, input_mode="sarif")

    with pytest.raises(WorkflowError, match="CREATED -> NORMALIZED"):
        journal.transition(WorkflowState.NORMALIZED, event_type="invalid_skip")

    error_record = journal.write_artifact(
        "metadata/error.json",
        b'{"error":"invalid"}\n',
        role="metadata",
        media_type="application/json",
    )
    manifest = journal.fail(
        WorkflowState.INVALID_SARIF,
        error_code="INVALID_SARIF",
        error_artifact_sha256=error_record.sha256,
    )
    assert manifest.status == "failed"
    assert manifest.state is WorkflowState.INVALID_SARIF
    assert manifest.events[-1].error_code == "INVALID_SARIF"
    assert manifest.events[-1].output_sha256 == error_record.sha256
    with pytest.raises(WorkflowError, match="finalized"):
        journal.fail(WorkflowState.INVALID_SARIF, error_code="INVALID_SARIF")


def test_run_artifact_paths_and_inputs_fail_closed(tmp_path: Path) -> None:
    allocation = _allocation(tmp_path, "artifact-run")
    journal = RunJournal(allocation, input_mode="sarif")

    with pytest.raises(PathSafetyError, match="unsafe artifact"):
        journal.write_artifact(
            "../escape.sarif",
            b"{}",
            role="input",
            media_type="application/sarif+json",
        )

    external = tmp_path / "external.sarif"
    external.write_bytes(b"1234")
    link = tmp_path / "linked.sarif"
    link.symlink_to(external)
    with pytest.raises(PathSafetyError, match="symbolic link"):
        journal.ingest_file(link, "input/linked.sarif")
    with pytest.raises(WorkflowError, match="maximum size"):
        journal.ingest_file(external, "input/large.sarif", maximum_bytes=3)

    record, observed = journal.ingest_file(
        external,
        "input/source.sarif",
        media_type="application/sarif+json",
    )
    assert observed == b"1234"
    assert record.size_bytes == 4

    codeql_directory = allocation.workspace.artifact_run_root / "codeql"
    codeql_directory.mkdir()
    generated = codeql_directory / "results.sarif"
    generated.write_bytes(b'{"version":"2.1.0","runs":[]}')
    generated_record, generated_bytes = journal.record_existing_artifact(
        "codeql/results.sarif",
        role="tool-output",
        media_type="application/sarif+json",
    )
    assert generated_bytes == generated.read_bytes()
    assert generated_record.sha256 == hashlib.sha256(generated_bytes).hexdigest()

    with pytest.raises(WorkspaceConflictError, match="overwrite"):
        journal.write_artifact(
            "input/source.sarif",
            b"other",
            role="input",
            media_type="application/sarif+json",
        )


def test_run_journal_refuses_existing_or_symlinked_audit_paths(tmp_path: Path) -> None:
    allocation = _allocation(tmp_path, "conflict-run")
    run_root = allocation.workspace.artifact_run_root
    (run_root / "workflow-events.jsonl").write_text("occupied\n", encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="audit file"):
        RunJournal(allocation, input_mode="scan")

    second = _allocation(tmp_path, "symlink-run")
    outside = tmp_path / "outside"
    outside.mkdir()
    (second.workspace.artifact_run_root / "normalized").symlink_to(
        outside,
        target_is_directory=True,
    )
    journal = RunJournal(second, input_mode="sarif")
    with pytest.raises(PathSafetyError, match="symlink"):
        journal.write_artifact(
            "normalized/alerts.json",
            b"{}",
            role="normalized",
            media_type="application/json",
        )


def test_run_journal_refuses_to_finalize_a_tampered_artifact(tmp_path: Path) -> None:
    allocation = _allocation(tmp_path, "tampered-run")
    journal = RunJournal(allocation, input_mode="sarif")
    journal.transition(WorkflowState.PROJECT_VALIDATED, event_type="project_validated")
    journal.transition(WorkflowState.WORKSPACE_READY, event_type="workspace_ready")
    journal.transition(WorkflowState.SOURCE_READY, event_type="source_ready")
    raw = journal.write_artifact(
        "input/source.sarif",
        b'{"version":"2.1.0","runs":[]}\n',
        role="input",
        media_type="application/sarif+json",
    )
    journal.transition(
        WorkflowState.SARIF_INGESTED,
        event_type="sarif_ingested",
        input_sha256=raw.sha256,
        output_sha256=raw.sha256,
    )
    normalized = journal.write_artifact(
        "normalized/alerts.json",
        b'{"alerts":[]}\n',
        role="normalized",
        media_type="application/json",
    )
    journal.transition(
        WorkflowState.NORMALIZED,
        event_type="sarif_normalized",
        input_sha256=raw.sha256,
        output_sha256=normalized.sha256,
    )
    (allocation.workspace.artifact_run_root / raw.relative_path).write_bytes(b"tampered")

    with pytest.raises(WorkflowError, match=r"size changed|digest changed"):
        journal.complete()
    assert journal.manifest.status == "running"
