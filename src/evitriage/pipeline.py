"""Gate B input pipelines that converge on one SARIF normalizer."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from evitriage.codeql import CodeQLRunner, CodeQLRunResult
from evitriage.domain.alerts import AlertBundle
from evitriage.domain.project import ResolvedProjectSpec
from evitriage.domain.run import (
    ArtifactRecord,
    NormalizedRunSummary,
    WorkflowState,
)
from evitriage.domain.workspace import WorkspaceAllocation
from evitriage.errors import EviTriageError, FeatureNotAvailableError
from evitriage.observability import redact
from evitriage.projects.registry import ProjectRegistry
from evitriage.run_artifacts import RunJournal
from evitriage.sarif import InvalidSarifError, SarifNormalizer, parse_sarif_bytes
from evitriage.workspace import WorkspaceManager

_NORMALIZER_VERSION = "1.0"
_SARIF_MEDIA_TYPE = "application/sarif+json"
_JSON_MEDIA_TYPE = "application/json"


@dataclass(frozen=True, slots=True)
class _PreparedRun:
    resolved: ResolvedProjectSpec
    allocation: WorkspaceAllocation
    journal: RunJournal


def run_sarif_ingest(
    repository_root: Path,
    *,
    project_config: Path,
    sarif_path: Path,
    allowed_source_roots: tuple[Path, ...] | None = None,
    command: Literal["ingest-sarif", "normalize"] = "ingest-sarif",
) -> NormalizedRunSummary:
    """Copy, hash, validate, and normalize an operator-supplied SARIF file."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="sarif",
    )
    try:
        raw_record, raw = prepared.journal.ingest_file(
            sarif_path,
            "input/source.sarif",
            role="input",
            media_type=_SARIF_MEDIA_TYPE,
            maximum_bytes=128 * 1024 * 1024,
        )
        prepared.journal.transition(
            WorkflowState.SARIF_INGESTED,
            event_type="sarif_ingested",
            input_sha256=raw_record.sha256,
            output_sha256=raw_record.sha256,
        )
        return _normalize_and_complete(
            prepared,
            raw=raw,
            raw_record=raw_record,
            command=command,
            source_kind="ingest",
            real_codeql=False,
        )
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.INVALID_SARIF, error)
        raise


def run_codeql_scan(
    repository_root: Path,
    *,
    project_config: Path,
    allowed_source_roots: tuple[Path, ...] | None = None,
    runner: CodeQLRunner | None = None,
) -> NormalizedRunSummary:
    """Execute a real CodeQL scan, then use the same normalizer as ingest."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="scan",
    )
    prepared.journal.transition(WorkflowState.BUILD_READY, event_type="build_plan_ready")
    selected_runner = runner or CodeQLRunner()
    try:
        scan_result = selected_runner.scan(
            codeql=prepared.resolved.spec.codeql,
            build=prepared.resolved.spec.build,
            workspace=prepared.allocation.workspace,
        )
        prepared.journal.add_tool_versions(
            {
                "codeql": scan_result.codeql_version,
                "java": scan_result.java_version,
                "javac": scan_result.javac_version,
                "maven-distribution-pin": scan_result.maven_distribution_version,
                "maven-distribution-sha256": scan_result.maven_distribution_sha256,
                "sarif-normalizer": _NORMALIZER_VERSION,
            }
        )
        run_metadata = _record_codeql_artifacts(prepared, scan_result)
        raw_relative = scan_result.sarif_path.relative_to(
            prepared.allocation.workspace.artifact_run_root
        ).as_posix()
        raw_record, raw = prepared.journal.record_existing_artifact(
            raw_relative,
            role="tool-output",
            media_type=_SARIF_MEDIA_TYPE,
            maximum_bytes=128 * 1024 * 1024,
        )
        if raw_record.sha256 != scan_result.sarif_sha256:
            raise InvalidSarifError("CodeQL SARIF changed after the runner validated it")
        prepared.journal.transition(
            WorkflowState.CODEQL_DB_READY,
            event_type="codeql_database_ready",
            tool_manifest_sha256=run_metadata.sha256,
        )
        prepared.journal.transition(
            WorkflowState.SCANNED,
            event_type="codeql_scan_completed",
            output_sha256=raw_record.sha256,
            tool_manifest_sha256=run_metadata.sha256,
        )
    except EviTriageError as error:
        _record_partial_codeql_artifacts(prepared, error)
        _fail_run(prepared, WorkflowState.CODEQL_FAILED, error)
        raise

    try:
        return _normalize_and_complete(
            prepared,
            raw=raw,
            raw_record=raw_record,
            command="scan",
            source_kind="scan",
            real_codeql=True,
        )
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.INVALID_SARIF, error)
        raise


def _prepare_run(
    repository_root: Path,
    *,
    project_config: Path,
    allowed_source_roots: tuple[Path, ...] | None,
    input_mode: Literal["sarif", "scan"],
) -> _PreparedRun:
    registry = ProjectRegistry(
        repository_root,
        allowed_source_roots=allowed_source_roots,
    )
    resolved = registry.validate_path(project_config)
    source_path = resolved.source_path
    if source_path is None:
        raise FeatureNotAvailableError(
            "Gate B executes only local ProjectSpec sources",
            details={"project_id": resolved.project_id},
        )
    manager = WorkspaceManager(resolved.workspace_root, resolved.artifact_root)
    allocation = manager.prepare(
        source_path,
        resolved.project_id,
        resolved.canonical_json,
    )
    journal = RunJournal(allocation, input_mode=input_mode)
    journal.transition(
        WorkflowState.PROJECT_VALIDATED,
        event_type="project_validated",
        input_sha256=resolved.digest,
        output_sha256=resolved.digest,
    )
    journal.transition(WorkflowState.WORKSPACE_READY, event_type="workspace_ready")
    journal.transition(
        WorkflowState.SOURCE_READY,
        event_type="source_ready",
        output_sha256=allocation.snapshot.source_tree_sha256,
    )
    return _PreparedRun(resolved=resolved, allocation=allocation, journal=journal)


def _normalize_and_complete(
    prepared: _PreparedRun,
    *,
    raw: bytes,
    raw_record: ArtifactRecord,
    command: Literal["ingest-sarif", "normalize", "scan"],
    source_kind: Literal["ingest", "scan"],
    real_codeql: bool,
) -> NormalizedRunSummary:
    document = parse_sarif_bytes(raw)
    bundle = SarifNormalizer(prepared.allocation.workspace.source_snapshot).normalize(
        document,
        run_id=prepared.allocation.workspace.run_id,
        repository_identity=prepared.allocation.snapshot.source_tree_sha256,
        commit_sha=prepared.allocation.snapshot.full_commit,
        raw_sarif_sha256=raw_record.sha256,
    )
    normalized = _serialize_bundle(bundle)
    normalized_record = prepared.journal.write_artifact(
        "normalized/alerts.json",
        normalized,
        role="normalized",
        media_type=_JSON_MEDIA_TYPE,
    )
    prepared.journal.add_tool_versions({"sarif-normalizer": _NORMALIZER_VERSION})
    prepared.journal.transition(
        WorkflowState.NORMALIZED,
        event_type="sarif_normalized",
        input_sha256=raw_record.sha256,
        output_sha256=normalized_record.sha256,
    )
    manifest = prepared.journal.complete()
    return NormalizedRunSummary(
        command=command,
        source_kind=source_kind,
        real_codeql=real_codeql,
        run_id=manifest.run_id,
        project_id=manifest.project_id,
        project_spec_sha256=manifest.project_spec_sha256,
        snapshot_identity=manifest.snapshot_identity,
        artifact_run_root=str(prepared.allocation.workspace.artifact_run_root),
        raw_sarif=raw_record,
        normalized_bundle=normalized_record,
        alert_count=len(bundle.alerts),
        path_count=sum(len(alert.paths) for alert in bundle.alerts),
        no_path_alert_count=sum(not alert.has_code_flows for alert in bundle.alerts),
        tool_versions=manifest.tool_versions,
    )


def _serialize_bundle(bundle: AlertBundle) -> bytes:
    return (
        json.dumps(
            bundle.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _record_codeql_artifacts(
    prepared: _PreparedRun, scan_result: CodeQLRunResult
) -> ArtifactRecord:
    run_root = prepared.allocation.workspace.artifact_run_root
    for command in scan_result.commands:
        for path in (command.stdout_path, command.stderr_path):
            prepared.journal.record_existing_artifact(
                path.relative_to(run_root).as_posix(),
                role="tool-log",
                media_type="text/plain",
            )
        command_metadata = command.stdout_path.parent / f"{command.name}.command.json"
        prepared.journal.record_existing_artifact(
            command_metadata.relative_to(run_root).as_posix(),
            role="metadata",
            media_type=_JSON_MEDIA_TYPE,
        )
    metadata_path = scan_result.sarif_path.parent / "run.json"
    metadata, _ = prepared.journal.record_existing_artifact(
        metadata_path.relative_to(run_root).as_posix(),
        role="metadata",
        media_type=_JSON_MEDIA_TYPE,
    )
    return metadata


def _fail_run(
    prepared: _PreparedRun,
    state: WorkflowState,
    error: EviTriageError,
) -> None:
    error.details.setdefault("run_id", prepared.allocation.workspace.run_id)
    error.details.setdefault(
        "artifact_run_root", str(prepared.allocation.workspace.artifact_run_root)
    )
    error_artifact_sha256: str | None = None
    try:
        serialized_error = (
            json.dumps(
                redact(error.as_dict()),
                allow_nan=False,
                default=str,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        error_record = prepared.journal.write_artifact(
            "metadata/error.json",
            serialized_error,
            role="metadata",
            media_type=_JSON_MEDIA_TYPE,
        )
        error_artifact_sha256 = error_record.sha256
    except EviTriageError as journal_error:
        error.details.setdefault("journal_error", journal_error.code)
    try:
        prepared.journal.fail(
            state,
            error_code=error.code,
            error_artifact_sha256=error_artifact_sha256,
        )
    except EviTriageError as journal_error:
        error.details.setdefault("journal_error", journal_error.code)


def _record_partial_codeql_artifacts(prepared: _PreparedRun, error: EviTriageError) -> None:
    directory = prepared.allocation.workspace.artifact_run_root / "codeql"
    if not directory.is_dir() or directory.is_symlink():
        return
    existing = {artifact.relative_path for artifact in prepared.journal.manifest.artifacts}
    allowed_names = {
        f"{command}.{suffix}"
        for command in (
            "codeql-version",
            "java-version",
            "javac-version",
            "database-create",
            "database-analyze",
        )
        for suffix in ("stdout.log", "stderr.log", "command.json")
    }
    allowed_names.add("results.sarif")
    try:
        paths = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        error.details.setdefault("partial_artifact_error", "CODEQL_ARTIFACT_LIST_FAILED")
        return
    for path in paths:
        relative = path.relative_to(prepared.allocation.workspace.artifact_run_root).as_posix()
        if path.name not in allowed_names or relative in existing:
            continue
        is_sarif = path.name == "results.sarif"
        media_type = (
            _SARIF_MEDIA_TYPE
            if is_sarif
            else (_JSON_MEDIA_TYPE if path.suffix == ".json" else "text/plain")
        )
        try:
            prepared.journal.record_existing_artifact(
                relative,
                role=(
                    "tool-output"
                    if is_sarif
                    else ("metadata" if path.suffix == ".json" else "tool-log")
                ),
                media_type=media_type,
                maximum_bytes=128 * 1024 * 1024 if is_sarif else 64 * 1024 * 1024,
            )
        except EviTriageError as capture_error:
            error.details.setdefault("partial_artifact_error", capture_error.code)


__all__ = ["run_codeql_scan", "run_sarif_ingest"]
