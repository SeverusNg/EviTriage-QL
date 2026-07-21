"""Immutable audit records for one EviTriage workflow run."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"),
]
ArtifactRole = Literal[
    "input",
    "normalized",
    "context",
    "evidence",
    "tool-log",
    "tool-output",
    "metadata",
]


class WorkflowState(StrEnum):
    """Gate states implemented through the shared Gate C evidence stage."""

    CREATED = "CREATED"
    PROJECT_VALIDATED = "PROJECT_VALIDATED"
    WORKSPACE_READY = "WORKSPACE_READY"
    SOURCE_READY = "SOURCE_READY"
    BUILD_READY = "BUILD_READY"
    CODEQL_DB_READY = "CODEQL_DB_READY"
    SCANNED = "SCANNED"
    SARIF_INGESTED = "SARIF_INGESTED"
    NORMALIZED = "NORMALIZED"
    CONTEXT_READY = "CONTEXT_READY"
    INVALID_SARIF = "INVALID_SARIF"
    CODEQL_FAILED = "CODEQL_FAILED"
    CONTEXT_INCOMPLETE = "CONTEXT_INCOMPLETE"


class _ImmutableModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactRecord(_ImmutableModel):
    """Content identity and run-relative location of one persisted artifact."""

    relative_path: Annotated[str, Field(min_length=1, max_length=4096)]
    sha256: Sha256
    size_bytes: Annotated[int, Field(ge=0)]
    role: ArtifactRole
    media_type: Annotated[str, Field(min_length=1, max_length=200)]

    @field_validator("relative_path")
    @classmethod
    def _relative_path_is_safe(cls, value: str) -> str:
        if "\\" in value or any(ord(character) < 32 for character in value):
            raise ValueError("artifact paths must be clean POSIX relative paths")
        candidate = PurePosixPath(value)
        if candidate.is_absolute() or candidate.as_posix() in {"", "."}:
            raise ValueError("artifact paths must be relative files")
        if ".." in candidate.parts:
            raise ValueError("artifact paths must not contain parent traversal")
        return candidate.as_posix()


class WorkflowEvent(_ImmutableModel):
    """One append-only, ordered transition in the run audit trail."""

    sequence: Annotated[int, Field(ge=0)]
    event_type: Annotated[
        str,
        Field(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_]*$"),
    ]
    from_state: WorkflowState | None
    to_state: WorkflowState
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    input_sha256: Sha256 | None = None
    output_sha256: Sha256 | None = None
    tool_manifest_sha256: Sha256 | None = None
    error_code: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    retry_count: Annotated[int, Field(ge=0)] = 0
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("workflow event timestamps must include a timezone")
        return value.astimezone(UTC)


class RunManifest(_ImmutableModel):
    """Current auditable summary reconstructed from the append-only event log."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: SafeIdentifier
    project_id: SafeIdentifier
    input_mode: Literal["sarif", "scan"]
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    state: WorkflowState
    status: Literal["running", "completed", "failed"]
    artifacts: tuple[ArtifactRecord, ...] = ()
    events: Annotated[tuple[WorkflowEvent, ...], Field(min_length=1)]
    tool_versions: dict[str, str] = Field(default_factory=dict)
    started_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None

    @field_validator("started_at", "updated_at", "completed_at")
    @classmethod
    def _timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("run timestamps must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _audit_chain_is_consistent(self) -> Self:
        first = self.events[0]
        if (
            first.sequence != 0
            or first.from_state is not None
            or first.to_state is not WorkflowState.CREATED
        ):
            raise ValueError("run event history must begin with sequence 0 at CREATED")
        previous = WorkflowState.CREATED
        for index, event in enumerate(self.events):
            if event.sequence != index:
                raise ValueError("run event sequences must be contiguous")
            if event.project_spec_sha256 != self.project_spec_sha256:
                raise ValueError("run event project specification digest does not match manifest")
            if event.snapshot_identity != self.snapshot_identity:
                raise ValueError("run event snapshot identity does not match manifest")
            if index > 0:
                if event.from_state is not previous:
                    raise ValueError("run event state chain is discontinuous")
                if not _workflow_transition_is_allowed(previous, event.to_state):
                    raise ValueError("run event contains an invalid workflow transition")
            previous = event.to_state
        if previous is not self.state:
            raise ValueError("manifest state must equal the final event state")
        if len({artifact.relative_path for artifact in self.artifacts}) != len(self.artifacts):
            raise ValueError("manifest artifact paths must be unique")
        if self.input_mode == "sarif" and any(
            event.to_state
            in {WorkflowState.BUILD_READY, WorkflowState.CODEQL_DB_READY, WorkflowState.SCANNED}
            for event in self.events
        ):
            raise ValueError("SARIF input runs cannot contain CodeQL branch states")
        if self.input_mode == "scan" and any(
            event.to_state is WorkflowState.SARIF_INGESTED for event in self.events
        ):
            raise ValueError("scan runs cannot contain the SARIF ingest branch state")
        if self.input_mode == "sarif" and self.state is WorkflowState.CODEQL_FAILED:
            raise ValueError("SARIF input runs cannot terminate in CODEQL_FAILED")
        terminal_failure = self.state in {
            WorkflowState.INVALID_SARIF,
            WorkflowState.CODEQL_FAILED,
            WorkflowState.CONTEXT_INCOMPLETE,
        }
        if self.status == "running" and self.completed_at is not None:
            raise ValueError("running manifests must not have completed_at")
        if self.status == "completed" and (
            self.state is not WorkflowState.CONTEXT_READY or self.completed_at is None
        ):
            raise ValueError("completed manifests must terminate at CONTEXT_READY")
        if self.status == "failed" and (not terminal_failure or self.completed_at is None):
            raise ValueError("failed manifests must terminate in a failure state")
        if self.status != "failed" and terminal_failure:
            raise ValueError("failure states require failed status")
        if self.updated_at < self.started_at:
            raise ValueError("manifest updated_at precedes started_at")
        if self.completed_at is not None and self.completed_at < self.started_at:
            raise ValueError("manifest completed_at precedes started_at")
        if self.updated_at < self.events[-1].occurred_at:
            raise ValueError("manifest updated_at precedes its final event")
        if any(
            not name or not version or any(ord(character) < 32 for character in name + version)
            for name, version in self.tool_versions.items()
        ):
            raise ValueError("tool versions must be non-empty printable text")
        return self


class NormalizedRunSummary(_ImmutableModel):
    """Stable CLI-facing summary of a completed SARIF input run."""

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ok"] = "ok"
    command: Literal["ingest-sarif", "normalize", "scan"]
    source_kind: Literal["ingest", "scan"]
    real_codeql: bool
    run_id: SafeIdentifier
    project_id: SafeIdentifier
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    state: Literal["NORMALIZED"] = "NORMALIZED"
    artifact_run_root: Annotated[str, Field(min_length=1, max_length=4096)]
    raw_sarif: ArtifactRecord
    normalized_bundle: ArtifactRecord
    alert_count: Annotated[int, Field(ge=0)]
    path_count: Annotated[int, Field(ge=0)]
    no_path_alert_count: Annotated[int, Field(ge=0)]
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _branch_and_counts_are_consistent(self) -> Self:
        is_scan = self.command == "scan"
        if is_scan != (self.source_kind == "scan") or is_scan != self.real_codeql:
            raise ValueError("scan provenance fields are inconsistent")
        if self.no_path_alert_count > self.alert_count:
            raise ValueError("no_path_alert_count exceeds alert_count")
        if self.raw_sarif.relative_path == self.normalized_bundle.relative_path:
            raise ValueError("raw and normalized artifacts must be distinct")
        if self.normalized_bundle.role != "normalized":
            raise ValueError("normalized bundle must have the normalized artifact role")
        expected_raw_role = "tool-output" if is_scan else "input"
        if self.raw_sarif.role != expected_raw_role:
            raise ValueError("raw SARIF artifact role does not match input provenance")
        return self


class ContextRunSummary(_ImmutableModel):
    """Stable CLI-facing summary of a completed Gate C input/context run."""

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ok"] = "ok"
    command: Literal["ingest-sarif", "normalize", "scan"]
    source_kind: Literal["ingest", "scan"]
    real_codeql: bool
    run_id: SafeIdentifier
    project_id: SafeIdentifier
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    state: Literal["CONTEXT_READY"] = "CONTEXT_READY"
    artifact_run_root: Annotated[str, Field(min_length=1, max_length=4096)]
    raw_sarif: ArtifactRecord
    normalized_bundle: ArtifactRecord
    slice_artifacts: tuple[ArtifactRecord, ...]
    context_index: ArtifactRecord
    evidence_registry: ArtifactRecord
    evidence_graph: ArtifactRecord
    source_map: ArtifactRecord
    alert_count: Annotated[int, Field(ge=0)]
    path_count: Annotated[int, Field(ge=0)]
    no_path_alert_count: Annotated[int, Field(ge=0)]
    complete_context_count: Annotated[int, Field(ge=0)]
    partial_context_count: Annotated[int, Field(ge=0)]
    evidence_count: Annotated[int, Field(ge=0)]
    claim_count: Annotated[int, Field(ge=0)] = 0
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_gate_c_outputs(self) -> Self:
        is_scan = self.command == "scan"
        if is_scan != (self.source_kind == "scan") or is_scan != self.real_codeql:
            raise ValueError("scan provenance fields are inconsistent")
        if self.no_path_alert_count > self.alert_count:
            raise ValueError("no_path_alert_count exceeds alert_count")
        if self.complete_context_count + self.partial_context_count != self.alert_count:
            raise ValueError("context completeness counts must equal alert_count")
        if len(self.slice_artifacts) != self.alert_count:
            raise ValueError("every alert occurrence must have one slice artifact")
        expected_roles = {
            self.normalized_bundle.relative_path: "normalized",
            self.context_index.relative_path: "context",
            self.evidence_registry.relative_path: "evidence",
            self.evidence_graph.relative_path: "evidence",
            self.source_map.relative_path: "context",
        }
        expected_roles.update(
            {artifact.relative_path: "context" for artifact in self.slice_artifacts}
        )
        records = (
            self.normalized_bundle,
            self.context_index,
            self.evidence_registry,
            self.evidence_graph,
            self.source_map,
            *self.slice_artifacts,
        )
        if any(record.role != expected_roles[record.relative_path] for record in records):
            raise ValueError("Gate C artifact roles are inconsistent")
        expected_raw_role = "tool-output" if is_scan else "input"
        if self.raw_sarif.role != expected_raw_role:
            raise ValueError("raw SARIF artifact role does not match input provenance")
        return self


def _workflow_transition_is_allowed(previous: WorkflowState, following: WorkflowState) -> bool:
    if following in {
        WorkflowState.INVALID_SARIF,
        WorkflowState.CODEQL_FAILED,
        WorkflowState.CONTEXT_INCOMPLETE,
    }:
        return previous not in {
            WorkflowState.INVALID_SARIF,
            WorkflowState.CODEQL_FAILED,
            WorkflowState.CONTEXT_INCOMPLETE,
        }
    allowed: dict[WorkflowState, frozenset[WorkflowState]] = {
        WorkflowState.CREATED: frozenset({WorkflowState.PROJECT_VALIDATED}),
        WorkflowState.PROJECT_VALIDATED: frozenset({WorkflowState.WORKSPACE_READY}),
        WorkflowState.WORKSPACE_READY: frozenset({WorkflowState.SOURCE_READY}),
        WorkflowState.SOURCE_READY: frozenset(
            {WorkflowState.BUILD_READY, WorkflowState.SARIF_INGESTED}
        ),
        WorkflowState.BUILD_READY: frozenset({WorkflowState.CODEQL_DB_READY}),
        WorkflowState.CODEQL_DB_READY: frozenset({WorkflowState.SCANNED}),
        WorkflowState.SCANNED: frozenset({WorkflowState.NORMALIZED}),
        WorkflowState.SARIF_INGESTED: frozenset({WorkflowState.NORMALIZED}),
        WorkflowState.NORMALIZED: frozenset({WorkflowState.CONTEXT_READY}),
        WorkflowState.CONTEXT_READY: frozenset(),
        WorkflowState.INVALID_SARIF: frozenset(),
        WorkflowState.CODEQL_FAILED: frozenset(),
        WorkflowState.CONTEXT_INCOMPLETE: frozenset(),
    }
    return following in allowed[previous]


__all__ = [
    "ArtifactRecord",
    "ArtifactRole",
    "ContextRunSummary",
    "NormalizedRunSummary",
    "RunManifest",
    "WorkflowEvent",
    "WorkflowState",
]
