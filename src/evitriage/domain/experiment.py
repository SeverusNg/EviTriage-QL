"""Strict existing-SARIF experiment manifest and aggregate audit contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from evitriage.domain.alerts import Sha256
from evitriage.domain.resource import QueryFamily
from evitriage.errors import PathSafetyError


class _ExperimentModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ExperimentCase(_ExperimentModel):
    """One immutable existing-SARIF triage or audit-only case."""

    id: Annotated[str, Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)]
    source_root: Annotated[str, Field(min_length=1, max_length=4096)]
    source_commit: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    sarif_path: Annotated[str, Field(min_length=1, max_length=4096)]
    sarif_sha256: Sha256
    expected_query_family: QueryFamily | Literal["mixed_audit"]
    expected_result_count: Annotated[int, Field(ge=0)]
    mode: Literal["triage", "audit_only"]
    project_spec: Annotated[str, Field(min_length=1, max_length=4096)]
    baseline_id_prefix: Annotated[str, Field(pattern=r"^[A-Z]$")] | None = None

    @field_validator("source_root", "sarif_path", "project_spec")
    @classmethod
    def validate_paths(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("experiment paths must not contain control characters")
        return value

    @model_validator(mode="after")
    def validate_mode_family(self) -> Self:
        if self.mode == "triage" and self.expected_query_family == "mixed_audit":
            raise ValueError("triage cases require one exact executable query family")
        if self.mode == "audit_only" and self.expected_query_family != "mixed_audit":
            raise ValueError("audit-only cases must declare mixed_audit")
        if self.baseline_id_prefix is not None and self.mode != "triage":
            raise ValueError("baseline IDs may bind only triaged cases")
        if self.baseline_id_prefix is not None and self.expected_result_count == 0:
            raise ValueError("zero-result cases cannot bind baseline row IDs")
        return self


class HistoricalTarget(_ExperimentModel):
    """Manifest-only target used for automatic before/after comparison."""

    rule_id: Annotated[str, Field(min_length=1, max_length=512)]
    source_path: Annotated[str, Field(min_length=1, max_length=4096)]
    enclosing_symbol: Annotated[str, Field(min_length=1, max_length=512)]


class HistoricalComparisonSpec(_ExperimentModel):
    before_case_id: str
    after_case_id: str
    full_before_case_id: str
    full_after_case_id: str
    target: HistoricalTarget


class BaselineEvaluationSpec(_ExperimentModel):
    """Deferred input: the path is never opened by preflight or model execution."""

    baseline_path: Annotated[str, Field(min_length=1, max_length=4096)]

    @field_validator("baseline_path")
    @classmethod
    def validate_baseline_path(cls, value: str) -> str:
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("baseline path must not contain control characters")
        return value


class ExistingSarifExperimentManifest(_ExperimentModel):
    """Top-level preflight-closed experiment specification."""

    schema_version: Literal["1.0"] = "1.0"
    experiment_id: Annotated[str, Field(pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$", max_length=100)]
    llm_profile: Annotated[str, Field(min_length=1, max_length=4096)]
    artifact_root: Annotated[str, Field(min_length=1, max_length=4096)]
    run_artifact_root: Annotated[str, Field(min_length=1, max_length=4096)]
    workspace_root: Annotated[str, Field(min_length=1, max_length=4096)]
    historical_comparison: HistoricalComparisonSpec | None = None
    baseline_evaluation: BaselineEvaluationSpec | None = None
    cases: Annotated[
        tuple[ExperimentCase, ...],
        BeforeValidator(lambda value: tuple(value) if isinstance(value, list) else value),
        Field(min_length=1, max_length=100),
    ]

    @model_validator(mode="after")
    def validate_unique_cases(self) -> Self:
        ids = [case.id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("experiment case IDs must be unique")
        if not any(case.mode == "triage" for case in self.cases):
            raise ValueError("experiment manifest requires at least one triage case")
        prefixes = [case.baseline_id_prefix for case in self.cases if case.baseline_id_prefix]
        if len(prefixes) != len(set(prefixes)):
            raise ValueError("baseline ID prefixes must be unique")
        if self.historical_comparison is not None:
            by_id = {case.id: case for case in self.cases}
            comparison_ids = (
                self.historical_comparison.before_case_id,
                self.historical_comparison.after_case_id,
                self.historical_comparison.full_before_case_id,
                self.historical_comparison.full_after_case_id,
            )
            if any(case_id not in by_id for case_id in comparison_ids):
                raise ValueError("historical comparison references an unknown case")
            if any(by_id[case_id].mode != "triage" for case_id in comparison_ids[:2]):
                raise ValueError("historical alert cases must be triaged")
            if any(by_id[case_id].mode != "audit_only" for case_id in comparison_ids[2:]):
                raise ValueError("historical full-suite cases must be audit-only")
        if self.baseline_evaluation is not None and not prefixes:
            raise ValueError("baseline evaluation requires identity-bound triage cases")
        return self


class ExperimentPreflightCase(_ExperimentModel):
    """Resolved identities checked before any model adapter is created."""

    id: str
    source_root: str
    source_commit: str
    source_clean: Literal[True] = True
    sarif_path: str
    sarif_sha256: Sha256
    result_count: Annotated[int, Field(ge=0)]
    rule_counts: dict[str, Annotated[int, Field(ge=0)]]
    mode: Literal["triage", "audit_only"]
    project_spec: str


class ExperimentPreflight(_ExperimentModel):
    """Complete preflight result safe to persist before model authorization."""

    schema_version: Literal["1.0"] = "1.0"
    experiment_id: str
    status: Literal["ok"] = "ok"
    triage_alert_count: Annotated[int, Field(ge=0)]
    minimum_model_calls: Annotated[int, Field(ge=0)]
    maximum_model_calls: Annotated[int, Field(ge=0)]
    cases: tuple[ExperimentPreflightCase, ...]


class ExperimentCaseResult(_ExperimentModel):
    """One case outcome; model failures remain failures, never fake NMCs."""

    case_id: str
    status: Literal["completed", "failed", "audit_only", "preflight_only"]
    run_id: str | None = None
    run_artifact_root: str | None = None
    decisions_path: str | None = None
    decisions_sha256: Sha256 | None = None
    raw_sarif_sha256: Sha256
    alert_count: Annotated[int, Field(ge=0)]
    tp_count: Annotated[int, Field(ge=0)] = 0
    fp_count: Annotated[int, Field(ge=0)] = 0
    nmc_count: Annotated[int, Field(ge=0)] = 0
    invocation_count: Annotated[int, Field(ge=0)] = 0
    error_code: Annotated[str, Field(min_length=1, max_length=128)] | None = None

    skip_reason: Annotated[str, Field(min_length=1, max_length=256)] | None = None

    @model_validator(mode="after")
    def validate_skip_reason(self) -> Self:
        if self.status == "preflight_only" and self.skip_reason is None:
            raise ValueError("preflight-only cases require a skip reason")
        if self.status != "preflight_only" and self.skip_reason is not None:
            raise ValueError("skip reasons are valid only for preflight-only cases")
        return self


class ExperimentSummary(_ExperimentModel):
    """Aggregate completion status and per-case durable run identities."""

    schema_version: Literal["1.0"] = "1.0"
    experiment_id: str
    status: Literal["completed", "incomplete", "dry_run"]
    started_at: datetime
    completed_at: datetime
    baseline_evaluated: Literal[False] = False
    triage_alert_count: Annotated[int, Field(ge=0)]
    decided_alert_count: Annotated[int, Field(ge=0)]
    invocation_count: Annotated[int, Field(ge=0)]
    cases: tuple[ExperimentCaseResult, ...]

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("experiment timestamps require a timezone")
        return value.astimezone(UTC)


def resolve_manifest_path(repository_root: Path, value: str) -> Path:
    """Anchor relative operator paths to the checkout without resolving final links."""

    path = Path(value)
    if path.is_absolute():
        return path
    if ".." in path.parts:
        raise PathSafetyError("relative experiment paths must not traverse parent directories")
    return repository_root / path


__all__ = [
    "ExistingSarifExperimentManifest",
    "ExperimentCase",
    "ExperimentCaseResult",
    "ExperimentPreflight",
    "ExperimentPreflightCase",
    "ExperimentSummary",
    "resolve_manifest_path",
]
