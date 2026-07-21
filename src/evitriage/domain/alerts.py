"""Strict, immutable normalized alert contracts.

These models contain no filesystem or SARIF parsing logic.  Every path is a
source-root-relative POSIX path produced by the SARIF trust-boundary layer.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PositiveCoordinate = Annotated[int, Field(ge=1)]
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]


class AlertDomainModel(BaseModel):
    """Shared configuration for public normalized SARIF records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class SourceLocation(AlertDomainModel):
    """A validated source-root-relative physical location."""

    path: Annotated[str, Field(min_length=1, max_length=4096)]
    start_line: PositiveCoordinate
    start_column: PositiveCoordinate = 1
    end_line: PositiveCoordinate | None = None
    end_column: PositiveCoordinate | None = None
    artifact_sha256: Sha256 | None = None
    snippet: Annotated[str, Field(max_length=1_000_000)] | None = None

    @field_validator("path")
    @classmethod
    def validate_relative_posix_path(cls, value: str) -> str:
        if value.startswith(("/", "\\")) or "\\" in value:
            raise ValueError("source path must be a relative POSIX path")
        parts = value.split("/")
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("source path contains an unsafe component")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("source path contains control characters")
        return value

    @model_validator(mode="after")
    def validate_region_order(self) -> Self:
        if self.end_line is None and self.end_column is not None:
            raise ValueError("end_column requires end_line")
        if self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line precedes start_line")
        if (
            self.end_line == self.start_line
            and self.end_column is not None
            and self.end_column < self.start_column
        ):
            raise ValueError("end_column precedes start_column")
        return self


class RuleMetadata(AlertDomainModel):
    """Rule metadata resolved from the result and its tool driver."""

    rule_id: Annotated[str, Field(min_length=1, max_length=512)]
    name: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    description: Annotated[str, Field(max_length=100_000)] | None = None
    cwe_ids: tuple[Annotated[str, Field(pattern=r"^CWE-[1-9][0-9]*$")], ...] = ()
    severity: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    security_severity: Annotated[float, Field(ge=0, le=10)] | None = None
    query_help_uri: Annotated[str, Field(max_length=4096)] | None = None
    query_pack: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    query_pack_version: Annotated[str, Field(min_length=1, max_length=128)] | None = None
    tags: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = ()

    @model_validator(mode="after")
    def validate_pack_provenance(self) -> Self:
        if (self.query_pack is None) != (self.query_pack_version is None):
            raise ValueError("query pack name and version must be present together")
        return self


class PathStep(AlertDomainModel):
    """One ordered occurrence in a SARIF thread-flow path."""

    index: Annotated[int, Field(ge=0)]
    location: SourceLocation
    message: Annotated[str, Field(max_length=1_000_000)] | None = None
    step_kind: Literal["source", "sink", "intermediate", "unknown"]
    kinds: tuple[Annotated[str, Field(min_length=1, max_length=128)], ...] = ()
    nesting_level: Annotated[int, Field(ge=0)] | None = None
    execution_order: Annotated[int, Field(ge=0)] | None = None
    importance: Literal["important", "essential", "unimportant"] | None = None
    provenance: Literal["sarif.codeFlows"] = "sarif.codeFlows"


class DataFlowPath(AlertDomainModel):
    """One threadFlow, preserved in original occurrence order."""

    ordinal: Annotated[int, Field(ge=0)]
    steps: Annotated[tuple[PathStep, ...], Field(min_length=1)]
    path_fingerprint: Sha256
    completeness: Literal["complete", "partial"]
    unresolved_edges: tuple[Annotated[str, Field(min_length=1, max_length=1000)], ...] = ()
    message: Annotated[str, Field(max_length=1_000_000)] | None = None

    @model_validator(mode="after")
    def validate_step_indexes(self) -> Self:
        if tuple(step.index for step in self.steps) != tuple(range(len(self.steps))):
            raise ValueError("path step indexes must be contiguous and ordered")
        return self

    @property
    def source(self) -> PathStep:
        """Return the first path step."""

        return self.steps[0]

    @property
    def sink(self) -> PathStep:
        """Return the final path step."""

        return self.steps[-1]


class RawResultReference(AlertDomainModel):
    """Stable pointer into the immutable raw SARIF artifact."""

    raw_sarif_sha256: Sha256
    run_index: Annotated[int, Field(ge=0)]
    result_index: Annotated[int, Field(ge=0)]


class NormalizedAlert(AlertDomainModel):
    """Provider-neutral normalized representation of one SARIF result."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    repository_identity: Annotated[str, Field(min_length=1, max_length=4096)]
    commit_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None = None
    rule: RuleMetadata
    message: Annotated[str, Field(min_length=1, max_length=1_000_000)]
    level: Annotated[str, Field(min_length=1, max_length=64)] | None = None
    primary_location: SourceLocation
    additional_locations: tuple[SourceLocation, ...] = ()
    related_locations: tuple[SourceLocation, ...] = ()
    paths: tuple[DataFlowPath, ...] = ()
    has_code_flows: bool
    fingerprints: dict[str, str] = Field(default_factory=dict)
    partial_fingerprints: dict[str, str] = Field(default_factory=dict)
    result_properties: dict[str, JsonValue] = Field(default_factory=dict)
    alert_fingerprint: Sha256
    raw_result_reference: RawResultReference

    @model_validator(mode="after")
    def validate_path_provenance(self) -> Self:
        if self.has_code_flows != bool(self.paths):
            raise ValueError("has_code_flows must match normalized path presence")
        if tuple(path.ordinal for path in self.paths) != tuple(range(len(self.paths))):
            raise ValueError("path ordinals must be contiguous and ordered")
        return self


class AlertBundle(AlertDomainModel):
    """All normalized results from one raw SARIF artifact."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    repository_identity: Annotated[str, Field(min_length=1, max_length=4096)]
    commit_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None = None
    raw_sarif_sha256: Sha256
    alerts: tuple[NormalizedAlert, ...]

    @model_validator(mode="after")
    def validate_alert_provenance(self) -> Self:
        references: set[tuple[int, int]] = set()
        for alert in self.alerts:
            if (
                alert.run_id != self.run_id
                or alert.repository_identity != self.repository_identity
                or alert.commit_sha != self.commit_sha
                or alert.raw_result_reference.raw_sarif_sha256 != self.raw_sarif_sha256
            ):
                raise ValueError("alert provenance does not match its bundle")
            reference = (
                alert.raw_result_reference.run_index,
                alert.raw_result_reference.result_index,
            )
            if reference in references:
                raise ValueError("raw SARIF result references must be unique")
            references.add(reference)
        return self


__all__ = [
    "AlertBundle",
    "DataFlowPath",
    "JsonValue",
    "NormalizedAlert",
    "PathStep",
    "RawResultReference",
    "RuleMetadata",
    "SourceLocation",
]
