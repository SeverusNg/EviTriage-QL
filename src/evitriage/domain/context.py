"""Strict contracts for bounded, source-addressed alert context."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evitriage.domain.alerts import (
    DataFlowPath,
    RawResultReference,
    RuleMetadata,
    Sha256,
    SourceLocation,
)

ContextPolicyName = Literal["fixed_window", "path_function_slice"]
ContextOmissionCode = Literal[
    "source_file_missing",
    "resource_context_bound",
    "source_not_regular",
    "source_too_large",
    "binary_source",
    "unsupported_encoding",
    "coordinate_out_of_bounds",
    "source_digest_mismatch",
    "function_boundary_unresolved",
    "token_budget_exceeded",
]


class ContextDomainModel(BaseModel):
    """Shared strict, immutable configuration for context records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ContextReference(ContextDomainModel):
    """Why one normalized source location selected a source slice."""

    kind: Literal["primary", "additional", "related", "source", "sink", "path_step", "callee"]
    location: SourceLocation
    path_ordinal: Annotated[int, Field(ge=0)] | None = None
    step_index: Annotated[int, Field(ge=0)] | None = None

    @model_validator(mode="after")
    def validate_path_coordinates(self) -> Self:
        if self.kind in {"primary", "additional", "related", "callee"}:
            if self.path_ordinal is not None or self.step_index is not None:
                raise ValueError("non-path context references cannot identify a path step")
        elif self.path_ordinal is None or self.step_index is None:
            raise ValueError("path context references require path_ordinal and step_index")
        return self


class SourceSlice(ContextDomainModel):
    """One bounded source excerpt selected for one or more alert locations."""

    slice_id: Annotated[str, Field(pattern=r"^slice_[0-9a-f]{64}$")]
    selection: Literal["fixed_window", "enclosing_function"]
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    start_line: Annotated[int, Field(ge=1)]
    end_line: Annotated[int, Field(ge=1)]
    artifact_sha256: Sha256
    content_sha256: Sha256
    content: Annotated[str, Field(max_length=1_000_000)]
    enclosing_symbol: Annotated[str, Field(min_length=1, max_length=512)] | None = None
    references: Annotated[tuple[ContextReference, ...], Field(min_length=1)]

    @field_validator("path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if (
            value.startswith(("/", "\\"))
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("source slice path must be a safe relative POSIX path")
        return PurePosixPath(value).as_posix()

    @model_validator(mode="after")
    def validate_content_identity(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("source slice end_line precedes start_line")
        if hashlib.sha256(self.content.encode("utf-8")).hexdigest() != self.content_sha256:
            raise ValueError("source slice content_sha256 does not match content")
        identity = {
            "artifact_sha256": self.artifact_sha256,
            "content_sha256": self.content_sha256,
            "end_line": self.end_line,
            "path": self.path,
            "selection": self.selection,
            "start_line": self.start_line,
        }
        expected = (
            "slice_"
            + hashlib.sha256(
                json.dumps(identity, separators=(",", ":"), sort_keys=True).encode("utf-8")
            ).hexdigest()
        )
        if self.slice_id != expected:
            raise ValueError("source slice id does not match its stable content identity")
        return self


class ContextCandidate(ContextDomainModel):
    """A lexical guard or sanitizer candidate, never a semantic fact."""

    kind: Literal["guard", "sanitizer"]
    location: SourceLocation
    excerpt: Annotated[str, Field(min_length=1, max_length=100_000)]
    extractor: Literal["java-lexical-candidate@1"] = "java-lexical-candidate@1"


class ContextOmission(ContextDomainModel):
    """One explicit reason requested context could not be included."""

    code: ContextOmissionCode
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    detail: Annotated[str, Field(min_length=1, max_length=1000)]


class LevelZeroContext(ContextDomainModel):
    """Normalized alert facts included without reparsing SARIF."""

    rule: RuleMetadata
    message: Annotated[str, Field(min_length=1, max_length=1_000_000)]
    primary_location: SourceLocation
    additional_locations: tuple[SourceLocation, ...] = ()
    related_locations: tuple[SourceLocation, ...] = ()
    paths: tuple[DataFlowPath, ...]


class SliceContent(ContextDomainModel):
    """Hashable payload for one alert's Level 0/1 context."""

    alert_fingerprint: Sha256
    raw_result_reference: RawResultReference
    context_policy: ContextPolicyName
    context_version: Literal["1.0"] = "1.0"
    level_zero: LevelZeroContext
    source_slices: tuple[SourceSlice, ...]
    guards: tuple[ContextCandidate, ...] = ()
    candidate_sanitizers: tuple[ContextCandidate, ...] = ()
    token_estimate: Annotated[int, Field(ge=0)]
    maximum_token_budget: Annotated[int, Field(ge=1)]
    completeness: Literal["complete", "partial"]
    omitted: tuple[ContextOmission, ...] = ()

    @model_validator(mode="after")
    def validate_completeness(self) -> Self:
        if (self.completeness == "partial") != bool(self.omitted):
            raise ValueError("partial context must have omissions and complete context must not")
        if self.token_estimate > self.maximum_token_budget and not any(
            omission.code == "token_budget_exceeded" for omission in self.omitted
        ):
            raise ValueError("over-budget context must record a token budget omission")
        return self


class SliceArtifact(ContextDomainModel):
    """One reproducible alert context with a digest over its canonical content."""

    schema_version: Literal["1.0"] = "1.0"
    slice_sha256: Sha256
    content: SliceContent

    @model_validator(mode="after")
    def validate_slice_digest(self) -> Self:
        serialized = json.dumps(
            self.content.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if hashlib.sha256(serialized).hexdigest() != self.slice_sha256:
            raise ValueError("slice_sha256 does not match canonical slice content")
        return self


class SliceArtifactReference(ContextDomainModel):
    """Content address and run-relative path of one persisted SliceArtifact."""

    alert_fingerprint: Sha256
    raw_result_reference: RawResultReference
    relative_path: Annotated[str, Field(min_length=1, max_length=4096)]
    artifact_sha256: Sha256
    slice_sha256: Sha256

    @field_validator("relative_path")
    @classmethod
    def validate_artifact_path(cls, value: str) -> str:
        if (
            value.startswith(("/", "\\"))
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("slice artifact path must be a safe relative POSIX path")
        return PurePosixPath(value).as_posix()


class ContextIndex(ContextDomainModel):
    """Index binding all per-alert slices to one normalized bundle."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    repository_identity: Annotated[str, Field(min_length=1, max_length=4096)]
    raw_sarif_sha256: Sha256
    normalized_bundle_sha256: Sha256
    context_policy: ContextPolicyName
    context_version: Literal["1.0"] = "1.0"
    slices: tuple[SliceArtifactReference, ...]

    @model_validator(mode="after")
    def validate_unique_alert_occurrences(self) -> Self:
        references = [
            (item.raw_result_reference.run_index, item.raw_result_reference.result_index)
            for item in self.slices
        ]
        if len(references) != len(set(references)):
            raise ValueError("context index contains duplicate raw result references")
        if any(
            item.raw_result_reference.raw_sarif_sha256 != self.raw_sarif_sha256
            for item in self.slices
        ):
            raise ValueError("context slice raw SARIF provenance does not match its index")
        return self


__all__ = [
    "ContextCandidate",
    "ContextIndex",
    "ContextOmission",
    "ContextOmissionCode",
    "ContextPolicyName",
    "ContextReference",
    "LevelZeroContext",
    "SliceArtifact",
    "SliceArtifactReference",
    "SliceContent",
    "SourceSlice",
]
