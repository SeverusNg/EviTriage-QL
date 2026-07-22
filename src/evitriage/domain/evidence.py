"""Strict evidence and claim contracts with closed reference validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from evitriage.domain.alerts import RawResultReference, Sha256, SourceLocation

EvidenceId = Annotated[str, Field(pattern=r"^ev_[0-9a-f]{64}$")]
ClaimId = Annotated[str, Field(pattern=r"^cl_[0-9a-f]{64}$")]
EvidenceType = Literal[
    "source_control",
    "data_flow",
    "sink_semantics",
    "guard",
    "sanitizer",
    "config",
    "permission",
    "test",
    "verification",
    "rebuttal",
    "rule_semantics",
]
EvidencePolarity = Literal["supports_tp", "supports_fp", "neutral"]
EvidenceStrength = Literal["low", "medium", "high", "decisive"]
EvidenceOrigin = Literal["codeql", "repository", "build", "test", "verifier", "human"]
SupplementKind = Literal["human", "test", "verification"]


class EvidenceDomainModel(BaseModel):
    """Shared strict, immutable configuration for evidence records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class EvidenceArtifactReference(EvidenceDomainModel):
    """A content-addressed artifact that evidence is allowed to cite."""

    kind: Literal["normalized", "slice", "build", "test", "verification", "human"]
    relative_path: Annotated[str, Field(min_length=1, max_length=4096)]
    artifact_sha256: Sha256

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        if (
            value.startswith(("/", "\\"))
            or "\\" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("evidence artifact path must be a safe relative POSIX path")
        return PurePosixPath(value).as_posix()


class EvidenceItem(EvidenceDomainModel):
    """One provenance-bound fact or observation available to later agents."""

    evidence_id: EvidenceId
    alert_fingerprint: Sha256
    raw_result_reference: RawResultReference
    type: EvidenceType
    polarity: EvidencePolarity
    strength: EvidenceStrength
    origin: EvidenceOrigin
    location: SourceLocation | None = None
    excerpt: Annotated[str, Field(max_length=1_000_000)] | None = None
    artifact_sha256: Sha256
    extractor: Annotated[str, Field(min_length=1, max_length=200)]
    summary: Annotated[str, Field(min_length=1, max_length=10_000)]
    path_fingerprint: Sha256 | None = None
    source_anchor: Annotated[str, Field(pattern=r"^slice_[0-9a-f]{64}-L[1-9][0-9]*$")] | None = None

    @model_validator(mode="after")
    def validate_content_addressed_id(self) -> Self:
        content = self.model_dump(mode="json", exclude={"evidence_id"})
        serialized = json.dumps(
            content,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        expected = "ev_" + hashlib.sha256(serialized).hexdigest()
        if self.evidence_id != expected:
            raise ValueError("evidence_id does not match canonical evidence content")
        return self


class EvidenceSupplementEntry(EvidenceDomainModel):
    """One explicit, occurrence-bound observation supplied outside CodeQL."""

    run_index: Annotated[int, Field(ge=0)]
    result_index: Annotated[int, Field(ge=0)]
    type: EvidenceType
    polarity: EvidencePolarity
    strength: EvidenceStrength
    summary: Annotated[str, Field(min_length=1, max_length=10_000)]

    @model_validator(mode="after")
    def validate_semantic_shape(self) -> Self:
        if self.summary.strip() != self.summary:
            raise ValueError("supplement evidence summary must not have surrounding whitespace")
        if any(ord(character) < 32 and character not in "\n\t" for character in self.summary):
            raise ValueError("supplement evidence summary contains control characters")
        if self.polarity == "neutral" and self.strength == "decisive":
            raise ValueError("neutral supplement evidence cannot be decisive")
        return self


class EvidenceSupplement(EvidenceDomainModel):
    """Strict trusted input for human, test, or verifier observations."""

    schema_version: Literal["1.0"] = "1.0"
    project_id: Annotated[
        str,
        Field(min_length=1, max_length=63, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
    ]
    repository_identity: Sha256
    raw_sarif_sha256: Sha256
    kind: SupplementKind
    producer: Annotated[str, Field(min_length=1, max_length=200)]
    purpose: Annotated[str, Field(min_length=1, max_length=1000)]
    entries: Annotated[tuple[EvidenceSupplementEntry, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_supplement(self) -> Self:
        for field_name, value in (("producer", self.producer), ("purpose", self.purpose)):
            if value.strip() != value:
                raise ValueError(f"supplement {field_name} must not have surrounding whitespace")
            if any(ord(character) < 32 and character not in "\n\t" for character in value):
                raise ValueError(f"supplement {field_name} contains control characters")
        identities = [
            (
                entry.run_index,
                entry.result_index,
                entry.type,
                entry.polarity,
                entry.strength,
                entry.summary,
            )
            for entry in self.entries
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("supplement contains duplicate evidence entries")
        return self


class EvidenceRelationship(EvidenceDomainModel):
    """A typed edge between two registered evidence items."""

    source_evidence_id: EvidenceId
    relation: Literal["supports", "rebuts", "depends_on", "unresolved"]
    target_evidence_id: EvidenceId

    @model_validator(mode="after")
    def reject_self_edge(self) -> Self:
        if self.source_evidence_id == self.target_evidence_id:
            raise ValueError("evidence relationships cannot be self-referential")
        return self


class Claim(EvidenceDomainModel):
    """A later-agent assertion whose evidence references must resolve."""

    schema_version: Literal["1.0"] = "1.0"
    claim_id: ClaimId
    kind: Literal[
        "source_controllable",
        "path_feasible",
        "sanitizer_effective",
        "sink_dangerous",
        "exploit_succeeds",
    ]
    statement: Annotated[str, Field(min_length=1, max_length=20_000)]
    status: Literal["supported", "rebutted", "unresolved"]
    evidence_ids: tuple[EvidenceId, ...] = ()
    produced_by: Literal["analyst", "rebuttal", "judge"]

    @model_validator(mode="after")
    def validate_local_evidence_shape(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("claim evidence references must be unique")
        if self.status != "unresolved" and not self.evidence_ids:
            raise ValueError("supported and rebutted claims require evidence")
        return self


class EvidenceRegistry(EvidenceDomainModel):
    """Immutable registry that rejects unknown artifacts and dangling graph edges."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    repository_identity: Annotated[str, Field(min_length=1, max_length=4096)]
    raw_sarif_sha256: Sha256
    artifacts: Annotated[tuple[EvidenceArtifactReference, ...], Field(min_length=1)]
    items: tuple[EvidenceItem, ...]
    relationships: tuple[EvidenceRelationship, ...] = ()
    claims: tuple[Claim, ...] = ()

    @model_validator(mode="after")
    def validate_closed_registry(self) -> Self:
        artifact_hashes = [artifact.artifact_sha256 for artifact in self.artifacts]
        if len(artifact_hashes) != len(set(artifact_hashes)):
            raise ValueError("evidence artifact hashes must be unique")
        evidence_ids = [item.evidence_id for item in self.items]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique")
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("claim IDs must be unique")
        known_artifacts = set(artifact_hashes)
        known_evidence = set(evidence_ids)
        for item in self.items:
            if item.artifact_sha256 not in known_artifacts:
                raise ValueError(f"evidence {item.evidence_id} cites an unknown artifact")
            if item.raw_result_reference.raw_sarif_sha256 != self.raw_sarif_sha256:
                raise ValueError("evidence raw SARIF provenance does not match its registry")
        for relationship in self.relationships:
            if (
                relationship.source_evidence_id not in known_evidence
                or relationship.target_evidence_id not in known_evidence
            ):
                raise ValueError("evidence relationship contains a dangling evidence ID")
        for claim in self.claims:
            if not set(claim.evidence_ids).issubset(known_evidence):
                raise ValueError(f"claim {claim.claim_id} contains a dangling evidence ID")
        return self


__all__ = [
    "Claim",
    "ClaimId",
    "EvidenceArtifactReference",
    "EvidenceId",
    "EvidenceItem",
    "EvidenceOrigin",
    "EvidencePolarity",
    "EvidenceRegistry",
    "EvidenceRelationship",
    "EvidenceStrength",
    "EvidenceSupplement",
    "EvidenceSupplementEntry",
    "EvidenceType",
    "SupplementKind",
]
