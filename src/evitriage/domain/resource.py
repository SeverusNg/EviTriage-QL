"""Strict resource-leak query-family and structured triage contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evitriage.domain.evidence import Claim, ClaimId, EvidenceId

ShortText = Annotated[str, Field(min_length=1, max_length=10_000)]
TriageLabel = Literal["TP", "FP", "NMC"]

ResourceKind = Literal["input", "output", "database", "lock"]
QueryFamily = Literal[
    "resource_input",
    "resource_output",
    "resource_database",
    "resource_lock",
    "legacy_security",
]
ResourceClaimKind = Literal[
    "resource_acquisition",
    "resource_release",
    "control_flow_exit",
    "exception_flow",
    "release_coverage",
    "feasible_unreleased_exit",
    "ownership_transfer",
    "resource_escape",
    "callee_summary",
    "lifecycle_contract",
    "context_gap",
]

_RESOURCE_RULE_FAMILIES: dict[str, QueryFamily] = {
    "java/input-resource-leak": "resource_input",
    "java/output-resource-leak": "resource_output",
    "java/database-resource-leak": "resource_database",
    "java/unreleased-lock": "resource_lock",
}
_FAMILY_RESOURCE_KINDS: dict[QueryFamily, ResourceKind] = {
    "resource_input": "input",
    "resource_output": "output",
    "resource_database": "database",
    "resource_lock": "lock",
}


class _ResourceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ResourceAssessment(_ResourceModel):
    """Evidence-bound answer for one lifecycle question."""

    status: Literal["confirmed", "absent", "unknown", "conflicting"]
    detail: ShortText
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("resource assessment evidence references must be unique")
        return self


class ResourceReleaseSite(_ResourceModel):
    """One candidate release operation for a specific resource identity."""

    resource_identity: ShortText
    operation: ShortText
    condition: ShortText
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_unique_evidence(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("release-site evidence references must be unique")
        return self


class ResourceExitAssessment(_ResourceModel):
    """Whether a feasible acquired-resource exit lacks a matching release."""

    status: Literal["confirmed", "absent", "unknown", "conflicting"]
    exit_kind: Literal["normal", "return", "throw", "break", "continue"] | None = None
    detail: ShortText
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_exit(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("resource-exit evidence references must be unique")
        if self.status == "confirmed" and self.exit_kind is None:
            raise ValueError("confirmed unreleased exits require an exit_kind")
        return self


class ResourceContextGap(_ResourceModel):
    """One explicit missing fact that prevents safe lifecycle reasoning."""

    kind: Literal[
        "resource_identity",
        "acquisition_success",
        "exception_path",
        "early_exit",
        "callee_behavior",
        "ownership_contract",
        "lifecycle_contract",
        "third_party_source",
        "generated_source",
        "truncated_context",
        "custom_protocol",
        "conflicting_evidence",
    ]
    detail: ShortText
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_unique_evidence(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("resource context-gap evidence references must be unique")
        return self


class ResourceClaimDraft(_ResourceModel):
    """Resource-specific claim content before code assigns a stable claim ID."""

    kind: ResourceClaimKind
    statement: Annotated[str, Field(min_length=1, max_length=20_000)]
    status: Literal["supported", "rebutted", "unresolved"]
    evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("resource claim evidence references must be unique")
        return self


class ResourceAnalystOutput(_ResourceModel):
    """Resource Analyst result with explicit acquisition and path obligations."""

    schema_version: Literal["1.0"] = "1.0"
    resource_kind: ResourceKind
    acquisition_succeeds: Literal["yes", "no", "unknown"]
    acquisition_condition: ShortText
    acquisition_evidence_ids: Annotated[tuple[EvidenceId, ...], Field(min_length=1)]
    release_sites: Annotated[tuple[ResourceReleaseSite, ...], Field(max_length=64)] = ()
    release_coverage: ResourceAssessment
    feasible_unreleased_exit: ResourceExitAssessment
    ownership_transfer: ResourceAssessment
    resource_escape: ResourceAssessment
    callee_release_behavior: ResourceAssessment
    lifecycle_contract: ResourceAssessment
    context_gaps: Annotated[tuple[ResourceContextGap, ...], Field(max_length=64)] = ()
    claims: Annotated[tuple[ResourceClaimDraft, ...], Field(max_length=64)]
    unknowns: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def validate_lists(self) -> Self:
        if len(self.acquisition_evidence_ids) != len(set(self.acquisition_evidence_ids)):
            raise ValueError("acquisition evidence references must be unique")
        if len(self.unknowns) != len(set(self.unknowns)):
            raise ValueError("Resource Analyst unknowns must be unique")
        return self


class ResourceRebuttalOutput(_ResourceModel):
    """Resource Rebuttal result testing release and ownership counter-evidence."""

    schema_version: Literal["1.0"] = "1.0"
    resource_kind: ResourceKind
    release_coverage: ResourceAssessment
    ownership_transfer: ResourceAssessment
    resource_escape: ResourceAssessment
    callee_release_behavior: ResourceAssessment
    lifecycle_contract: ResourceAssessment
    context_gaps: Annotated[tuple[ResourceContextGap, ...], Field(max_length=64)] = ()
    claims: Annotated[tuple[ResourceClaimDraft, ...], Field(max_length=64)]
    rebutted_claim_ids: Annotated[tuple[ClaimId, ...], Field(max_length=64)] = ()
    unknowns: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def validate_unique_references(self) -> Self:
        if len(self.rebutted_claim_ids) != len(set(self.rebutted_claim_ids)):
            raise ValueError("resource rebutted claim references must be unique")
        if len(self.unknowns) != len(set(self.unknowns)):
            raise ValueError("Resource Rebuttal unknowns must be unique")
        return self


class ResourceJudgeOutput(_ResourceModel):
    """Untrusted resource Judge candidate evaluated by deterministic policy."""

    schema_version: Literal["1.0"] = "1.0"
    resource_kind: ResourceKind
    label: TriageLabel
    raw_confidence: Annotated[float, Field(ge=0, le=1)]
    critical_claim_ids: Annotated[tuple[ClaimId, ...], Field(max_length=128)] = ()
    critical_evidence_ids: Annotated[tuple[EvidenceId, ...], Field(max_length=128)] = ()
    unknowns: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()
    reasoning_summary: Annotated[str, Field(min_length=1, max_length=20_000)]
    next_actions: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()
    fix_guidance: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def validate_unique_lists(self) -> Self:
        fields = (
            self.critical_claim_ids,
            self.critical_evidence_ids,
            self.unknowns,
            self.next_actions,
            self.fix_guidance,
        )
        if any(len(values) != len(set(values)) for values in fields):
            raise ValueError("Resource Judge references and text lists must be unique")
        return self


def classify_query_family(rule_id: str) -> QueryFamily:
    """Classify an exact structured SARIF rule ID without parsing prose."""

    return _RESOURCE_RULE_FAMILIES.get(rule_id, "legacy_security")


def resource_kind_for_family(family: QueryFamily) -> ResourceKind | None:
    """Return the resource kind for a resource family, otherwise ``None``."""

    return _FAMILY_RESOURCE_KINDS.get(family)


def materialize_resource_claim(
    draft: ResourceClaimDraft,
    *,
    produced_by: Literal["analyst", "rebuttal"],
) -> Claim:
    """Assign a legacy-compatible content ID to a resource-specific claim."""

    content = {
        "schema_version": "1.0",
        "kind": draft.kind,
        "statement": draft.statement,
        "status": draft.status,
        "evidence_ids": list(draft.evidence_ids),
        "produced_by": produced_by,
    }
    serialized = json.dumps(
        content,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return Claim(
        claim_id="cl_" + hashlib.sha256(serialized).hexdigest(),
        kind=draft.kind,
        statement=draft.statement,
        status=draft.status,
        evidence_ids=draft.evidence_ids,
        produced_by=produced_by,
    )


__all__ = [
    "QueryFamily",
    "ResourceAnalystOutput",
    "ResourceAssessment",
    "ResourceClaimDraft",
    "ResourceClaimKind",
    "ResourceContextGap",
    "ResourceExitAssessment",
    "ResourceJudgeOutput",
    "ResourceKind",
    "ResourceRebuttalOutput",
    "ResourceReleaseSite",
    "classify_query_family",
    "materialize_resource_claim",
    "resource_kind_for_family",
]
