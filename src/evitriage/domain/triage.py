"""Strict Gate D agent outputs and deterministic decision records."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evitriage.domain.alerts import RawResultReference, Sha256
from evitriage.domain.evidence import Claim, ClaimId, EvidenceId
from evitriage.domain.resource import (
    ResourceAnalystOutput,
    ResourceJudgeOutput,
    ResourceRebuttalOutput,
)
from evitriage.domain.run import ArtifactRecord

AgentRole = Literal["analyst", "rebuttal", "judge"]
TriageLabel = Literal["TP", "FP", "NMC"]
ShortText = Annotated[str, Field(min_length=1, max_length=10_000)]
PolicyFlag = Literal[
    "auto_dismiss_disabled",
    "conflicting_high_strength_evidence",
    "critical_evidence_missing",
    "fp_decisive_rebuttal_present",
    "fp_missing_decisive_rebuttal",
    "high_strength_fp_blocks_tp",
    "judge_label_accepted",
    "judge_requested_nmc",
    "tp_support_missing",
    "unknown_or_unresolved",
    "resource_acquisition_missing",
    "resource_context_incomplete",
    "resource_evidence_conflict",
    "resource_fp_basis_missing",
    "resource_ownership_confirmed",
    "resource_release_coverage_confirmed",
    "resource_tp_basis_confirmed",
    "resource_unreleased_exit_missing",
]


class TriageDomainModel(BaseModel):
    """Shared strict and immutable configuration for Gate D records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class TriageTarget(TriageDomainModel):
    """One exact upstream result occurrence selected for triage."""

    alert_fingerprint: Sha256
    raw_result_reference: RawResultReference


class ClaimDraft(TriageDomainModel):
    """Agent-authored claim content before code assigns a stable claim ID."""

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

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> Self:
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ValueError("claim draft evidence references must be unique")
        if self.status != "unresolved" and not self.evidence_ids:
            raise ValueError("supported and rebutted claim drafts require evidence")
        return self


class AnalystOutput(TriageDomainModel):
    """Structured Analyst result; it proposes claims but no final label."""

    schema_version: Literal["1.0"] = "1.0"
    claims: Annotated[tuple[ClaimDraft, ...], Field(max_length=64)]
    unknowns: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def validate_unique_unknowns(self) -> Self:
        if len(self.unknowns) != len(set(self.unknowns)):
            raise ValueError("Analyst unknowns must be unique")
        return self


class RebuttalOutput(TriageDomainModel):
    """Structured Rebuttal result tied to existing Analyst claim IDs."""

    schema_version: Literal["1.0"] = "1.0"
    claims: Annotated[tuple[ClaimDraft, ...], Field(max_length=64)]
    rebutted_claim_ids: Annotated[tuple[ClaimId, ...], Field(max_length=64)] = ()
    unknowns: Annotated[tuple[ShortText, ...], Field(max_length=64)] = ()

    @model_validator(mode="after")
    def validate_unique_references(self) -> Self:
        if len(self.rebutted_claim_ids) != len(set(self.rebutted_claim_ids)):
            raise ValueError("rebutted claim references must be unique")
        if len(self.unknowns) != len(set(self.unknowns)):
            raise ValueError("Rebuttal unknowns must be unique")
        return self


class JudgeOutput(TriageDomainModel):
    """Untrusted Judge candidate evaluated by deterministic code policy."""

    schema_version: Literal["1.0"] = "1.0"
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
            raise ValueError("Judge references and text lists must be unique")
        return self


class ModelInvocationRecord(TriageDomainModel):
    """Non-secret provenance for one accepted or rejected structured call."""

    agent_role: AgentRole
    attempt: Annotated[int, Field(ge=0, le=1)]
    request_sha256: Sha256
    prompt_sha256: Sha256
    response_sha256: Sha256 | None = None
    response_schema: Annotated[str, Field(min_length=1, max_length=200)]
    profile_id: Annotated[
        str,
        Field(min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$"),
    ]
    model_id: Annotated[str, Field(min_length=1, max_length=200)]
    status: Literal["accepted", "invalid"]
    error_code: Literal["MODEL_RESPONSE_INVALID"] | None = None

    @model_validator(mode="after")
    def validate_status_metadata(self) -> Self:
        if self.status == "accepted" and self.error_code is not None:
            raise ValueError("accepted model invocations cannot contain an error code")
        if self.status == "invalid" and self.error_code != "MODEL_RESPONSE_INVALID":
            raise ValueError("invalid model invocations require MODEL_RESPONSE_INVALID")
        return self


class FinalDecision(TriageDomainModel):
    """Judge candidate after the fail-closed deterministic policy is applied."""

    schema_version: Literal["1.0"] = "1.0"
    target: TriageTarget
    label: TriageLabel
    requested_label: TriageLabel
    raw_confidence: Annotated[float, Field(ge=0, le=1)]
    calibrated_probabilities: Literal[None] = None
    critical_claim_ids: tuple[ClaimId, ...] = ()
    critical_evidence_ids: tuple[EvidenceId, ...] = ()
    unknowns: tuple[ShortText, ...] = ()
    reasoning_summary: Annotated[str, Field(min_length=1, max_length=20_000)]
    next_actions: tuple[ShortText, ...] = ()
    fix_guidance: tuple[ShortText, ...] = ()
    policy_flags: Annotated[tuple[PolicyFlag, ...], Field(min_length=1)]
    auto_dismiss: Literal[False] = False

    @model_validator(mode="after")
    def validate_unique_references(self) -> Self:
        fields = (
            self.critical_claim_ids,
            self.critical_evidence_ids,
            self.unknowns,
            self.next_actions,
            self.fix_guidance,
            self.policy_flags,
        )
        if any(len(values) != len(set(values)) for values in fields):
            raise ValueError("final decision references, text, and flags must be unique")
        return self


class TriageResult(TriageDomainModel):
    """Complete in-memory Gate D result for one exact alert occurrence."""

    schema_version: Literal["1.0"] = "1.0"
    target: TriageTarget
    analyst: AnalystOutput | ResourceAnalystOutput
    analyst_claims: tuple[Claim, ...]
    rebuttal: RebuttalOutput | ResourceRebuttalOutput
    rebuttal_claims: tuple[Claim, ...]
    judge: JudgeOutput | ResourceJudgeOutput
    final_decision: FinalDecision
    invocations: Annotated[tuple[ModelInvocationRecord, ...], Field(min_length=3, max_length=6)]

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        if self.final_decision.target != self.target:
            raise ValueError("triage result and final decision targets differ")
        claim_ids = [claim.claim_id for claim in (*self.analyst_claims, *self.rebuttal_claims)]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("triage result claim IDs must be unique")
        accepted_roles = tuple(
            invocation.agent_role
            for invocation in self.invocations
            if invocation.status == "accepted"
        )
        if accepted_roles != ("analyst", "rebuttal", "judge"):
            raise ValueError("triage requires one accepted Analyst, Rebuttal, then Judge call")
        return self


class AnalystStageRecord(TriageDomainModel):
    """Persistable Analyst output and invocation trace for one occurrence."""

    target: TriageTarget
    output: AnalystOutput | ResourceAnalystOutput
    claims: tuple[Claim, ...]
    invocations: Annotated[tuple[ModelInvocationRecord, ...], Field(min_length=1, max_length=2)]

    @model_validator(mode="after")
    def validate_analyst_trace(self) -> Self:
        if any(claim.produced_by != "analyst" for claim in self.claims):
            raise ValueError("Analyst stage contains a non-Analyst claim")
        accepted = [item for item in self.invocations if item.status == "accepted"]
        if len(accepted) != 1 or any(item.agent_role != "analyst" for item in self.invocations):
            raise ValueError("Analyst stage requires exactly one accepted Analyst invocation")
        return self


class RebuttalStageRecord(TriageDomainModel):
    """Persistable Rebuttal output and invocation trace for one occurrence."""

    target: TriageTarget
    output: RebuttalOutput | ResourceRebuttalOutput
    claims: tuple[Claim, ...]
    invocations: Annotated[tuple[ModelInvocationRecord, ...], Field(min_length=1, max_length=2)]

    @model_validator(mode="after")
    def validate_rebuttal_trace(self) -> Self:
        if any(claim.produced_by != "rebuttal" for claim in self.claims):
            raise ValueError("Rebuttal stage contains a non-Rebuttal claim")
        accepted = [item for item in self.invocations if item.status == "accepted"]
        if len(accepted) != 1 or any(item.agent_role != "rebuttal" for item in self.invocations):
            raise ValueError("Rebuttal stage requires exactly one accepted Rebuttal invocation")
        return self


class AnalystRunArtifact(TriageDomainModel):
    """All Analyst outputs persisted before the ANALYZED transition."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    analysis_identity: Annotated[str, Field(min_length=1, max_length=128)]
    results: tuple[AnalystStageRecord, ...]

    @model_validator(mode="after")
    def validate_unique_targets(self) -> Self:
        _validate_unique_targets(tuple(result.target for result in self.results))
        return self


class RebuttalRunArtifact(TriageDomainModel):
    """All Rebuttal outputs persisted before the REBUTTED transition."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    analysis_identity: Annotated[str, Field(min_length=1, max_length=128)]
    results: tuple[RebuttalStageRecord, ...]

    @model_validator(mode="after")
    def validate_unique_targets(self) -> Self:
        _validate_unique_targets(tuple(result.target for result in self.results))
        return self


class JudgedRunArtifact(TriageDomainModel):
    """All complete Gate D results persisted before the JUDGED transition."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    analysis_identity: Annotated[str, Field(min_length=1, max_length=128)]
    results: tuple[TriageResult, ...]

    @model_validator(mode="after")
    def validate_unique_targets(self) -> Self:
        _validate_unique_targets(tuple(result.target for result in self.results))
        return self


class TriageRunSummary(TriageDomainModel):
    """Stable CLI summary for a judged run with integrated Gate E reports."""

    schema_version: Literal["1.0"] = "1.0"
    status: Literal["ok"] = "ok"
    command: Literal["triage"] = "triage"
    source_kind: Literal["ingest", "scan"] = "ingest"
    real_codeql: bool = False
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    project_id: Annotated[str, Field(min_length=1, max_length=128)]
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    analysis_identity: Annotated[str, Field(min_length=1, max_length=128)]
    state: Literal["JUDGED"] = "JUDGED"
    artifact_run_root: Annotated[str, Field(min_length=1, max_length=4096)]
    raw_sarif: ArtifactRecord
    normalized_bundle: ArtifactRecord
    slice_artifacts: tuple[ArtifactRecord, ...]
    context_index: ArtifactRecord
    evidence_registry: ArtifactRecord
    evidence_graph: ArtifactRecord
    source_map: ArtifactRecord
    evidence_supplement: ArtifactRecord | None = None
    analyst_artifact: ArtifactRecord
    rebuttal_artifact: ArtifactRecord
    judged_artifact: ArtifactRecord
    report_jsonl: ArtifactRecord
    report_html: ArtifactRecord
    alert_count: Annotated[int, Field(ge=0)]
    path_count: Annotated[int, Field(ge=0)]
    evidence_count: Annotated[int, Field(ge=0)]
    claim_count: Annotated[int, Field(ge=0)]
    invocation_count: Annotated[int, Field(ge=0)]
    tp_count: Annotated[int, Field(ge=0)]
    fp_count: Annotated[int, Field(ge=0)]
    nmc_count: Annotated[int, Field(ge=0)]
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts_and_roles(self) -> Self:
        if self.real_codeql != (self.source_kind == "scan"):
            raise ValueError("triage source kind and real CodeQL provenance disagree")
        if self.tp_count + self.fp_count + self.nmc_count != self.alert_count:
            raise ValueError("triage label counts must equal alert_count")
        if len(self.slice_artifacts) != self.alert_count:
            raise ValueError("every triaged alert must retain one slice artifact")
        expected_roles = {
            self.normalized_bundle.relative_path: "normalized",
            self.context_index.relative_path: "context",
            self.evidence_registry.relative_path: "evidence",
            self.evidence_graph.relative_path: "evidence",
            self.source_map.relative_path: "context",
            self.analyst_artifact.relative_path: "model",
            self.rebuttal_artifact.relative_path: "model",
            self.judged_artifact.relative_path: "decision",
            self.report_jsonl.relative_path: "report",
            self.report_html.relative_path: "report",
        }
        records = (
            self.normalized_bundle,
            self.context_index,
            self.evidence_registry,
            self.evidence_graph,
            self.source_map,
            self.analyst_artifact,
            self.rebuttal_artifact,
            self.judged_artifact,
            self.report_jsonl,
            self.report_html,
        )
        if any(record.role != expected_roles[record.relative_path] for record in records):
            raise ValueError("triage/report artifact roles are inconsistent")
        if any(record.role != "context" for record in self.slice_artifacts):
            raise ValueError("triage slice artifact roles are inconsistent")
        expected_raw_role = "tool-output" if self.real_codeql else "input"
        if self.raw_sarif.role != expected_raw_role:
            raise ValueError("triage raw SARIF role disagrees with its source kind")
        if self.evidence_supplement is not None and self.evidence_supplement.role != "input":
            raise ValueError("triage evidence supplement must retain the input artifact role")
        return self


def materialize_claim(draft: ClaimDraft, *, produced_by: Literal["analyst", "rebuttal"]) -> Claim:
    """Assign a stable content-derived ID to a validated agent claim draft."""

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


def _validate_unique_targets(targets: tuple[TriageTarget, ...]) -> None:
    keys = [
        (
            target.alert_fingerprint,
            target.raw_result_reference.raw_sarif_sha256,
            target.raw_result_reference.run_index,
            target.raw_result_reference.result_index,
        )
        for target in targets
    ]
    if len(keys) != len(set(keys)):
        raise ValueError("triage run artifacts must contain unique alert occurrences")


__all__ = [
    "AgentRole",
    "AnalystOutput",
    "AnalystRunArtifact",
    "AnalystStageRecord",
    "ClaimDraft",
    "FinalDecision",
    "JudgeOutput",
    "JudgedRunArtifact",
    "ModelInvocationRecord",
    "PolicyFlag",
    "RebuttalOutput",
    "RebuttalRunArtifact",
    "RebuttalStageRecord",
    "TriageLabel",
    "TriageResult",
    "TriageRunSummary",
    "TriageTarget",
    "materialize_claim",
]
