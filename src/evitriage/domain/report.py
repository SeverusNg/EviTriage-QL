"""Strict Gate E offline report contracts and evidence-closure checks."""

from __future__ import annotations

from typing import Annotated, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evitriage.domain.alerts import NormalizedAlert, Sha256
from evitriage.domain.context import ContextOmission, ContextPolicyName, SliceArtifact
from evitriage.domain.evidence import EvidenceItem
from evitriage.domain.triage import ClaimDraft, TriageResult, materialize_claim


class ReportDomainModel(BaseModel):
    """Shared strict and immutable configuration for published report records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ReportRunMetadata(ReportDomainModel):
    """Non-secret provenance repeated in every independently usable JSONL row."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    project_id: Annotated[str, Field(min_length=1, max_length=128)]
    analysis_identity: Annotated[str, Field(min_length=1, max_length=128)]
    input_mode: Literal["sarif", "scan"]
    real_codeql: bool
    project_spec_sha256: Sha256
    snapshot_identity: Sha256
    repository_identity: Annotated[str, Field(min_length=1, max_length=4096)]
    commit_sha: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")] | None = None
    raw_sarif_sha256: Sha256
    tool_versions: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_tool_versions(self) -> Self:
        if self.real_codeql != (self.input_mode == "scan"):
            raise ValueError("report input mode and real CodeQL provenance disagree")
        if any(
            not name or not version or any(ord(character) < 32 for character in name + version)
            for name, version in self.tool_versions.items()
        ):
            raise ValueError("report tool versions must be non-empty printable text")
        return self


class ReportContextStage(ReportDomainModel):
    """One bounded context selection recorded for audit and later expansion."""

    context_policy: ContextPolicyName
    context_version: Literal["1.0"] = "1.0"
    completeness: Literal["complete", "partial"]
    token_estimate: Annotated[int, Field(ge=0)]
    maximum_token_budget: Annotated[int, Field(ge=1)]
    omitted: tuple[ContextOmission, ...] = ()

    @model_validator(mode="after")
    def validate_completeness(self) -> Self:
        if (self.completeness == "partial") != bool(self.omitted):
            raise ValueError("report context completeness and omissions disagree")
        return self


class ReportVerificationSummary(ReportDomainModel):
    """Explicitly distinguish absent verification from successful verification."""

    status: Literal["not_performed"] = "not_performed"
    results: tuple[Annotated[str, Field(min_length=1, max_length=10_000)], ...] = ()
    reason: Annotated[str, Field(min_length=1, max_length=10_000)]

    @model_validator(mode="after")
    def reject_results_without_verification(self) -> Self:
        if self.results:
            raise ValueError("not-performed verification cannot contain results")
        return self


class AlertReport(ReportDomainModel):
    """One evidence-closed, independently parseable Gate E alert report row."""

    schema_version: Literal["1.0"] = "1.0"
    run: ReportRunMetadata
    alert: NormalizedAlert
    slice_artifact: SliceArtifact
    evidence: tuple[EvidenceItem, ...]
    triage: TriageResult
    context_expansion_history: Annotated[tuple[ReportContextStage, ...], Field(min_length=1)]
    verification: ReportVerificationSummary
    unknowns: tuple[Annotated[str, Field(min_length=1, max_length=10_000)], ...] = ()
    limitations: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=10_000)], ...],
        Field(min_length=1),
    ]
    human_label: Literal[None] = None
    human_disagreement: Literal[None] = None

    @model_validator(mode="after")
    def validate_closed_alert_report(self) -> Self:
        target = self.triage.target
        content = self.slice_artifact.content
        expected = (target.alert_fingerprint, target.raw_result_reference)
        if (self.alert.alert_fingerprint, self.alert.raw_result_reference) != expected:
            raise ValueError("report alert and triage target differ")
        if (content.alert_fingerprint, content.raw_result_reference) != expected:
            raise ValueError("report slice and triage target differ")
        if self.alert.run_id != self.run.analysis_identity:
            raise ValueError("report alert analysis identity differs from run metadata")
        if self.alert.repository_identity != self.run.repository_identity:
            raise ValueError("report repository identity differs from normalized alert")
        if self.alert.commit_sha != self.run.commit_sha:
            raise ValueError("report commit differs from normalized alert")
        if self.alert.raw_result_reference.raw_sarif_sha256 != self.run.raw_sarif_sha256:
            raise ValueError("report raw SARIF identity differs from alert provenance")

        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("report evidence IDs must be unique")
        if any(
            (item.alert_fingerprint, item.raw_result_reference) != expected
            for item in self.evidence
        ):
            raise ValueError("report evidence contains another alert occurrence")
        known_evidence = set(evidence_ids)
        claims = (*self.triage.analyst_claims, *self.triage.rebuttal_claims)
        expected_analyst_claims = tuple(
            materialize_claim(cast(ClaimDraft, draft), produced_by="analyst")
            for draft in self.triage.analyst.claims
        )
        expected_rebuttal_claims = tuple(
            materialize_claim(cast(ClaimDraft, draft), produced_by="rebuttal")
            for draft in self.triage.rebuttal.claims
        )
        if self.triage.analyst_claims != expected_analyst_claims:
            raise ValueError("report Analyst drafts and materialized Claims differ")
        if self.triage.rebuttal_claims != expected_rebuttal_claims:
            raise ValueError("report Rebuttal drafts and materialized Claims differ")
        analyst_claim_ids = {claim.claim_id for claim in self.triage.analyst_claims}
        if not set(self.triage.rebuttal.rebutted_claim_ids).issubset(analyst_claim_ids):
            raise ValueError("report Rebuttal cites an unavailable Analyst Claim")
        if any(not set(claim.evidence_ids).issubset(known_evidence) for claim in claims):
            raise ValueError("report claim contains an unavailable evidence ID")
        if not set(self.triage.final_decision.critical_evidence_ids).issubset(known_evidence):
            raise ValueError("report decision contains an unavailable critical evidence ID")
        known_claims = {claim.claim_id for claim in claims}
        if not set(self.triage.final_decision.critical_claim_ids).issubset(known_claims):
            raise ValueError("report decision contains an unavailable critical claim ID")

        final_context = self.context_expansion_history[-1]
        if (
            final_context.context_policy != content.context_policy
            or final_context.context_version != content.context_version
            or final_context.completeness != content.completeness
            or final_context.token_estimate != content.token_estimate
            or final_context.maximum_token_budget != content.maximum_token_budget
            or final_context.omitted != content.omitted
        ):
            raise ValueError("report context history does not end at the persisted slice")
        if len(self.unknowns) != len(set(self.unknowns)):
            raise ValueError("report unknowns must be unique")
        if len(self.limitations) != len(set(self.limitations)):
            raise ValueError("report limitations must be unique")
        return self


class TriageReportBundle(ReportDomainModel):
    """All report rows and shared provenance for one completed triage run."""

    schema_version: Literal["1.0"] = "1.0"
    run: ReportRunMetadata
    alerts: tuple[AlertReport, ...]

    @model_validator(mode="after")
    def validate_run_identity(self) -> Self:
        if any(report.run != self.run for report in self.alerts):
            raise ValueError("report bundle contains a row from another run")
        references = [
            (
                report.alert.raw_result_reference.run_index,
                report.alert.raw_result_reference.result_index,
            )
            for report in self.alerts
        ]
        if len(references) != len(set(references)):
            raise ValueError("report bundle contains duplicate alert occurrences")
        return self


__all__ = [
    "AlertReport",
    "ReportContextStage",
    "ReportRunMetadata",
    "ReportVerificationSummary",
    "TriageReportBundle",
]
