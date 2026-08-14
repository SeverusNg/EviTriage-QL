"""Fail-closed deterministic policy for resource-leak Judge candidates."""

from __future__ import annotations

from collections.abc import Iterable

from evitriage.domain.evidence import Claim, EvidenceRegistry
from evitriage.domain.resource import (
    ResourceAnalystOutput,
    ResourceJudgeOutput,
    ResourceRebuttalOutput,
)
from evitriage.domain.triage import FinalDecision, PolicyFlag, TriageLabel, TriageTarget
from evitriage.errors import PolicyRejectedError

_TP_CLAIMS = frozenset({"resource_acquisition", "feasible_unreleased_exit"})
_FP_CLAIMS = frozenset(
    {"release_coverage", "ownership_transfer", "callee_summary", "lifecycle_contract"}
)


class ResourceDecisionPolicy:
    """Require acquisition/exit or complete release/ownership evidence by shape."""

    def apply(
        self,
        *,
        registry: EvidenceRegistry,
        target: TriageTarget,
        analyst: ResourceAnalystOutput,
        analyst_claims: tuple[Claim, ...],
        rebuttal: ResourceRebuttalOutput,
        rebuttal_claims: tuple[Claim, ...],
        judge: ResourceJudgeOutput,
    ) -> FinalDecision:
        """Validate exact references and conservatively accept TP/FP or return NMC."""

        target_evidence = {
            item.evidence_id: item
            for item in registry.items
            if item.alert_fingerprint == target.alert_fingerprint
            and item.raw_result_reference == target.raw_result_reference
        }
        claims = {claim.claim_id: claim for claim in (*analyst_claims, *rebuttal_claims)}
        if not target_evidence:
            raise PolicyRejectedError("resource triage target has no registered evidence")
        if not set(judge.critical_claim_ids).issubset(claims):
            raise PolicyRejectedError("Resource Judge cites a claim outside the triage trace")
        if not set(judge.critical_evidence_ids).issubset(target_evidence):
            raise PolicyRejectedError("Resource Judge cites evidence outside the occurrence")

        critical_claims = tuple(claims[item] for item in judge.critical_claim_ids)
        considered_ids = set(judge.critical_evidence_ids)
        considered_ids.update(
            evidence_id for claim in critical_claims for evidence_id in claim.evidence_ids
        )
        if not considered_ids.issubset(target_evidence):
            raise PolicyRejectedError("critical resource claims cite another occurrence")

        flags: list[PolicyFlag] = ["auto_dismiss_disabled"]
        unknowns = _stable_unique((*analyst.unknowns, *rebuttal.unknowns, *judge.unknowns))
        context_incomplete = any(item.type == "context_gap" for item in target_evidence.values())
        output_gaps = bool(analyst.context_gaps or rebuttal.context_gaps)
        assessment_unknown = _has_unknown_assessment(analyst, rebuttal)
        conflicting = _has_conflict(analyst, rebuttal)
        unresolved = any(claim.status == "unresolved" for claim in critical_claims)
        label: TriageLabel = "NMC"

        if judge.label == "NMC":
            flags.append("judge_requested_nmc")
        elif context_incomplete or output_gaps:
            flags.append("resource_context_incomplete")
        elif conflicting:
            flags.append("resource_evidence_conflict")
        elif unknowns or unresolved or assessment_unknown:
            flags.append("unknown_or_unresolved")
        elif judge.label == "TP":
            if analyst.acquisition_succeeds != "yes":
                flags.append("resource_acquisition_missing")
            elif analyst.feasible_unreleased_exit.status != "confirmed":
                flags.append("resource_unreleased_exit_missing")
            elif _positive_ownership_or_release(analyst, rebuttal):
                flags.append("resource_evidence_conflict")
            elif not _has_claim_kinds(critical_claims, _TP_CLAIMS, status="supported"):
                flags.append("tp_support_missing")
            else:
                flags.extend(("resource_tp_basis_confirmed", "judge_label_accepted"))
                label = "TP"
        elif _fp_basis(rebuttal) and _has_claim_kind(
            critical_claims,
            _FP_CLAIMS,
            statuses=frozenset({"supported", "rebutted"}),
        ):
            if rebuttal.release_coverage.status == "confirmed":
                flags.append("resource_release_coverage_confirmed")
            else:
                flags.append("resource_ownership_confirmed")
            flags.append("judge_label_accepted")
            label = "FP"
        else:
            flags.append("resource_fp_basis_missing")

        return FinalDecision(
            target=target,
            label=label,
            requested_label=judge.label,
            raw_confidence=judge.raw_confidence,
            critical_claim_ids=judge.critical_claim_ids,
            critical_evidence_ids=judge.critical_evidence_ids,
            unknowns=unknowns,
            reasoning_summary=judge.reasoning_summary,
            next_actions=judge.next_actions,
            fix_guidance=judge.fix_guidance,
            policy_flags=tuple(flags),
            auto_dismiss=False,
        )


def _fp_basis(rebuttal: ResourceRebuttalOutput) -> bool:
    return any(
        assessment.status == "confirmed"
        for assessment in (
            rebuttal.release_coverage,
            rebuttal.ownership_transfer,
            rebuttal.callee_release_behavior,
            rebuttal.lifecycle_contract,
        )
    )


def _positive_ownership_or_release(
    analyst: ResourceAnalystOutput,
    rebuttal: ResourceRebuttalOutput,
) -> bool:
    return any(
        assessment.status == "confirmed"
        for assessment in (
            analyst.release_coverage,
            analyst.ownership_transfer,
            analyst.callee_release_behavior,
            analyst.lifecycle_contract,
            rebuttal.release_coverage,
            rebuttal.ownership_transfer,
            rebuttal.callee_release_behavior,
            rebuttal.lifecycle_contract,
        )
    )


def _has_conflict(
    analyst: ResourceAnalystOutput,
    rebuttal: ResourceRebuttalOutput,
) -> bool:
    return any(
        assessment.status == "conflicting"
        for assessment in (
            analyst.release_coverage,
            analyst.feasible_unreleased_exit,
            analyst.ownership_transfer,
            analyst.resource_escape,
            analyst.callee_release_behavior,
            analyst.lifecycle_contract,
            rebuttal.release_coverage,
            rebuttal.ownership_transfer,
            rebuttal.resource_escape,
            rebuttal.callee_release_behavior,
            rebuttal.lifecycle_contract,
        )
    )


def _has_unknown_assessment(
    analyst: ResourceAnalystOutput,
    rebuttal: ResourceRebuttalOutput,
) -> bool:
    return any(
        assessment.status == "unknown"
        for assessment in (
            analyst.release_coverage,
            analyst.feasible_unreleased_exit,
            analyst.ownership_transfer,
            analyst.resource_escape,
            analyst.callee_release_behavior,
            analyst.lifecycle_contract,
            rebuttal.release_coverage,
            rebuttal.ownership_transfer,
            rebuttal.resource_escape,
            rebuttal.callee_release_behavior,
            rebuttal.lifecycle_contract,
        )
    )


def _has_claim_kinds(
    claims: Iterable[Claim],
    kinds: frozenset[str],
    *,
    status: str,
) -> bool:
    found = {claim.kind for claim in claims if claim.status == status and claim.evidence_ids}
    return kinds.issubset(found)


def _has_claim_kind(
    claims: Iterable[Claim],
    kinds: frozenset[str],
    *,
    statuses: frozenset[str],
) -> bool:
    return any(
        claim.kind in kinds and claim.status in statuses and claim.evidence_ids for claim in claims
    )


def _stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


__all__ = ["ResourceDecisionPolicy"]
