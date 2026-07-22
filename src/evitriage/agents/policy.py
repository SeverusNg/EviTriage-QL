"""Fail-closed deterministic policy for Gate D Judge candidates."""

from __future__ import annotations

from collections.abc import Iterable

from evitriage.domain.evidence import Claim, EvidenceItem, EvidenceRegistry
from evitriage.domain.triage import (
    AnalystOutput,
    FinalDecision,
    JudgeOutput,
    PolicyFlag,
    RebuttalOutput,
    TriageLabel,
    TriageTarget,
)
from evitriage.errors import PolicyRejectedError


class DeterministicDecisionPolicy:
    """Accept safe candidates and deterministically downgrade uncertainty to NMC."""

    def apply(
        self,
        *,
        registry: EvidenceRegistry,
        target: TriageTarget,
        analyst: AnalystOutput,
        analyst_claims: tuple[Claim, ...],
        rebuttal: RebuttalOutput,
        rebuttal_claims: tuple[Claim, ...],
        judge: JudgeOutput,
    ) -> FinalDecision:
        """Apply evidence-strength, conflict, and completeness gates."""

        target_evidence = {
            item.evidence_id: item
            for item in registry.items
            if item.alert_fingerprint == target.alert_fingerprint
            and item.raw_result_reference == target.raw_result_reference
        }
        claims = {claim.claim_id: claim for claim in (*analyst_claims, *rebuttal_claims)}
        if not target_evidence:
            raise PolicyRejectedError("triage target has no evidence in the registry")
        if not set(judge.critical_claim_ids).issubset(claims):
            raise PolicyRejectedError("Judge cites a claim outside the bounded triage trace")
        if not set(judge.critical_evidence_ids).issubset(target_evidence):
            raise PolicyRejectedError("Judge cites evidence outside the exact alert occurrence")

        critical_claims = tuple(claims[claim_id] for claim_id in judge.critical_claim_ids)
        considered_ids = set(judge.critical_evidence_ids)
        considered_ids.update(
            evidence_id for claim in critical_claims for evidence_id in claim.evidence_ids
        )
        if not considered_ids.issubset(target_evidence):
            raise PolicyRejectedError("critical claims cite evidence outside the triage target")
        considered = tuple(target_evidence[evidence_id] for evidence_id in sorted(considered_ids))

        flags: list[PolicyFlag] = ["auto_dismiss_disabled"]
        label: TriageLabel = judge.label
        unknowns = _stable_unique((*analyst.unknowns, *rebuttal.unknowns, *judge.unknowns))
        unresolved = any(claim.status == "unresolved" for claim in critical_claims)

        high_tp = _has_high_polarity(considered, "supports_tp")
        high_fp = _has_high_polarity(considered, "supports_fp")
        if judge.label == "NMC":
            flags.append("judge_requested_nmc")
            label = "NMC"
        elif not considered:
            flags.append("critical_evidence_missing")
            label = "NMC"
        elif unknowns or unresolved:
            flags.append("unknown_or_unresolved")
            label = "NMC"
        elif high_tp and high_fp:
            flags.append("conflicting_high_strength_evidence")
            label = "NMC"
        elif judge.label == "TP" and high_fp:
            flags.append("high_strength_fp_blocks_tp")
            label = "NMC"
        elif judge.label == "FP":
            if _has_decisive_rebuttal(
                critical_claims=critical_claims,
                rebuttal_claims=rebuttal_claims,
                evidence=target_evidence,
            ):
                flags.extend(("fp_decisive_rebuttal_present", "judge_label_accepted"))
                label = "FP"
            else:
                flags.append("fp_missing_decisive_rebuttal")
                label = "NMC"
        elif _has_supported_tp_case(
            critical_claims=critical_claims,
            analyst_claims=analyst_claims,
            evidence=target_evidence,
        ):
            flags.append("judge_label_accepted")
            label = "TP"
        else:
            flags.append("tp_support_missing")
            label = "NMC"

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


def _has_high_polarity(
    evidence: Iterable[EvidenceItem],
    polarity: str,
) -> bool:
    return any(
        item.polarity == polarity and item.strength in {"high", "decisive"} for item in evidence
    )


def _has_decisive_rebuttal(
    *,
    critical_claims: tuple[Claim, ...],
    rebuttal_claims: tuple[Claim, ...],
    evidence: dict[str, EvidenceItem],
) -> bool:
    critical_ids = {claim.claim_id for claim in critical_claims}
    return any(
        claim.claim_id in critical_ids
        and claim.status == "rebutted"
        and any(
            evidence[evidence_id].polarity == "supports_fp"
            and evidence[evidence_id].strength == "decisive"
            for evidence_id in claim.evidence_ids
        )
        for claim in rebuttal_claims
    )


def _has_supported_tp_case(
    *,
    critical_claims: tuple[Claim, ...],
    analyst_claims: tuple[Claim, ...],
    evidence: dict[str, EvidenceItem],
) -> bool:
    critical_ids = {claim.claim_id for claim in critical_claims}
    critical_analyst_claims = tuple(
        claim
        for claim in analyst_claims
        if claim.claim_id in critical_ids and claim.status == "supported"
    )
    decisive_verification = any(
        claim.kind == "exploit_succeeds"
        and any(
            evidence[evidence_id].type == "verification"
            and evidence[evidence_id].polarity == "supports_tp"
            and evidence[evidence_id].strength == "decisive"
            for evidence_id in claim.evidence_ids
        )
        for claim in critical_analyst_claims
    )
    if decisive_verification:
        return True
    required_evidence_types = {
        "source_controllable": "source_control",
        "path_feasible": "data_flow",
        "sink_dangerous": "sink_semantics",
    }
    return all(
        any(
            claim.kind == claim_kind
            and any(
                evidence[evidence_id].type == evidence_type
                and evidence[evidence_id].polarity == "supports_tp"
                and evidence[evidence_id].strength in {"medium", "high", "decisive"}
                for evidence_id in claim.evidence_ids
            )
            for claim in critical_analyst_claims
        )
        for claim_kind, evidence_type in required_evidence_types.items()
    )


def _stable_unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


__all__ = ["DeterministicDecisionPolicy"]
