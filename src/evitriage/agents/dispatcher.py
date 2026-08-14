"""Exact rule-ID dispatch between legacy security and resource triage."""

from __future__ import annotations

from evitriage.agents.resource_workflow import ResourceTriageWorkflow
from evitriage.agents.workflow import TriageLimits, TriageWorkflow
from evitriage.domain.evidence import EvidenceRegistry
from evitriage.domain.resource import classify_query_family, resource_kind_for_family
from evitriage.domain.triage import TriageResult, TriageTarget
from evitriage.errors import PolicyRejectedError
from evitriage.llm import LLMProfile, StructuredLLM


class TriageDispatcher:
    """Select a domain workflow solely from the structured SARIF rule ID."""

    def __init__(self, *, profile: LLMProfile, limits: TriageLimits | None = None) -> None:
        self._legacy = TriageWorkflow(profile=profile, limits=limits)
        self._resource = ResourceTriageWorkflow(profile=profile, limits=limits)

    def triage(
        self,
        *,
        registry: EvidenceRegistry,
        target: TriageTarget,
        rule_id: str,
        llm: StructuredLLM,
    ) -> TriageResult:
        """Dispatch an exact occurrence without parsing natural-language summaries."""

        family = classify_query_family(rule_id)
        resource_kind = resource_kind_for_family(family)
        if resource_kind is None:
            if family != "legacy_security":
                raise PolicyRejectedError("query family has no executable triage workflow")
            return self._legacy.triage(registry=registry, target=target, llm=llm)
        return self._resource.triage(
            registry=registry,
            target=target,
            resource_kind=resource_kind,
            llm=llm,
        )


__all__ = ["TriageDispatcher"]
