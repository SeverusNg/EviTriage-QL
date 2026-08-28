"""Bounded lexical observations for Java resource-lifecycle context."""

from __future__ import annotations

import re
from dataclasses import dataclass

from evitriage.domain.evidence import EvidenceType


@dataclass(frozen=True, slots=True)
class ResourceObservation:
    """One line-addressed lexical observation, never a semantic conclusion."""

    type: EvidenceType
    line_number: int
    excerpt: str
    summary: str


_PATTERNS: tuple[tuple[EvidenceType, re.Pattern[str], str], ...] = (
    (
        "resource_acquisition",
        re.compile(
            r"\b(?:new\s+[A-Za-z_$][A-Za-z0-9_$.<>]*|tryLock|lockInterruptibly|\.lock)\s*\("
        ),
        "Lexical acquisition candidate; success and object identity require reasoning.",
    ),
    (
        "resource_release",
        re.compile(r"\b(?:close|unlock|release)\s*\("),
        "Lexical release candidate; matching identity and all-path coverage are unverified.",
    ),
    (
        "control_flow_exit",
        re.compile(r"\b(?:return|break|continue)\b"),
        "Lexical control-flow exit candidate requiring acquired-resource path analysis.",
    ),
    (
        "exception_flow",
        re.compile(r"\b(?:throw|throws|catch|finally)\b"),
        "Lexical exception-flow candidate; feasibility and release coverage are unresolved.",
    ),
    (
        "release_coverage",
        re.compile(r"\btry\s*\(|\bfinally\b"),
        "Lexical try-with-resources or finally candidate; coverage is not implied.",
    ),
    (
        "resource_escape",
        re.compile(r"\breturn\b|\bthis\.[A-Za-z_$][A-Za-z0-9_$]*\s*=|\.(?:add|put)\s*\("),
        "Lexical return, field, or collection escape candidate; ownership is unverified.",
    ),
)


def extract_resource_observations(
    content: str,
    *,
    start_line: int,
) -> tuple[ResourceObservation, ...]:
    """Return deterministic lifecycle candidates from one already bounded source slice."""

    result: list[ResourceObservation] = []
    observed: set[tuple[EvidenceType, int, str]] = set()
    for offset, line in enumerate(content.splitlines()):
        excerpt = line.strip()
        if not excerpt:
            continue
        line_number = start_line + offset
        for evidence_type, pattern, summary in _PATTERNS:
            identity = (evidence_type, line_number, excerpt)
            if pattern.search(line) is None or identity in observed:
                continue
            observed.add(identity)
            result.append(
                ResourceObservation(
                    type=evidence_type,
                    line_number=line_number,
                    excerpt=excerpt,
                    summary=summary,
                )
            )
    return tuple(result)


__all__ = ["ResourceObservation", "extract_resource_observations"]
