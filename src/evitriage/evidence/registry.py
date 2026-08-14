"""Build and export a closed, artifact-addressed Gate C evidence registry."""

from __future__ import annotations

import hashlib
import html
import json
from collections.abc import Mapping
from typing import Literal

from pydantic import BaseModel

from evitriage.domain.alerts import AlertBundle, NormalizedAlert, SourceLocation
from evitriage.domain.context import SliceArtifact
from evitriage.domain.evidence import (
    EvidenceArtifactReference,
    EvidenceItem,
    EvidenceOrigin,
    EvidencePolarity,
    EvidenceRegistry,
    EvidenceRelationship,
    EvidenceStrength,
    EvidenceSupplement,
    EvidenceType,
)
from evitriage.domain.resource import classify_query_family
from evitriage.domain.run import ArtifactRecord
from evitriage.errors import PolicyRejectedError
from evitriage.evidence.resource import extract_resource_observations

_REGISTRY_EXTRACTOR = "evidence-registry@1.0"
_SUPPLEMENT_EXTRACTOR = "evidence-supplement@1.0"


def build_evidence_registry(
    bundle: AlertBundle,
    *,
    normalized_artifact: ArtifactRecord,
    persisted_slices: tuple[tuple[SliceArtifact, ArtifactRecord], ...],
) -> EvidenceRegistry:
    """Derive bounded evidence without upgrading CodeQL facts into verdicts."""

    by_occurrence = {
        (
            artifact.content.raw_result_reference.run_index,
            artifact.content.raw_result_reference.result_index,
        ): (artifact, record)
        for artifact, record in persisted_slices
    }
    artifacts = [
        EvidenceArtifactReference(
            kind="normalized",
            relative_path=normalized_artifact.relative_path,
            artifact_sha256=normalized_artifact.sha256,
        )
    ]
    artifacts.extend(
        EvidenceArtifactReference(
            kind="slice",
            relative_path=record.relative_path,
            artifact_sha256=record.sha256,
        )
        for _artifact, record in persisted_slices
    )
    items: list[EvidenceItem] = []
    relationships: list[EvidenceRelationship] = []
    for alert in bundle.alerts:
        occurrence = (
            alert.raw_result_reference.run_index,
            alert.raw_result_reference.result_index,
        )
        persisted = by_occurrence.get(occurrence)
        location_anchors: dict[tuple[str, int], str] = {}
        if persisted is not None:
            for source_slice in persisted[0].content.source_slices:
                for line_number in range(source_slice.start_line, source_slice.end_line + 1):
                    location_anchors[(source_slice.path, line_number)] = (
                        f"{source_slice.slice_id}-L{line_number}"
                    )
        rule_item = _evidence_item(
            alert,
            type="rule_semantics",
            polarity="neutral",
            strength="low",
            origin="codeql",
            location=alert.primary_location,
            excerpt=None,
            artifact_sha256=normalized_artifact.sha256,
            extractor="sarif-normalizer@1.0",
            summary=(
                f"Normalized CodeQL rule metadata for {alert.rule.rule_id}; this is upstream "
                "alert context, not an EviTriage vulnerability verdict."
            ),
            source_anchor=location_anchors.get(
                (alert.primary_location.path, alert.primary_location.start_line)
            ),
        )
        items.append(rule_item)
        path_items: dict[int, EvidenceItem] = {}
        for path in alert.paths:
            path_item = _evidence_item(
                alert,
                type="data_flow",
                polarity="supports_tp",
                strength="medium",
                origin="codeql",
                location=path.source.location,
                excerpt=None,
                artifact_sha256=normalized_artifact.sha256,
                extractor="sarif-normalizer@1.0",
                summary=(
                    f"CodeQL recorded ordered path {path.ordinal} with {len(path.steps)} "
                    "occurrence(s); feasibility and exploitability remain unverified."
                ),
                path_fingerprint=path.path_fingerprint,
                source_anchor=location_anchors.get(
                    (path.source.location.path, path.source.location.start_line)
                ),
            )
            items.append(path_item)
            path_items[path.ordinal] = path_item
            relationships.append(
                EvidenceRelationship(
                    source_evidence_id=path_item.evidence_id,
                    relation="depends_on",
                    target_evidence_id=rule_item.evidence_id,
                )
            )
        if persisted is None:
            continue
        slice_artifact, slice_record = persisted
        resource_family = classify_query_family(alert.rule.rule_id)
        slice_evidence: dict[str, EvidenceItem] = {}
        for source_slice in slice_artifact.content.source_slices:
            location = SourceLocation(
                path=source_slice.path,
                column_kind="unicodeCodePoints",
                start_line=source_slice.start_line,
                start_column=1,
                end_line=source_slice.end_line,
                artifact_sha256=source_slice.artifact_sha256,
            )
            is_resource = resource_family != "legacy_security"
            source_item = _evidence_item(
                alert,
                type="resource_lifecycle" if is_resource else "data_flow",
                polarity="neutral",
                strength="low",
                origin="repository",
                location=location,
                excerpt=source_slice.content if is_resource else None,
                artifact_sha256=slice_record.sha256,
                extractor="java-resource-context@1.0" if is_resource else "java-context@1.0",
                summary=(
                    f"Bounded repository excerpt selected by {source_slice.selection}; code text "
                    "is untrusted data and carries no standalone security semantics."
                ),
                source_anchor=f"{source_slice.slice_id}-L{source_slice.start_line}",
            )
            items.append(source_item)
            slice_evidence[source_slice.slice_id] = source_item
            if is_resource:
                lifecycle_items = tuple(
                    _evidence_item(
                        alert,
                        type=observation.type,
                        polarity="neutral",
                        strength="low",
                        origin="repository",
                        location=SourceLocation(
                            path=source_slice.path,
                            column_kind="unicodeCodePoints",
                            start_line=observation.line_number,
                            start_column=1,
                            end_line=observation.line_number,
                            end_column=len(observation.excerpt) + 1,
                            artifact_sha256=source_slice.artifact_sha256,
                        ),
                        excerpt=observation.excerpt,
                        artifact_sha256=slice_record.sha256,
                        extractor="java-resource-lexical@1.0",
                        summary=observation.summary,
                        source_anchor=(f"{source_slice.slice_id}-L{observation.line_number}"),
                    )
                    for observation in extract_resource_observations(
                        source_slice.content,
                        start_line=source_slice.start_line,
                    )
                )
                items.extend(lifecycle_items)
                relationships.extend(
                    EvidenceRelationship(
                        source_evidence_id=item.evidence_id,
                        relation="depends_on",
                        target_evidence_id=source_item.evidence_id,
                    )
                    for item in lifecycle_items
                )
            dependencies = {
                path_items[reference.path_ordinal].evidence_id
                for reference in source_slice.references
                if reference.path_ordinal is not None and reference.path_ordinal in path_items
            }
            if not dependencies:
                dependencies = {rule_item.evidence_id}
            relationships.extend(
                EvidenceRelationship(
                    source_evidence_id=source_item.evidence_id,
                    relation="depends_on",
                    target_evidence_id=dependency,
                )
                for dependency in sorted(dependencies)
            )
        if resource_family != "legacy_security":
            for omission in slice_artifact.content.omitted:
                gap_item = _evidence_item(
                    alert,
                    type="context_gap",
                    polarity="neutral",
                    strength="high",
                    origin="repository",
                    location=None,
                    excerpt=None,
                    artifact_sha256=slice_record.sha256,
                    extractor="java-resource-context@1.0",
                    summary=f"Resource context omission {omission.code}: {omission.detail}",
                )
                items.append(gap_item)
                relationships.append(
                    EvidenceRelationship(
                        source_evidence_id=gap_item.evidence_id,
                        relation="depends_on",
                        target_evidence_id=rule_item.evidence_id,
                    )
                )
        for candidate in (
            *slice_artifact.content.guards,
            *slice_artifact.content.candidate_sanitizers,
        ):
            containing = next(
                (
                    source_slice
                    for source_slice in slice_artifact.content.source_slices
                    if source_slice.path == candidate.location.path
                    and source_slice.start_line
                    <= candidate.location.start_line
                    <= source_slice.end_line
                ),
                None,
            )
            if containing is None:
                continue
            candidate_item = _evidence_item(
                alert,
                type=candidate.kind,
                polarity="neutral",
                strength="low",
                origin="repository",
                location=candidate.location,
                excerpt=candidate.excerpt,
                artifact_sha256=slice_record.sha256,
                extractor=candidate.extractor,
                summary=(
                    f"Lexical {candidate.kind} candidate only; semantic effectiveness is "
                    "unresolved and must not be inferred from its name or text."
                ),
                source_anchor=f"{containing.slice_id}-L{candidate.location.start_line}",
            )
            items.append(candidate_item)
            relationships.append(
                EvidenceRelationship(
                    source_evidence_id=candidate_item.evidence_id,
                    relation="depends_on",
                    target_evidence_id=slice_evidence[containing.slice_id].evidence_id,
                )
            )
    return EvidenceRegistry(
        run_id=bundle.run_id,
        repository_identity=bundle.repository_identity,
        raw_sarif_sha256=bundle.raw_sarif_sha256,
        artifacts=tuple(artifacts),
        items=tuple(items),
        relationships=tuple(relationships),
        claims=(),
    )


def merge_evidence_supplement(
    registry: EvidenceRegistry,
    bundle: AlertBundle,
    supplement: EvidenceSupplement,
    *,
    supplement_artifact: ArtifactRecord,
) -> EvidenceRegistry:
    """Materialize explicit observations without letting them change alert identity."""

    if supplement.repository_identity != registry.repository_identity:
        raise PolicyRejectedError("evidence supplement source identity does not match the run")
    if supplement.raw_sarif_sha256 != registry.raw_sarif_sha256:
        raise PolicyRejectedError("evidence supplement SARIF identity does not match the run")
    if supplement_artifact.role != "input":
        raise PolicyRejectedError("evidence supplement artifact must retain the input role")

    alerts_by_occurrence = {
        (
            alert.raw_result_reference.run_index,
            alert.raw_result_reference.result_index,
        ): alert
        for alert in bundle.alerts
    }
    origin_by_kind: dict[str, EvidenceOrigin] = {
        "human": "human",
        "test": "test",
        "verification": "verifier",
    }
    artifact_kind_by_supplement: dict[str, Literal["human", "test", "verification"]] = {
        "human": "human",
        "test": "test",
        "verification": "verification",
    }
    added_items: list[EvidenceItem] = []
    for entry in supplement.entries:
        occurrence = (entry.run_index, entry.result_index)
        alert = alerts_by_occurrence.get(occurrence)
        if alert is None:
            raise PolicyRejectedError(
                "evidence supplement cites an unavailable SARIF result occurrence",
                details={"run_index": entry.run_index, "result_index": entry.result_index},
            )
        added_items.append(
            _evidence_item(
                alert,
                type=entry.type,
                polarity=entry.polarity,
                strength=entry.strength,
                origin=origin_by_kind[supplement.kind],
                location=None,
                excerpt=None,
                artifact_sha256=supplement_artifact.sha256,
                extractor=_SUPPLEMENT_EXTRACTOR,
                summary=entry.summary,
            )
        )

    return EvidenceRegistry(
        run_id=registry.run_id,
        repository_identity=registry.repository_identity,
        raw_sarif_sha256=registry.raw_sarif_sha256,
        artifacts=(
            *registry.artifacts,
            EvidenceArtifactReference(
                kind=artifact_kind_by_supplement[supplement.kind],
                relative_path=supplement_artifact.relative_path,
                artifact_sha256=supplement_artifact.sha256,
            ),
        ),
        items=(*registry.items, *added_items),
        relationships=registry.relationships,
        claims=registry.claims,
    )


def evidence_graph_dot(registry: EvidenceRegistry) -> str:
    """Return a deterministic Graphviz DOT view of the validated evidence graph."""

    lines = ["digraph evidence {", "  rankdir=LR;"]
    for item in registry.items:
        label = _dot_escape(f"{item.type}\n{item.evidence_id[:15]}")
        lines.append(f'  "{item.evidence_id}" [label="{label}"];')
    for relationship in registry.relationships:
        label = _dot_escape(relationship.relation)
        lines.append(
            f'  "{relationship.source_evidence_id}" -> '
            f'"{relationship.target_evidence_id}" [label="{label}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def source_map_html(
    slices: tuple[SliceArtifact, ...],
    registry: EvidenceRegistry,
) -> str:
    """Render an escaped, non-verdict HTML index for source/path navigation."""

    unique_slices = {
        source_slice.slice_id: source_slice
        for artifact in slices
        for source_slice in artifact.content.source_slices
    }
    location_anchors = {
        (source_slice.path, line_number): f"{source_slice.slice_id}-L{line_number}"
        for source_slice in unique_slices.values()
        for line_number in range(source_slice.start_line, source_slice.end_line + 1)
    }
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        "<title>EviTriage Gate C source map</title></head><body>",
        "<h1>EviTriage Gate C source map</h1>",
        "<p>This navigation artifact contains untrusted source/SARIF data. "
        "It is not a vulnerability classification or security verdict.</p>",
        "<h2>Evidence</h2><ul>",
    ]
    for item in registry.items:
        target = (
            f' href="#{html.escape(item.source_anchor, quote=True)}"' if item.source_anchor else ""
        )
        parts.append(
            f"<li><a{target}>{html.escape(item.evidence_id)}</a>: {html.escape(item.summary)}</li>"
        )
    parts.append("</ul><h2>Alert paths</h2>")
    for artifact in slices:
        content = artifact.content
        parts.append(
            f"<section><h3>{html.escape(content.level_zero.rule.rule_id)} — "
            f"{html.escape(content.alert_fingerprint)}</h3>"
        )
        primary = content.level_zero.primary_location
        primary_text = f"{html.escape(primary.path)}:{primary.start_line}"
        primary_anchor = location_anchors.get((primary.path, primary.start_line))
        if primary_anchor is not None:
            escaped_anchor = html.escape(primary_anchor, quote=True)
            primary_text = f'<a href="#{escaped_anchor}">{primary_text}</a>'
        parts.append(f"<p>primary: {primary_text}</p>")
        for label, locations in (
            ("additional", content.level_zero.additional_locations),
            ("related", content.level_zero.related_locations),
        ):
            for ordinal, location in enumerate(locations):
                location_text = f"{html.escape(location.path)}:{location.start_line}"
                location_anchor = location_anchors.get((location.path, location.start_line))
                if location_anchor is not None:
                    escaped_anchor = html.escape(location_anchor, quote=True)
                    location_text = f'<a href="#{escaped_anchor}">{location_text}</a>'
                parts.append(f"<p>{label} {ordinal}: {location_text}</p>")
        parts.append("<ol>")
        for path in content.level_zero.paths:
            rendered_step_list: list[str] = []
            for step in path.steps:
                step_text = (
                    f"{html.escape(step.step_kind)} {html.escape(step.location.path)}:"
                    f"{step.location.start_line}"
                )
                step_anchor = location_anchors.get((step.location.path, step.location.start_line))
                if step_anchor is not None:
                    escaped_anchor = html.escape(step_anchor, quote=True)
                    step_text = f'<a href="#{escaped_anchor}">{step_text}</a>'
                rendered_step_list.append(step_text)
            rendered_steps = " → ".join(rendered_step_list)
            parts.append(f"<li>path {path.ordinal}: {rendered_steps}</li>")
        parts.append("</ol></section>")
    parts.append("<h2>Selected source</h2>")
    for source_slice in unique_slices.values():
        symbol = (
            f" ({html.escape(source_slice.enclosing_symbol)})"
            if source_slice.enclosing_symbol
            else ""
        )
        parts.append(
            f'<section id="{html.escape(source_slice.slice_id, quote=True)}"><h3>'
            f"{html.escape(source_slice.path)}:{source_slice.start_line}-{source_slice.end_line}"
            f"{symbol}</h3><pre><code>"
        )
        source_lines = source_slice.content.splitlines()
        for offset, line in enumerate(source_lines):
            line_number = source_slice.start_line + offset
            anchor = f"{source_slice.slice_id}-L{line_number}"
            escaped_anchor = html.escape(anchor, quote=True)
            parts.append(
                f'<span id="{escaped_anchor}"><a href="#{escaped_anchor}">'
                f"{line_number:6d}</a> {html.escape(line)}</span>\n"
            )
        parts.append("</code></pre></section>")
    parts.append("</body></html>\n")
    return "".join(parts)


def _evidence_item(
    alert: NormalizedAlert,
    *,
    type: EvidenceType,
    polarity: EvidencePolarity,
    strength: EvidenceStrength,
    origin: EvidenceOrigin,
    location: SourceLocation | None,
    excerpt: str | None,
    artifact_sha256: str,
    extractor: str,
    summary: str,
    path_fingerprint: str | None = None,
    source_anchor: str | None = None,
) -> EvidenceItem:
    fields: dict[str, object] = {
        "type": type,
        "polarity": polarity,
        "strength": strength,
        "origin": origin,
        "location": location,
        "excerpt": excerpt,
        "artifact_sha256": artifact_sha256,
        "extractor": extractor,
        "summary": summary,
        "path_fingerprint": path_fingerprint,
        "source_anchor": source_anchor,
    }
    identity: dict[str, object] = {
        "alert_fingerprint": alert.alert_fingerprint,
        "raw_result_reference": alert.raw_result_reference.model_dump(mode="json"),
        **fields,
    }
    canonical = json.dumps(
        _json_compatible(identity),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return EvidenceItem(
        evidence_id="ev_" + hashlib.sha256(canonical).hexdigest(),
        alert_fingerprint=alert.alert_fingerprint,
        raw_result_reference=alert.raw_result_reference,
        type=type,
        polarity=polarity,
        strength=strength,
        origin=origin,
        location=location,
        excerpt=excerpt,
        artifact_sha256=artifact_sha256,
        extractor=extractor,
        summary=summary,
        path_fingerprint=path_fingerprint,
        source_anchor=source_anchor,
    )


def _json_compatible(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    return value


def _dot_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


__all__ = [
    "build_evidence_registry",
    "evidence_graph_dot",
    "merge_evidence_supplement",
    "source_map_html",
]
