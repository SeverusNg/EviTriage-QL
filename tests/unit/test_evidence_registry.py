from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from evitriage.context import ContextBuilder
from evitriage.domain.context import SliceArtifact
from evitriage.domain.evidence import EvidenceRegistry
from evitriage.domain.run import ArtifactRecord
from evitriage.evidence import build_evidence_registry, evidence_graph_dot, source_map_html
from evitriage.sarif import ingest_sarif

FIXTURES = Path(__file__).parents[1] / "fixtures"
SOURCE_ROOT = FIXTURES / "java-microbench/path-app"


def _registry() -> tuple[EvidenceRegistry, tuple[SliceArtifact, ...]]:
    bundle = ingest_sarif(
        FIXTURES / "sarif/single-path.sarif",
        source_root=SOURCE_ROOT,
        run_id="gate-c-evidence",
        repository_identity="fixture-repository",
    )
    slices = ContextBuilder(SOURCE_ROOT.resolve()).build(bundle, policy_name="path_function_slice")
    normalized = ArtifactRecord(
        relative_path="normalized/alerts.json",
        sha256="1" * 64,
        size_bytes=100,
        role="normalized",
        media_type="application/json",
    )
    slice_record = ArtifactRecord(
        relative_path="context/slices/run-000000-result-000000.json",
        sha256="2" * 64,
        size_bytes=200,
        role="context",
        media_type="application/json",
    )
    registry = build_evidence_registry(
        bundle,
        normalized_artifact=normalized,
        persisted_slices=((slices[0], slice_record),),
    )
    return registry, slices


def test_registry_is_artifact_addressed_and_exports_closed_graph_and_source_map() -> None:
    registry, slices = _registry()

    assert registry.claims == ()
    assert {item.origin for item in registry.items} == {"codeql", "repository"}
    assert {item.polarity for item in registry.items} <= {"neutral", "supports_tp"}
    assert all(item.strength != "decisive" for item in registry.items)
    assert all(
        item.artifact_sha256 in {artifact.artifact_sha256 for artifact in registry.artifacts}
        for item in registry.items
    )
    assert registry.relationships
    assert any(item.source_anchor for item in registry.items)

    dot = evidence_graph_dot(registry)
    assert dot.startswith("digraph evidence {")
    assert all(item.evidence_id in dot for item in registry.items)
    html = source_map_html(slices, registry)
    assert "not a vulnerability classification" in html
    assert "readRequestedFile" in html
    assert "source" in html and "sink" in html
    assert "related 0" in html
    source_anchor = next(item.source_anchor for item in registry.items if item.source_anchor)
    assert f'href="#{source_anchor}"' in html
    assert f'id="{source_anchor}"' in html
    source_slice = slices[0].content.source_slices[0]
    for line_number in (12, 15):
        assert f'href="#{source_slice.slice_id}-L{line_number}"' in html


def test_registry_rejects_dangling_relationship_claim_and_artifact_references() -> None:
    registry, _ = _registry()
    unknown_evidence = "ev_" + "f" * 64

    relationship_payload = registry.model_dump(mode="python")
    relationship_payload["relationships"] = (
        *relationship_payload["relationships"],
        {
            "source_evidence_id": registry.items[0].evidence_id,
            "relation": "depends_on",
            "target_evidence_id": unknown_evidence,
        },
    )
    with pytest.raises(ValidationError, match="dangling evidence ID"):
        EvidenceRegistry.model_validate(relationship_payload, strict=True)

    claim_payload = registry.model_dump(mode="python")
    claim_payload["claims"] = (
        {
            "schema_version": "1.0",
            "claim_id": "cl_" + "a" * 64,
            "kind": "path_feasible",
            "statement": "This intentionally invalid claim cites missing evidence.",
            "status": "supported",
            "evidence_ids": (unknown_evidence,),
            "produced_by": "analyst",
        },
    )
    with pytest.raises(ValidationError, match="dangling evidence ID"):
        EvidenceRegistry.model_validate(claim_payload, strict=True)

    artifact_payload = registry.model_dump(mode="python")
    artifact_payload["artifacts"] = artifact_payload["artifacts"][:1]
    with pytest.raises(ValidationError, match="unknown artifact"):
        EvidenceRegistry.model_validate(artifact_payload, strict=True)

    item_payload = registry.items[0].model_dump(mode="python")
    item_payload["summary"] = "tampered after ID allocation"
    with pytest.raises(ValidationError, match="canonical evidence content"):
        type(registry.items[0]).model_validate(item_payload, strict=True)
