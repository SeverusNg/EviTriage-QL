from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from pydantic import BaseModel

from evitriage.domain.resource import ResourceClaimDraft, materialize_resource_claim
from evitriage.evaluation import (
    LegacyBaselineBinding,
    bind_legacy_baseline_after_finalization,
    evaluate_final_decisions,
)
from evitriage.llm import (
    InvocationContext,
    LLMProfile,
    ReplayLLM,
    canonical_request_sha256,
)
from evitriage.pipeline import run_sarif_triage


class _ResourceCacheProducer:
    """Test-only producer for synthetic, request-addressed resource responses."""

    def __init__(self, profile: LLMProfile, cache: Path) -> None:
        self.profile = profile
        self.cache = cache

    def complete[ResponseT: BaseModel](
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[ResponseT],
        invocation_context: InvocationContext,
    ) -> ResponseT:
        evidence = cast(
            list[dict[str, object]],
            cast(dict[str, object], user_payload["untrusted_code_data"])["evidence_items"],
        )
        evidence_by_type = {str(item["type"]): str(item["evidence_id"]) for item in evidence}
        source = evidence_by_type["resource_lifecycle"]
        acquisition = evidence_by_type["resource_acquisition"]
        exit_evidence = evidence_by_type["control_flow_exit"]
        not_applicable = {
            "status": "absent",
            "detail": "The bounded local lock path invokes no external owner.",
            "evidence_ids": [source],
        }
        absent = {
            "status": "absent",
            "detail": "The bounded method contains no ownership escape or release.",
            "evidence_ids": [source],
        }
        analyst_drafts = (
            ResourceClaimDraft(
                kind="resource_acquisition",
                statement="The lock call is a successful acquisition candidate.",
                status="supported",
                evidence_ids=(acquisition, source),
            ),
            ResourceClaimDraft(
                kind="feasible_unreleased_exit",
                statement="A return follows acquisition without unlock.",
                status="supported",
                evidence_ids=(exit_evidence, source),
            ),
        )
        if invocation_context.agent_role == "analyst":
            payload: dict[str, object] = {
                "schema_version": "1.0",
                "resource_kind": "lock",
                "acquisition_succeeds": "yes",
                "acquisition_condition": "lock() returns normally.",
                "acquisition_evidence_ids": [acquisition, source],
                "release_sites": [],
                "release_coverage": absent,
                "feasible_unreleased_exit": {
                    "status": "confirmed",
                    "exit_kind": "return",
                    "detail": "The acquired lock reaches return without unlock.",
                    "evidence_ids": [exit_evidence, source],
                },
                "ownership_transfer": absent,
                "resource_escape": absent,
                "callee_release_behavior": not_applicable,
                "lifecycle_contract": not_applicable,
                "context_gaps": [],
                "claims": [item.model_dump(mode="json") for item in analyst_drafts],
                "unknowns": [],
            }
        elif invocation_context.agent_role == "rebuttal":
            payload = {
                "schema_version": "1.0",
                "resource_kind": "lock",
                "release_coverage": absent,
                "ownership_transfer": absent,
                "resource_escape": absent,
                "callee_release_behavior": not_applicable,
                "lifecycle_contract": not_applicable,
                "context_gaps": [],
                "claims": [],
                "rebutted_claim_ids": [],
                "unknowns": [],
            }
        else:
            claims = tuple(
                materialize_resource_claim(item, produced_by="analyst") for item in analyst_drafts
            )
            payload = {
                "schema_version": "1.0",
                "resource_kind": "lock",
                "label": "TP",
                "raw_confidence": 0.9,
                "critical_claim_ids": [item.claim_id for item in claims],
                "critical_evidence_ids": [source, acquisition, exit_evidence],
                "unknowns": [],
                "reasoning_summary": "Synthetic acquired-return path lacks unlock.",
                "next_actions": [],
                "fix_guidance": ["Use a finally block to unlock after acquisition."],
            }
        request_sha = canonical_request_sha256(
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_model=response_model,
            invocation_context=invocation_context,
        )
        (self.cache / f"{request_sha}.json").write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8"
        )
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return response_model.model_validate_json(serialized, strict=True)


def test_resource_pipeline_is_canonical_replayable_and_report_closed(
    repository_root: Path, tmp_path: Path
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Resource.java").write_text(
        """class Resource {
  boolean check(java.util.concurrent.locks.Lock lock) {
    lock.lock();
    return true;
  }
}
""",
        encoding="utf-8",
    )
    sarif = tmp_path / "resource.sarif"
    sarif.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "columnKind": "unicodeCodePoints",
                        "tool": {
                            "driver": {
                                "name": "CodeQL",
                                "rules": [{"id": "java/unreleased-lock"}],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "java/unreleased-lock",
                                "message": {"text": "Lock may not be released"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "Resource.java"},
                                            "region": {"startLine": 3},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    project = tmp_path / "project.yaml"
    project.write_text(
        f"""schema_version: "1.0"
project:
  id: resource-replay-test
  display_name: Resource Replay Test
  language: java
source:
  type: local
  path: {source_root}
  snapshot_mode: copy
  require_clean_git: false
  submodules: false
build:
  adapter: maven
  jdk: "17"
  command: ["./mvnw", "--offline", "package"]
  network_policy: disabled
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: [security-and-quality]
  query_packs: []
  model_packs: []
  include_query_help: true
analysis:
  target_cwes: [CWE-404]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
security:
  source_upload_policy: offline_only
  allow_build_network: false
  allow_submodules: false
  allow_generated_shell: false
storage:
  workspace_root: {tmp_path / "workspaces"}
  artifact_root: {tmp_path / "artifacts"}
""",
        encoding="utf-8",
    )
    cache = tmp_path / "cache"
    cache.mkdir()
    profile = LLMProfile(
        id="replay-v0.1",
        provider="replay",
        model_id="evitriage-offline-replay-v0.1",
    )
    first = run_sarif_triage(
        repository_root,
        project_config=project,
        sarif_path=sarif,
        profile=profile,
        llm=_ResourceCacheProducer(profile, cache),
        allowed_source_roots=(source_root,),
        allowed_workspace_roots=(tmp_path / "workspaces",),
        allowed_artifact_roots=(tmp_path / "artifacts",),
    )
    second = run_sarif_triage(
        repository_root,
        project_config=project,
        sarif_path=sarif,
        profile=profile,
        llm=ReplayLLM(profile, cache),
        allowed_source_roots=(source_root,),
        allowed_workspace_roots=(tmp_path / "workspaces",),
        allowed_artifact_roots=(tmp_path / "artifacts",),
    )

    assert first.tp_count == second.tp_count == 1
    assert first.invocation_count == second.invocation_count == 3
    assert len(tuple(cache.glob("*.json"))) == 3
    decision = Path(second.artifact_run_root) / second.report_jsonl.relative_path
    row = json.loads(decision.read_text(encoding="utf-8"))
    assert row["triage"]["final_decision"]["auto_dismiss"] is False
    assert row["triage"]["final_decision"]["label"] == "TP"

    # Human input is introduced only after the pipeline has frozen the
    # automatic decision artifact read-only.
    baseline_marker = "HUMAN-BASELINE-MUST-NOT-BE-MODEL-EVIDENCE"
    baseline = tmp_path / "baseline.jsonl"
    baseline.write_text(
        json.dumps(
            {
                "id": "L-0",
                "query": "java/unreleased-lock",
                "file": "Resource.java",
                "line": 3,
                "method": "check",
                "scope": "synthetic-test",
                "label": "TP",
                "label_basis": "human_evidence_review",
                "evidence": baseline_marker,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    reference = row["alert"]["raw_result_reference"]
    bindings = (
        LegacyBaselineBinding(
            id_prefix="L",
            raw_sarif_sha256=reference["raw_sarif_sha256"],
            rule_id="java/unreleased-lock",
        ),
    )
    human = bind_legacy_baseline_after_finalization((decision,), baseline, bindings)
    evaluation = evaluate_final_decisions((decision,), human)

    assert evaluation.aligned_count == 1
    assert evaluation.agreement == 1
    assert evaluation.baseline_registered_as_model_evidence is False
    assert baseline_marker not in decision.read_text(encoding="utf-8")
