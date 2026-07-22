from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import ClassVar, cast

import pytest
import yaml
from pydantic import BaseModel, JsonValue, ValidationError
from typer.testing import CliRunner

from evitriage.agents import TriageWorkflow
from evitriage.cli import app
from evitriage.codeql import CodeQLVersionMismatchError
from evitriage.domain.evidence import EvidenceRegistry
from evitriage.domain.report import AlertReport
from evitriage.domain.triage import (
    AgentRole,
    ClaimDraft,
    JudgedRunArtifact,
    TriageRunSummary,
    TriageTarget,
    materialize_claim,
)
from evitriage.errors import FeatureNotAvailableError, PolicyRejectedError, ReplayMissError
from evitriage.llm import (
    DeepSeekLLM,
    InvocationContext,
    LLMProfile,
    ReplayLLM,
    ScriptedResponse,
    canonical_request_sha256,
)
from evitriage.pipeline import (
    run_codeql_scan,
    run_sarif_ingest,
    run_sarif_triage,
)
from evitriage.sarif import InvalidSarifError

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sarif"
runner = CliRunner()


class _ReplayFixtureRecorder:
    def __init__(self, responses: Sequence[ScriptedResponse]) -> None:
        self._responses = tuple(responses)
        self._cursor = 0
        self.request_sha256s: list[str] = []

    def complete[ResponseT: BaseModel](
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[ResponseT],
        invocation_context: InvocationContext,
    ) -> ResponseT:
        scripted = self._responses[self._cursor]
        self._cursor += 1
        assert scripted.agent_role == invocation_context.agent_role
        assert not isinstance(scripted.payload, bytes)
        self.request_sha256s.append(
            canonical_request_sha256(
                system_prompt=system_prompt,
                user_payload=user_payload,
                response_model=response_model,
                invocation_context=invocation_context,
            )
        )
        return response_model.model_validate_json(
            json.dumps(scripted.payload),
            strict=True,
        )


class _QueuedDeepSeekResponse:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self.status = 200

    def read(self, maximum_bytes: int) -> bytes:
        return self._payload[:maximum_bytes]


class _QueuedDeepSeekConnection:
    responses: ClassVar[list[bytes]] = []
    requests: ClassVar[list[dict[str, object]]] = []

    def __init__(self, host: str, port: int, *, timeout: int) -> None:
        self._connection = {"host": host, "port": port, "timeout": timeout}

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.requests.append(
            {
                **self._connection,
                "method": method,
                "path": path,
                "body": body,
                "headers": headers,
            }
        )

    def getresponse(self) -> _QueuedDeepSeekResponse:
        return _QueuedDeepSeekResponse(self.responses.pop(0))

    def close(self) -> None:
        return None


def _nmc_replay_responses(registry: EvidenceRegistry) -> tuple[ScriptedResponse, ...]:
    evidence = registry.items[0]
    draft = ClaimDraft(
        kind="path_feasible",
        statement="The supplied evidence does not resolve complete path feasibility.",
        status="unresolved",
    )
    claim = materialize_claim(draft, produced_by="analyst")
    payloads: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "analyst",
            {
                "schema_version": "1.0",
                "claims": [draft.model_dump(mode="json")],
                "unknowns": ["Source control and sink semantics remain unresolved."],
            },
        ),
        (
            "rebuttal",
            {
                "schema_version": "1.0",
                "claims": [],
                "rebutted_claim_ids": [],
                "unknowns": ["No decisive false-positive evidence is present."],
            },
        ),
        (
            "judge",
            {
                "schema_version": "1.0",
                "label": "NMC",
                "raw_confidence": 0.5,
                "critical_claim_ids": [claim.claim_id],
                "critical_evidence_ids": [evidence.evidence_id],
                "unknowns": ["Exploitability is not established."],
                "reasoning_summary": "The bounded record is insufficient for TP or FP.",
                "next_actions": ["Obtain source-control and sink-semantics evidence."],
                "fix_guidance": [],
            },
        ),
    )
    return tuple(
        ScriptedResponse(cast(AgentRole, role), cast(JsonValue, payload))
        for role, payload in payloads
    )


def _gate_b_repository(tmp_path: Path) -> tuple[Path, Path, bytes]:
    repository = tmp_path / "repository"
    source = repository / "fixture"
    config = repository / "configs" / "projects" / "fixture.yaml"
    source_file = source / "src/main/java/org/evitriage/fixture/PathReader.java"
    source_file.parent.mkdir(parents=True)
    config.parent.mkdir(parents=True)
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "evitriage-ql"\n', encoding="utf-8"
    )
    source_bytes = (
        Path(__file__).parents[1]
        / "fixtures/java-microbench/path-app/src/main/java/org/evitriage/fixture/PathReader.java"
    ).read_bytes()
    source_file.write_bytes(source_bytes)
    wrapper = source / "mvnw"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o700)
    wrapper_properties = source / ".mvn" / "wrapper" / "maven-wrapper.properties"
    wrapper_properties.parent.mkdir(parents=True)
    wrapper_properties.write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/"
        "apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n"
        "distributionSha256Sum="
        "4ec3f26fb1a692473aea0235c300bd20f0f9fe741947c82c1234cefd76ac3a3c\n",
        encoding="utf-8",
    )
    config.write_text(
        """\
schema_version: "1.0"
project:
  id: gate-b-fixture
  display_name: Gate B Fixture
  language: java
  license_hint: Apache-2.0
source:
  type: local
  path: fixture
  snapshot_mode: copy
  require_clean_git: false
  submodules: false
build:
  adapter: maven
  jdk: "17"
  working_directory: "."
  command: ["./mvnw", "--offline", "-q", "package"]
  timeout_seconds: 60
  network_policy: disabled
codeql:
  cli_version: "2.26.1"
  language: java-kotlin
  query_suites: [security-extended]
  query_packs: []
  model_packs: []
  include_query_help: true
analysis:
  target_cwes: [CWE-22]
  context_policy: path_function_slice
  workflow: evidence_three_agent
  llm_profile: replay-v0.1
security:
  source_upload_policy: offline_only
  allow_build_network: false
  allow_submodules: false
  allow_generated_shell: false
storage:
  workspace_root: workspaces
  artifact_root: artifacts
""",
        encoding="utf-8",
    )
    return repository, config, source_bytes


def _write_replay_cache(
    cache: Path,
    *,
    profile: LLMProfile,
    registry: EvidenceRegistry,
) -> None:
    cache.mkdir()
    evidence = registry.items[0]
    target = TriageTarget(
        alert_fingerprint=evidence.alert_fingerprint,
        raw_result_reference=evidence.raw_result_reference,
    )
    responses = _nmc_replay_responses(registry)
    recorder = _ReplayFixtureRecorder(responses)
    result = TriageWorkflow(profile=profile).triage(
        registry=registry,
        target=target,
        llm=recorder,
    )
    assert result.final_decision.label == "NMC"
    for request_sha256, scripted in zip(recorder.request_sha256s, responses, strict=True):
        assert not isinstance(scripted.payload, bytes)
        (cache / f"{request_sha256}.json").write_text(
            json.dumps(scripted.payload, sort_keys=True),
            encoding="utf-8",
        )


@pytest.mark.integration
def test_ingest_and_normalize_cli_share_one_auditable_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, source_bytes = _gate_b_repository(tmp_path)
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository))
    sarif = FIXTURES / "single-path.sarif"

    ingested = runner.invoke(
        app,
        [
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(sarif),
            "--json",
        ],
    )
    normalized = runner.invoke(
        app,
        [
            "normalize",
            "--project-config",
            str(config),
            "--sarif",
            str(sarif),
            "--json",
        ],
    )

    assert ingested.exit_code == 0, ingested.output
    assert normalized.exit_code == 0, normalized.output
    first = json.loads(ingested.stdout)
    second = json.loads(normalized.stdout)
    assert first["status"] == second["status"] == "ok"
    assert first["command"] == "ingest-sarif"
    assert second["command"] == "normalize"
    assert first["real_codeql"] is second["real_codeql"] is False
    assert first["alert_count"] == second["alert_count"] == 1
    assert first["path_count"] == second["path_count"] == 1
    assert first["state"] == second["state"] == "CONTEXT_READY"
    assert first["complete_context_count"] == second["complete_context_count"] == 1
    assert first["partial_context_count"] == second["partial_context_count"] == 0
    assert first["evidence_count"] >= 3
    assert first["claim_count"] == 0
    assert first["run_id"] != second["run_id"]

    first_root = Path(first["artifact_run_root"])
    copied_raw = first_root / first["raw_sarif"]["relative_path"]
    assert copied_raw.read_bytes() == sarif.read_bytes()
    assert first["raw_sarif"]["sha256"] == hashlib.sha256(sarif.read_bytes()).hexdigest()
    first_alert = json.loads(
        (first_root / first["normalized_bundle"]["relative_path"]).read_text(encoding="utf-8")
    )["alerts"][0]
    second_alert = json.loads(
        (
            Path(second["artifact_run_root"]) / second["normalized_bundle"]["relative_path"]
        ).read_text(encoding="utf-8")
    )["alerts"][0]
    assert first_alert["alert_fingerprint"] == second_alert["alert_fingerprint"]
    assert (
        repository / "fixture/src/main/java/org/evitriage/fixture/PathReader.java"
    ).read_bytes() == source_bytes

    manifest = json.loads((first_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert manifest["state"] == "CONTEXT_READY"
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "SARIF_INGESTED",
        "NORMALIZED",
        "CONTEXT_READY",
    ]
    registered = {artifact["relative_path"]: artifact for artifact in manifest["artifacts"]}
    assert {
        "context/index.json",
        "context/slices/run-000000-result-000000.json",
        "context/source-map.html",
        "evidence/graph.dot",
        "evidence/registry.json",
    }.issubset(registered)
    evidence = json.loads((first_root / "evidence/registry.json").read_text(encoding="utf-8"))
    assert evidence["claims"] == []
    assert {item["origin"] for item in evidence["items"]} == {"codeql", "repository"}
    assert all(
        item["artifact_sha256"]
        in {artifact["artifact_sha256"] for artifact in evidence["artifacts"]}
        for item in evidence["items"]
    )


@pytest.mark.integration
def test_triage_cli_replays_to_judged_with_durable_decision_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _source_bytes = _gate_b_repository(tmp_path)
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository))
    sarif_document = json.loads((FIXTURES / "single-path.sarif").read_text(encoding="utf-8"))
    sarif_document["runs"][0]["results"][0]["message"]["text"] = (
        'Untrusted <script>alert("report-xss")</script> message.'
    )
    sarif = tmp_path / "report-escape.sarif"
    sarif.write_text(json.dumps(sarif_document), encoding="utf-8")
    baseline = run_sarif_ingest(
        repository,
        project_config=config,
        sarif_path=sarif,
    )
    baseline_root = Path(baseline.artifact_run_root)
    registry = EvidenceRegistry.model_validate_json(
        (baseline_root / baseline.evidence_registry.relative_path).read_bytes(),
        strict=True,
    )
    profile_path = Path(__file__).parents[2] / "configs/llm/replay-v0.1.yaml"
    profile = LLMProfile(
        id="replay-v0.1",
        provider="replay",
        model_id="evitriage-offline-replay-v0.1",
    )
    replay_cache = tmp_path / "replay-cache"
    _write_replay_cache(replay_cache, profile=profile, registry=registry)

    completed = runner.invoke(
        app,
        [
            "triage",
            "--project-config",
            str(config),
            "--sarif",
            str(sarif),
            "--llm-profile",
            str(profile_path),
            "--replay-cache",
            str(replay_cache),
            "--json",
        ],
    )

    assert completed.exit_code == 0, completed.output
    summary = json.loads(completed.stdout)
    assert summary["status"] == "ok"
    assert summary["command"] == "triage"
    assert summary["state"] == "JUDGED"
    assert summary["alert_count"] == summary["nmc_count"] == 1
    assert summary["tp_count"] == summary["fp_count"] == 0
    assert summary["invocation_count"] == 3
    assert summary["analysis_identity"] == registry.run_id
    assert summary["report_jsonl"]["relative_path"] == "reports/decisions.jsonl"
    assert summary["report_html"]["relative_path"] == "reports/index.html"

    run_root = Path(summary["artifact_run_root"])
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "completed"
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "SARIF_INGESTED",
        "NORMALIZED",
        "CONTEXT_READY",
        "ANALYZED",
        "REBUTTED",
        "JUDGED",
    ]
    registered = {item["relative_path"]: item for item in manifest["artifacts"]}
    assert registered["triage/analyst.json"]["role"] == "model"
    assert registered["triage/rebuttal.json"]["role"] == "model"
    assert registered["triage/judged.json"]["role"] == "decision"
    assert registered["reports/decisions.jsonl"]["role"] == "report"
    assert registered["reports/index.html"]["role"] == "report"
    judged = JudgedRunArtifact.model_validate_json(
        (run_root / "triage/judged.json").read_bytes(), strict=True
    )
    assert judged.analysis_identity == registry.run_id
    assert judged.results[0].final_decision.label == "NMC"
    assert judged.results[0].final_decision.auto_dismiss is False
    report_lines = (run_root / "reports/decisions.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(report_lines) == 1
    report = AlertReport.model_validate_json(report_lines[0], strict=True)
    assert report.run.run_id == summary["run_id"]
    assert report.run.analysis_identity == registry.run_id
    assert report.run.tool_versions["report-renderer"] == "1.0"
    assert report.alert.paths[0].source.step_kind == "source"
    assert report.alert.paths[0].sink.step_kind == "sink"
    assert report.triage.final_decision.label == "NMC"
    assert report.triage.final_decision.auto_dismiss is False
    assert report.verification.status == "not_performed"
    assert report.human_label is None
    assert report.unknowns
    broken_report = report.model_dump(mode="python")
    broken_report["triage"]["final_decision"]["critical_evidence_ids"] = ("ev_" + "f" * 64,)
    with pytest.raises(ValidationError, match="unavailable critical evidence"):
        AlertReport.model_validate(broken_report, strict=True)
    html_report = (run_root / "reports/index.html").read_text(encoding="utf-8")
    assert "EviTriage offline triage report" in html_report
    assert "&lt;script&gt;alert(&quot;report-xss&quot;)&lt;/script&gt;" in html_report
    assert '<script>alert("report-xss")</script>' not in html_report
    assert "No alert was automatically dismissed" in html_report
    replayed_registry = EvidenceRegistry.model_validate_json(
        (run_root / "evidence/registry.json").read_bytes(), strict=True
    )
    assert [item.evidence_id for item in replayed_registry.items] == [
        item.evidence_id for item in registry.items
    ]
    for relative_path in (*registered, "run-manifest.json", "workflow-events.jsonl"):
        assert stat.S_IMODE((run_root / relative_path).stat().st_mode) == 0o400


@pytest.mark.integration
def test_triage_replay_miss_finalizes_model_failure_with_request_provenance(
    tmp_path: Path,
) -> None:
    repository, config, _source_bytes = _gate_b_repository(tmp_path)
    empty_cache = tmp_path / "empty-replay-cache"
    empty_cache.mkdir()
    profile = LLMProfile(
        id="replay-v0.1",
        provider="replay",
        model_id="evitriage-offline-replay-v0.1",
    )

    with pytest.raises(ReplayMissError) as raised:
        run_sarif_triage(
            repository,
            project_config=config,
            sarif_path=FIXTURES / "single-path.sarif",
            profile=profile,
            llm=ReplayLLM(profile, empty_cache),
        )

    assert raised.value.details["agent_role"] == "analyst"
    assert raised.value.details["response_schema"] == "AnalystOutput"
    assert len(cast(str, raised.value.details["request_sha256"])) == 64
    run_root = Path(cast(str, raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["state"] == "MODEL_FAILED"
    assert manifest["events"][-1]["error_code"] == "MODEL_REPLAY_MISS"
    persisted_error = json.loads((run_root / "metadata/error.json").read_text(encoding="utf-8"))
    assert persisted_error["error"]["details"]["agent_role"] == "analyst"
    assert (
        persisted_error["error"]["details"]["request_sha256"]
        == raised.value.details["request_sha256"]
    )
    assert not (run_root / "triage/analyst.json").exists()
    for artifact in manifest["artifacts"]:
        assert stat.S_IMODE((run_root / artifact["relative_path"]).stat().st_mode) == 0o400


@pytest.mark.integration
@pytest.mark.parametrize(
    ("mismatch", "error_text"),
    (
        ("project", "project does not match"),
        ("source", "source identity"),
        ("sarif", "SARIF identity"),
        ("schema", "strict validation"),
    ),
)
def test_triage_rejects_invalid_or_mismatched_supplement(
    tmp_path: Path,
    mismatch: str,
    error_text: str,
) -> None:
    repository, config, _source_bytes = _gate_b_repository(tmp_path)
    sarif = FIXTURES / "single-path.sarif"
    supplement = tmp_path / "mismatched-supplement.json"
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "project_id": "gate-b-fixture",
        "repository_identity": "f" * 64,
        "raw_sarif_sha256": hashlib.sha256(sarif.read_bytes()).hexdigest(),
        "kind": "test",
        "producer": "EviTriage-QL tests",
        "purpose": "This mismatch must fail before any model call.",
        "entries": [
            {
                "run_index": 0,
                "result_index": 0,
                "type": "guard",
                "polarity": "supports_fp",
                "strength": "decisive",
                "summary": "A deliberately mismatched fixture observation.",
            }
        ],
    }
    if mismatch != "source":
        baseline = run_sarif_ingest(
            repository,
            project_config=config,
            sarif_path=sarif,
        )
        payload["repository_identity"] = baseline.snapshot_identity
    if mismatch == "project":
        payload["project_id"] = "another-project"
    elif mismatch == "sarif":
        payload["raw_sarif_sha256"] = "e" * 64
    elif mismatch == "schema":
        payload["unexpected"] = True
    supplement.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )
    cache = tmp_path / "unused-replay-cache"
    cache.mkdir()
    profile = LLMProfile(
        id="replay-v0.1",
        provider="replay",
        model_id="evitriage-offline-replay-v0.1",
    )

    with pytest.raises(PolicyRejectedError, match=error_text) as raised:
        run_sarif_triage(
            repository,
            project_config=config,
            sarif_path=sarif,
            profile=profile,
            llm=ReplayLLM(profile, cache),
            evidence_supplement_path=supplement,
        )

    run_root = Path(cast(str, raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["state"] == "POLICY_REJECTED"
    registered = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert "input/source.sarif" in registered
    assert "input/evidence-supplement.json" in registered
    assert "metadata/error.json" in registered


@pytest.mark.integration
def test_triage_rejects_runtime_profile_not_bound_by_project_spec(tmp_path: Path) -> None:
    repository, config, _source_bytes = _gate_b_repository(tmp_path)
    replay_cache = tmp_path / "replay-cache"
    replay_cache.mkdir()
    profile = LLMProfile(
        id="other-replay-v0.1",
        provider="replay",
        model_id="offline-fixture",
    )

    with pytest.raises(PolicyRejectedError) as raised:
        run_sarif_triage(
            repository,
            project_config=config,
            sarif_path=FIXTURES / "single-path.sarif",
            profile=profile,
            llm=ReplayLLM(profile, replay_cache),
        )

    run_root = Path(cast(str, raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "POLICY_REJECTED"
    assert manifest["events"][-1]["error_code"] == "POLICY_REJECTED"


@pytest.mark.integration
def test_triage_deepseek_v4_cli_uses_remote_policy_and_official_endpoint_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, replay_config, _source_bytes = _gate_b_repository(tmp_path)
    deepseek_config = replay_config.with_name("deepseek.yaml")
    deepseek_config.write_text(
        replay_config.read_text(encoding="utf-8")
        .replace("id: gate-b-fixture", "id: gate-b-deepseek-v4")
        .replace("llm_profile: replay-v0.1", "llm_profile: deepseek-v4-pro")
        .replace("source_upload_policy: offline_only", "source_upload_policy: remote_llm_allowed"),
        encoding="utf-8",
    )
    sarif = FIXTURES / "single-path.sarif"
    baseline = run_sarif_ingest(
        repository,
        project_config=deepseek_config,
        sarif_path=sarif,
    )
    registry = EvidenceRegistry.model_validate_json(
        (Path(baseline.artifact_run_root) / baseline.evidence_registry.relative_path).read_bytes(),
        strict=True,
    )
    responses = _nmc_replay_responses(registry)
    _QueuedDeepSeekConnection.responses = [
        json.dumps(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": json.dumps(scripted.payload)},
                    }
                ]
            }
        ).encode()
        for scripted in responses
    ]
    _QueuedDeepSeekConnection.requests = []
    api_key = "test-only-deepseek-key"
    monkeypatch.setenv("DEEPSEEK_API_KEY", api_key)
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository))
    monkeypatch.setattr(
        "evitriage.llm.structured.http.client.HTTPSConnection",
        _QueuedDeepSeekConnection,
    )
    profile_path = Path(__file__).parents[2] / "configs/llm/deepseek-v4-pro.yaml"

    completed = runner.invoke(
        app,
        [
            "triage",
            "--project-config",
            str(deepseek_config),
            "--sarif",
            str(sarif),
            "--llm-profile",
            str(profile_path),
            "--json",
        ],
    )

    assert completed.exit_code == 0, completed.output
    summary = json.loads(completed.stdout)
    assert summary["state"] == "JUDGED"
    assert summary["nmc_count"] == 1
    run_root = Path(summary["artifact_run_root"])
    assert api_key not in completed.output
    assert all(
        api_key.encode() not in path.read_bytes() for path in run_root.rglob("*") if path.is_file()
    )
    assert len(_QueuedDeepSeekConnection.requests) == 3
    for request in _QueuedDeepSeekConnection.requests:
        assert (request["host"], request["port"], request["path"]) == (
            "api.deepseek.com",
            443,
            "/chat/completions",
        )
        headers = cast(dict[str, str], request["headers"])
        assert headers["Authorization"] == f"Bearer {api_key}"
        body = cast(bytes, request["body"])
        assert json.loads(body)["model"] == "deepseek-v4-pro"
        assert api_key.encode() not in body


@pytest.mark.integration
def test_triage_blocks_deepseek_when_project_upload_policy_is_offline(
    tmp_path: Path,
) -> None:
    repository, replay_config, _source_bytes = _gate_b_repository(tmp_path)
    unsafe_config = replay_config.with_name("unsafe-deepseek.yaml")
    unsafe_config.write_text(
        replay_config.read_text(encoding="utf-8")
        .replace("id: gate-b-fixture", "id: gate-b-unsafe-deepseek")
        .replace("llm_profile: replay-v0.1", "llm_profile: deepseek-v4-pro"),
        encoding="utf-8",
    )
    profile = LLMProfile(
        id="deepseek-v4-pro",
        provider="deepseek",
        model_id="deepseek-v4-pro",
        data_policy="remote_llm_allowed",
    )

    with pytest.raises(PolicyRejectedError) as raised:
        run_sarif_triage(
            repository,
            project_config=unsafe_config,
            sarif_path=FIXTURES / "single-path.sarif",
            profile=profile,
            llm=DeepSeekLLM(profile, api_key="test-only-key"),
        )

    assert raised.value.details["project_data_policy"] == "offline_only"
    run_root = Path(cast(str, raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["state"] == "POLICY_REJECTED"


@pytest.mark.integration
def test_invalid_sarif_and_missing_codeql_are_structured_failed_runs(tmp_path: Path) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    environment = os.environ.copy()
    environment["EVITRIAGE_PROJECT_ROOT"] = str(repository)
    environment["PATH"] = "/usr/bin:/bin"

    invalid = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(FIXTURES / "malicious-uri.sarif"),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert invalid.returncode == 3
    invalid_error = json.loads(invalid.stderr)["error"]
    assert invalid_error["code"] == "UNSAFE_SARIF_URI"
    invalid_manifest = json.loads(
        (Path(invalid_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert invalid_manifest["status"] == "failed"
    assert invalid_manifest["state"] == "INVALID_SARIF"
    invalid_artifacts = {artifact["relative_path"] for artifact in invalid_manifest["artifacts"]}
    assert "metadata/error.json" in invalid_artifacts
    assert invalid_manifest["events"][-1]["output_sha256"] is not None

    malformed_document = json.loads((FIXTURES / "single-path.sarif").read_text(encoding="utf-8"))
    malformed_document["runs"][0]["artifacts"][0]["location"]["uri"] = "src/%FF.java"
    malformed_sarif = repository / "malformed-uri.sarif"
    malformed_sarif.write_text(json.dumps(malformed_document), encoding="utf-8")
    malformed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "ingest-sarif",
            "--project-config",
            str(config),
            "--sarif",
            str(malformed_sarif),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert malformed.returncode == 3
    malformed_error = json.loads(malformed.stderr)["error"]
    assert malformed_error["code"] == "UNSAFE_SARIF_URI"
    malformed_manifest = json.loads(
        (Path(malformed_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert malformed_manifest["status"] == "failed"
    assert malformed_manifest["state"] == "INVALID_SARIF"

    scan = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "scan",
            "--project-config",
            str(config),
            "--json",
        ],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
        shell=False,
    )
    assert scan.returncode == 7
    scan_error = json.loads(scan.stderr)["error"]
    assert scan_error["code"] == "CODEQL_TOOL_UNAVAILABLE"
    assert scan_error["details"]["tool"] == "codeql"
    scan_manifest = json.loads(
        (Path(scan_error["details"]["artifact_run_root"]) / "run-manifest.json").read_text(
            encoding="utf-8"
        )
    )
    assert scan_manifest["status"] == "failed"
    assert scan_manifest["state"] == "CODEQL_FAILED"
    scan_artifacts = {artifact["relative_path"] for artifact in scan_manifest["artifacts"]}
    assert "metadata/error.json" in scan_artifacts


@pytest.mark.integration
def test_unsupported_context_policy_records_context_incomplete(tmp_path: Path) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    document["analysis"]["context_policy"] = "adaptive_slice"
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(FeatureNotAvailableError, match="adaptive_slice") as raised:
        run_sarif_ingest(
            repository,
            project_config=config,
            sarif_path=FIXTURES / "single-path.sarif",
        )

    run_root = Path(str(raised.value.details["artifact_run_root"]))
    manifest = json.loads((run_root / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["status"] == "failed"
    assert manifest["state"] == "CONTEXT_INCOMPLETE"
    assert manifest["events"][-2]["to_state"] == "NORMALIZED"
    assert manifest["events"][-1]["error_code"] == "FEATURE_NOT_AVAILABLE"
    artifacts = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert "normalized/alerts.json" in artifacts
    assert "metadata/error.json" in artifacts
    assert "evidence/registry.json" not in artifacts


@pytest.mark.integration
def test_scan_converges_on_the_same_normalizer_after_a_real_runner_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)

    def which(value: str) -> str | None:
        return {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value)

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["shell"] is False
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="",
                stderr='openjdk version "17.0.10"\n',
            )
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
        if arguments[1:3] == ["database", "create"]:
            Path(arguments[3]).mkdir()
            return subprocess.CompletedProcess(arguments, 0, stdout="created\n", stderr="")
        if arguments[1:3] == ["database", "analyze"]:
            output = next(item for item in arguments if item.startswith("--output="))
            Path(output.removeprefix("--output=")).write_bytes(
                (FIXTURES / "single-path.sarif").read_bytes()
            )
            return subprocess.CompletedProcess(arguments, 0, stdout="analyzed\n", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr("evitriage.codeql.runner.shutil.which", which)
    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", fake_run)

    summary = run_codeql_scan(repository, project_config=config)

    assert summary.status == "ok"
    assert summary.command == "scan"
    assert summary.source_kind == "scan"
    assert summary.real_codeql is True
    assert summary.alert_count == 1
    assert summary.path_count == 1
    assert summary.tool_versions["codeql"] == "2.26.1"
    assert summary.tool_versions["maven-distribution-pin"] == "3.9.9"
    root = Path(summary.artifact_run_root)
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "BUILD_READY",
        "CODEQL_DB_READY",
        "SCANNED",
        "NORMALIZED",
        "CONTEXT_READY",
    ]
    artifact_paths = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert {
        "codeql/results.sarif",
        "codeql/run.json",
        "codeql/database-create.command.json",
        "normalized/alerts.json",
    } <= artifact_paths


@pytest.mark.integration
def test_scan_can_continue_in_the_same_run_through_triage_and_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository))
    baseline = run_sarif_ingest(
        repository,
        project_config=config,
        sarif_path=FIXTURES / "single-path.sarif",
    )
    baseline_root = Path(baseline.artifact_run_root)
    registry = EvidenceRegistry.model_validate_json(
        (baseline_root / baseline.evidence_registry.relative_path).read_bytes(), strict=True
    )
    profile = LLMProfile(
        id="replay-v0.1",
        provider="replay",
        model_id="evitriage-offline-replay-v0.1",
    )
    replay_cache = tmp_path / "scan-replay-cache"
    _write_replay_cache(replay_cache, profile=profile, registry=registry)

    def which(value: str) -> str | None:
        return {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value)

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["shell"] is False
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="",
                stderr='openjdk version "17.0.10"\n',
            )
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
        if arguments[1:3] == ["database", "create"]:
            Path(arguments[3]).mkdir()
            return subprocess.CompletedProcess(arguments, 0, stdout="created\n", stderr="")
        if arguments[1:3] == ["database", "analyze"]:
            output = next(item for item in arguments if item.startswith("--output="))
            Path(output.removeprefix("--output=")).write_bytes(
                (FIXTURES / "single-path.sarif").read_bytes()
            )
            return subprocess.CompletedProcess(arguments, 0, stdout="analyzed\n", stderr="")
        raise AssertionError(arguments)

    monkeypatch.setattr("evitriage.codeql.runner.shutil.which", which)
    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", fake_run)

    completed = runner.invoke(
        app,
        [
            "triage",
            "--project-config",
            str(config),
            "--scan",
            "--llm-profile",
            str(Path(__file__).parents[2] / "configs/llm/replay-v0.1.yaml"),
            "--replay-cache",
            str(replay_cache),
            "--json",
        ],
    )

    assert completed.exit_code == 0, completed.output
    summary = TriageRunSummary.model_validate_json(completed.stdout, strict=True)
    assert summary.status == "ok"
    assert summary.source_kind == "scan"
    assert summary.real_codeql is True
    assert summary.state == "JUDGED"
    assert summary.analysis_identity == registry.run_id
    assert summary.raw_sarif.role == "tool-output"
    assert summary.alert_count == summary.nmc_count == 1
    root = Path(summary.artifact_run_root)
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    assert [event["to_state"] for event in manifest["events"]] == [
        "CREATED",
        "PROJECT_VALIDATED",
        "WORKSPACE_READY",
        "SOURCE_READY",
        "BUILD_READY",
        "CODEQL_DB_READY",
        "SCANNED",
        "NORMALIZED",
        "CONTEXT_READY",
        "ANALYZED",
        "REBUTTED",
        "JUDGED",
    ]
    report = AlertReport.model_validate_json(
        (root / summary.report_jsonl.relative_path).read_text(encoding="utf-8").strip(),
        strict=True,
    )
    assert report.run.input_mode == "scan"
    assert report.run.real_codeql is True
    assert report.triage.final_decision.label == "NMC"


@pytest.mark.integration
def test_failed_runner_indexes_partial_logs_and_structured_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository, config, _ = _gate_b_repository(tmp_path)
    monkeypatch.setattr(
        "evitriage.codeql.runner.shutil.which",
        lambda value: {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value),
    )
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda arguments, **_kwargs: subprocess.CompletedProcess(
            arguments, 0, stdout="2.25.0\n", stderr=""
        ),
    )

    with pytest.raises(CodeQLVersionMismatchError) as raised:
        run_codeql_scan(repository, project_config=config)

    root = Path(str(raised.value.details["artifact_run_root"]))
    manifest = json.loads((root / "run-manifest.json").read_text(encoding="utf-8"))
    artifact_paths = {artifact["relative_path"] for artifact in manifest["artifacts"]}
    assert {
        "codeql/codeql-version.stdout.log",
        "codeql/codeql-version.stderr.log",
        "codeql/codeql-version.command.json",
        "metadata/error.json",
    } <= artifact_paths
    assert manifest["state"] == "CODEQL_FAILED"
    assert manifest["events"][-1]["output_sha256"] is not None
    assert all(
        (root / relative_path).stat().st_mode & 0o222 == 0 for relative_path in artifact_paths
    )

    invalid_repository, invalid_config, _ = _gate_b_repository(tmp_path / "invalid-output")

    def invalid_output(arguments: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(
                arguments, 0, stdout="", stderr='openjdk version "17.0.10"\n'
            )
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
        if arguments[1:3] == ["database", "create"]:
            Path(arguments[3]).mkdir()
            return subprocess.CompletedProcess(arguments, 0, stdout="created\n", stderr="")
        output = next(item for item in arguments if item.startswith("--output="))
        Path(output.removeprefix("--output=")).write_text(
            '{"version":"2.0.0","runs":[]}\n', encoding="utf-8"
        )
        return subprocess.CompletedProcess(arguments, 0, stdout="analyzed\n", stderr="")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", invalid_output)
    with pytest.raises(InvalidSarifError) as invalid:
        run_codeql_scan(invalid_repository, project_config=invalid_config)

    invalid_root = Path(str(invalid.value.details["artifact_run_root"]))
    invalid_manifest = json.loads((invalid_root / "run-manifest.json").read_text(encoding="utf-8"))
    invalid_artifacts = {artifact["relative_path"] for artifact in invalid_manifest["artifacts"]}
    assert "codeql/results.sarif" in invalid_artifacts
    assert (invalid_root / "codeql/results.sarif").stat().st_mode & 0o222 == 0
