"""Input pipelines converging on shared normalization, context, and evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ValidationError

from evitriage.agents import TriageLimits
from evitriage.agents.dispatcher import TriageDispatcher
from evitriage.codeql import CodeQLRunner, CodeQLRunResult
from evitriage.context import ContextBuilder
from evitriage.domain.alerts import AlertBundle
from evitriage.domain.context import (
    ContextIndex,
    ContextPolicyName,
    SliceArtifact,
    SliceArtifactReference,
)
from evitriage.domain.evidence import EvidenceRegistry, EvidenceSupplement
from evitriage.domain.project import ResolvedProjectSpec
from evitriage.domain.run import (
    ArtifactRecord,
    ContextRunSummary,
    RunManifest,
    WorkflowState,
)
from evitriage.domain.triage import (
    AnalystRunArtifact,
    AnalystStageRecord,
    JudgedRunArtifact,
    RebuttalRunArtifact,
    RebuttalStageRecord,
    TriageRunSummary,
    TriageTarget,
)
from evitriage.domain.workspace import WorkspaceAllocation
from evitriage.errors import (
    EviTriageError,
    FeatureNotAvailableError,
    ModelError,
    PolicyRejectedError,
)
from evitriage.evidence import (
    build_evidence_registry,
    evidence_graph_dot,
    merge_evidence_supplement,
    source_map_html,
)
from evitriage.llm import LLMProfile, StructuredLLM
from evitriage.observability import redact
from evitriage.projects.registry import ProjectRegistry
from evitriage.reporting import build_triage_report, render_report_html, render_report_jsonl
from evitriage.run_artifacts import RunJournal
from evitriage.sarif import InvalidSarifError, SarifNormalizer, parse_sarif_bytes
from evitriage.workspace import WorkspaceManager

_NORMALIZER_VERSION = "1.0"
_CONTEXT_VERSION: Literal["1.0"] = "1.0"
_EVIDENCE_REGISTRY_VERSION = "1.0"
_AGENT_WORKFLOW_VERSION = "1.0"
_DECISION_POLICY_VERSION = "1.0"
_REPORT_RENDERER_VERSION = "1.0"
_EVIDENCE_SUPPLEMENT_VERSION = "1.0"
_SARIF_MEDIA_TYPE = "application/sarif+json"
_JSON_MEDIA_TYPE = "application/json"


@dataclass(frozen=True, slots=True)
class _PreparedRun:
    resolved: ResolvedProjectSpec
    allocation: WorkspaceAllocation
    journal: RunJournal


@dataclass(frozen=True, slots=True)
class _ContextProducts:
    raw_record: ArtifactRecord
    bundle: AlertBundle
    normalized_record: ArtifactRecord
    slices: tuple[SliceArtifact, ...]
    persisted_slices: tuple[tuple[SliceArtifact, ArtifactRecord], ...]
    context_index_record: ArtifactRecord
    registry: EvidenceRegistry
    registry_record: ArtifactRecord
    graph_record: ArtifactRecord
    source_map_record: ArtifactRecord
    supplement_record: ArtifactRecord | None


def run_sarif_ingest(
    repository_root: Path,
    *,
    project_config: Path,
    sarif_path: Path,
    allowed_source_roots: tuple[Path, ...] | None = None,
    command: Literal["ingest-sarif", "normalize"] = "ingest-sarif",
) -> ContextRunSummary:
    """Ingest SARIF, then build the shared normalized/context/evidence artifacts."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="sarif",
    )
    raw_record, raw = _ingest_sarif_input(prepared, sarif_path)
    return _normalize_context_and_complete(
        prepared,
        raw=raw,
        raw_record=raw_record,
        command=command,
        source_kind="ingest",
        real_codeql=False,
    )


def run_sarif_triage(
    repository_root: Path,
    *,
    project_config: Path,
    sarif_path: Path,
    profile: LLMProfile,
    llm: StructuredLLM,
    limits: TriageLimits | None = None,
    allowed_workspace_roots: tuple[Path, ...] | None = None,
    allowed_artifact_roots: tuple[Path, ...] | None = None,
    evidence_supplement_path: Path | None = None,
    allowed_source_roots: tuple[Path, ...] | None = None,
) -> TriageRunSummary:
    """Ingest existing SARIF and continue through triage and Gate E reports."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="sarif",
        allowed_workspace_roots=allowed_workspace_roots,
        allowed_artifact_roots=allowed_artifact_roots,
    )
    _validate_triage_profile(prepared, profile)
    raw_record, raw = _ingest_sarif_input(prepared, sarif_path)
    supplement = _ingest_evidence_supplement(
        prepared,
        evidence_supplement_path=evidence_supplement_path,
        raw_sarif_sha256=raw_record.sha256,
    )
    products = _normalize_context(
        prepared,
        raw=raw,
        raw_record=raw_record,
        supplement=supplement,
    )
    return _triage_and_complete(
        prepared,
        products=products,
        profile=profile,
        llm=llm,
        limits=limits,
        real_codeql=False,
    )


def _validate_triage_profile(prepared: _PreparedRun, profile: LLMProfile) -> None:
    if prepared.resolved.spec.analysis.llm_profile != profile.id:
        error = PolicyRejectedError(
            "ProjectSpec LLM profile does not match the trusted runtime profile",
            details={
                "project_profile": prepared.resolved.spec.analysis.llm_profile,
                "runtime_profile": profile.id,
            },
        )
        _fail_run(prepared, WorkflowState.POLICY_REJECTED, error)
        raise error
    project_data_policy = prepared.resolved.spec.security.source_upload_policy
    if project_data_policy != profile.data_policy:
        error = PolicyRejectedError(
            "ProjectSpec source-upload policy does not match the LLM profile",
            details={
                "project_data_policy": project_data_policy,
                "profile_data_policy": profile.data_policy,
            },
        )
        _fail_run(prepared, WorkflowState.POLICY_REJECTED, error)
        raise error


def _ingest_sarif_input(
    prepared: _PreparedRun,
    sarif_path: Path,
) -> tuple[ArtifactRecord, bytes]:
    try:
        raw_record, raw = prepared.journal.ingest_file(
            sarif_path,
            "input/source.sarif",
            role="input",
            media_type=_SARIF_MEDIA_TYPE,
            maximum_bytes=128 * 1024 * 1024,
        )
        prepared.journal.transition(
            WorkflowState.SARIF_INGESTED,
            event_type="sarif_ingested",
            input_sha256=raw_record.sha256,
            output_sha256=raw_record.sha256,
        )
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.INVALID_SARIF, error)
        raise
    return raw_record, raw


def _ingest_evidence_supplement(
    prepared: _PreparedRun,
    *,
    evidence_supplement_path: Path | None,
    raw_sarif_sha256: str,
) -> tuple[EvidenceSupplement, ArtifactRecord] | None:
    if evidence_supplement_path is None:
        return None
    try:
        record, raw = prepared.journal.ingest_file(
            evidence_supplement_path,
            "input/evidence-supplement.json",
            role="input",
            media_type=_JSON_MEDIA_TYPE,
            maximum_bytes=2 * 1024 * 1024,
        )
        supplement = EvidenceSupplement.model_validate_json(raw, strict=True)
        if supplement.project_id != prepared.resolved.project_id:
            raise PolicyRejectedError("evidence supplement project does not match the run")
        if supplement.repository_identity != prepared.allocation.snapshot.source_tree_sha256:
            raise PolicyRejectedError("evidence supplement source identity does not match the run")
        if supplement.raw_sarif_sha256 != raw_sarif_sha256:
            raise PolicyRejectedError("evidence supplement SARIF identity does not match the run")
    except ValidationError as error:
        rejected = PolicyRejectedError(
            "evidence supplement failed strict validation",
            details={
                "issues": [
                    {
                        "type": str(issue["type"]),
                        "location": [str(part) for part in issue["loc"]],
                        "message": str(issue["msg"]),
                    }
                    for issue in error.errors(
                        include_url=False,
                        include_context=False,
                        include_input=False,
                    )
                ]
            },
        )
        _fail_run(prepared, WorkflowState.POLICY_REJECTED, rejected)
        raise rejected from error
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.POLICY_REJECTED, error)
        raise
    return supplement, record


def run_codeql_scan(
    repository_root: Path,
    *,
    project_config: Path,
    allowed_source_roots: tuple[Path, ...] | None = None,
    runner: CodeQLRunner | None = None,
) -> ContextRunSummary:
    """Execute CodeQL, then use the same normalize/context path as ingest."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="scan",
    )
    raw_record, raw = _scan_codeql_input(prepared, runner=runner)
    return _normalize_context_and_complete(
        prepared,
        raw=raw,
        raw_record=raw_record,
        command="scan",
        source_kind="scan",
        real_codeql=True,
    )


def run_codeql_triage(
    repository_root: Path,
    *,
    project_config: Path,
    profile: LLMProfile,
    llm: StructuredLLM,
    limits: TriageLimits | None = None,
    evidence_supplement_path: Path | None = None,
    allowed_source_roots: tuple[Path, ...] | None = None,
    runner: CodeQLRunner | None = None,
) -> TriageRunSummary:
    """Execute CodeQL and continue the same run through triage and reporting."""

    prepared = _prepare_run(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_source_roots,
        input_mode="scan",
    )
    _validate_triage_profile(prepared, profile)
    raw_record, raw = _scan_codeql_input(prepared, runner=runner)
    supplement = _ingest_evidence_supplement(
        prepared,
        evidence_supplement_path=evidence_supplement_path,
        raw_sarif_sha256=raw_record.sha256,
    )
    products = _normalize_context(
        prepared,
        raw=raw,
        raw_record=raw_record,
        supplement=supplement,
    )
    return _triage_and_complete(
        prepared,
        products=products,
        profile=profile,
        llm=llm,
        limits=limits,
        real_codeql=True,
    )


def _scan_codeql_input(
    prepared: _PreparedRun,
    *,
    runner: CodeQLRunner | None,
) -> tuple[ArtifactRecord, bytes]:
    prepared.journal.transition(WorkflowState.BUILD_READY, event_type="build_plan_ready")
    selected_runner = runner or CodeQLRunner()
    try:
        scan_result = selected_runner.scan(
            codeql=prepared.resolved.spec.codeql,
            build=prepared.resolved.spec.build,
            workspace=prepared.allocation.workspace,
        )
        prepared.journal.add_tool_versions(
            {
                "codeql": scan_result.codeql_version,
                "java": scan_result.java_version,
                "javac": scan_result.javac_version,
                "maven-distribution-pin": scan_result.maven_distribution_version,
                "maven-distribution-sha256": scan_result.maven_distribution_sha256,
                "sarif-normalizer": _NORMALIZER_VERSION,
            }
        )
        run_metadata = _record_codeql_artifacts(prepared, scan_result)
        raw_relative = scan_result.sarif_path.relative_to(
            prepared.allocation.workspace.artifact_run_root
        ).as_posix()
        raw_record, raw = prepared.journal.record_existing_artifact(
            raw_relative,
            role="tool-output",
            media_type=_SARIF_MEDIA_TYPE,
            maximum_bytes=128 * 1024 * 1024,
        )
        if raw_record.sha256 != scan_result.sarif_sha256:
            raise InvalidSarifError("CodeQL SARIF changed after the runner validated it")
        prepared.journal.transition(
            WorkflowState.CODEQL_DB_READY,
            event_type="codeql_database_ready",
            tool_manifest_sha256=run_metadata.sha256,
        )
        prepared.journal.transition(
            WorkflowState.SCANNED,
            event_type="codeql_scan_completed",
            output_sha256=raw_record.sha256,
            tool_manifest_sha256=run_metadata.sha256,
        )
    except EviTriageError as error:
        _record_partial_codeql_artifacts(prepared, error)
        _fail_run(prepared, WorkflowState.CODEQL_FAILED, error)
        raise

    return raw_record, raw


def _prepare_run(
    repository_root: Path,
    *,
    project_config: Path,
    allowed_source_roots: tuple[Path, ...] | None,
    input_mode: Literal["sarif", "scan"],
    allowed_workspace_roots: tuple[Path, ...] | None = None,
    allowed_artifact_roots: tuple[Path, ...] | None = None,
) -> _PreparedRun:
    registry = ProjectRegistry(
        repository_root,
        allowed_source_roots=allowed_source_roots,
        allowed_workspace_roots=allowed_workspace_roots,
        allowed_artifact_roots=allowed_artifact_roots,
    )
    resolved = registry.validate_path(project_config)
    source_path = resolved.source_path
    if source_path is None:
        raise FeatureNotAvailableError(
            "Gate B executes only local ProjectSpec sources",
            details={"project_id": resolved.project_id},
        )
    manager = WorkspaceManager(resolved.workspace_root, resolved.artifact_root)
    allocation = manager.prepare(
        source_path,
        resolved.project_id,
        resolved.canonical_json,
    )
    journal = RunJournal(allocation, input_mode=input_mode)
    journal.transition(
        WorkflowState.PROJECT_VALIDATED,
        event_type="project_validated",
        input_sha256=resolved.digest,
        output_sha256=resolved.digest,
    )
    journal.transition(WorkflowState.WORKSPACE_READY, event_type="workspace_ready")
    journal.transition(
        WorkflowState.SOURCE_READY,
        event_type="source_ready",
        output_sha256=allocation.snapshot.source_tree_sha256,
    )
    return _PreparedRun(resolved=resolved, allocation=allocation, journal=journal)


def _normalize_context_and_complete(
    prepared: _PreparedRun,
    *,
    raw: bytes,
    raw_record: ArtifactRecord,
    command: Literal["ingest-sarif", "normalize", "scan"],
    source_kind: Literal["ingest", "scan"],
    real_codeql: bool,
) -> ContextRunSummary:
    products = _normalize_context(prepared, raw=raw, raw_record=raw_record)
    try:
        manifest = prepared.journal.complete()
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.CONTEXT_INCOMPLETE, error)
        raise
    return _context_run_summary(
        prepared,
        products=products,
        manifest=manifest,
        command=command,
        source_kind=source_kind,
        real_codeql=real_codeql,
    )


def _normalize_context(
    prepared: _PreparedRun,
    *,
    raw: bytes,
    raw_record: ArtifactRecord,
    supplement: tuple[EvidenceSupplement, ArtifactRecord] | None = None,
) -> _ContextProducts:
    try:
        document = parse_sarif_bytes(raw)
        bundle = SarifNormalizer(prepared.allocation.workspace.source_snapshot).normalize(
            document,
            run_id=_analysis_identity(prepared, raw_record),
            repository_identity=prepared.allocation.snapshot.source_tree_sha256,
            commit_sha=prepared.allocation.snapshot.full_commit,
            raw_sarif_sha256=raw_record.sha256,
        )
        normalized_record = prepared.journal.write_artifact(
            "normalized/alerts.json",
            _serialize_model(bundle),
            role="normalized",
            media_type=_JSON_MEDIA_TYPE,
        )
        prepared.journal.add_tool_versions({"sarif-normalizer": _NORMALIZER_VERSION})
        prepared.journal.transition(
            WorkflowState.NORMALIZED,
            event_type="sarif_normalized",
            input_sha256=raw_record.sha256,
            output_sha256=normalized_record.sha256,
        )
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.INVALID_SARIF, error)
        raise

    try:
        policy_name = prepared.resolved.spec.analysis.context_policy
        slices = ContextBuilder(prepared.allocation.workspace.source_snapshot).build(
            bundle,
            policy_name=policy_name,
        )
        persisted_slices = _record_slice_artifacts(prepared, slices)
        context_policy = cast(ContextPolicyName, policy_name)
        context_index = ContextIndex(
            run_id=bundle.run_id,
            repository_identity=bundle.repository_identity,
            raw_sarif_sha256=bundle.raw_sarif_sha256,
            normalized_bundle_sha256=normalized_record.sha256,
            context_policy=context_policy,
            context_version=_CONTEXT_VERSION,
            slices=tuple(
                SliceArtifactReference(
                    alert_fingerprint=slice_artifact.content.alert_fingerprint,
                    raw_result_reference=slice_artifact.content.raw_result_reference,
                    relative_path=record.relative_path,
                    artifact_sha256=record.sha256,
                    slice_sha256=slice_artifact.slice_sha256,
                )
                for slice_artifact, record in persisted_slices
            ),
        )
        context_index_record = prepared.journal.write_artifact(
            "context/index.json",
            _serialize_model(context_index),
            role="context",
            media_type=_JSON_MEDIA_TYPE,
        )
        registry = build_evidence_registry(
            bundle,
            normalized_artifact=normalized_record,
            persisted_slices=persisted_slices,
        )
        supplement_record: ArtifactRecord | None = None
        if supplement is not None:
            supplement_input, supplement_record = supplement
            registry = merge_evidence_supplement(
                registry,
                bundle,
                supplement_input,
                supplement_artifact=supplement_record,
            )
        registry_record = prepared.journal.write_artifact(
            "evidence/registry.json",
            _serialize_model(registry),
            role="evidence",
            media_type=_JSON_MEDIA_TYPE,
        )
        graph_record = prepared.journal.write_artifact(
            "evidence/graph.dot",
            evidence_graph_dot(registry).encode("utf-8"),
            role="evidence",
            media_type="text/vnd.graphviz",
        )
        source_map_record = prepared.journal.write_artifact(
            "context/source-map.html",
            source_map_html(slices, registry).encode("utf-8"),
            role="context",
            media_type="text/html",
        )
        prepared.journal.add_tool_versions(
            {
                "context-extractor": _CONTEXT_VERSION,
                "evidence-registry": _EVIDENCE_REGISTRY_VERSION,
                **(
                    {"evidence-supplement": _EVIDENCE_SUPPLEMENT_VERSION}
                    if supplement_record is not None
                    else {}
                ),
            }
        )
        prepared.journal.transition(
            WorkflowState.CONTEXT_READY,
            event_type="context_evidence_ready",
            input_sha256=normalized_record.sha256,
            output_sha256=registry_record.sha256,
        )
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.CONTEXT_INCOMPLETE, error)
        raise

    return _ContextProducts(
        raw_record=raw_record,
        bundle=bundle,
        normalized_record=normalized_record,
        slices=slices,
        persisted_slices=persisted_slices,
        context_index_record=context_index_record,
        registry=registry,
        registry_record=registry_record,
        graph_record=graph_record,
        source_map_record=source_map_record,
        supplement_record=supplement_record,
    )


def _context_run_summary(
    prepared: _PreparedRun,
    *,
    products: _ContextProducts,
    manifest: RunManifest,
    command: Literal["ingest-sarif", "normalize", "scan"],
    source_kind: Literal["ingest", "scan"],
    real_codeql: bool,
) -> ContextRunSummary:
    return ContextRunSummary(
        command=command,
        source_kind=source_kind,
        real_codeql=real_codeql,
        run_id=manifest.run_id,
        project_id=manifest.project_id,
        project_spec_sha256=manifest.project_spec_sha256,
        snapshot_identity=manifest.snapshot_identity,
        artifact_run_root=str(prepared.allocation.workspace.artifact_run_root),
        raw_sarif=products.raw_record,
        normalized_bundle=products.normalized_record,
        slice_artifacts=tuple(record for _slice, record in products.persisted_slices),
        context_index=products.context_index_record,
        evidence_registry=products.registry_record,
        evidence_graph=products.graph_record,
        source_map=products.source_map_record,
        alert_count=len(products.bundle.alerts),
        path_count=sum(len(alert.paths) for alert in products.bundle.alerts),
        no_path_alert_count=sum(not alert.has_code_flows for alert in products.bundle.alerts),
        complete_context_count=sum(
            slice_artifact.content.completeness == "complete" for slice_artifact in products.slices
        ),
        partial_context_count=sum(
            slice_artifact.content.completeness == "partial" for slice_artifact in products.slices
        ),
        evidence_count=len(products.registry.items),
        claim_count=len(products.registry.claims),
        tool_versions=manifest.tool_versions,
    )


def _triage_and_complete(
    prepared: _PreparedRun,
    *,
    products: _ContextProducts,
    profile: LLMProfile,
    llm: StructuredLLM,
    limits: TriageLimits | None,
    real_codeql: bool,
) -> TriageRunSummary:
    workflow = TriageDispatcher(profile=profile, limits=limits)
    try:
        prepared.journal.add_tool_versions(
            {
                "agent-workflow": _AGENT_WORKFLOW_VERSION,
                "decision-policy": _DECISION_POLICY_VERSION,
                "llm-model": profile.model_id,
                "llm-profile": f"{profile.id}@sha256:{profile.digest}",
                "llm-provider": profile.provider,
            }
        )
        results = tuple(
            workflow.triage(
                registry=products.registry,
                target=TriageTarget(
                    alert_fingerprint=alert.alert_fingerprint,
                    raw_result_reference=alert.raw_result_reference,
                ),
                llm=llm,
                rule_id=alert.rule.rule_id,
            )
            for alert in products.bundle.alerts
        )
        operational_run_id = prepared.allocation.workspace.run_id
        analyst = AnalystRunArtifact(
            run_id=operational_run_id,
            analysis_identity=products.registry.run_id,
            results=tuple(
                AnalystStageRecord(
                    target=result.target,
                    output=result.analyst,
                    claims=result.analyst_claims,
                    invocations=tuple(
                        invocation
                        for invocation in result.invocations
                        if invocation.agent_role == "analyst"
                    ),
                )
                for result in results
            ),
        )
        analyst_record = prepared.journal.write_artifact(
            "triage/analyst.json",
            _serialize_model(analyst),
            role="model",
            media_type=_JSON_MEDIA_TYPE,
        )
        prepared.journal.transition(
            WorkflowState.ANALYZED,
            event_type="analyst_completed",
            input_sha256=products.registry_record.sha256,
            output_sha256=analyst_record.sha256,
        )

        rebuttal = RebuttalRunArtifact(
            run_id=operational_run_id,
            analysis_identity=products.registry.run_id,
            results=tuple(
                RebuttalStageRecord(
                    target=result.target,
                    output=result.rebuttal,
                    claims=result.rebuttal_claims,
                    invocations=tuple(
                        invocation
                        for invocation in result.invocations
                        if invocation.agent_role == "rebuttal"
                    ),
                )
                for result in results
            ),
        )
        rebuttal_record = prepared.journal.write_artifact(
            "triage/rebuttal.json",
            _serialize_model(rebuttal),
            role="model",
            media_type=_JSON_MEDIA_TYPE,
        )
        prepared.journal.transition(
            WorkflowState.REBUTTED,
            event_type="rebuttal_completed",
            input_sha256=analyst_record.sha256,
            output_sha256=rebuttal_record.sha256,
        )

        judged = JudgedRunArtifact(
            run_id=operational_run_id,
            analysis_identity=products.registry.run_id,
            results=results,
        )
        judged_record = prepared.journal.write_artifact(
            "triage/judged.json",
            _serialize_model(judged),
            role="decision",
            media_type=_JSON_MEDIA_TYPE,
        )
        prepared.journal.transition(
            WorkflowState.JUDGED,
            event_type="judge_completed",
            input_sha256=rebuttal_record.sha256,
            output_sha256=judged_record.sha256,
        )
        prepared.journal.add_tool_versions({"report-renderer": _REPORT_RENDERER_VERSION})
        report = build_triage_report(
            manifest=prepared.journal.manifest,
            bundle=products.bundle,
            slices=products.slices,
            registry=products.registry,
            results=results,
            real_codeql=real_codeql,
        )
        report_jsonl_record = prepared.journal.write_artifact(
            "reports/decisions.jsonl",
            render_report_jsonl(report),
            role="report",
            media_type="application/x-ndjson",
        )
        report_html_record = prepared.journal.write_artifact(
            "reports/index.html",
            render_report_html(report),
            role="report",
            media_type="text/html",
        )
        manifest = prepared.journal.complete()
    except PolicyRejectedError as error:
        _fail_run(prepared, WorkflowState.POLICY_REJECTED, error)
        raise
    except ModelError as error:
        _fail_run(prepared, WorkflowState.MODEL_FAILED, error)
        raise
    except EviTriageError as error:
        _fail_run(prepared, WorkflowState.MODEL_FAILED, error)
        raise

    decisions = tuple(result.final_decision for result in results)
    return TriageRunSummary(
        run_id=manifest.run_id,
        project_id=manifest.project_id,
        project_spec_sha256=manifest.project_spec_sha256,
        snapshot_identity=manifest.snapshot_identity,
        analysis_identity=products.registry.run_id,
        artifact_run_root=str(prepared.allocation.workspace.artifact_run_root),
        raw_sarif=products.raw_record,
        normalized_bundle=products.normalized_record,
        slice_artifacts=tuple(record for _slice, record in products.persisted_slices),
        context_index=products.context_index_record,
        evidence_registry=products.registry_record,
        evidence_graph=products.graph_record,
        source_map=products.source_map_record,
        evidence_supplement=products.supplement_record,
        analyst_artifact=analyst_record,
        rebuttal_artifact=rebuttal_record,
        judged_artifact=judged_record,
        report_jsonl=report_jsonl_record,
        report_html=report_html_record,
        alert_count=len(products.bundle.alerts),
        path_count=sum(len(alert.paths) for alert in products.bundle.alerts),
        evidence_count=len(products.registry.items),
        claim_count=sum(
            len(result.analyst_claims) + len(result.rebuttal_claims) for result in results
        ),
        invocation_count=sum(len(result.invocations) for result in results),
        tp_count=sum(decision.label == "TP" for decision in decisions),
        fp_count=sum(decision.label == "FP" for decision in decisions),
        nmc_count=sum(decision.label == "NMC" for decision in decisions),
        tool_versions=manifest.tool_versions,
        source_kind="scan" if real_codeql else "ingest",
        real_codeql=real_codeql,
    )


def _analysis_identity(prepared: _PreparedRun, raw_record: ArtifactRecord) -> str:
    """Derive a stable request/cache identity independent of the writable run ID."""

    payload = {
        "commit_sha": prepared.allocation.snapshot.full_commit,
        "normalizer_version": _NORMALIZER_VERSION,
        "raw_sarif_sha256": raw_record.sha256,
        "repository_identity": prepared.allocation.snapshot.source_tree_sha256,
    }
    serialized = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return "analysis-" + hashlib.sha256(serialized).hexdigest()


def _serialize_model(model: BaseModel) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _record_slice_artifacts(
    prepared: _PreparedRun,
    slices: tuple[SliceArtifact, ...],
) -> tuple[tuple[SliceArtifact, ArtifactRecord], ...]:
    persisted: list[tuple[SliceArtifact, ArtifactRecord]] = []
    for slice_artifact in slices:
        reference = slice_artifact.content.raw_result_reference
        relative_path = (
            f"context/slices/run-{reference.run_index:06d}-result-{reference.result_index:06d}.json"
        )
        record = prepared.journal.write_artifact(
            relative_path,
            _serialize_model(slice_artifact),
            role="context",
            media_type=_JSON_MEDIA_TYPE,
        )
        persisted.append((slice_artifact, record))
    return tuple(persisted)


def _record_codeql_artifacts(
    prepared: _PreparedRun, scan_result: CodeQLRunResult
) -> ArtifactRecord:
    run_root = prepared.allocation.workspace.artifact_run_root
    for command in scan_result.commands:
        for path in (command.stdout_path, command.stderr_path):
            prepared.journal.record_existing_artifact(
                path.relative_to(run_root).as_posix(),
                role="tool-log",
                media_type="text/plain",
            )
        command_metadata = command.stdout_path.parent / f"{command.name}.command.json"
        prepared.journal.record_existing_artifact(
            command_metadata.relative_to(run_root).as_posix(),
            role="metadata",
            media_type=_JSON_MEDIA_TYPE,
        )
    metadata_path = scan_result.sarif_path.parent / "run.json"
    metadata, _ = prepared.journal.record_existing_artifact(
        metadata_path.relative_to(run_root).as_posix(),
        role="metadata",
        media_type=_JSON_MEDIA_TYPE,
    )
    return metadata


def _fail_run(
    prepared: _PreparedRun,
    state: WorkflowState,
    error: EviTriageError,
) -> None:
    error.details.setdefault("run_id", prepared.allocation.workspace.run_id)
    error.details.setdefault(
        "artifact_run_root", str(prepared.allocation.workspace.artifact_run_root)
    )
    error_artifact_sha256: str | None = None
    try:
        serialized_error = (
            json.dumps(
                redact(error.as_dict()),
                allow_nan=False,
                default=str,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        error_record = prepared.journal.write_artifact(
            "metadata/error.json",
            serialized_error,
            role="metadata",
            media_type=_JSON_MEDIA_TYPE,
        )
        error_artifact_sha256 = error_record.sha256
    except EviTriageError as journal_error:
        error.details.setdefault("journal_error", journal_error.code)
    try:
        prepared.journal.fail(
            state,
            error_code=error.code,
            error_artifact_sha256=error_artifact_sha256,
        )
    except EviTriageError as journal_error:
        error.details.setdefault("journal_error", journal_error.code)


def _record_partial_codeql_artifacts(prepared: _PreparedRun, error: EviTriageError) -> None:
    directory = prepared.allocation.workspace.artifact_run_root / "codeql"
    if not directory.is_dir() or directory.is_symlink():
        return
    existing = {artifact.relative_path for artifact in prepared.journal.manifest.artifacts}
    allowed_names = {
        f"{command}.{suffix}"
        for command in (
            "codeql-version",
            "java-version",
            "javac-version",
            "database-create",
            "database-analyze",
        )
        for suffix in ("stdout.log", "stderr.log", "command.json")
    }
    allowed_names.add("results.sarif")
    try:
        paths = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        error.details.setdefault("partial_artifact_error", "CODEQL_ARTIFACT_LIST_FAILED")
        return
    for path in paths:
        relative = path.relative_to(prepared.allocation.workspace.artifact_run_root).as_posix()
        if path.name not in allowed_names or relative in existing:
            continue
        is_sarif = path.name == "results.sarif"
        media_type = (
            _SARIF_MEDIA_TYPE
            if is_sarif
            else (_JSON_MEDIA_TYPE if path.suffix == ".json" else "text/plain")
        )
        try:
            prepared.journal.record_existing_artifact(
                relative,
                role=(
                    "tool-output"
                    if is_sarif
                    else ("metadata" if path.suffix == ".json" else "tool-log")
                ),
                media_type=media_type,
                maximum_bytes=128 * 1024 * 1024 if is_sarif else 64 * 1024 * 1024,
            )
        except EviTriageError as capture_error:
            error.details.setdefault("partial_artifact_error", capture_error.code)


__all__ = [
    "run_codeql_scan",
    "run_codeql_triage",
    "run_sarif_ingest",
    "run_sarif_triage",
]
