"""Build deterministic JSONL and escaped HTML from validated Gate D products."""

from __future__ import annotations

import html
import json

from evitriage.domain.alerts import AlertBundle, RawResultReference, SourceLocation
from evitriage.domain.context import SliceArtifact
from evitriage.domain.evidence import Claim, EvidenceRegistry
from evitriage.domain.report import (
    AlertReport,
    ReportContextStage,
    ReportRunMetadata,
    ReportVerificationSummary,
    TriageReportBundle,
)
from evitriage.domain.run import RunManifest
from evitriage.domain.triage import TriageResult

_REPORT_LIMITATIONS = (
    "This secondary-triage report is not proof of vulnerability or safety.",
    "No upstream alert is automatically dismissed; human review remains required.",
    "Raw model confidence is uncalibrated and calibrated probabilities are unavailable.",
    "Dynamic verification was not performed for this run.",
)


def build_triage_report(
    *,
    manifest: RunManifest,
    bundle: AlertBundle,
    slices: tuple[SliceArtifact, ...],
    registry: EvidenceRegistry,
    results: tuple[TriageResult, ...],
    real_codeql: bool,
) -> TriageReportBundle:
    """Join exact alert occurrences into strict, evidence-closed report rows."""

    if (
        registry.run_id != bundle.run_id
        or registry.repository_identity != bundle.repository_identity
        or registry.raw_sarif_sha256 != bundle.raw_sarif_sha256
    ):
        raise ValueError("report bundle and Evidence Registry provenance differ")

    run = ReportRunMetadata(
        run_id=manifest.run_id,
        project_id=manifest.project_id,
        analysis_identity=bundle.run_id,
        input_mode=manifest.input_mode,
        real_codeql=real_codeql,
        project_spec_sha256=manifest.project_spec_sha256,
        snapshot_identity=manifest.snapshot_identity,
        repository_identity=bundle.repository_identity,
        commit_sha=bundle.commit_sha,
        raw_sarif_sha256=bundle.raw_sarif_sha256,
        tool_versions=manifest.tool_versions,
    )
    slices_by_occurrence = {_occurrence(item.content.raw_result_reference): item for item in slices}
    results_by_occurrence = {
        _occurrence(item.target.raw_result_reference): item for item in results
    }
    if len(slices_by_occurrence) != len(slices) or len(results_by_occurrence) != len(results):
        raise ValueError("report inputs contain duplicate alert occurrences")

    reports: list[AlertReport] = []
    for alert in bundle.alerts:
        occurrence = _occurrence(alert.raw_result_reference)
        source_slice = slices_by_occurrence.get(occurrence)
        result = results_by_occurrence.get(occurrence)
        if source_slice is None or result is None:
            raise ValueError("every normalized alert requires a slice and triage result")
        evidence = tuple(
            item
            for item in registry.items
            if item.alert_fingerprint == alert.alert_fingerprint
            and item.raw_result_reference == alert.raw_result_reference
        )
        unknowns = _unique_text(
            (
                *result.analyst.unknowns,
                *result.rebuttal.unknowns,
                *result.judge.unknowns,
                *result.final_decision.unknowns,
                *(
                    f"Context omission {omission.code}: {omission.detail}"
                    for omission in source_slice.content.omitted
                ),
            )
        )
        reports.append(
            AlertReport(
                run=run,
                alert=alert,
                slice_artifact=source_slice,
                evidence=evidence,
                triage=result,
                context_expansion_history=(
                    ReportContextStage(
                        context_policy=source_slice.content.context_policy,
                        context_version=source_slice.content.context_version,
                        completeness=source_slice.content.completeness,
                        token_estimate=source_slice.content.token_estimate,
                        maximum_token_budget=source_slice.content.maximum_token_budget,
                        omitted=source_slice.content.omitted,
                    ),
                ),
                verification=ReportVerificationSummary(
                    reason="Gate E v0.1 report generation does not execute a verifier.",
                ),
                unknowns=unknowns,
                limitations=_REPORT_LIMITATIONS,
            )
        )
    if len(reports) != len(results) or len(reports) != len(slices):
        raise ValueError("report inputs contain results or slices without a normalized alert")
    return TriageReportBundle(run=run, alerts=tuple(reports))


def render_report_jsonl(report: TriageReportBundle) -> bytes:
    """Render one canonical JSON object per alert for training and evaluation."""

    return b"".join(
        json.dumps(
            item.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
        for item in report.alerts
    )


def render_report_html(report: TriageReportBundle) -> bytes:
    """Render a self-contained audit view with all untrusted text HTML-escaped."""

    run = report.run
    counts = {
        label: sum(item.triage.final_decision.label == label for item in report.alerts)
        for label in ("TP", "FP", "NMC")
    }
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        "<title>EviTriage offline triage report</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
        "padding:0 1rem;line-height:1.45}code,pre{font-family:ui-monospace,monospace}"
        "pre{overflow:auto;background:#f5f5f5;padding:1rem}table{border-collapse:collapse}"
        "th,td{border:1px solid #bbb;padding:.35rem;text-align:left;vertical-align:top}"
        ".TP{color:#a00}.FP{color:#075}.NMC{color:#865b00}.notice{border-left:4px solid #865b00;"
        "padding:.5rem 1rem;background:#fff8df}</style></head><body>",
        "<h1>EviTriage offline triage report</h1>",
        '<p class="notice">Secondary triage only. No alert was automatically dismissed; '
        "human review remains required.</p>",
        "<h2>Run provenance</h2><table><tbody>",
        _row("run ID", run.run_id),
        _row("project ID", run.project_id),
        _row("analysis identity", run.analysis_identity),
        _row("input", f"{run.input_mode}; real_codeql={str(run.real_codeql).lower()}"),
        _row("project spec SHA-256", run.project_spec_sha256),
        _row("snapshot identity", run.snapshot_identity),
        _row("repository identity", run.repository_identity),
        _row("commit", run.commit_sha or "unknown"),
        _row("raw SARIF SHA-256", run.raw_sarif_sha256),
        "</tbody></table>",
        "<h3>Tool versions</h3><ul>",
        *(
            f"<li><code>{_escape(name)}</code>: {_escape(version)}</li>"
            for name, version in sorted(run.tool_versions.items())
        ),
        "</ul>",
        f"<p>Alerts: {len(report.alerts)}; TP: {counts['TP']}; FP: {counts['FP']}; "
        f"NMC: {counts['NMC']}.</p>",
    ]
    for ordinal, item in enumerate(report.alerts, start=1):
        parts.extend(_render_alert(ordinal, item))
    parts.append("</body></html>\n")
    return "".join(parts).encode("utf-8")


def _render_alert(ordinal: int, item: AlertReport) -> list[str]:
    alert = item.alert
    decision = item.triage.final_decision
    primary = alert.primary_location
    parts = [
        "<hr>",
        f'<article><h2>Alert {ordinal}: <span class="{decision.label}">'
        f"{decision.label}</span> — {_escape(alert.rule.rule_id)}</h2>",
        "<table><tbody>",
        _row("fingerprint", alert.alert_fingerprint),
        _row(
            "raw result",
            f"run {alert.raw_result_reference.run_index}, result "
            f"{alert.raw_result_reference.result_index}",
        ),
        _row("CWE", ", ".join(alert.rule.cwe_ids) or "unknown"),
        _row("severity", alert.rule.severity or alert.level or "unknown"),
        _row("primary location", _location_text(primary)),
        _row("requested label", decision.requested_label),
        _row("raw confidence", f"{decision.raw_confidence:.6f} (uncalibrated)"),
        _row("calibrated probability", "unavailable"),
        _row("human label", item.human_label or "unavailable"),
        _row("human disagreement", item.human_disagreement or "unavailable"),
        _row("auto dismiss", str(decision.auto_dismiss).lower()),
        "</tbody></table>",
        f"<h3>SARIF message</h3><p>{_escape(alert.message)}</p>",
        "<h3>Source-to-sink paths</h3>",
    ]
    if alert.paths:
        parts.append("<ol>")
        for path in alert.paths:
            parts.append(f"<li>Path {path.ordinal}; completeness={_escape(path.completeness)}<ol>")
            for step in path.steps:
                message = f" — {_escape(step.message)}" if step.message else ""
                parts.append(
                    f"<li>{_escape(step.step_kind)}: {_escape(_location_text(step.location))}"
                    f"{message}</li>"
                )
            parts.append("</ol></li>")
        parts.append("</ol>")
    else:
        parts.append("<p>No SARIF code flow was supplied.</p>")

    parts.extend(_render_claims("Analyst claims", item.triage.analyst_claims))
    parts.extend(_render_claims("Rebuttal claims", item.triage.rebuttal_claims))
    parts.extend(
        [
            "<h3>Decision</h3>",
            f"<p>{_escape(decision.reasoning_summary)}</p>",
            "<p>Policy flags: "
            + ", ".join(_escape(flag) for flag in decision.policy_flags)
            + ".</p>",
            "<h3>Evidence</h3><ul>",
        ]
    )
    critical = set(decision.critical_evidence_ids)
    for evidence in item.evidence:
        marker = " <strong>[critical]</strong>" if evidence.evidence_id in critical else ""
        location = f" at {_escape(_location_text(evidence.location))}" if evidence.location else ""
        excerpt = (
            f"<pre><code>{_escape(evidence.excerpt)}</code></pre>"
            if evidence.excerpt is not None
            else ""
        )
        parts.append(
            f"<li><code>{_escape(evidence.evidence_id)}</code>{marker}: "
            f"{_escape(evidence.type)}/{_escape(evidence.polarity)}/"
            f"{_escape(evidence.strength)}{location} — {_escape(evidence.summary)}{excerpt}</li>"
        )
    parts.append("</ul><h3>Selected source context</h3>")
    for source_slice in item.slice_artifact.content.source_slices:
        symbol = (
            f" ({_escape(source_slice.enclosing_symbol)})" if source_slice.enclosing_symbol else ""
        )
        parts.append(
            f"<details><summary>{_escape(source_slice.path)}:{source_slice.start_line}-"
            f"{source_slice.end_line}{symbol}</summary><pre><code>"
            f"{_escape(source_slice.content)}</code></pre></details>"
        )
    context = item.context_expansion_history[-1]
    parts.extend(
        [
            "<h3>Context and verification</h3>",
            f"<p>Context policy {_escape(context.context_policy)}@"
            f"{_escape(context.context_version)}; {context.completeness}; "
            f"estimated tokens {context.token_estimate}/{context.maximum_token_budget}.</p>",
            f"<p>Verification: {_escape(item.verification.status)} — "
            f"{_escape(item.verification.reason)}</p>",
        ]
    )
    parts.extend(_render_text_list("Unknowns", item.unknowns))
    parts.extend(_render_text_list("Next actions", decision.next_actions))
    parts.extend(_render_text_list("Fix guidance", decision.fix_guidance))
    parts.extend(_render_text_list("Limitations", item.limitations))
    parts.append("</article>")
    return parts


def _render_claims(title: str, claims: tuple[Claim, ...]) -> list[str]:
    parts = [f"<h3>{_escape(title)}</h3>"]
    if not claims:
        return [*parts, "<p>None.</p>"]
    parts.append("<ul>")
    for claim in claims:
        references = ", ".join(_escape(item) for item in claim.evidence_ids) or "none"
        parts.append(
            f"<li><code>{_escape(claim.claim_id)}</code> [{_escape(claim.status)}] "
            f"{_escape(claim.statement)}<br>Evidence: {references}</li>"
        )
    parts.append("</ul>")
    return parts


def _render_text_list(title: str, values: tuple[str, ...]) -> list[str]:
    if not values:
        return [f"<h3>{_escape(title)}</h3><p>None.</p>"]
    return [
        f"<h3>{_escape(title)}</h3><ul>",
        *(f"<li>{_escape(value)}</li>" for value in values),
        "</ul>",
    ]


def _row(name: str, value: str) -> str:
    return f"<tr><th>{_escape(name)}</th><td>{_escape(value)}</td></tr>"


def _location_text(location: SourceLocation) -> str:
    return f"{location.path}:{location.start_line}:{location.start_column}"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _occurrence(reference: RawResultReference) -> tuple[int, int]:
    return reference.run_index, reference.result_index


def _unique_text(values: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


__all__ = ["build_triage_report", "render_report_html", "render_report_jsonl"]
