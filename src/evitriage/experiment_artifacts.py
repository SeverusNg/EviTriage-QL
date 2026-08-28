"""Experiment-level aggregation, comparison, and immutable artifact finalization."""

from __future__ import annotations

import hashlib
import html
import json
import os
import stat
from collections import Counter
from pathlib import Path

from pydantic import BaseModel

from evitriage.domain.experiment import (
    ExistingSarifExperimentManifest,
    ExperimentPreflight,
    ExperimentSummary,
    resolve_manifest_path,
)
from evitriage.domain.report import AlertReport
from evitriage.errors import ConfigurationError, PolicyRejectedError, StorageError
from evitriage.evaluation import (
    BaselineEvaluation,
    LegacyBaselineBinding,
    bind_legacy_baseline_after_finalization,
    evaluate_final_decisions,
)

_MAXIMUM_DECISION_BYTES = 512 * 1024 * 1024


def finalize_experiment_artifacts(
    repository_root: Path,
    manifest: ExistingSarifExperimentManifest,
    preflight: ExperimentPreflight,
    summary: ExperimentSummary,
) -> tuple[Path, ...]:
    """Write deterministic aggregates after all independent runs have completed."""

    root = _fresh_output_root(resolve_manifest_path(repository_root, manifest.artifact_root))
    _write(root / "preflight.json", _model_json(preflight))
    _write(root / "batch-manifest.resolved.json", _model_json(manifest))
    _write(root / "summary.json", _model_json(summary))
    decisions = root / "automatic-decisions.jsonl"
    decision_paths = tuple(
        Path(item.decisions_path)
        for item in summary.cases
        if item.status == "completed" and item.decisions_path is not None
    )
    # Preserve every independently successful case even when a sibling case
    # failed. The summary/historical status still marks the batch incomplete;
    # partial success must not be erased or represented as a complete run.
    _aggregate_decisions(decision_paths, decisions)
    historical: dict[str, object] = (
        _historical_comparison(manifest, preflight, decision_paths)
        if summary.status == "completed"
        else {"schema_version": "1.0", "status": "incomplete"}
    )
    _write(
        root / "historical-comparison.json",
        json.dumps(historical, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n",
    )
    _write(root / "report.md", _report_markdown(summary, historical, chinese=False))
    _write(root / "report.zh-CN.md", _report_markdown(summary, historical, chinese=True))
    _write(root / "report.html", _report_html(summary, historical))
    _write(
        root / "execution-summary.redacted.json",
        _model_json(summary),
    )
    _write_checksums(root)
    _freeze_tree(root)
    return tuple(sorted(root.iterdir(), key=lambda item: item.name))


def evaluate_frozen_experiment(
    repository_root: Path,
    manifest: ExistingSarifExperimentManifest,
) -> BaselineEvaluation:
    """Read the human baseline only after the automatic aggregate is read-only."""

    specification = manifest.baseline_evaluation
    if specification is None:
        raise ConfigurationError("experiment manifest has no baseline evaluation input")
    root = resolve_manifest_path(repository_root, manifest.artifact_root).resolve(strict=True)
    automatic = root / "automatic-decisions.jsonl"
    _require_read_only_regular(automatic)
    bindings = tuple(
        LegacyBaselineBinding(
            id_prefix=case.baseline_id_prefix,
            raw_sarif_sha256=case.sarif_sha256,
            rule_id=_family_rule_id(case.expected_query_family),
        )
        for case in manifest.cases
        if case.baseline_id_prefix is not None
    )
    baseline = bind_legacy_baseline_after_finalization(
        (automatic,),
        resolve_manifest_path(repository_root, specification.baseline_path),
        bindings,
    )
    evaluation = evaluate_final_decisions((automatic,), baseline)
    target = root / "evaluation-v1-baseline.json"
    _write(target, _model_json(evaluation))
    target.chmod(0o400, follow_symlinks=False)
    # SHA256SUMS was frozen before blind evaluation. Replace it safely with a
    # new complete index only after the evaluation artifact is durable.
    checksum_path = root / "SHA256SUMS"
    checksum_path.chmod(0o600, follow_symlinks=False)
    checksum_path.unlink()
    _write_checksums(root).chmod(0o400, follow_symlinks=False)
    return evaluation


def _historical_comparison(
    manifest: ExistingSarifExperimentManifest,
    preflight: ExperimentPreflight,
    decision_paths: tuple[Path, ...],
) -> dict[str, object]:
    specification = manifest.historical_comparison
    if specification is None:
        return {"schema_version": "1.0", "status": "not_configured"}
    checked = {case.id: case for case in preflight.cases}
    reports = _decision_reports(decision_paths)
    before = checked[specification.before_case_id]
    after = checked[specification.after_case_id]
    full_before = checked[specification.full_before_case_id]
    full_after = checked[specification.full_after_case_id]
    target = specification.target
    before_targets = [
        report
        for report in reports
        if report.alert.raw_result_reference.raw_sarif_sha256 == before.sarif_sha256
        and report.alert.rule.rule_id == target.rule_id
        and report.alert.primary_location.path == target.source_path
        and any(
            item.enclosing_symbol == target.enclosing_symbol
            for item in report.slice_artifact.content.source_slices
        )
    ]
    after_targets = [
        report
        for report in reports
        if report.alert.raw_result_reference.raw_sarif_sha256 == after.sarif_sha256
        and report.alert.rule.rule_id == target.rule_id
        and report.alert.primary_location.path == target.source_path
        and any(
            item.enclosing_symbol == target.enclosing_symbol
            for item in report.slice_artifact.content.source_slices
        )
    ]
    if len(before_targets) != 1 or after_targets:
        raise PolicyRejectedError("historical target occurrence comparison is not unique")
    decision = before_targets[0].triage.final_decision
    return {
        "schema_version": "1.0",
        "status": "confirmed",
        "before_alert_count": before.result_count,
        "after_alert_count": after.result_count,
        "full_suite_before_count": full_before.result_count,
        "full_suite_after_count": full_after.result_count,
        "target": target.model_dump(mode="json"),
        "before_target": {
            "label": decision.label,
            "critical_evidence_ids": list(decision.critical_evidence_ids),
            "raw_result_reference": before_targets[0].alert.raw_result_reference.model_dump(
                mode="json"
            ),
        },
        "after_target": {"present": False, "meaning": "codeql_alert_absent_not_model_fp"},
    }


def _aggregate_decisions(paths: tuple[Path, ...], target: Path) -> None:
    content = bytearray()
    identities: set[tuple[str, int, int]] = set()
    for report in _decision_reports(paths):
        ref = report.alert.raw_result_reference
        identity = (ref.raw_sarif_sha256, ref.run_index, ref.result_index)
        if identity in identities:
            raise PolicyRejectedError("experiment aggregate contains a duplicate occurrence")
        identities.add(identity)
        content.extend(
            json.dumps(
                report.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        content.extend(b"\n")
    _write(target, bytes(content))


def _decision_reports(paths: tuple[Path, ...]) -> tuple[AlertReport, ...]:
    reports: list[AlertReport] = []
    for path in paths:
        raw = _read_regular(path, maximum_bytes=_MAXIMUM_DECISION_BYTES)
        reports.extend(
            AlertReport.model_validate_json(line, strict=True) for line in raw.splitlines()
        )
    return tuple(reports)


def _report_markdown(
    summary: ExperimentSummary, historical: dict[str, object], *, chinese: bool
) -> bytes:
    counts: Counter[str] = Counter()
    for case in summary.cases:
        counts.update({"TP": case.tp_count, "FP": case.fp_count, "NMC": case.nmc_count})
    if chinese:
        text = f"""# Existing-SARIF 资源泄露实验报告  # noqa: RUF001

[English](report.md) | 简体中文

- 状态: `{summary.status}`
- 告警: {summary.decided_alert_count}/{summary.triage_alert_count}
- 决策: TP {counts["TP"]} / FP {counts["FP"]} / NMC {counts["NMC"]}
- 模型调用: {summary.invocation_count}
- 历史对比: `{historical.get("status")}`

这是自动二次研判, 不会自动关闭上游告警。
V1 人工复核仅能在本报告固化后由独立评估命令读取;
它不是独立验证的绝对 ground truth。
"""
    else:
        text = f"""# Existing-SARIF resource-leak experiment report

English | [简体中文](report.zh-CN.md)

- Status: `{summary.status}`
- Alerts: {summary.decided_alert_count}/{summary.triage_alert_count}
- Decisions: TP {counts["TP"]} / FP {counts["FP"]} / NMC {counts["NMC"]}
- Model calls: {summary.invocation_count}
- Historical comparison: `{historical.get("status")}`

This is automated secondary triage and never dismisses an upstream alert.
The V1 human review may be read only by the separate evaluation command after
this report is frozen; it is not independently verified absolute ground truth.
"""
    return text.encode() + b"\n"


def _report_html(summary: ExperimentSummary, historical: dict[str, object]) -> bytes:
    body = (
        '<!doctype html><html><head><meta charset="utf-8"><title>Experiment</title></head>'
        f"<body><h1>Resource-leak experiment</h1><p>Status: {html.escape(summary.status)}</p>"
        f"<p>Alerts: {summary.decided_alert_count}/{summary.triage_alert_count}</p>"
        f"<p>Historical: {html.escape(str(historical.get('status')))}</p>"
        "<p>No upstream alert was automatically dismissed.</p></body></html>\n"
    )
    return body.encode()


def _family_rule_id(family: str) -> str:
    mapping = {
        "resource_input": "java/input-resource-leak",
        "resource_output": "java/output-resource-leak",
        "resource_database": "java/database-resource-leak",
        "resource_lock": "java/unreleased-lock",
    }
    try:
        return mapping[family]
    except KeyError as error:
        raise ConfigurationError("baseline binding requires a resource query family") from error


def _fresh_output_root(root: Path) -> Path:
    if root.exists():
        allowed = {"runs"}
        if (
            not root.is_dir()
            or root.is_symlink()
            or any(item.name not in allowed for item in root.iterdir())
        ):
            raise StorageError("experiment artifact root must be a new empty directory")
    else:
        root.mkdir(parents=True, mode=0o700)
    return root.resolve(strict=True)


def _write_checksums(root: Path) -> Path:
    target = root / "SHA256SUMS"
    lines = []
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        if path == target or not path.is_file() or path.is_symlink():
            continue
        lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n")
    _write(target, "".join(lines).encode())
    return target


def _freeze_tree(root: Path) -> None:
    for path in root.iterdir():
        if path.is_file() and not path.is_symlink():
            path.chmod(0o400, follow_symlinks=False)


def _require_read_only_regular(path: Path) -> None:
    metadata = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o200:
        raise PolicyRejectedError("automatic experiment decisions must be read-only")


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise PolicyRejectedError("experiment aggregate input must not be a symbolic link")
    metadata = absolute.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
        raise ConfigurationError("experiment aggregate input is unsafe or oversized")
    return absolute.read_bytes()


def _model_json(model: BaseModel) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ).encode()
        + b"\n"
    )


def _write(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise StorageError("experiment artifact write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["evaluate_frozen_experiment", "finalize_experiment_artifacts"]
