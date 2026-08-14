"""Manifest-driven existing-SARIF experiment preflight and sequential execution."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import yaml
from pydantic import BaseModel, ValidationError

from evitriage.config import _UniqueKeySafeLoader, load_llm_profile
from evitriage.domain.experiment import (
    ExistingSarifExperimentManifest,
    ExperimentCaseResult,
    ExperimentPreflight,
    ExperimentPreflightCase,
    ExperimentSummary,
    resolve_manifest_path,
)
from evitriage.domain.resource import classify_query_family
from evitriage.errors import (
    ConfigurationError,
    EviTriageError,
    PathSafetyError,
    PolicyRejectedError,
    StorageError,
)
from evitriage.llm import StructuredLLM
from evitriage.pipeline import run_sarif_triage
from evitriage.projects.registry import ProjectRegistry
from evitriage.sarif import parse_sarif_bytes

_MAXIMUM_MANIFEST_BYTES = 1024 * 1024
_MAXIMUM_SARIF_BYTES = 128 * 1024 * 1024


def load_experiment_manifest(path: Path) -> ExistingSarifExperimentManifest:
    """Read one strict duplicate-safe experiment manifest without following links."""

    raw = _read_regular(path, maximum_bytes=_MAXIMUM_MANIFEST_BYTES)
    try:
        value = yaml.load(raw.decode("utf-8"), Loader=_UniqueKeySafeLoader)  # noqa: S506
        if not isinstance(value, dict):
            raise ValueError("experiment manifest root must be a mapping")
        return ExistingSarifExperimentManifest.model_validate(value, strict=True)
    except (UnicodeError, ValueError, yaml.YAMLError, ValidationError) as error:
        raise ConfigurationError(
            "experiment manifest failed strict validation",
            details={"reason": type(error).__name__},
        ) from error


def preflight_existing_sarif_experiment(
    repository_root: Path,
    manifest: ExistingSarifExperimentManifest,
) -> ExperimentPreflight:
    """Validate every source/SARIF/spec identity before any LLM or credential access."""

    resolved: list[ExperimentPreflightCase] = []
    aggregate_root = resolve_manifest_path(repository_root, manifest.artifact_root).resolve(
        strict=False
    )
    run_root = resolve_manifest_path(repository_root, manifest.run_artifact_root).resolve(
        strict=False
    )
    workspace_root = resolve_manifest_path(repository_root, manifest.workspace_root).resolve(
        strict=False
    )
    source_roots = tuple(
        resolve_manifest_path(repository_root, case.source_root).resolve(strict=False)
        for case in manifest.cases
    )
    _validate_output_roots(aggregate_root, run_root, workspace_root, source_roots)
    for case in manifest.cases:
        source_root = resolve_manifest_path(repository_root, case.source_root)
        sarif_path = resolve_manifest_path(repository_root, case.sarif_path)
        project_spec = resolve_manifest_path(repository_root, case.project_spec)
        _require_source_identity(source_root, case.source_commit)
        raw = _read_regular(sarif_path, maximum_bytes=_MAXIMUM_SARIF_BYTES)
        observed_sha = hashlib.sha256(raw).hexdigest()
        if observed_sha != case.sarif_sha256:
            raise PolicyRejectedError(
                "experiment SARIF SHA-256 does not match the manifest",
                details={"case_id": case.id, "observed_sha256": observed_sha},
            )
        document = parse_sarif_bytes(raw)
        rules = Counter(
            _result_rule_id(run, result) for run in document.runs for result in run.results
        )
        result_count = sum(rules.values())
        if result_count != case.expected_result_count:
            raise PolicyRejectedError(
                "experiment SARIF result count does not match the manifest",
                details={
                    "case_id": case.id,
                    "expected": case.expected_result_count,
                    "observed": result_count,
                },
            )
        if case.mode == "triage":
            unexpected = {
                rule_id: classify_query_family(rule_id)
                for rule_id in rules
                if classify_query_family(rule_id) != case.expected_query_family
            }
            if unexpected:
                raise PolicyRejectedError(
                    "triage SARIF contains an unexpected query family",
                    details={"case_id": case.id, "unexpected_rule_count": len(unexpected)},
                )
        registry = ProjectRegistry(
            repository_root,
            allowed_source_roots=(source_root,),
            allowed_workspace_roots=(workspace_root,),
            allowed_artifact_roots=(run_root,),
        )
        spec = registry.validate_path(project_spec)
        if spec.source_path is None or Path(spec.source_path) != source_root.resolve(strict=True):
            raise PolicyRejectedError(
                "experiment ProjectSpec source does not match its case source root",
                details={"case_id": case.id},
            )
        if spec.workspace_root != str(workspace_root):
            raise PolicyRejectedError("ProjectSpec workspace root does not match the experiment")
        if spec.artifact_root != str(run_root):
            raise PolicyRejectedError("ProjectSpec artifact root does not match the experiment")
        resolved.append(
            ExperimentPreflightCase(
                id=case.id,
                source_root=str(source_root.resolve(strict=True)),
                source_commit=case.source_commit,
                sarif_path=str(sarif_path.resolve(strict=True)),
                sarif_sha256=observed_sha,
                result_count=result_count,
                rule_counts=dict(sorted(rules.items())),
                mode=case.mode,
                project_spec=str(project_spec.resolve(strict=True)),
            )
        )
    alert_count = sum(item.result_count for item in resolved if item.mode == "triage")
    return ExperimentPreflight(
        experiment_id=manifest.experiment_id,
        triage_alert_count=alert_count,
        minimum_model_calls=alert_count * 3,
        maximum_model_calls=alert_count * 6,
        cases=tuple(resolved),
    )


def run_existing_sarif_experiment(
    repository_root: Path,
    manifest: ExistingSarifExperimentManifest,
    *,
    llm: StructuredLLM | None,
    dry_run: bool,
) -> ExperimentSummary:
    """Preflight globally, then execute independent cases sequentially."""

    started = datetime.now(UTC)
    preflight = preflight_existing_sarif_experiment(repository_root, manifest)
    if dry_run:
        return ExperimentSummary(
            experiment_id=manifest.experiment_id,
            status="dry_run",
            started_at=started,
            completed_at=datetime.now(UTC),
            triage_alert_count=preflight.triage_alert_count,
            decided_alert_count=0,
            invocation_count=0,
            cases=tuple(
                ExperimentCaseResult(
                    case_id=item.id,
                    status="preflight_only",
                    skip_reason="dry_run_no_model_calls",
                    raw_sarif_sha256=item.sarif_sha256,
                    alert_count=item.result_count,
                )
                for item in preflight.cases
            ),
        )
    if llm is None:
        raise ConfigurationError("an LLM adapter is required for non-dry experiment execution")
    profile = load_llm_profile(resolve_manifest_path(repository_root, manifest.llm_profile))
    cases_by_id = {item.id: item for item in manifest.cases}
    outcomes: list[ExperimentCaseResult] = []
    for checked in preflight.cases:
        case = cases_by_id[checked.id]
        if case.mode == "audit_only":
            outcomes.append(
                ExperimentCaseResult(
                    case_id=case.id,
                    status="audit_only",
                    raw_sarif_sha256=checked.sarif_sha256,
                    alert_count=checked.result_count,
                )
            )
            continue
        try:
            summary = run_sarif_triage(
                repository_root,
                project_config=Path(checked.project_spec),
                sarif_path=Path(checked.sarif_path),
                profile=profile,
                llm=llm,
                allowed_source_roots=(Path(checked.source_root),),
                allowed_workspace_roots=(Path(manifest.workspace_root),),
                allowed_artifact_roots=(Path(manifest.run_artifact_root),),
            )
            decisions_path = Path(summary.artifact_run_root) / summary.report_jsonl.relative_path
            decisions_sha256 = hashlib.sha256(
                _read_regular(decisions_path, maximum_bytes=_MAXIMUM_SARIF_BYTES)
            ).hexdigest()
            outcomes.append(
                ExperimentCaseResult(
                    case_id=case.id,
                    status="completed",
                    run_id=summary.run_id,
                    run_artifact_root=summary.artifact_run_root,
                    decisions_path=str(decisions_path.resolve(strict=True)),
                    decisions_sha256=decisions_sha256,
                    raw_sarif_sha256=checked.sarif_sha256,
                    alert_count=summary.alert_count,
                    tp_count=summary.tp_count,
                    fp_count=summary.fp_count,
                    nmc_count=summary.nmc_count,
                    invocation_count=summary.invocation_count,
                )
            )
        except EviTriageError as error:
            details = error.details
            outcomes.append(
                ExperimentCaseResult(
                    case_id=case.id,
                    status="failed",
                    run_id=cast(str | None, details.get("run_id")),
                    run_artifact_root=cast(str | None, details.get("artifact_run_root")),
                    raw_sarif_sha256=checked.sarif_sha256,
                    alert_count=checked.result_count,
                    error_code=error.code,
                )
            )
    decided = sum(item.alert_count for item in outcomes if item.status == "completed")
    return ExperimentSummary(
        experiment_id=manifest.experiment_id,
        status="incomplete" if any(item.status == "failed" for item in outcomes) else "completed",
        started_at=started,
        completed_at=datetime.now(UTC),
        triage_alert_count=preflight.triage_alert_count,
        decided_alert_count=decided,
        invocation_count=sum(item.invocation_count for item in outcomes),
        cases=tuple(outcomes),
    )


def persist_experiment_preflight(root: Path, preflight: ExperimentPreflight) -> Path:
    """Create one no-overwrite preflight artifact in the validated experiment root."""

    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    target = root / "preflight.json"
    payload = _model_json(preflight)
    _write_new(target, payload)
    return target


def _result_rule_id(run: object, result: object) -> str:
    result_rule = getattr(result, "rule_id")  # noqa: B009 - strict SARIF model
    if result_rule is not None:
        return cast(str, result_rule)
    index = getattr(result, "rule_index")  # noqa: B009 - strict SARIF model
    tool = getattr(run, "tool")  # noqa: B009 - strict SARIF model
    driver = getattr(tool, "driver")  # noqa: B009 - strict SARIF model
    rules = getattr(driver, "rules")  # noqa: B009 - strict SARIF model
    if index is None or index >= len(rules):
        raise PolicyRejectedError("SARIF result does not resolve to a structured rule ID")
    return cast(str, rules[index].id)


def _require_source_identity(source_root: Path, commit: str) -> None:
    canonical = source_root.resolve(strict=True)
    if not canonical.is_dir() or canonical.is_symlink():
        raise PathSafetyError("experiment source must be a non-symlink directory")
    head = _git(canonical, ("rev-parse", "HEAD")).strip()
    if head != commit:
        raise PolicyRejectedError(
            "experiment source commit does not match the manifest",
            details={"expected": commit, "observed": head},
        )
    if _git(canonical, ("status", "--porcelain", "--untracked-files=all")):
        raise PolicyRejectedError("experiment source worktree is not clean")


def _git(cwd: Path, arguments: tuple[str, ...]) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ConfigurationError("git is unavailable for experiment source inspection")
    try:
        completed = subprocess.run(  # noqa: S603 - fixed git argv and validated cwd
            (executable, *arguments),
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ConfigurationError("cannot inspect experiment Git source") from error
    if completed.returncode != 0:
        raise ConfigurationError(
            "experiment Git source inspection failed",
            details={"exit_code": completed.returncode},
        )
    return completed.stdout


def _validate_output_roots(
    aggregate_root: Path,
    run_root: Path,
    workspace_root: Path,
    source_roots: tuple[Path, ...],
) -> None:
    if run_root == aggregate_root or not run_root.is_relative_to(aggregate_root):
        raise PathSafetyError("experiment run artifact root must be below aggregate root")
    if workspace_root == aggregate_root or workspace_root.is_relative_to(aggregate_root):
        raise PathSafetyError("experiment workspace and aggregate roots must not overlap")
    if aggregate_root.is_relative_to(workspace_root):
        raise PathSafetyError("experiment workspace and aggregate roots must not overlap")
    for source_root in source_roots:
        if any(
            output == source_root
            or output.is_relative_to(source_root)
            or source_root.is_relative_to(output)
            for output in (aggregate_root, workspace_root)
        ):
            raise PathSafetyError("experiment output roots must not overlap a source root")
    for root in (aggregate_root, run_root, workspace_root):
        current = Path(root.anchor)
        for part in root.parts[1:]:
            current /= part
            if current.is_symlink():
                raise PathSafetyError("experiment output path contains a symbolic link")


def _read_regular(path: Path, *, maximum_bytes: int) -> bytes:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink():
            raise PathSafetyError(f"experiment input path contains a symbolic link: {current}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags)
    except OSError as error:
        raise ConfigurationError("cannot open experiment input") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_bytes:
            raise ConfigurationError("experiment input is unsafe or oversized")
        chunks: list[bytes] = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) != metadata.st_size:
            raise ConfigurationError("experiment input changed or exceeded its bound")
        return content
    finally:
        os.close(descriptor)


def _model_json(model: BaseModel) -> bytes:
    value = cast(object, model.model_dump(mode="json"))
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"


def _write_new(path: Path, content: bytes) -> None:
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


__all__ = [
    "load_experiment_manifest",
    "persist_experiment_preflight",
    "preflight_existing_sarif_experiment",
    "run_existing_sarif_experiment",
]
