"""Post-finalization comparison against a separately supplied human baseline."""

from __future__ import annotations

import json
import os
import stat
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evitriage.domain.alerts import Sha256
from evitriage.domain.report import AlertReport
from evitriage.errors import ConfigurationError, PolicyRejectedError

Label = Literal["TP", "FP", "NMC"]


class _EvaluationModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class BaselineRecord(_EvaluationModel):
    """One human label already bound to an immutable SARIF occurrence."""

    raw_sarif_sha256: Sha256
    run_index: Annotated[int, Field(ge=0)]
    result_index: Annotated[int, Field(ge=0)]
    label: Label


class LegacyBaselineBinding(_EvaluationModel):
    """Bind one V1 review ID prefix to an exact frozen SARIF identity."""

    id_prefix: Annotated[str, Field(pattern=r"^[A-Z]$")]
    raw_sarif_sha256: Sha256
    rule_id: Annotated[str, Field(min_length=1, max_length=512)]


class LegacyBaselineRow(_EvaluationModel):
    """Strict frozen V1 human-review row read only after decisions finalize."""

    id: Annotated[str, Field(pattern=r"^[A-Z]-[0-9]+$")]
    query: Annotated[str, Field(min_length=1, max_length=512)]
    file: Annotated[str, Field(min_length=1, max_length=4096)]
    line: Annotated[int, Field(ge=1)]
    method: Annotated[str, Field(min_length=1, max_length=512)]
    scope: Annotated[str, Field(min_length=1, max_length=64)]
    label: Label
    label_basis: Literal["human_evidence_review"]
    evidence: Annotated[str, Field(min_length=1, max_length=100_000)]


class EvaluationRow(_EvaluationModel):
    raw_sarif_sha256: Sha256
    run_index: int
    result_index: int
    automatic_label: Label | None
    baseline_label: Label | None
    agreement: bool | None


class ClassMetric(_EvaluationModel):
    precision: float
    recall: float
    f1: float
    support: Annotated[int, Field(ge=0)]


class BaselineEvaluation(_EvaluationModel):
    """Blind engineering comparison, explicitly not independent ground truth."""

    schema_version: Literal["1.0"] = "1.0"
    evaluated_at: datetime
    decisions_finalized_before_evaluation: Literal[True] = True
    baseline_registered_as_model_evidence: Literal[False] = False
    baseline_status: Literal["human_review_not_independent_ground_truth"]
    automatic_counts: dict[Label, int]
    baseline_counts: dict[Label, int]
    confusion_matrix: dict[Label, dict[Label, int]]
    metrics: dict[Label, ClassMetric]
    agreement: float
    determined_rate: float
    nmc_rate: float
    aligned_count: Annotated[int, Field(ge=0)]
    missing_automatic: Annotated[int, Field(ge=0)]
    missing_baseline: Annotated[int, Field(ge=0)]
    rows: tuple[EvaluationRow, ...]

    @model_validator(mode="after")
    def validate_rates(self) -> Self:
        if any(value < 0 or value > 1 for value in self._rates):
            raise ValueError("evaluation rates must be within [0, 1]")
        return self

    @property
    def _rates(self) -> tuple[float, float, float]:
        return self.agreement, self.determined_rate, self.nmc_rate


def bind_legacy_baseline_after_finalization(
    decisions_paths: tuple[Path, ...],
    baseline_path: Path,
    bindings: tuple[LegacyBaselineBinding, ...],
) -> tuple[BaselineRecord, ...]:
    """Convert V1 IDs after immutable decisions exist.

    Prefix plus numeric suffix supplies identity. Query and location only
    cross-check that identity and never choose or infer a human label.
    """

    decisions = _load_decisions(decisions_paths)
    _finalized_regular(baseline_path, require_read_only=False)
    by_prefix = {item.id_prefix: item for item in bindings}
    if len(by_prefix) != len(bindings):
        raise ConfigurationError("legacy baseline bindings contain duplicate prefixes")
    bound: list[BaselineRecord] = []
    for line in baseline_path.read_bytes().splitlines():
        row = LegacyBaselineRow.model_validate(json.loads(line), strict=True)
        prefix, numeric = row.id.split("-", maxsplit=1)
        binding = by_prefix.get(prefix)
        if binding is None:
            raise ConfigurationError("legacy baseline row has no exact SARIF binding")
        key = (binding.raw_sarif_sha256, 0, int(numeric))
        report = decisions.get(key)
        if report is None:
            raise PolicyRejectedError("legacy baseline identity has no finalized decision")
        location = report.alert.primary_location
        if (
            report.alert.rule.rule_id != binding.rule_id
            or row.query != binding.rule_id
            or row.file != location.path
            or row.line != location.start_line
        ):
            raise PolicyRejectedError(
                "legacy baseline cross-check disagrees with the bound SARIF occurrence"
            )
        bound.append(
            BaselineRecord(
                raw_sarif_sha256=binding.raw_sarif_sha256,
                run_index=0,
                result_index=int(numeric),
                label=row.label,
            )
        )
    return tuple(bound)


def evaluate_final_decisions(
    decisions_paths: tuple[Path, ...], baseline: tuple[BaselineRecord, ...]
) -> BaselineEvaluation:
    """Compare only by exact raw SARIF occurrence identity."""

    reports = _load_decisions(decisions_paths)
    automatic = {key: item.triage.final_decision.label for key, item in reports.items()}
    human: dict[tuple[str, int, int], Label] = {}
    for record in baseline:
        key = (record.raw_sarif_sha256, record.run_index, record.result_index)
        if key in human:
            raise PolicyRejectedError("baseline contains duplicate occurrences")
        human[key] = record.label
    keys = sorted(set(automatic) | set(human))
    rows = tuple(
        EvaluationRow(
            raw_sarif_sha256=key[0],
            run_index=key[1],
            result_index=key[2],
            automatic_label=automatic.get(key),
            baseline_label=human.get(key),
            agreement=(automatic[key] == human[key] if key in automatic and key in human else None),
        )
        for key in keys
    )
    aligned = tuple(item for item in rows if item.agreement is not None)
    labels: tuple[Label, ...] = ("TP", "FP", "NMC")
    matrix: dict[Label, dict[Label, int]] = {
        expected: {actual: 0 for actual in labels} for expected in labels
    }
    for row in aligned:
        if row.baseline_label is not None and row.automatic_label is not None:
            matrix[row.baseline_label][row.automatic_label] += 1
    automatic_counts = Counter(
        row.automatic_label for row in aligned if row.automatic_label is not None
    )
    human_counts = Counter(human.values())
    # Rates cover only the exact baseline-aligned cohort; historical cases are
    # retained as missing_baseline rows and cannot distort this comparison.
    total = len(aligned)
    return BaselineEvaluation(
        evaluated_at=datetime.now(UTC),
        baseline_status="human_review_not_independent_ground_truth",
        automatic_counts={label: automatic_counts[label] for label in labels},
        baseline_counts={label: human_counts[label] for label in labels},
        confusion_matrix=matrix,
        metrics={label: _metric(label, matrix, labels) for label in labels},
        agreement=(
            sum(item.agreement is True for item in aligned) / len(aligned) if aligned else 0
        ),
        determined_rate=((automatic_counts["TP"] + automatic_counts["FP"]) / total if total else 0),
        nmc_rate=(automatic_counts["NMC"] / total if total else 0),
        aligned_count=len(aligned),
        missing_automatic=sum(item.automatic_label is None for item in rows),
        missing_baseline=sum(item.baseline_label is None for item in rows),
        rows=rows,
    )


def _load_decisions(paths: tuple[Path, ...]) -> dict[tuple[str, int, int], AlertReport]:
    reports: dict[tuple[str, int, int], AlertReport] = {}
    for path in paths:
        _finalized_regular(path)
        for line in path.read_bytes().splitlines():
            report = AlertReport.model_validate_json(line, strict=True)
            ref = report.alert.raw_result_reference
            key = (ref.raw_sarif_sha256, ref.run_index, ref.result_index)
            if key in reports:
                raise PolicyRejectedError("automatic decisions contain duplicate occurrences")
            reports[key] = report
    return reports


def _metric(
    label: Label,
    matrix: dict[Label, dict[Label, int]],
    labels: tuple[Label, ...],
) -> ClassMetric:
    true_positive = matrix[label][label]
    false_positive = sum(matrix[expected][label] for expected in labels if expected != label)
    false_negative = sum(matrix[label][actual] for actual in labels if actual != label)
    precision = (
        true_positive / (true_positive + false_positive) if true_positive + false_positive else 0
    )
    recall = (
        true_positive / (true_positive + false_negative) if true_positive + false_negative else 0
    )
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0
    return ClassMetric(
        precision=precision,
        recall=recall,
        f1=f1,
        support=true_positive + false_negative,
    )


def _finalized_regular(path: Path, *, require_read_only: bool = True) -> os.stat_result:
    absolute = Path(os.path.abspath(path))
    if absolute.is_symlink():
        raise PolicyRejectedError("evaluation input must not be a symbolic link")
    try:
        metadata = absolute.stat(follow_symlinks=False)
    except OSError as error:
        raise ConfigurationError("cannot inspect evaluation input") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyRejectedError("evaluation input must be a regular file")
    if require_read_only and stat.S_IMODE(metadata.st_mode) & 0o200:
        raise PolicyRejectedError("automatic decisions must be finalized read-only artifacts")
    return metadata


__all__ = [
    "BaselineEvaluation",
    "BaselineRecord",
    "ClassMetric",
    "EvaluationRow",
    "LegacyBaselineBinding",
    "bind_legacy_baseline_after_finalization",
    "evaluate_final_decisions",
]
