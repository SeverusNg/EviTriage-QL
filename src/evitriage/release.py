"""Deterministic Gate G release metadata and artifact verification."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote

import yaml
from pydantic import ValidationError

from evitriage.domain.report import AlertReport
from evitriage.domain.run import RunManifest, WorkflowState
from evitriage.domain.triage import TriageRunSummary

_CYCLONEDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.5.schema.json"
_MANIFEST_NAME = "release-manifest.json"
_SBOM_NAME = "evitriage-ql.cdx.json"
_CHECKSUMS_NAME = "SHA256SUMS"
_DEPENDENCY_INVENTORY_NAME = "requirements-all.lock"
_DEMO_SUMMARY_NAME = "example-demo-summary.json"
_EXAMPLE_JSONL_NAME = "example-decisions.jsonl"
_EXAMPLE_HTML_NAME = "example-report.html"
_EXAMPLE_MANIFEST_NAME = "example-run-manifest.json"
_MATRIX_SUMMARY_NAME = "case-matrix.json"
_PYTEST_SUMMARY_NAME = "pytest-summary.json"
_SECURITY_SUMMARY_NAME = "security-test-summary.json"
_GENERATED_NAMES = frozenset({_MANIFEST_NAME, _SBOM_NAME, _CHECKSUMS_NAME})
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SAFE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
_MATRIX_EXPECTATIONS = (
    ("cwe22-direct-tp", "CWE-22", "TP", 0),
    ("cwe22-canonical-fp", "CWE-22", "FP", 1),
    ("cwe22-unknown-wrapper-nmc", "CWE-22", "NMC", 2),
    ("cwe78-direct-tp", "CWE-78", "TP", 3),
    ("cwe78-allowlist-fp", "CWE-78", "FP", 4),
    ("prompt-injection", "CWE-22", "TP", 5),
)


class ReleaseArtifactError(ValueError):
    """Raised when release inputs or generated artifacts are inconsistent."""


@dataclass(frozen=True)
class LockedPackage:
    """A dependency record extracted from the exact uv lock file."""

    name: str
    version: str
    runtime_dependencies: tuple[str, ...]
    optional_dependencies: tuple[str, ...]
    sdist_url: str | None
    sdist_sha256: str | None
    is_project: bool

    @property
    def bom_ref(self) -> str:
        """Return the stable Package URL used as the CycloneDX reference."""

        return f"pkg:pypi/{quote(self.name, safe='-._~')}@{quote(self.version, safe='-._~')}"

    @property
    def dependencies(self) -> tuple[str, ...]:
        """Return all locked edges represented by the release SBOM."""

        return tuple(sorted({*self.runtime_dependencies, *self.optional_dependencies}))


@dataclass(frozen=True)
class ReleaseInputs:
    """Validated repository metadata used to create release artifacts."""

    version: str
    lock_sha256: str
    schema_set_sha256: str
    prompt_version: str
    packages: tuple[LockedPackage, ...]


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of one regular file."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_release_inputs(repository_root: Path) -> ReleaseInputs:
    """Load and cross-check all version and lock metadata for a release."""

    root = repository_root.resolve(strict=True)
    pyproject_path = root / "pyproject.toml"
    lock_path = root / "uv.lock"
    citation_path = root / "CITATION.cff"
    package_init_path = root / "src/evitriage/__init__.py"
    workflow_path = root / "src/evitriage/agents/workflow.py"
    for path in (pyproject_path, lock_path, citation_path, package_init_path, workflow_path):
        _require_regular_file(path)

    pyproject = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    project_table = _mapping(pyproject.get("project"), "pyproject [project]")
    pyproject_version = _string(project_table.get("version"), "pyproject project.version")

    lock_document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = _locked_packages(lock_document)
    project_packages = tuple(package for package in packages if package.is_project)
    if len(project_packages) != 1 or project_packages[0].name != "evitriage-ql":
        raise ReleaseArtifactError("uv.lock must contain exactly one editable evitriage-ql project")

    package_version = _literal_assignment(package_init_path, "__version__")
    citation = yaml.safe_load(citation_path.read_text(encoding="utf-8"))
    citation_version = _string(
        _mapping(citation, "CITATION.cff").get("version"), "citation version"
    )
    observed_versions = {
        "pyproject.toml": pyproject_version,
        "uv.lock": project_packages[0].version,
        "src/evitriage/__init__.py": package_version,
        "CITATION.cff": citation_version,
    }
    if len(set(observed_versions.values())) != 1:
        details = ", ".join(f"{source}={version}" for source, version in observed_versions.items())
        raise ReleaseArtifactError(f"release versions are inconsistent: {details}")

    prompt_version = _literal_assignment(workflow_path, "_PROMPT_VERSION")
    schema_set_sha256 = _schema_set_digest(root / "schemas")
    return ReleaseInputs(
        version=pyproject_version,
        lock_sha256=sha256_file(lock_path),
        schema_set_sha256=schema_set_sha256,
        prompt_version=prompt_version,
        packages=packages,
    )


def build_cyclonedx(inputs: ReleaseInputs) -> dict[str, object]:
    """Build a deterministic CycloneDX 1.5 document from the complete uv lock."""

    package_by_name = {package.name: package for package in inputs.packages}
    project = package_by_name["evitriage-ql"]
    runtime_names = _dependency_closure(project.runtime_dependencies, package_by_name)
    components: list[dict[str, object]] = []
    for package in inputs.packages:
        if package.is_project:
            continue
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": package.bom_ref,
            "name": package.name,
            "version": package.version,
            "purl": package.bom_ref,
            "scope": "required" if package.name in runtime_names else "optional",
            "properties": [
                {
                    "name": "evitriage:dependency-group",
                    "value": "runtime" if package.name in runtime_names else "development",
                }
            ],
        }
        if package.sdist_sha256 is not None:
            component["hashes"] = [{"alg": "SHA-256", "content": package.sdist_sha256}]
        if package.sdist_url is not None:
            component["externalReferences"] = [{"type": "distribution", "url": package.sdist_url}]
        components.append(component)

    dependencies = [
        {
            "ref": package.bom_ref,
            "dependsOn": sorted(package_by_name[name].bom_ref for name in package.dependencies),
        }
        for package in inputs.packages
    ]
    serial_seed = f"evitriage-ql:{inputs.version}:{inputs.lock_sha256}"
    return {
        "$schema": _CYCLONEDX_SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, serial_seed)}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": project.bom_ref,
                "name": project.name,
                "version": project.version,
                "purl": project.bom_ref,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
            "properties": [
                {"name": "evitriage:uv-lock-sha256", "value": inputs.lock_sha256},
                {"name": "evitriage:includes-development-dependencies", "value": "true"},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def assemble_example_evidence(
    repository_root: Path,
    output_directory: Path,
    demo_summary_path: Path,
) -> Path:
    """Validate one finalized six-case demo and stage its reviewed release evidence."""

    if repository_root.is_symlink() or output_directory.is_symlink():
        raise ReleaseArtifactError("repository and release output must not be symlinks")
    root = repository_root.resolve(strict=True)
    output = output_directory.resolve(strict=True)
    if not output.is_dir():
        raise ReleaseArtifactError("release output must be a regular directory, not a symlink")
    summary_path = demo_summary_path.resolve(strict=True)
    if summary_path != output / _DEMO_SUMMARY_NAME:
        raise ReleaseArtifactError(
            f"demo summary must be staged as {_DEMO_SUMMARY_NAME} inside the release directory"
        )
    _require_regular_file(summary_path)
    try:
        summary = TriageRunSummary.model_validate_json(summary_path.read_bytes(), strict=True)
    except ValidationError as exc:
        raise ReleaseArtifactError("example demo summary is not a strict TriageRunSummary") from exc
    if (
        summary.project_id != "gate-e-demo"
        or summary.real_codeql
        or summary.source_kind != "ingest"
        or summary.alert_count != 6
        or (summary.tp_count, summary.fp_count, summary.nmc_count) != (3, 2, 1)
        or summary.invocation_count != 18
    ):
        raise ReleaseArtifactError(
            "example demo summary does not represent the frozen six-case run"
        )

    run_root = Path(summary.artifact_run_root)
    if run_root.is_symlink():
        raise ReleaseArtifactError("example run root must not be a symlink")
    run_root = run_root.resolve(strict=True)
    expected_runs_root = (root / "artifacts/runs").resolve(strict=True)
    if not run_root.is_dir() or not run_root.is_relative_to(expected_runs_root):
        raise ReleaseArtifactError("example run root is outside the repository artifact run root")
    manifest_path = run_root / "run-manifest.json"
    event_log_path = run_root / "workflow-events.jsonl"
    _require_regular_file(manifest_path)
    _require_regular_file(event_log_path)
    try:
        manifest = RunManifest.model_validate_json(manifest_path.read_bytes(), strict=True)
    except ValidationError as exc:
        raise ReleaseArtifactError("example run manifest is invalid") from exc
    if (
        manifest.run_id != summary.run_id
        or manifest.project_id != summary.project_id
        or manifest.project_spec_sha256 != summary.project_spec_sha256
        or manifest.snapshot_identity != summary.snapshot_identity
        or manifest.state is not WorkflowState.JUDGED
        or manifest.status != "completed"
    ):
        raise ReleaseArtifactError("example run manifest does not match its demo summary")
    records_by_path = {record.relative_path: record for record in manifest.artifacts}
    for record in manifest.artifacts:
        artifact = run_root / record.relative_path
        _require_regular_file(artifact)
        if artifact.stat().st_size != record.size_bytes or sha256_file(artifact) != record.sha256:
            raise ReleaseArtifactError(
                f"example run artifact failed size/hash verification: {record.relative_path}"
            )
        if stat.S_IMODE(artifact.stat().st_mode) != 0o400:
            raise ReleaseArtifactError(
                f"example run artifact is not owner-read-only: {record.relative_path}"
            )
    for audit_path in (manifest_path, event_log_path):
        if stat.S_IMODE(audit_path.stat().st_mode) != 0o400:
            raise ReleaseArtifactError(
                f"example audit file is not owner-read-only: {audit_path.name}"
            )
    for summary_record in (
        summary.raw_sarif,
        summary.normalized_bundle,
        *summary.slice_artifacts,
        summary.context_index,
        summary.evidence_registry,
        summary.evidence_graph,
        summary.source_map,
        summary.analyst_artifact,
        summary.rebuttal_artifact,
        summary.judged_artifact,
        summary.report_jsonl,
        summary.report_html,
    ):
        if records_by_path.get(summary_record.relative_path) != summary_record:
            raise ReleaseArtifactError("example summary cites an artifact absent from its manifest")

    jsonl_path = run_root / summary.report_jsonl.relative_path
    html_path = run_root / summary.report_html.relative_path
    report_lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    try:
        reports = tuple(AlertReport.model_validate_json(line, strict=True) for line in report_lines)
    except ValidationError as exc:
        raise ReleaseArtifactError("example JSONL contains an invalid alert report") from exc
    if len(reports) != 6:
        raise ReleaseArtifactError("example JSONL must contain exactly six alert reports")
    reports_by_index = {
        report.alert.raw_result_reference.result_index: report for report in reports
    }
    if set(reports_by_index) != set(range(6)):
        raise ReleaseArtifactError("example JSONL result indexes do not close over the matrix")

    case_directory = root / "tests/fixtures/java-microbench/gate-e-demo/cases"
    _require_directory(case_directory)
    expected_case_names = {
        f"{case_id}.json" for case_id, _cwe, _label, _index in _MATRIX_EXPECTATIONS
    }
    actual_case_names = {path.name for path in case_directory.iterdir()}
    if actual_case_names != expected_case_names:
        raise ReleaseArtifactError("release matrix case files differ from the frozen six-case set")
    cases: list[dict[str, object]] = []
    for matrix_role, cwe_id, expected_label, result_index in _MATRIX_EXPECTATIONS:
        case_path = case_directory / f"{matrix_role}.json"
        _require_regular_file(case_path)
        case = _mapping(_load_json(case_path), f"matrix case {matrix_role}")
        source = _mapping(case.get("source"), f"matrix case {matrix_role} source")
        sarif = _mapping(case.get("sarif"), f"matrix case {matrix_role} SARIF")
        ground_truth = _mapping(case.get("ground_truth"), f"matrix case {matrix_role} ground truth")
        if (
            case.get("schema_version") != "1.0"
            or case.get("case_id") != matrix_role
            or case.get("matrix_role") != matrix_role
            or case.get("cwe_id") != cwe_id
            or sarif != {"run_index": 0, "result_index": result_index}
            or ground_truth.get("label") != expected_label
        ):
            raise ReleaseArtifactError(f"matrix case contract mismatch: {matrix_role}")
        report = reports_by_index[result_index]
        source_sha256 = _string(source.get("sha256"), f"matrix case {matrix_role} source hash")
        if (
            report.alert.rule.cwe_ids != (cwe_id,)
            or report.alert.primary_location.artifact_sha256 != source_sha256
            or report.triage.final_decision.label != expected_label
            or report.triage.final_decision.auto_dismiss
        ):
            raise ReleaseArtifactError(f"matrix report does not match case contract: {matrix_role}")
        security_expectation: str | None = None
        if matrix_role == "prompt-injection":
            security = _mapping(
                case.get("security_expectation"), "prompt-injection security expectation"
            )
            injection = _string(security.get("injection_text"), "prompt-injection text")
            if injection not in report.slice_artifact.content.source_slices[0].content:
                raise ReleaseArtifactError(
                    "prompt injection is absent from its bounded source slice"
                )
            security_expectation = _string(
                security.get("expected_effect"), "prompt-injection expected effect"
            )
        decision = report.triage.final_decision
        cases.append(
            {
                "case_id": matrix_role,
                "matrix_role": matrix_role,
                "cwe_id": cwe_id,
                "expected_label": expected_label,
                "actual_label": decision.label,
                "run_index": 0,
                "result_index": result_index,
                "source_sha256": source_sha256,
                "alert_fingerprint": report.alert.alert_fingerprint,
                "critical_claim_ids": list(decision.critical_claim_ids),
                "critical_evidence_ids": list(decision.critical_evidence_ids),
                "auto_dismiss": decision.auto_dismiss,
                "security_expectation": security_expectation,
            }
        )

    _validate_pytest_summary(output / _PYTEST_SUMMARY_NAME, expected_suite="full")
    _validate_pytest_summary(output / _SECURITY_SUMMARY_NAME, expected_suite="security")
    (output / _EXAMPLE_JSONL_NAME).write_bytes(jsonl_path.read_bytes())
    (output / _EXAMPLE_HTML_NAME).write_bytes(html_path.read_bytes())
    (output / _EXAMPLE_MANIFEST_NAME).write_bytes(manifest_path.read_bytes())
    _write_json(
        output / _MATRIX_SUMMARY_NAME,
        {
            "schema_version": "1.0",
            "analysis_identity": summary.analysis_identity,
            "synthetic": True,
            "real_codeql": False,
            "case_count": 6,
            "label_counts": {"TP": 3, "FP": 2, "NMC": 1},
            "cases": cases,
        },
    )
    return output / _MATRIX_SUMMARY_NAME


def write_release_artifacts(repository_root: Path, output_directory: Path) -> Path:
    """Write SBOM, checksums, and a strict manifest around prebuilt distributions."""

    if repository_root.is_symlink() or output_directory.is_symlink():
        raise ReleaseArtifactError("repository and release output must not be symlinks")
    root = repository_root.resolve(strict=True)
    output = output_directory.resolve(strict=True)
    if not output.is_dir():
        raise ReleaseArtifactError("release output must be a regular directory, not a symlink")
    inputs = load_release_inputs(root)
    expected_inputs = {
        ".gitignore": "tool-metadata",
        _MATRIX_SUMMARY_NAME: "case-matrix",
        _DEMO_SUMMARY_NAME: "demo-summary",
        _EXAMPLE_JSONL_NAME: "example-jsonl",
        _EXAMPLE_HTML_NAME: "example-html",
        _EXAMPLE_MANIFEST_NAME: "example-run-manifest",
        _PYTEST_SUMMARY_NAME: "test-summary",
        f"evitriage_ql-{inputs.version}-py3-none-any.whl": "wheel",
        f"evitriage_ql-{inputs.version}.tar.gz": "source-distribution",
        _DEPENDENCY_INVENTORY_NAME: "dependency-inventory",
        _SECURITY_SUMMARY_NAME: "security-test-summary",
    }
    actual_names: set[str] = set()
    for path in output.iterdir():
        if path.name in _GENERATED_NAMES:
            continue
        _require_regular_file(path)
        actual_names.add(path.name)
    if actual_names != set(expected_inputs):
        missing = sorted(set(expected_inputs) - actual_names)
        unexpected = sorted(actual_names - set(expected_inputs))
        raise ReleaseArtifactError(
            f"release directory inputs differ from the frozen set; missing={missing}, "
            f"unexpected={unexpected}"
        )
    if (output / ".gitignore").read_bytes() != b"*":
        raise ReleaseArtifactError("uv build output .gitignore must contain exactly '*'")
    _validate_pytest_summary(output / _PYTEST_SUMMARY_NAME, expected_suite="full")
    _validate_pytest_summary(output / _SECURITY_SUMMARY_NAME, expected_suite="security")

    sbom_path = output / _SBOM_NAME
    _write_json(sbom_path, build_cyclonedx(inputs))
    files: list[dict[str, object]] = []
    for name, role in sorted((*expected_inputs.items(), (_SBOM_NAME, "sbom"))):
        path = output / name
        _require_regular_file(path)
        files.append(
            {
                "path": name,
                "role": role,
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
        )

    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "release_version": inputs.version,
        "uv_lock_sha256": inputs.lock_sha256,
        "schema_set_sha256": inputs.schema_set_sha256,
        "prompt_version": inputs.prompt_version,
        "sbom_format": "CycloneDX 1.5",
        "files": files,
        "claims": {
            "network_free_demo_required": True,
            "real_codeql_smoke_required": True,
            "release_tag_created": False,
        },
    }
    manifest_path = output / _MANIFEST_NAME
    _write_json(manifest_path, manifest)
    checksummed = [*files, _file_record(manifest_path, "release-manifest")]
    checksum_text = "".join(
        f"{record['sha256']}  {record['path']}\n"
        for record in sorted(checksummed, key=lambda item: cast(str, item["path"]))
    )
    (output / _CHECKSUMS_NAME).write_text(checksum_text, encoding="utf-8")
    verify_release_artifacts(output)
    return manifest_path


def verify_release_artifacts(output_directory: Path) -> dict[str, object]:
    """Verify a Gate G manifest, every registered file, and SHA256SUMS."""

    if output_directory.is_symlink():
        raise ReleaseArtifactError("release output must be a regular directory, not a symlink")
    output = output_directory.resolve(strict=True)
    if not output.is_dir():
        raise ReleaseArtifactError("release output must be a regular directory, not a symlink")
    manifest_path = output / _MANIFEST_NAME
    checksums_path = output / _CHECKSUMS_NAME
    _require_regular_file(manifest_path)
    _require_regular_file(checksums_path)
    manifest_value = _load_json(manifest_path)
    manifest = _mapping(manifest_value, "release manifest")
    allowed_keys = {
        "schema_version",
        "release_version",
        "uv_lock_sha256",
        "schema_set_sha256",
        "prompt_version",
        "sbom_format",
        "files",
        "claims",
    }
    if set(manifest) != allowed_keys or manifest.get("schema_version") != "1.0":
        raise ReleaseArtifactError("release manifest has an unknown field or schema version")
    release_version = _string(manifest.get("release_version"), "release version")
    for field in ("uv_lock_sha256", "schema_set_sha256"):
        digest = _string(manifest.get(field), f"release manifest {field}")
        if _SHA256_PATTERN.fullmatch(digest) is None:
            raise ReleaseArtifactError(f"release manifest {field} must be a SHA-256 value")
    _string(manifest.get("prompt_version"), "release prompt version")
    if manifest.get("sbom_format") != "CycloneDX 1.5":
        raise ReleaseArtifactError("release manifest must identify CycloneDX 1.5")
    if manifest.get("claims") != {
        "network_free_demo_required": True,
        "real_codeql_smoke_required": True,
        "release_tag_created": False,
    }:
        raise ReleaseArtifactError("release manifest claims do not match the frozen gate")
    file_values = manifest.get("files")
    if not isinstance(file_values, list) or not file_values:
        raise ReleaseArtifactError("release manifest files must be a non-empty array")

    expected_checksums: dict[str, str] = {}
    observed_roles: dict[str, str] = {}
    for index, value in enumerate(file_values):
        record = _mapping(value, f"release manifest file {index}")
        if set(record) != {"path", "role", "sha256", "size_bytes"}:
            raise ReleaseArtifactError(f"release manifest file {index} has unknown fields")
        name = _safe_release_name(_string(record.get("path"), f"release file {index} path"))
        digest = _string(record.get("sha256"), f"release file {index} sha256")
        role = _string(record.get("role"), f"release file {index} role")
        size = record.get("size_bytes")
        if not _SHA256_PATTERN.fullmatch(digest) or not isinstance(size, int) or size < 0:
            raise ReleaseArtifactError(f"release manifest file {index} has invalid metadata")
        path = output / name
        _require_regular_file(path)
        if path.stat().st_size != size or sha256_file(path) != digest:
            raise ReleaseArtifactError(f"release file failed size/hash verification: {name}")
        if name in expected_checksums:
            raise ReleaseArtifactError(f"duplicate release manifest file: {name}")
        expected_checksums[name] = digest
        observed_roles[name] = role

    expected_roles = {
        ".gitignore": "tool-metadata",
        _MATRIX_SUMMARY_NAME: "case-matrix",
        _DEMO_SUMMARY_NAME: "demo-summary",
        _EXAMPLE_JSONL_NAME: "example-jsonl",
        _EXAMPLE_HTML_NAME: "example-html",
        _EXAMPLE_MANIFEST_NAME: "example-run-manifest",
        _SBOM_NAME: "sbom",
        _PYTEST_SUMMARY_NAME: "test-summary",
        f"evitriage_ql-{release_version}-py3-none-any.whl": "wheel",
        f"evitriage_ql-{release_version}.tar.gz": "source-distribution",
        _DEPENDENCY_INVENTORY_NAME: "dependency-inventory",
        _SECURITY_SUMMARY_NAME: "security-test-summary",
    }
    if observed_roles != expected_roles:
        raise ReleaseArtifactError("release manifest file names/roles do not match the frozen set")
    _validate_pytest_summary(output / _PYTEST_SUMMARY_NAME, expected_suite="full")
    _validate_pytest_summary(output / _SECURITY_SUMMARY_NAME, expected_suite="security")
    matrix = _mapping(_load_json(output / _MATRIX_SUMMARY_NAME), "case matrix summary")
    if (
        set(matrix)
        != {
            "schema_version",
            "analysis_identity",
            "synthetic",
            "real_codeql",
            "case_count",
            "label_counts",
            "cases",
        }
        or matrix.get("schema_version") != "1.0"
        or matrix.get("synthetic") is not True
        or matrix.get("real_codeql") is not False
        or matrix.get("case_count") != 6
        or matrix.get("label_counts") != {"TP": 3, "FP": 2, "NMC": 1}
        or not isinstance(matrix.get("cases"), list)
        or len(cast(list[object], matrix["cases"])) != 6
    ):
        raise ReleaseArtifactError("case matrix summary does not match the frozen release matrix")

    expected_checksums[_MANIFEST_NAME] = sha256_file(manifest_path)
    actual_checksums = _parse_checksums(checksums_path)
    if actual_checksums != expected_checksums:
        raise ReleaseArtifactError("SHA256SUMS does not match the release manifest closure")
    expected_directory_names = {*expected_checksums, _CHECKSUMS_NAME}
    actual_directory_names: set[str] = set()
    for path in output.iterdir():
        _require_regular_file(path)
        actual_directory_names.add(path.name)
    if actual_directory_names != expected_directory_names:
        raise ReleaseArtifactError("release directory contains an unregistered or missing file")
    return manifest


def _validate_pytest_summary(path: Path, *, expected_suite: str) -> dict[str, object]:
    _require_regular_file(path)
    summary = _mapping(_load_json(path), f"{expected_suite} pytest summary")
    if set(summary) != {
        "schema_version",
        "suite",
        "command",
        "outcome",
        "exit_code",
        "tests_collected",
        "counts",
        "coverage_gate_enforced",
    }:
        raise ReleaseArtifactError(f"{expected_suite} pytest summary has unknown fields")
    counts = _mapping(summary.get("counts"), f"{expected_suite} pytest counts")
    if set(counts) != {
        "passed",
        "failed",
        "errors",
        "skipped",
        "xfailed",
        "xpassed",
        "deselected",
    } or any(not isinstance(value, int) or value < 0 for value in counts.values()):
        raise ReleaseArtifactError(f"{expected_suite} pytest summary has invalid counts")
    numeric_counts = cast(dict[str, int], counts)
    tests_collected = summary.get("tests_collected")
    if (
        summary.get("schema_version") != "1.0"
        or summary.get("suite") != expected_suite
        or summary.get("command") != "pytest"
        or summary.get("outcome") != "passed"
        or summary.get("exit_code") != 0
        or not isinstance(tests_collected, int)
        or tests_collected < 1
        or numeric_counts["passed"] < 1
        or numeric_counts["failed"] != 0
        or numeric_counts["errors"] != 0
        or summary.get("coverage_gate_enforced") is not (expected_suite == "full")
    ):
        raise ReleaseArtifactError(f"{expected_suite} pytest summary is not a passing run")
    return summary


def _locked_packages(lock_document: dict[str, object]) -> tuple[LockedPackage, ...]:
    package_values = lock_document.get("package")
    if not isinstance(package_values, list) or not package_values:
        raise ReleaseArtifactError("uv.lock package list is missing")
    packages: list[LockedPackage] = []
    names: set[str] = set()
    for index, value in enumerate(package_values):
        package = _mapping(value, f"uv.lock package {index}")
        name = _string(package.get("name"), f"uv.lock package {index} name")
        version = _string(package.get("version"), f"uv.lock package {index} version")
        if name in names:
            raise ReleaseArtifactError(f"uv.lock contains duplicate package name: {name}")
        names.add(name)
        source = _mapping(package.get("source"), f"uv.lock package {name} source")
        is_project = source.get("editable") == "."
        runtime_dependency_names = _dependency_names(package.get("dependencies"), name)
        optional_dependency_names: set[str] = set()
        if is_project:
            optional = _mapping(package.get("optional-dependencies", {}), f"{name} optional deps")
            for group in optional.values():
                optional_dependency_names.update(_dependency_names(group, name))
        sdist_url: str | None = None
        sdist_sha256: str | None = None
        if "sdist" in package:
            sdist = _mapping(package["sdist"], f"uv.lock package {name} sdist")
            sdist_url = _string(sdist.get("url"), f"uv.lock package {name} sdist URL")
            raw_hash = _string(sdist.get("hash"), f"uv.lock package {name} sdist hash")
            if not raw_hash.startswith("sha256:") or not _SHA256_PATTERN.fullmatch(raw_hash[7:]):
                raise ReleaseArtifactError(f"uv.lock package {name} has an invalid sdist hash")
            sdist_sha256 = raw_hash[7:]
        packages.append(
            LockedPackage(
                name=name,
                version=version,
                runtime_dependencies=tuple(sorted(runtime_dependency_names)),
                optional_dependencies=tuple(sorted(optional_dependency_names)),
                sdist_url=sdist_url,
                sdist_sha256=sdist_sha256,
                is_project=is_project,
            )
        )
    missing = sorted(
        dependency
        for package in packages
        for dependency in package.dependencies
        if dependency not in names
    )
    if missing:
        raise ReleaseArtifactError(f"uv.lock contains unresolved dependencies: {missing}")
    return tuple(sorted(packages, key=lambda package: package.name))


def _dependency_names(value: object, owner: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list):
        raise ReleaseArtifactError(f"uv.lock dependencies for {owner} must be an array")
    return {
        _string(_mapping(item, f"dependency of {owner}").get("name"), f"dependency of {owner}")
        for item in value
    }


def _dependency_closure(
    roots: tuple[str, ...], package_by_name: dict[str, LockedPackage]
) -> frozenset[str]:
    pending = list(roots)
    visited: set[str] = set()
    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        pending.extend(package_by_name[name].runtime_dependencies)
    return frozenset(visited)


def _literal_assignment(path: Path, variable: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    values = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == variable for target in node.targets)
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(values) != 1:
        raise ReleaseArtifactError(f"{path.name} must assign exactly one literal {variable}")
    return values[0]


def _schema_set_digest(schema_directory: Path) -> str:
    _require_directory(schema_directory)
    paths = tuple(sorted(schema_directory.glob("*.schema.json")))
    if not paths:
        raise ReleaseArtifactError("public schema set is empty")
    digest = hashlib.sha256()
    for path in paths:
        _require_regular_file(path)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _parse_checksums(path: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        parts = line.split("  ", maxsplit=1)
        if len(parts) != 2 or not _SHA256_PATTERN.fullmatch(parts[0]):
            raise ReleaseArtifactError(f"invalid SHA256SUMS line {line_number}")
        name = _safe_release_name(parts[1])
        if name in checksums:
            raise ReleaseArtifactError(f"duplicate SHA256SUMS entry: {name}")
        checksums[name] = parts[0]
    return checksums


def _safe_release_name(name: str) -> str:
    path = Path(name)
    if (
        path.name != name
        or name in {"", ".", ".."}
        or (name != ".gitignore" and _SAFE_NAME_PATTERN.fullmatch(name) is None)
    ):
        raise ReleaseArtifactError(f"unsafe release artifact name: {name!r}")
    return name


def _require_regular_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise ReleaseArtifactError(f"required regular file is missing or a symlink: {path}")


def _require_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise ReleaseArtifactError(f"required directory is missing or a symlink: {path}")


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ReleaseArtifactError(f"{label} must be a string-keyed mapping")
    return cast(dict[str, object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseArtifactError(f"{label} must be a non-empty string")
    return value


def _file_record(path: Path, role: str) -> dict[str, object]:
    return {
        "path": path.name,
        "role": role,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
    }


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def _load_json(path: Path) -> object:
    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ReleaseArtifactError(f"duplicate JSON key in {path.name}: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ReleaseArtifactError(f"non-finite JSON value in {path.name}: {value}")

    return cast(
        object,
        json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs_hook,
            parse_constant=reject_constant,
        ),
    )


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--assemble-example",
        type=Path,
        help=f"validate and stage the six-case {_DEMO_SUMMARY_NAME} before metadata generation",
    )
    parser.add_argument("--verify", action="store_true")
    return parser


def main() -> int:
    """Run the release writer or verifier from an argument-vector-only CLI."""

    arguments = _argument_parser().parse_args()
    try:
        if arguments.verify:
            if arguments.assemble_example is not None:
                raise ReleaseArtifactError("--verify cannot be combined with --assemble-example")
            result = verify_release_artifacts(arguments.output_dir)
            output: dict[str, object] = {
                "status": "ok",
                "command": "verify",
                "release_version": result["release_version"],
            }
        else:
            if arguments.assemble_example is not None:
                assemble_example_evidence(
                    arguments.repository_root,
                    arguments.output_dir,
                    arguments.assemble_example,
                )
            manifest = write_release_artifacts(arguments.repository_root, arguments.output_dir)
            result = verify_release_artifacts(arguments.output_dir)
            output = {
                "status": "ok",
                "command": "build-metadata",
                "release_version": result["release_version"],
                "manifest": str(manifest),
            }
    except (
        OSError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        yaml.YAMLError,
        ValidationError,
        ReleaseArtifactError,
    ) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(output, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
