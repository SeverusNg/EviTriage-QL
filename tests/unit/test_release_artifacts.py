from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import cast

import pytest

from evitriage.release import (
    ReleaseArtifactError,
    build_cyclonedx,
    load_release_inputs,
    verify_release_artifacts,
    write_release_artifacts,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _release_inputs(output: Path, version: str = "0.1.0") -> None:
    output.mkdir()
    (output / ".gitignore").write_bytes(b"*")
    (output / f"evitriage_ql-{version}-py3-none-any.whl").write_bytes(b"wheel\n")
    (output / f"evitriage_ql-{version}.tar.gz").write_bytes(b"source\n")
    (output / "requirements-all.lock").write_text(
        "alembic==1.18.5 --hash=sha256:" + "1" * 64 + "\n",
        encoding="utf-8",
    )
    for name in (
        "example-demo-summary.json",
        "example-decisions.jsonl",
        "example-report.html",
        "example-run-manifest.json",
    ):
        (output / name).write_text("example\n", encoding="utf-8")
    (output / "case-matrix.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "analysis_identity": "analysis-" + "a" * 64,
                "synthetic": True,
                "real_codeql": False,
                "case_count": 6,
                "label_counts": {"TP": 3, "FP": 2, "NMC": 1},
                "cases": [{"result_index": index} for index in range(6)],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    for name, suite, coverage in (
        ("pytest-summary.json", "full", True),
        ("security-test-summary.json", "security", False),
    ):
        (output / name).write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "suite": suite,
                    "command": "pytest",
                    "outcome": "passed",
                    "exit_code": 0,
                    "tests_collected": 6,
                    "counts": {
                        "passed": 6,
                        "failed": 0,
                        "errors": 0,
                        "skipped": 0,
                        "xfailed": 0,
                        "xpassed": 0,
                        "deselected": 0,
                    },
                    "coverage_gate_enforced": coverage,
                }
            )
            + "\n",
            encoding="utf-8",
        )


def test_cyclonedx_closes_over_exact_uv_lock_and_separates_runtime_from_dev() -> None:
    makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "uv build --offline --out-dir $(RELEASE_DIR)" in makefile
    assert "uv export --quiet --all-extras --locked --no-header --no-emit-project" in makefile
    assert "--release-summary=$(RELEASE_DIR)/pytest-summary.json" in makefile
    assert "--release-summary=$(RELEASE_DIR)/security-test-summary.json" in makefile
    assert "--assemble-example $(RELEASE_DIR)/example-demo-summary.json" in makefile
    inputs = load_release_inputs(REPOSITORY_ROOT)
    first = build_cyclonedx(inputs)
    second = build_cyclonedx(inputs)

    assert inputs.version == "0.1.0"
    assert inputs.prompt_version == "gate-d-1.0"
    assert len(inputs.packages) == 40
    assert first == second
    assert first["bomFormat"] == "CycloneDX"
    assert first["specVersion"] == "1.5"
    components = first["components"]
    assert isinstance(components, list)
    assert len(components) == len(inputs.packages) - 1
    by_name = {component["name"]: component for component in components}
    assert by_name["alembic"]["scope"] == "required"
    assert by_name["pytest"]["scope"] == "optional"
    assert by_name["alembic"]["hashes"][0]["content"] == next(
        package.sdist_sha256 for package in inputs.packages if package.name == "alembic"
    )

    dependencies = first["dependencies"]
    assert isinstance(dependencies, list)
    known_refs = {component["bom-ref"] for component in components}
    metadata = cast(dict[str, object], first["metadata"])
    project_component = cast(dict[str, object], metadata["component"])
    project_ref = project_component["bom-ref"]
    known_refs.add(project_ref)
    assert {entry["ref"] for entry in dependencies} == known_refs
    assert all(set(entry["dependsOn"]).issubset(known_refs) for entry in dependencies)


def test_release_writer_registers_and_reverifies_every_file(tmp_path: Path) -> None:
    output = tmp_path / "release"
    _release_inputs(output)

    manifest_path = write_release_artifacts(REPOSITORY_ROOT, output)
    manifest = verify_release_artifacts(output)

    assert manifest_path == output / "release-manifest.json"
    assert manifest["release_version"] == "0.1.0"
    assert manifest["prompt_version"] == "gate-d-1.0"
    assert manifest["sbom_format"] == "CycloneDX 1.5"
    assert manifest["claims"] == {
        "network_free_demo_required": True,
        "real_codeql_smoke_required": True,
        "release_tag_created": False,
    }
    records = cast(list[dict[str, object]], manifest["files"])
    assert {record["role"] for record in records} == {
        "case-matrix",
        "dependency-inventory",
        "demo-summary",
        "example-html",
        "example-jsonl",
        "example-run-manifest",
        "security-test-summary",
        "sbom",
        "source-distribution",
        "test-summary",
        "tool-metadata",
        "wheel",
    }
    checksum_lines = (output / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert len(checksum_lines) == len(records) + 1

    sbom = json.loads((output / "evitriage-ql.cdx.json").read_text(encoding="utf-8"))
    assert sbom["metadata"]["properties"][0]["value"] == manifest["uv_lock_sha256"]


def test_release_verifier_rejects_tampering_and_checksum_traversal(tmp_path: Path) -> None:
    output = tmp_path / "release"
    _release_inputs(output)
    write_release_artifacts(REPOSITORY_ROOT, output)
    wheel = output / "evitriage_ql-0.1.0-py3-none-any.whl"
    wheel.write_bytes(b"changed")

    with pytest.raises(ReleaseArtifactError, match="size/hash verification"):
        verify_release_artifacts(output)

    wheel.write_bytes(b"wheel\n")
    write_release_artifacts(REPOSITORY_ROOT, output)
    checksums = output / "SHA256SUMS"
    checksums.write_text(
        checksums.read_text(encoding="utf-8").replace(
            "  release-manifest.json", "  ../release-manifest.json"
        ),
        encoding="utf-8",
    )
    with pytest.raises(ReleaseArtifactError, match="unsafe release artifact name"):
        verify_release_artifacts(output)

    write_release_artifacts(REPOSITORY_ROOT, output)
    (output / "unregistered.txt").write_text("not closed\n", encoding="utf-8")
    with pytest.raises(ReleaseArtifactError, match="unregistered or missing"):
        verify_release_artifacts(output)


def test_release_writer_rejects_stale_files_and_symlink_outputs(tmp_path: Path) -> None:
    output = tmp_path / "release"
    _release_inputs(output)
    (output / "old-release.whl").write_bytes(b"stale")
    with pytest.raises(ReleaseArtifactError, match="frozen set"):
        write_release_artifacts(REPOSITORY_ROOT, output)

    linked_output = tmp_path / "linked-release"
    linked_output.symlink_to(output, target_is_directory=True)
    with pytest.raises(ReleaseArtifactError, match="must not be symlinks"):
        write_release_artifacts(REPOSITORY_ROOT, linked_output)
    with pytest.raises(ReleaseArtifactError, match="not a symlink"):
        verify_release_artifacts(linked_output)


def test_release_writer_rejects_failed_machine_test_summary(tmp_path: Path) -> None:
    output = tmp_path / "release"
    _release_inputs(output)
    summary = json.loads((output / "pytest-summary.json").read_text(encoding="utf-8"))
    summary["outcome"] = "failed"
    summary["exit_code"] = 1
    summary["counts"]["failed"] = 1
    (output / "pytest-summary.json").write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(ReleaseArtifactError, match="not a passing run"):
        write_release_artifacts(REPOSITORY_ROOT, output)


def test_release_versions_must_match_all_public_surfaces(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    for relative in (
        "pyproject.toml",
        "uv.lock",
        "CITATION.cff",
        "src/evitriage/__init__.py",
        "src/evitriage/agents/workflow.py",
    ):
        source = REPOSITORY_ROOT / relative
        destination = repository / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
    shutil.copytree(REPOSITORY_ROOT / "schemas", repository / "schemas")
    citation = repository / "CITATION.cff"
    citation.write_text(
        citation.read_text(encoding="utf-8").replace('version: "0.1.0"', 'version: "0.1.1"'),
        encoding="utf-8",
    )

    with pytest.raises(ReleaseArtifactError, match="versions are inconsistent"):
        load_release_inputs(repository)
