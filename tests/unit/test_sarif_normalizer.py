from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from evitriage.domain.alerts import AlertBundle
from evitriage.sarif import ingest_sarif

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sarif"


def test_single_path_normalizes_rule_locations_and_raw_reference(tmp_path: Path) -> None:
    sarif_path = FIXTURES / "single-path.sarif"
    bundle = ingest_sarif(
        sarif_path,
        source_root=tmp_path,
        run_id="run-one",
        repository_identity="fixture-repository",
        commit_sha="A" * 40,
    )

    assert bundle.raw_sarif_sha256 == hashlib.sha256(sarif_path.read_bytes()).hexdigest()
    assert len(bundle.alerts) == 1
    alert = bundle.alerts[0]
    assert alert.commit_sha == "a" * 40
    assert alert.rule.rule_id == "java/path-injection"
    assert alert.rule.cwe_ids == ("CWE-22",)
    assert alert.rule.security_severity == 7.5
    assert alert.rule.query_pack is None
    assert alert.rule.query_pack_version is None
    assert alert.primary_location.path == "src/main/java/org/evitriage/fixture/PathReader.java"
    assert alert.primary_location.artifact_sha256 is None
    assert (
        alert.primary_location.snippet == "Files.readString(requestedPath, StandardCharsets.UTF_8)"
    )
    assert alert.related_locations[0].start_line == 15
    assert alert.fingerprints == {"stable": "stable-result-v1"}
    assert alert.partial_fingerprints == {"primaryLocationLineHash": "line-hash-v1"}
    assert alert.result_properties == {"precision": "high", "kind": "path-problem"}
    assert alert.has_code_flows is True
    assert len(alert.paths) == 1
    assert [step.location.start_line for step in alert.paths[0].steps] == [12, 15]
    assert [step.step_kind for step in alert.paths[0].steps] == ["source", "sink"]
    assert alert.paths[0].steps[1].message == "file open"
    assert alert.raw_result_reference.raw_sarif_sha256 == bundle.raw_sarif_sha256
    assert alert.raw_result_reference.run_index == 0
    assert alert.raw_result_reference.result_index == 0

    inconsistent = bundle.model_dump(mode="python")
    inconsistent["alerts"][0]["run_id"] = "another-run"
    with pytest.raises(ValidationError, match="provenance"):
        AlertBundle.model_validate(inconsistent, strict=True)


def test_multiple_and_duplicate_thread_flows_preserve_occurrence_order(
    tmp_path: Path,
) -> None:
    first = ingest_sarif(
        FIXTURES / "multi-path.sarif",
        source_root=tmp_path,
        run_id="run-paths",
        repository_identity="fixture-repository",
    )
    second = ingest_sarif(
        FIXTURES / "multi-path.sarif",
        source_root=tmp_path,
        run_id="run-paths",
        repository_identity="fixture-repository",
    )
    paths = first.alerts[0].paths

    assert [path.ordinal for path in paths] == [0, 1, 2]
    assert len(paths) == 3
    assert paths[0].path_fingerprint == paths[1].path_fingerprint
    assert paths[2].path_fingerprint != paths[0].path_fingerprint
    assert paths[0].steps[0].location.path == "src/Cmd.java"
    assert paths[2].steps[0].location.path == "src/Other.java"
    assert first.alerts[0].alert_fingerprint == second.alerts[0].alert_fingerprint


def test_result_without_codeflows_is_explicitly_pathless(tmp_path: Path) -> None:
    alert = ingest_sarif(
        FIXTURES / "no-codeflows.sarif",
        source_root=tmp_path,
        run_id="run-no-path",
        repository_identity="fixture-repository",
    ).alerts[0]

    assert alert.message == "A result with no path."
    assert alert.paths == ()
    assert alert.has_code_flows is False
    assert alert.rule.rule_id == "java/example"


def test_duplicate_results_are_preserved_with_stable_identity(tmp_path: Path) -> None:
    alerts = ingest_sarif(
        FIXTURES / "duplicate-results.sarif",
        source_root=tmp_path,
        run_id="run-duplicates",
        repository_identity="fixture-repository",
    ).alerts

    assert len(alerts) == 2
    assert alerts[0].alert_fingerprint == alerts[1].alert_fingerprint
    assert [alert.raw_result_reference.result_index for alert in alerts] == [0, 1]


def test_missing_snippet_is_preserved_as_unknown_not_invented(tmp_path: Path) -> None:
    alert = ingest_sarif(
        FIXTURES / "missing-snippet.sarif",
        source_root=tmp_path,
        run_id="run-missing-snippet",
        repository_identity="fixture-repository",
    ).alerts[0]

    assert alert.primary_location.snippet is None


def test_multiple_runs_have_precise_raw_result_references(tmp_path: Path) -> None:
    bundle = ingest_sarif(
        FIXTURES / "multi-run.sarif",
        source_root=tmp_path,
        run_id="run-many",
        repository_identity="fixture-repository",
    )

    assert [alert.rule.rule_id for alert in bundle.alerts] == ["rule/a", "rule/b"]
    assert [alert.raw_result_reference.run_index for alert in bundle.alerts] == [0, 1]
    assert [alert.raw_result_reference.result_index for alert in bundle.alerts] == [0, 0]


def test_windows_uri_base_normalizes_to_portable_relative_path(tmp_path: Path) -> None:
    alert = ingest_sarif(
        FIXTURES / "windows-uri.sarif",
        source_root=tmp_path,
        run_id="run-windows",
        repository_identity="fixture-repository",
    ).alerts[0]

    assert alert.primary_location.path == "src/Win.java"
