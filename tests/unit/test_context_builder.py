from __future__ import annotations

import json
from pathlib import Path

import pytest

from evitriage.context import ContextBuilder
from evitriage.domain.alerts import AlertBundle
from evitriage.domain.context import SliceArtifact
from evitriage.errors import FeatureNotAvailableError
from evitriage.sarif import ingest_sarif

FIXTURES = Path(__file__).parents[1] / "fixtures"
SARIF = FIXTURES / "sarif/single-path.sarif"
SOURCE_ROOT = FIXTURES / "java-microbench/path-app"


def _bundle(source_root: Path = SOURCE_ROOT) -> AlertBundle:
    return ingest_sarif(
        SARIF,
        source_root=source_root,
        run_id="gate-c-context",
        repository_identity="fixture-repository",
    )


def test_path_function_slice_locates_source_sink_and_complete_callable() -> None:
    builder = ContextBuilder(SOURCE_ROOT.resolve())

    first = builder.build(_bundle(), policy_name="path_function_slice")[0]
    second = builder.build(_bundle(), policy_name="path_function_slice")[0]

    assert first == second
    assert first.content.completeness == "complete"
    assert first.content.context_policy == "path_function_slice"
    assert first.content.level_zero.paths[0].path_fingerprint
    assert first.content.token_estimate > 0
    assert first.content.token_estimate <= first.content.maximum_token_budget
    assert len(first.content.source_slices) == 1
    source_slice = first.content.source_slices[0]
    assert source_slice.selection == "enclosing_function"
    assert source_slice.enclosing_symbol == "readRequestedFile"
    assert (source_slice.start_line, source_slice.end_line) == (12, 16)
    assert "readRequestedFile" in source_slice.content
    assert "public static void main" not in source_slice.content
    assert {reference.kind for reference in source_slice.references} == {
        "primary",
        "related",
        "source",
        "sink",
    }
    assert first.content.level_zero.related_locations == _bundle().alerts[0].related_locations
    assert source_slice.artifact_sha256 == first.content.level_zero.primary_location.artifact_sha256


def test_fixed_window_is_real_and_budget_omissions_remain_explicit() -> None:
    fixed = ContextBuilder(SOURCE_ROOT.resolve()).build(_bundle(), policy_name="fixed_window")[0]
    constrained = ContextBuilder(SOURCE_ROOT.resolve(), maximum_token_budget=1).build(
        _bundle(), policy_name="path_function_slice"
    )[0]

    assert fixed.content.context_policy == "fixed_window"
    assert fixed.content.source_slices
    assert all(
        source_slice.selection == "fixed_window" for source_slice in fixed.content.source_slices
    )
    assert constrained.content.completeness == "partial"
    assert constrained.content.source_slices == ()
    assert constrained.content.token_estimate > constrained.content.maximum_token_budget
    assert {omission.code for omission in constrained.content.omitted} == {"token_budget_exceeded"}


def test_missing_source_and_symlink_are_unknown_not_invented(tmp_path: Path) -> None:
    missing = ContextBuilder(tmp_path.resolve()).build(
        _bundle(tmp_path), policy_name="path_function_slice"
    )[0]
    assert missing.content.completeness == "partial"
    assert missing.content.source_slices == ()
    assert {omission.code for omission in missing.content.omitted} == {"source_file_missing"}

    linked_root = tmp_path / "linked"
    linked_root.mkdir()
    linked_bundle = _bundle(linked_root)
    (linked_root / "src").symlink_to(SOURCE_ROOT / "src", target_is_directory=True)
    linked = ContextBuilder(linked_root.resolve()).build(
        linked_bundle, policy_name="path_function_slice"
    )[0]
    assert linked.content.source_slices == ()
    assert {omission.code for omission in linked.content.omitted} == {"source_not_regular"}


def test_adaptive_context_fails_explicitly() -> None:
    with pytest.raises(FeatureNotAvailableError, match=r"V0\.3") as raised:
        ContextBuilder(SOURCE_ROOT.resolve()).build(_bundle(), policy_name="adaptive_slice")

    assert raised.value.details == {"context_policy": "adaptive_slice"}


def test_column_kind_controls_non_bmp_coordinate_checks_and_all_locations_are_selected(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source = source_root / "src/Unicode.java"
    source.parent.mkdir(parents=True)
    source_line = 'class Unicode { String value = "😀"; }'
    source.write_bytes(b"\xef\xbb\xbf" + (source_line + "\n").encode("utf-8"))
    utf16_end_column = len(source_line.encode("utf-16-le")) // 2 + 1

    def build(column_kind: str, end_column: int, name: str) -> SliceArtifact:
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "columnKind": column_kind,
                    "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "rule"}]}},
                    "results": [
                        {
                            "ruleId": "rule",
                            "message": {"text": "unicode coordinates"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Unicode.java"},
                                        "region": {
                                            "startLine": 1,
                                            "startColumn": 1,
                                            "endLine": 1,
                                            "endColumn": end_column,
                                        },
                                    }
                                },
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Unicode.java"},
                                        "region": {"startLine": 1},
                                    }
                                },
                            ],
                            "relatedLocations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Unicode.java"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_path = tmp_path / f"{name}.sarif"
        sarif_path.write_text(json.dumps(document), encoding="utf-8")
        bundle = ingest_sarif(
            sarif_path,
            source_root=source_root,
            run_id=name,
            repository_identity="fixture-repository",
        )
        return ContextBuilder(source_root.resolve()).build(bundle, policy_name="fixed_window")[0]

    utf16 = build("utf16CodeUnits", utf16_end_column, "utf16")
    assert utf16.content.completeness == "complete"
    assert utf16.content.level_zero.primary_location.column_kind == "utf16CodeUnits"
    assert {reference.kind for reference in utf16.content.source_slices[0].references} == {
        "primary",
        "additional",
        "related",
    }

    invalid_code_points = build("unicodeCodePoints", utf16_end_column, "invalid-code-points")
    assert invalid_code_points.content.completeness == "partial"
    assert {omission.code for omission in invalid_code_points.content.omitted} == {
        "coordinate_out_of_bounds"
    }
    assert "unicodeCodePoints" in invalid_code_points.content.omitted[0].detail

    valid_code_points = build("unicodeCodePoints", len(source_line) + 1, "code-points")
    assert valid_code_points.content.completeness == "complete"


def test_path_function_slice_does_not_treat_try_resource_calls_as_java_functions(
    tmp_path: Path,
) -> None:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "columnKind": "utf16CodeUnits",
                "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "rule"}]}},
                "results": [
                    {
                        "ruleId": "rule",
                        "message": {"text": "Socket path reaches a file read"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": (
                                            "src/main/java/org/evitriage/fixture/"
                                            "SocketPathReader.java"
                                        )
                                    },
                                    "region": {"startLine": 26, "startColumn": 37},
                                }
                            }
                        ],
                        "codeFlows": [
                            {
                                "threadFlows": [
                                    {
                                        "locations": [
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": (
                                                                "src/main/java/org/evitriage/fixture/"
                                                                "SocketPathReader.java"
                                                            )
                                                        },
                                                        "region": {
                                                            "startLine": 20,
                                                            "startColumn": 33,
                                                        },
                                                    }
                                                },
                                                "kinds": ["source"],
                                            },
                                            {
                                                "location": {
                                                    "physicalLocation": {
                                                        "artifactLocation": {
                                                            "uri": (
                                                                "src/main/java/org/evitriage/fixture/"
                                                                "SocketPathReader.java"
                                                            )
                                                        },
                                                        "region": {
                                                            "startLine": 26,
                                                            "startColumn": 37,
                                                        },
                                                    }
                                                },
                                                "kinds": ["sink"],
                                            },
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                ],
            }
        ],
    }
    sarif_path = tmp_path / "socket-path.sarif"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")
    bundle = ingest_sarif(
        sarif_path,
        source_root=SOURCE_ROOT,
        run_id="socket-function-boundary",
        repository_identity="fixture-repository",
    )

    artifact = ContextBuilder(SOURCE_ROOT.resolve()).build(
        bundle, policy_name="path_function_slice"
    )[0]

    assert artifact.content.completeness == "complete"
    assert len(artifact.content.source_slices) == 1
    source_slice = artifact.content.source_slices[0]
    assert source_slice.enclosing_symbol == "readRequestedFile"
    assert (source_slice.start_line, source_slice.end_line) == (15, 28)
    assert "public static String readRequestedFile" in source_slice.content
