from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from evitriage.sarif import InvalidSarifError, UnsafeSarifUriError, ingest_sarif
from evitriage.sarif.ingest import parse_sarif_bytes, read_sarif_bytes

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sarif"


def _document_with_uri(uri: str) -> bytes:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "columnKind": "utf16CodeUnits",
                "tool": {"driver": {"name": "CodeQL", "rules": [{"id": "rule"}]}},
                "results": [
                    {
                        "ruleId": "rule",
                        "message": {"text": "message"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document).encode()


@pytest.mark.parametrize(
    "uri",
    [
        "%2e%2e/etc/passwd",
        "../outside.java",
        "https://attacker.invalid/source.java",
        "file://attacker.invalid/share/source.java",
        "file:///etc/passwd",
        "src/File.java?download=1",
        "src/%00evil.java",
        "src/%FF.java",
        "file://[bad/source.java",
        "//attacker.invalid/share/source.java",
        r"\\attacker.invalid\share\source.java",
    ],
)
def test_untrusted_uri_cannot_escape_or_select_remote_content(tmp_path: Path, uri: str) -> None:
    sarif_path = tmp_path / "unsafe.sarif"
    sarif_path.write_bytes(_document_with_uri(uri))
    with pytest.raises(UnsafeSarifUriError):
        ingest_sarif(
            sarif_path,
            source_root=tmp_path,
            run_id="unsafe-run",
            repository_identity="fixture",
        )


def test_uri_cannot_traverse_symlink_inside_snapshot(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    source_root = tmp_path / "snapshot"
    source_root.mkdir()
    (source_root / "linked").symlink_to(outside, target_is_directory=True)
    sarif_path = tmp_path / "linked.sarif"
    sarif_path.write_bytes(_document_with_uri("linked/Secret.java"))

    with pytest.raises(UnsafeSarifUriError):
        ingest_sarif(
            sarif_path,
            source_root=source_root,
            run_id="unsafe-run",
            repository_identity="fixture",
        )


def test_malicious_golden_fixture_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(UnsafeSarifUriError):
        ingest_sarif(
            FIXTURES / "malicious-uri.sarif",
            source_root=tmp_path,
            run_id="unsafe-run",
            repository_identity="fixture",
        )


def test_parser_rejects_wrong_version_duplicate_keys_and_invalid_coordinates(
    tmp_path: Path,
) -> None:
    with pytest.raises(InvalidSarifError):
        parse_sarif_bytes(b'{"version":"2.1.0","version":"2.1.0","runs":[]}')
    with pytest.raises(InvalidSarifError):
        parse_sarif_bytes(b'{"version":"2.0.0","runs":[]}')

    missing_column_kind = json.loads(_document_with_uri("src/Main.java"))
    del missing_column_kind["runs"][0]["columnKind"]
    with pytest.raises(InvalidSarifError, match="columnKind"):
        parse_sarif_bytes(json.dumps(missing_column_kind).encode())

    invalid_column_kind = json.loads(_document_with_uri("src/Main.java"))
    invalid_column_kind["runs"][0]["columnKind"] = "bytes"
    with pytest.raises(InvalidSarifError, match="columnKind"):
        parse_sarif_bytes(json.dumps(invalid_column_kind).encode())

    invalid = json.loads(_document_with_uri("src/Main.java"))
    invalid["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 0
    sarif_path = tmp_path / "invalid-region.sarif"
    sarif_path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(InvalidSarifError):
        ingest_sarif(
            sarif_path,
            source_root=tmp_path,
            run_id="invalid-run",
            repository_identity="fixture",
        )
    with pytest.raises(InvalidSarifError):
        ingest_sarif(
            FIXTURES / "invalid-region.sarif",
            source_root=tmp_path,
            run_id="invalid-golden",
            repository_identity="fixture",
        )


def test_ingest_rejects_symlink_and_oversized_raw_artifact(tmp_path: Path) -> None:
    actual = tmp_path / "actual.sarif"
    actual.write_bytes(b'{"version":"2.1.0","runs":[]}')
    linked = tmp_path / "linked.sarif"
    linked.symlink_to(actual)
    with pytest.raises(InvalidSarifError):
        read_sarif_bytes(linked)
    with pytest.raises(InvalidSarifError):
        read_sarif_bytes(actual, maximum_bytes=8)


def test_snapshot_hash_is_computed_and_conflicting_sarif_hash_is_rejected(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src" / "Main.java"
    source.parent.mkdir()
    source.write_bytes(b"class Main {}\n")
    observed = hashlib.sha256(source.read_bytes()).hexdigest()
    document = json.loads(_document_with_uri("src/Main.java"))
    run = document["runs"][0]
    run["artifacts"] = [
        {
            "location": {"uri": "src/Main.java"},
            "hashes": {"sha-256": observed},
        }
    ]
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"] = {"index": 0}
    sarif_path = tmp_path / "verified.sarif"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")

    alert = ingest_sarif(
        sarif_path,
        source_root=tmp_path,
        run_id="verified-run",
        repository_identity="fixture",
    ).alerts[0]
    assert alert.primary_location.artifact_sha256 == observed

    run["artifacts"][0]["hashes"]["sha-256"] = "a" * 64
    sarif_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(InvalidSarifError, match="does not match"):
        ingest_sarif(
            sarif_path,
            source_root=tmp_path,
            run_id="mismatch-run",
            repository_identity="fixture",
        )


def test_uri_base_chain_has_a_deterministic_depth_limit(tmp_path: Path) -> None:
    document = json.loads(_document_with_uri("Main.java"))
    bases: dict[str, dict[str, str]] = {"BASE0": {"uri": "src/"}}
    for index in range(1, 70):
        bases[f"BASE{index}"] = {
            "uri": f"level-{index}/",
            "uriBaseId": f"BASE{index - 1}",
        }
    run = document["runs"][0]
    run["originalUriBaseIds"] = bases
    run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = (
        "BASE69"
    )
    sarif_path = tmp_path / "deep-base.sarif"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(InvalidSarifError, match="maximum depth"):
        ingest_sarif(
            sarif_path,
            source_root=tmp_path,
            run_id="deep-run",
            repository_identity="fixture",
        )


def test_configured_srcroot_convention_is_bounded_but_other_unknown_bases_fail(
    tmp_path: Path,
) -> None:
    source = tmp_path / "src/Main.java"
    source.parent.mkdir()
    source.write_text("class Main {}\n", encoding="utf-8")
    document = json.loads(_document_with_uri("src/Main.java"))
    artifact_location = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]
    region = document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    region["endColumn"] = 6
    artifact_location["uriBaseId"] = "%SRCROOT%"
    sarif_path = tmp_path / "srcroot.sarif"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")

    alert = ingest_sarif(
        sarif_path,
        source_root=tmp_path,
        run_id="srcroot-run",
        repository_identity="fixture",
    ).alerts[0]
    assert alert.primary_location.path == "src/Main.java"
    assert alert.primary_location.end_line == 1
    assert alert.primary_location.end_column == 6
    assert alert.primary_location.artifact_sha256 == hashlib.sha256(source.read_bytes()).hexdigest()

    artifact_location["uriBaseId"] = "UNCONFIGURED"
    sarif_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(InvalidSarifError, match="unknown SARIF uriBaseId"):
        ingest_sarif(
            sarif_path,
            source_root=tmp_path,
            run_id="unknown-base-run",
            repository_identity="fixture",
        )
