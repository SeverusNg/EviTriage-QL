from __future__ import annotations

import json
from pathlib import Path

from evitriage.context import ContextBuilder
from evitriage.sarif import ingest_sarif


def test_resource_context_adds_bounded_same_file_callee_without_semantic_claim(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source = source_root / "Resource.java"
    source.parent.mkdir()
    source.write_text(
        """class Resource {
  boolean acquire() { return true; }
  boolean check() {
    return acquire();
  }
}
""",
        encoding="utf-8",
    )
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "columnKind": "unicodeCodePoints",
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [{"id": "java/unreleased-lock"}],
                    }
                },
                "results": [
                    {
                        "ruleId": "java/unreleased-lock",
                        "message": {"text": "Lock may not be released"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Resource.java"},
                                    "region": {"startLine": 4},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    sarif = tmp_path / "resource.sarif"
    sarif.write_text(json.dumps(document), encoding="utf-8")
    bundle = ingest_sarif(
        sarif,
        source_root=source_root,
        run_id="resource-callee",
        repository_identity="fixture-repository",
    )

    result = ContextBuilder(source_root.resolve()).build(bundle, policy_name="path_function_slice")[
        0
    ]

    assert {item.enclosing_symbol for item in result.content.source_slices} == {
        "check",
        "acquire",
    }
    callee = next(
        item for item in result.content.source_slices if item.enclosing_symbol == "acquire"
    )
    assert {reference.kind for reference in callee.references} == {"callee"}
