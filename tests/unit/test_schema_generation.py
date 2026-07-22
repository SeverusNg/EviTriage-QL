from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

from evitriage.schema_generation import main, schemas_match, write_schemas

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_schema_generation_is_deterministic(tmp_path: Path) -> None:
    write_schemas(tmp_path)
    first = (tmp_path / "schemas" / "project-spec.schema.json").read_bytes()
    assert {path.name for path in (tmp_path / "schemas").iterdir()} == {
        "alert-bundle.schema.json",
        "alert-report.schema.json",
        "analyst-output.schema.json",
        "analyst-run-artifact.schema.json",
        "context-index.schema.json",
        "context-run-summary.schema.json",
        "evidence.schema.json",
        "evidence-supplement.schema.json",
        "final-decision.schema.json",
        "judge-output.schema.json",
        "judged-run-artifact.schema.json",
        "llm-profile.schema.json",
        "normalized-run-summary.schema.json",
        "project-spec.schema.json",
        "rebuttal-output.schema.json",
        "rebuttal-run-artifact.schema.json",
        "run-manifest.schema.json",
        "slice-artifact.schema.json",
        "triage-result.schema.json",
        "triage-report-bundle.schema.json",
        "triage-run-summary.schema.json",
    }

    write_schemas(tmp_path)

    assert (tmp_path / "schemas" / "project-spec.schema.json").read_bytes() == first
    assert schemas_match(tmp_path)


def test_schema_generation_command_writes_then_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr("sys.argv", ["schema-generation", "--root", str(tmp_path)])
    assert main() == 0
    assert "project-spec.schema.json" in capsys.readouterr().out

    monkeypatch.setattr("sys.argv", ["schema-generation", "--root", str(tmp_path), "--check"])
    assert main() == 0
    assert "current" in capsys.readouterr().out

    (tmp_path / "schemas" / "project-spec.schema.json").write_text("{}\n", encoding="utf-8")
    assert main() == 1
    assert "stale" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("build", "command"),
        ("analysis", "target_cwes"),
        ("codeql", "query_suites"),
    ],
)
def test_public_json_schema_enforces_non_empty_arrays(
    section: str,
    field: str,
) -> None:
    schema = yaml.safe_load(
        (REPOSITORY_ROOT / "schemas/project-spec.schema.json").read_text(encoding="utf-8")
    )
    instance = yaml.safe_load(
        (REPOSITORY_ROOT / "configs/projects/example-local.yaml").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    assert not list(validator.iter_errors(instance))

    instance[section][field] = []
    assert list(validator.iter_errors(instance))
