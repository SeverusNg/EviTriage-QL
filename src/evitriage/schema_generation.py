"""Generate and verify committed public JSON Schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pydantic import BaseModel

from evitriage.domain.alerts import AlertBundle
from evitriage.domain.project import ProjectSpec
from evitriage.domain.run import NormalizedRunSummary, RunManifest

_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "alert-bundle.schema.json": AlertBundle,
    "normalized-run-summary.schema.json": NormalizedRunSummary,
    "project-spec.schema.json": ProjectSpec,
    "run-manifest.schema.json": RunManifest,
}


def rendered_project_schema() -> str:
    """Return the canonical ProjectSpec JSON Schema representation."""
    return rendered_schema(ProjectSpec)


def rendered_schema(model: type[BaseModel]) -> str:
    """Return one canonical public Pydantic JSON Schema."""

    return json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n"


def schema_path(repository_root: Path) -> Path:
    """Return the committed ProjectSpec schema path."""
    return repository_root / "schemas" / "project-spec.schema.json"


def write_schemas(repository_root: Path) -> None:
    """Write all public schemas implemented through Gate B."""

    schema_directory = repository_root / "schemas"
    schema_directory.mkdir(parents=True, exist_ok=True)
    for name, model in _SCHEMA_MODELS.items():
        (schema_directory / name).write_text(rendered_schema(model), encoding="utf-8")


def schemas_match(repository_root: Path) -> bool:
    """Return whether generated schemas match committed files exactly."""

    schema_directory = repository_root / "schemas"
    return all(
        (schema_directory / name).is_file()
        and (schema_directory / name).read_text(encoding="utf-8") == rendered_schema(model)
        for name, model in _SCHEMA_MODELS.items()
    )


def main() -> int:
    """Generate schemas, or fail when a committed schema is stale."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify without writing")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if arguments.check:
        if schemas_match(root):
            print("Public schemas are current")
            return 0
        print("Public schemas are missing or stale")
        return 1
    write_schemas(root)
    for name in _SCHEMA_MODELS:
        print(root / "schemas" / name)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
