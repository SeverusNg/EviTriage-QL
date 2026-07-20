"""Generate and verify committed public JSON Schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from evitriage.domain.project import ProjectSpec


def rendered_project_schema() -> str:
    """Return the canonical ProjectSpec JSON Schema representation."""
    return json.dumps(ProjectSpec.model_json_schema(), indent=2, sort_keys=True) + "\n"


def schema_path(repository_root: Path) -> Path:
    """Return the committed ProjectSpec schema path."""
    return repository_root / "schemas" / "project-spec.schema.json"


def write_schemas(repository_root: Path) -> None:
    """Write all public schemas implemented by Gate A."""
    destination = schema_path(repository_root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(rendered_project_schema(), encoding="utf-8")


def schemas_match(repository_root: Path) -> bool:
    """Return whether generated schemas match committed files exactly."""
    destination = schema_path(repository_root)
    return (
        destination.is_file()
        and destination.read_text(encoding="utf-8") == rendered_project_schema()
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
            print("ProjectSpec schema is current")
            return 0
        print("ProjectSpec schema is missing or stale")
        return 1
    write_schemas(root)
    print(schema_path(root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
