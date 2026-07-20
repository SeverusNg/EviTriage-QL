from __future__ import annotations

from pathlib import Path

import pytest

from evitriage.projects.registry import ProjectRegistry
from evitriage.workspace import WorkspaceManager


def _regular_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }


@pytest.mark.integration
def test_two_project_specs_allocate_independent_workspaces_without_source_mutation(
    tmp_path: Path,
    repository_root: Path,
) -> None:
    registry = ProjectRegistry(repository_root)
    path_project = registry.validate_path(Path("configs/projects/example-local.yaml"))
    command_project = registry.validate_path(Path("configs/projects/example-local-command.yaml"))
    assert path_project.source_path is not None
    assert command_project.source_path is not None
    path_source = Path(path_project.source_path)
    command_source = Path(command_project.source_path)
    before = {
        path_project.project_id: _regular_files(path_source),
        command_project.project_id: _regular_files(command_source),
    }
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")

    path_run = manager.prepare(
        path_source,
        path_project.project_id,
        path_project.canonical_json,
        "path-project-run",
    )
    command_run = manager.prepare(
        command_source,
        command_project.project_id,
        command_project.canonical_json,
        "command-project-run",
    )

    assert path_run.workspace.build_copy != command_run.workspace.build_copy
    assert path_run.workspace.artifact_run_root != command_run.workspace.artifact_run_root
    assert path_run.snapshot.source_tree_sha256 != command_run.snapshot.source_tree_sha256
    assert path_run.project_spec_sha256 == path_project.digest
    assert command_run.project_spec_sha256 == command_project.digest
    assert _regular_files(path_source) == before[path_project.project_id]
    assert _regular_files(command_source) == before[command_project.project_id]
    assert (path_run.workspace.artifact_run_root / "project-spec.resolved.yaml").is_file()
    assert (command_run.workspace.artifact_run_root / "project-spec.resolved.yaml").is_file()
