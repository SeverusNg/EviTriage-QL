from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

from evitriage.errors import ConfigurationError, PathSafetyError
from evitriage.projects.registry import ProjectRegistry

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def valid_project_mapping() -> dict[str, Any]:
    value = yaml.safe_load(
        (REPOSITORY_ROOT / "configs/projects/example-local.yaml").read_text(encoding="utf-8")
    )
    return cast(dict[str, Any], value)


@pytest.mark.integration
def test_two_checked_in_projects_use_the_same_registry_path() -> None:
    registry = ProjectRegistry(REPOSITORY_ROOT)

    path_project = registry.validate_path(Path("configs/projects/example-local.yaml"))
    command_project = registry.validate_path(Path("configs/projects/example-local-command.yaml"))

    assert path_project.project_id == "example-local"
    assert command_project.project_id == "example-local-command"
    assert path_project.source_path != command_project.source_path
    assert Path(path_project.source_path or "").is_dir()
    assert Path(command_project.source_path or "").is_dir()
    assert Path(path_project.workspace_root) == REPOSITORY_ROOT / "workspaces"
    assert Path(path_project.artifact_root) == REPOSITORY_ROOT / "artifacts"
    assert path_project.digest != command_project.digest
    assert (
        registry.validate_path(Path("configs/projects/example-local.yaml")).digest
        == path_project.digest
    )


@pytest.mark.integration
def test_registry_loads_by_declared_id_and_lists_both_projects() -> None:
    registry = ProjectRegistry(REPOSITORY_ROOT)

    assert registry.load("example-local").project_id == "example-local"
    assert registry.list_ids() == ("example-local-command", "example-local")
    with pytest.raises(ConfigurationError):
        registry.load("../escape")
    with pytest.raises(ConfigurationError):
        registry.load("does-not-exist")


@pytest.mark.integration
def test_local_source_must_exist_beneath_an_allowed_canonical_root(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    allowed = repository / "allowed"
    allowed.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    configs = repository / "configs"
    configs.mkdir()

    raw = valid_project_mapping()
    raw["source"]["path"] = "../outside"
    escaping_config = configs / "escaping.yaml"
    escaping_config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    registry = ProjectRegistry(repository, allowed_source_roots=(allowed,))
    with pytest.raises(PathSafetyError):
        registry.validate_path(escaping_config)

    raw["source"]["path"] = "allowed/missing"
    missing_config = configs / "missing.yaml"
    missing_config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError):
        registry.validate_path(missing_config)

    symlink = allowed / "symlink-escape"
    symlink.symlink_to(outside, target_is_directory=True)
    raw["source"]["path"] = "allowed/symlink-escape"
    symlink_config = configs / "symlink.yaml"
    symlink_config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError):
        registry.validate_path(symlink_config)


@pytest.mark.integration
def test_digest_ignores_yaml_key_order_and_config_filename(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "source"
    source.mkdir(parents=True)
    configs = repository / "configs"
    configs.mkdir()
    raw = valid_project_mapping()
    raw["source"]["path"] = "source"
    first_path = configs / "first.yaml"
    second_path = configs / "second.yaml"
    first_path.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    reordered = dict(reversed(list(deepcopy(raw).items())))
    second_path.write_text(yaml.safe_dump(reordered, sort_keys=False), encoding="utf-8")
    registry = ProjectRegistry(repository)

    first = registry.validate_path(first_path)
    second = registry.validate_path(second_path)

    assert first.digest == second.digest
    assert first.sanitized == second.sanitized
    assert first.config_path != second.config_path


@pytest.mark.integration
def test_same_id_cannot_silently_change_source(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    first_source = repository / "source-a"
    second_source = repository / "source-b"
    first_source.mkdir(parents=True)
    second_source.mkdir()
    configs = repository / "configs"
    configs.mkdir()
    first_raw = valid_project_mapping()
    first_raw["source"]["path"] = "source-a"
    second_raw = deepcopy(first_raw)
    second_raw["source"]["path"] = "source-b"
    first_path = configs / "first.yaml"
    second_path = configs / "second.yaml"
    first_path.write_text(yaml.safe_dump(first_raw, sort_keys=False), encoding="utf-8")
    second_path.write_text(yaml.safe_dump(second_raw, sort_keys=False), encoding="utf-8")
    registry = ProjectRegistry(repository)

    registry.validate_path(first_path)
    with pytest.raises(ConfigurationError, match="version the project id explicitly"):
        registry.validate_path(second_path)


@pytest.mark.integration
def test_fresh_registry_compares_external_config_with_checked_in_identity(
    tmp_path: Path,
) -> None:
    raw = valid_project_mapping()
    raw["source"]["path"] = "tests/fixtures/java-microbench/command-app"
    external = tmp_path / "collision.yaml"
    external.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(ConfigurationError, match="version the project id explicitly"):
        ProjectRegistry(REPOSITORY_ROOT).validate_path(external)


@pytest.mark.integration
def test_storage_roots_cannot_escape_the_repository(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    source = repository / "source"
    source.mkdir(parents=True)
    config = repository / "project.yaml"
    raw = valid_project_mapping()
    raw["source"]["path"] = "source"
    raw["storage"]["workspace_root"] = "../escaped-workspaces"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(PathSafetyError):
        ProjectRegistry(repository).validate_path(config)

    raw["storage"]["workspace_root"] = "workspaces/../workspaces"
    raw["storage"]["artifact_root"] = "artifacts"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError, match="parent traversal"):
        ProjectRegistry(repository).validate_path(config)

    raw["storage"]["workspace_root"] = "src"
    raw["storage"]["artifact_root"] = "docs"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError, match="trusted managed roots"):
        ProjectRegistry(repository).validate_path(config)

    raw["storage"]["workspace_root"] = "managed"
    raw["storage"]["artifact_root"] = "managed/artifacts"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError, match="non-overlapping"):
        ProjectRegistry(
            repository,
            allowed_workspace_roots=(repository / "managed",),
            allowed_artifact_roots=(repository / "managed/artifacts",),
        ).validate_path(config)

    raw["storage"]["workspace_root"] = "source/workspaces"
    raw["storage"]["artifact_root"] = "artifacts"
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")
    with pytest.raises(PathSafetyError, match="source must not overlap"):
        ProjectRegistry(
            repository,
            allowed_workspace_roots=(repository / "source/workspaces",),
        ).validate_path(config)


@pytest.mark.integration
def test_empty_source_allowlist_fails_closed(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()

    with pytest.raises(PathSafetyError, match="at least one allowed source root"):
        ProjectRegistry(repository, allowed_source_roots=())


@pytest.mark.integration
@pytest.mark.parametrize(
    ("root_name", "storage_field"),
    [("workspaces", "workspace_root"), ("artifacts", "artifact_root")],
)
def test_default_managed_root_must_not_be_a_symlink(
    tmp_path: Path,
    root_name: str,
    storage_field: str,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "source"
    source.mkdir(parents=True)
    outside = tmp_path / f"outside-{root_name}"
    outside.mkdir()
    (repository / root_name).symlink_to(outside, target_is_directory=True)
    config = repository / "project.yaml"
    raw = valid_project_mapping()
    raw["source"]["path"] = "source"
    raw["storage"][storage_field] = root_name
    config.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    with pytest.raises(PathSafetyError, match="symbolic-link component"):
        ProjectRegistry(repository).validate_path(config)


@pytest.mark.integration
def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    config = repository / "duplicate.yaml"
    config.write_text(
        "schema_version: '1.0'\nschema_version: '1.0'\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError):
        ProjectRegistry(repository).validate_path(config)


@pytest.mark.integration
@pytest.mark.parametrize("fixture_name", ["path-app", "command-app"])
def test_java_microbench_is_a_minimal_maven_project(fixture_name: str) -> None:
    fixture = REPOSITORY_ROOT / "tests/fixtures/java-microbench" / fixture_name
    pom = (fixture / "pom.xml").read_text(encoding="utf-8")

    assert "<modelVersion>4.0.0</modelVersion>" in pom
    assert "<maven.compiler.release>17</maven.compiler.release>" in pom
    sources = list((fixture / "src/main/java").rglob("*.java"))
    assert len(sources) == 1
    assert "public static void main" in sources[0].read_text(encoding="utf-8")
