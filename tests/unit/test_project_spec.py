from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from evitriage.config import load_system_config
from evitriage.domain.project import (
    DatasetSource,
    GitSource,
    LocalSource,
    ProjectSpec,
    compute_project_spec_digest,
)
from evitriage.errors import ConfigurationError

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def valid_project_mapping() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "project": {
            "id": "fixture-one",
            "display_name": "Fixture One",
            "language": "java",
            "license_hint": "Apache-2.0",
        },
        "source": {
            "type": "local",
            "path": "tests/fixtures/java-microbench/path-app",
            "snapshot_mode": "copy",
            "require_clean_git": False,
            "submodules": False,
        },
        "build": {
            "adapter": "maven",
            "jdk": "17",
            "working_directory": ".",
            "command": ["./mvnw", "--offline", "-q", "package"],
            "timeout_seconds": 600,
            "network_policy": "disabled",
        },
        "codeql": {
            "cli_version": "2.26.1",
            "language": "java-kotlin",
            "query_suites": ["security-extended"],
            "query_packs": [],
            "model_packs": [],
            "include_query_help": True,
        },
        "analysis": {
            "target_cwes": ["CWE-22"],
            "context_policy": "path_function_slice",
            "workflow": "evidence_three_agent",
            "llm_profile": "replay-v0.1",
        },
        "security": {
            "source_upload_policy": "offline_only",
            "allow_build_network": False,
            "allow_submodules": False,
            "allow_generated_shell": False,
        },
        "storage": {
            "workspace_root": "workspaces",
            "artifact_root": "artifacts",
        },
    }


def test_project_spec_is_strict_frozen_and_forbids_extra_fields() -> None:
    spec = ProjectSpec.model_validate(valid_project_mapping())

    assert isinstance(spec.source, LocalSource)
    assert spec.build.argv == ("./mvnw", "--offline", "-q", "package")
    assert isinstance(spec.build.command, tuple)
    assert isinstance(spec.analysis.target_cwes, tuple)
    assert spec.model_config["strict"] is True
    assert spec.model_config["frozen"] is True
    assert spec.model_config["extra"] == "forbid"
    with pytest.raises(ValidationError):
        spec.project.id = "changed"  # type: ignore[misc]

    with_extra = valid_project_mapping()
    with_extra["api_key"] = "must-not-be-accepted"
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(with_extra)


@pytest.mark.parametrize(
    "project_id",
    ["../escape", "UpperCase", "has space", "double--separator", "-leading", "trailing-"],
)
def test_project_id_must_be_a_safe_slug(project_id: str) -> None:
    raw = valid_project_mapping()
    raw["project"]["id"] = project_id

    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(raw)


def test_source_is_a_discriminated_union() -> None:
    local = ProjectSpec.model_validate(valid_project_mapping())
    assert isinstance(local.source, LocalSource)

    git_raw = valid_project_mapping()
    git_raw["source"] = {
        "type": "git",
        "url": "https://example.invalid/research/project.git",
        "commit": "A" * 40,
        "submodules": False,
    }
    git = ProjectSpec.model_validate(git_raw)
    assert isinstance(git.source, GitSource)
    assert git.source.commit == "a" * 40

    dataset_raw = valid_project_mapping()
    dataset_raw["source"] = {
        "type": "dataset",
        "adapter": "local-microbench",
        "dataset": "java-microbench",
        "case_id": "CWE22_001",
        "release": "2026-07-20",
    }
    dataset = ProjectSpec.model_validate(dataset_raw)
    assert isinstance(dataset.source, DatasetSource)
    assert dataset.source.case_id == "CWE22_001"

    mismatched = valid_project_mapping()
    mismatched["source"] = {"type": "local", "url": "https://example.invalid/x"}
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(mismatched)

    unsupported_snapshot = valid_project_mapping()
    unsupported_snapshot["source"]["snapshot_mode"] = "git-worktree"
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(unsupported_snapshot)


@pytest.mark.parametrize("commit", ["a" * 39, "a" * 41, "main", "g" * 40])
def test_git_source_requires_a_full_40_hex_commit(commit: str) -> None:
    raw = valid_project_mapping()
    raw["source"] = {
        "type": "git",
        "url": "https://example.invalid/research/project.git",
        "commit": commit,
        "submodules": False,
    }

    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(raw)


def test_build_command_must_be_an_argv_array_and_types_are_strict() -> None:
    shell_string = valid_project_mapping()
    shell_string["build"]["command"] = "mvn -q package"
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(shell_string)

    coerced_timeout = valid_project_mapping()
    coerced_timeout["build"]["timeout_seconds"] = "600"
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(coerced_timeout)

    shell = valid_project_mapping()
    shell["build"]["command"] = ["/bin/sh", "-c", "mvn package"]
    with pytest.raises(ValidationError, match="shell interpreter"):
        ProjectSpec.model_validate(shell)

    wrong_adapter = valid_project_mapping()
    wrong_adapter["build"]["command"] = ["python3", "build.py"]
    with pytest.raises(ValidationError, match="checked-in wrapper"):
        ProjectSpec.model_validate(wrong_adapter)

    absolute_adapter = valid_project_mapping()
    absolute_adapter["build"]["command"] = ["/untrusted/mvn", "package"]
    with pytest.raises(ValidationError, match="checked-in wrapper"):
        ProjectSpec.model_validate(absolute_adapter)

    host_maven = valid_project_mapping()
    host_maven["build"]["command"] = ["mvn", "package"]
    with pytest.raises(ValidationError, match="checked-in wrapper"):
        ProjectSpec.model_validate(host_maven)

    inline_interpreter = valid_project_mapping()
    inline_interpreter["build"]["adapter"] = "explicit"
    inline_interpreter["build"]["command"] = ["python3", "-c", "print('unsafe')"]
    with pytest.raises(ValidationError, match="maven"):
        ProjectSpec.model_validate(inline_interpreter)

    wrapped_shell = valid_project_mapping()
    wrapped_shell["build"]["adapter"] = "explicit"
    wrapped_shell["build"]["command"] = ["env", "sh", "-c", "touch owned"]
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(wrapped_shell)

    online_command = valid_project_mapping()
    online_command["build"]["command"] = ["./mvnw", "-q", "package"]
    with pytest.raises(ValidationError, match="--offline"):
        ProjectSpec.model_validate(online_command)


@pytest.mark.parametrize(
    "argument",
    [
        "-Dpassword=hunter2",
        "-Dservice.api_key=hidden",
        "--access-token=hidden",
        "https://user:token@example.invalid/archive.zip",
    ],
)
def test_build_command_rejects_embedded_credentials(argument: str) -> None:
    raw = valid_project_mapping()
    raw["build"]["command"].insert(-1, argument)

    with pytest.raises(ValidationError, match=r"credential|userinfo"):
        ProjectSpec.model_validate(raw)


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("analysis", "system_prompt"),
        ("analysis", "prompt_override"),
        ("security", "tool_permissions"),
        ("security", "api_key"),
        ("codeql", "tool_override"),
    ],
)
def test_project_cannot_inject_secrets_prompts_or_tool_overrides(
    section: str,
    field: str,
) -> None:
    raw = valid_project_mapping()
    raw[section][field] = "attacker-controlled"

    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(raw)


@pytest.mark.parametrize(
    "query_input",
    [
        "--output=/tmp/attacker.sarif",
        "../outside/query.qls",
        "/outside/query.qls",
        r"C:\outside\query.qls",
        "https://example.invalid/query.qls",
        "security extended",
    ],
)
def test_codeql_query_inputs_cannot_inject_options_or_escape_snapshot(
    query_input: str,
) -> None:
    raw = valid_project_mapping()
    raw["codeql"]["query_suites"] = [query_input]

    with pytest.raises(ValidationError, match="CodeQL query inputs"):
        ProjectSpec.model_validate(raw)


def test_codeql_query_inputs_reject_duplicates() -> None:
    raw = valid_project_mapping()
    raw["codeql"]["query_suites"] = ["security-extended", "security-extended"]

    with pytest.raises(ValidationError, match="duplicates"):
        ProjectSpec.model_validate(raw)


def test_codeql_packs_require_exact_versions() -> None:
    raw = valid_project_mapping()
    raw["codeql"]["query_packs"] = ["acme/java-queries"]
    with pytest.raises(ValidationError, match="exact"):
        ProjectSpec.model_validate(raw)

    raw["codeql"]["query_packs"] = ["acme/java-queries@1.2.3"]
    raw["codeql"]["model_packs"] = ["acme/java-models@4.5.6"]
    spec = ProjectSpec.model_validate(raw)
    assert spec.codeql.query_packs == ("acme/java-queries@1.2.3",)

    raw["codeql"]["include_query_help"] = False
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(raw)


def test_git_source_rejects_embedded_https_credentials() -> None:
    raw = valid_project_mapping()
    raw["source"] = {
        "type": "git",
        "url": "https://user:token@example.invalid/project.git",
        "commit": "a" * 40,
        "submodules": False,
    }

    with pytest.raises(ValidationError, match="embedded credentials"):
        ProjectSpec.model_validate(raw)


def test_security_declarations_fail_closed() -> None:
    submodules = valid_project_mapping()
    submodules["source"]["submodules"] = True
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(submodules)

    generated_shell = valid_project_mapping()
    generated_shell["security"]["allow_generated_shell"] = True
    with pytest.raises(ValidationError):
        ProjectSpec.model_validate(generated_shell)


def test_digest_is_stable_and_changes_with_semantics() -> None:
    first_raw = valid_project_mapping()
    second_raw = deepcopy(first_raw)
    second_raw["project"] = dict(reversed(list(second_raw["project"].items())))
    first = ProjectSpec.model_validate(first_raw)
    second = ProjectSpec.model_validate(second_raw)

    assert compute_project_spec_digest(first) == compute_project_spec_digest(second)
    changed_raw = valid_project_mapping()
    changed_raw["build"]["timeout_seconds"] = 601
    changed = ProjectSpec.model_validate(changed_raw)
    assert compute_project_spec_digest(first) != compute_project_spec_digest(changed)


def test_public_schema_contains_source_discriminator() -> None:
    schema = ProjectSpec.model_json_schema()
    source_schema = schema["properties"]["source"]
    if "$ref" in source_schema:
        source_schema = schema["$defs"][source_schema["$ref"].rsplit("/", maxsplit=1)[-1]]

    assert source_schema["discriminator"]["propertyName"] == "type"


def test_checked_in_system_config_is_strict_and_stable(tmp_path: Path) -> None:
    config = load_system_config(REPOSITORY_ROOT / "configs/system/v0.1.yaml")

    assert config.codeql.required_cli_version == "2.26.1"
    assert config.policy.labels == ("TP", "FP", "NMC")
    assert len(config.digest) == 64
    assert config.digest == load_system_config(REPOSITORY_ROOT / "configs/system/v0.1.yaml").digest

    invalid = tmp_path / "invalid-system.yaml"
    invalid.write_text(
        (REPOSITORY_ROOT / "configs/system/v0.1.yaml").read_text(encoding="utf-8")
        + "\napi_key: forbidden\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError):
        load_system_config(invalid)

    duplicate = tmp_path / "duplicate-system.yaml"
    duplicate.write_text("schema_version: '1.0'\nschema_version: '1.0'\n", encoding="utf-8")
    with pytest.raises(ConfigurationError):
        load_system_config(duplicate)
