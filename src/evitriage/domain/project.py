"""Strict, immutable project configuration domain models.

``ProjectSpec`` is the only untrusted, project-controlled configuration accepted
by EviTriage-QL.  Keep provider credentials, prompts, and runtime tool policy out
of these models: recursively forbidding extra fields makes such input fail closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

SAFE_SLUG_PATTERN = r"^[a-z0-9]+(?:-[a-z0-9]+)*$"
FULL_GIT_SHA_PATTERN = r"^[0-9a-fA-F]{40}$"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class FrozenStrictModel(BaseModel):
    """Base class for configuration supplied across a trust boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


SafeSlug = Annotated[
    str,
    Field(min_length=1, max_length=63, pattern=SAFE_SLUG_PATTERN),
]
ProfileId = Annotated[
    str,
    Field(min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$"),
]


def _reject_control_characters(value: str, *, field_name: str) -> str:
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value


def _list_to_tuple(value: object) -> object:
    """Normalize YAML arrays to deeply immutable tuples before strict validation."""
    return tuple(value) if isinstance(value, list) else value


class ProjectMetadata(FrozenStrictModel):
    """Human-facing metadata and the safe identifier used in managed paths."""

    id: SafeSlug
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    language: Annotated[
        str,
        Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9+-]*$"),
    ]
    license_hint: Annotated[str, Field(min_length=1, max_length=200)] | None = None

    @field_validator("display_name", "license_hint")
    @classmethod
    def validate_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        _reject_control_characters(value, field_name="project metadata")
        if value.strip() != value:
            raise ValueError("project metadata must not have surrounding whitespace")
        return value


class LocalSource(FrozenStrictModel):
    """An existing local source tree, resolved by :class:`ProjectRegistry`."""

    type: Literal["local"]
    path: Annotated[str, Field(min_length=1, max_length=4096)]
    snapshot_mode: Literal["copy", "git-worktree"] = "copy"
    require_clean_git: bool = True
    submodules: bool = False

    @field_validator("path")
    @classmethod
    def validate_path_text(cls, value: str) -> str:
        _reject_control_characters(value, field_name="source.path")
        return value


class GitSource(FrozenStrictModel):
    """A remote repository pinned to a reproducible, full object id."""

    type: Literal["git"]
    url: Annotated[str, Field(min_length=1, max_length=2048)]
    commit: Annotated[str, Field(pattern=FULL_GIT_SHA_PATTERN)]
    submodules: bool = False

    @field_validator("url")
    @classmethod
    def validate_git_url(cls, value: str) -> str:
        _reject_control_characters(value, field_name="source.url")
        if value.strip() != value or any(character.isspace() for character in value):
            raise ValueError("source.url must not contain whitespace")
        if not value.startswith(("https://", "ssh://", "git@")):
            raise ValueError("source.url must use https, ssh, or git scp syntax")
        return value

    @field_validator("commit")
    @classmethod
    def normalize_commit(cls, value: str) -> str:
        # Git object IDs are case-insensitive hexadecimal.  A single canonical
        # representation makes semantically identical specs hash identically.
        return value.lower()


class DatasetSource(FrozenStrictModel):
    """A case materialized by a named, deterministic dataset adapter."""

    type: Literal["dataset"]
    adapter: SafeSlug
    dataset: SafeSlug
    case_id: Annotated[
        str,
        Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$"),
    ]
    release: Annotated[str, Field(min_length=1, max_length=200)] | None = None

    @field_validator("release")
    @classmethod
    def validate_release(cls, value: str | None) -> str | None:
        if value is not None:
            _reject_control_characters(value, field_name="source.release")
        return value


type ProjectSource = Annotated[
    LocalSource | GitSource | DatasetSource,
    Field(discriminator="type"),
]


class BuildSpec(FrozenStrictModel):
    """A build plan expressed exclusively as an argv vector."""

    adapter: Literal["maven"]
    jdk: Annotated[str, Field(min_length=1, max_length=32)]
    working_directory: Annotated[str, Field(min_length=1, max_length=4096)] = "."
    command: Annotated[
        tuple[str, ...],
        Field(min_length=1, max_length=256),
        BeforeValidator(_list_to_tuple),
    ]
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)] = 1800
    network_policy: Literal["disabled", "allowed"] = "disabled"

    @field_validator("working_directory")
    @classmethod
    def validate_working_directory(cls, value: str) -> str:
        _reject_control_characters(value, field_name="build.working_directory")
        normalized = PurePosixPath(value.replace("\\", "/"))
        if normalized.is_absolute() or re.match(r"^[A-Za-z]:", value):
            raise ValueError("build.working_directory must be relative")
        if ".." in normalized.parts:
            raise ValueError("build.working_directory must not escape the source root")
        return normalized.as_posix()

    @field_validator("command")
    @classmethod
    def validate_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value[0].strip():
            raise ValueError("build.command executable must not be empty")
        for argument in value:
            if "\x00" in argument:
                raise ValueError("build.command arguments must not contain NUL")
        return value

    @model_validator(mode="after")
    def validate_adapter_executable(self) -> BuildSpec:
        command_token = self.command[0].replace("\\", "/").lower()
        executable = PurePosixPath(command_token).name
        shell_executables = {
            "bash",
            "cmd",
            "cmd.exe",
            "dash",
            "fish",
            "ksh",
            "powershell",
            "powershell.exe",
            "pwsh",
            "sh",
            "zsh",
        }
        if executable in shell_executables:
            raise ValueError("build.command must not invoke a shell interpreter")
        allowed = {"mvn", "mvn.cmd", "mvnw", "mvnw.cmd", "./mvnw", "./mvnw.cmd"}
        if command_token not in allowed:
            raise ValueError(
                f"build.command executable {command_token!r} is not valid for {self.adapter}"
            )
        return self

    @property
    def argv(self) -> tuple[str, ...]:
        """Return an immutable argv view for subprocess adapters."""

        return self.command


class CodeQLSpec(FrozenStrictModel):
    """Pinned CodeQL inputs that affect alert generation."""

    cli_version: Annotated[
        str,
        Field(
            min_length=1,
            max_length=64,
            pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
        ),
    ]
    language: Annotated[str, Field(min_length=1, max_length=64)]
    query_suites: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=200)], ...],
        Field(min_length=1),
        BeforeValidator(_list_to_tuple),
    ]
    query_packs: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=200)], ...],
        BeforeValidator(_list_to_tuple),
    ] = ()
    model_packs: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=200)], ...],
        BeforeValidator(_list_to_tuple),
    ] = ()
    include_query_help: bool = True


class AnalysisSpec(FrozenStrictModel):
    """Project-selected analysis goals, without provider or prompt overrides."""

    target_cwes: Annotated[
        tuple[str, ...],
        Field(min_length=1),
        BeforeValidator(_list_to_tuple),
    ]
    context_policy: Literal["fixed_window", "path_function_slice", "adaptive_slice"]
    workflow: Literal["evidence_three_agent"]
    llm_profile: ProfileId

    @field_validator("target_cwes")
    @classmethod
    def validate_cwes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("analysis.target_cwes must not contain duplicates")
        if any(re.fullmatch(r"CWE-[1-9][0-9]*", cwe) is None for cwe in value):
            raise ValueError("analysis.target_cwes entries must use the CWE-<number> form")
        return value


class SecuritySpec(FrozenStrictModel):
    """Restrictive project security declarations.

    Tool allowlists, prompts, credentials, endpoints, and model identifiers are
    intentionally absent.  Generated shell is a literal ``false`` in v0.1.
    """

    source_upload_policy: Literal["offline_only"] = "offline_only"
    allow_build_network: bool = False
    allow_submodules: bool = False
    allow_generated_shell: Literal[False] = False


class StorageSpec(FrozenStrictModel):
    """Repository-relative roots resolved and confined by the registry."""

    workspace_root: Annotated[str, Field(min_length=1, max_length=4096)] = "workspaces"
    artifact_root: Annotated[str, Field(min_length=1, max_length=4096)] = "artifacts"

    @field_validator("workspace_root", "artifact_root")
    @classmethod
    def validate_root_text(cls, value: str) -> str:
        _reject_control_characters(value, field_name="storage root")
        if not value.strip():
            raise ValueError("storage roots must not be blank")
        return value


class ProjectSpec(FrozenStrictModel):
    """Complete, strictly validated project-controlled configuration."""

    schema_version: Literal["1.0"]
    project: ProjectMetadata
    source: ProjectSource
    build: BuildSpec
    codeql: CodeQLSpec
    analysis: AnalysisSpec
    security: SecuritySpec = Field(default_factory=SecuritySpec)
    storage: StorageSpec = Field(default_factory=StorageSpec)

    @model_validator(mode="after")
    def validate_security_consistency(self) -> ProjectSpec:
        if (
            isinstance(self.source, (LocalSource, GitSource))
            and self.source.submodules
            and not self.security.allow_submodules
        ):
            raise ValueError("source.submodules requires security.allow_submodules=true")
        if self.build.network_policy == "allowed" and not self.security.allow_build_network:
            raise ValueError(
                "build.network_policy=allowed requires security.allow_build_network=true"
            )
        return self


def canonical_project_spec_json(spec: ProjectSpec) -> str:
    """Serialize a spec canonically for stable hashing and audit records."""

    data = spec.model_dump(mode="json", by_alias=False, exclude_none=False)
    return json.dumps(
        data,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def compute_project_spec_digest(spec: ProjectSpec) -> str:
    """Return the SHA-256 of the canonical resolved ProjectSpec JSON."""

    return hashlib.sha256(canonical_project_spec_json(spec).encode("utf-8")).hexdigest()


class ResolvedProjectSpec(FrozenStrictModel):
    """A ProjectSpec with canonical absolute paths plus its stable digest."""

    spec: ProjectSpec
    config_path: str
    digest: Annotated[str, Field(pattern=SHA256_PATTERN)]

    @property
    def project_id(self) -> str:
        return self.spec.project.id

    @property
    def source_path(self) -> str | None:
        if isinstance(self.spec.source, LocalSource):
            return self.spec.source.path
        return None

    @property
    def workspace_root(self) -> str:
        return self.spec.storage.workspace_root

    @property
    def artifact_root(self) -> str:
        return self.spec.storage.artifact_root

    @property
    def canonical_json(self) -> str:
        return canonical_project_spec_json(self.spec)

    @property
    def sanitized(self) -> dict[str, Any]:
        """Return the safe resolved config suitable for persistence.

        The schema has no credential, prompt, endpoint, or tool-override fields,
        so a validated model is already a security allowlist.  Returning a fresh
        mapping also prevents callers from mutating this frozen model.
        """

        return self.spec.model_dump(mode="json", by_alias=False, exclude_none=True)

    def as_sanitized_mapping(self) -> dict[str, Any]:
        """Method alias used by artifact and CLI adapters."""

        return self.sanitized


__all__ = [
    "AnalysisSpec",
    "BuildSpec",
    "CodeQLSpec",
    "DatasetSource",
    "GitSource",
    "LocalSource",
    "ProjectMetadata",
    "ProjectSource",
    "ProjectSpec",
    "ResolvedProjectSpec",
    "SecuritySpec",
    "StorageSpec",
    "canonical_project_spec_json",
    "compute_project_spec_digest",
]
