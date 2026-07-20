"""Immutable domain records for repository snapshots and run workspaces.

The models in this module deliberately perform no filesystem I/O.  Resolving,
copying, and validating paths belongs to :mod:`evitriage.workspace.manager`.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Sha256 = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
SafeIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]*$"),
]


class _ImmutableModel(BaseModel):
    """Common strict configuration for workspace domain records."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RepositorySnapshot(_ImmutableModel):
    """Identity and location of an immutable, locally materialized source tree."""

    schema_version: Literal["1.0"] = "1.0"
    snapshot_id: Sha256
    origin: str
    checkout_path: Path
    source_tree_sha256: Sha256
    repository_url: str | None = None
    full_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    dirty_patch_sha256: Sha256 | None = None
    submodule_shas: dict[str, str] = Field(default_factory=dict)
    license_hint: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("checkout_path")
    @classmethod
    def _checkout_path_is_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("checkout_path must be absolute")
        return value

    @field_validator("created_at")
    @classmethod
    def _created_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _content_identity_is_consistent(self) -> RepositorySnapshot:
        if self.snapshot_id != self.source_tree_sha256:
            raise ValueError("snapshot_id must equal source_tree_sha256")
        return self


class RunWorkspace(_ImmutableModel):
    """All writable and immutable managed paths allocated to one run."""

    schema_version: Literal["1.0"] = "1.0"
    run_id: SafeIdentifier
    project_id: SafeIdentifier
    snapshot_id: Sha256
    workspace_root: Path
    artifact_root: Path
    source_snapshot: Path
    build_copy: Path
    codeql_database: Path
    temporary: Path
    artifact_run_root: Path

    @field_validator(
        "workspace_root",
        "artifact_root",
        "source_snapshot",
        "build_copy",
        "codeql_database",
        "temporary",
        "artifact_run_root",
    )
    @classmethod
    def _managed_paths_are_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("managed workspace paths must be absolute")
        if ".." in value.parts:
            raise ValueError("managed workspace paths must not contain parent traversal")
        return value

    @model_validator(mode="after")
    def _paths_are_contained_and_roots_do_not_overlap(self) -> RunWorkspace:
        if _paths_overlap(self.workspace_root, self.artifact_root):
            raise ValueError("workspace_root and artifact_root must not overlap")
        for path in (
            self.source_snapshot,
            self.build_copy,
            self.codeql_database,
            self.temporary,
        ):
            if not _is_strict_child(path, self.workspace_root):
                raise ValueError("workspace paths must be below workspace_root")
        if not _is_strict_child(self.artifact_run_root, self.artifact_root):
            raise ValueError("artifact_run_root must be below artifact_root")
        return self


class WorkspaceAllocation(_ImmutableModel):
    """Result of atomically preparing a local source for a run."""

    schema_version: Literal["1.0"] = "1.0"
    snapshot: RepositorySnapshot
    workspace: RunWorkspace
    project_spec_sha256: Sha256
    prepared_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("prepared_at")
    @classmethod
    def _prepared_at_is_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("prepared_at must include a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def _snapshot_identity_matches_workspace(self) -> WorkspaceAllocation:
        if self.snapshot.snapshot_id != self.workspace.snapshot_id:
            raise ValueError("workspace snapshot_id must match the repository snapshot")
        return self


def _is_strict_child(path: Path, root: Path) -> bool:
    return path != root and path.is_relative_to(root)


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)
