"""Public domain contracts."""

from evitriage.domain.project import (
    AnalysisSpec,
    BuildSpec,
    CodeQLSpec,
    DatasetSource,
    GitSource,
    LocalSource,
    ProjectMetadata,
    ProjectSpec,
    ResolvedProjectSpec,
    SecuritySpec,
    StorageSpec,
    canonical_project_spec_json,
    compute_project_spec_digest,
)
from evitriage.domain.run import (
    ArtifactRecord,
    ContextRunSummary,
    NormalizedRunSummary,
    RunManifest,
    WorkflowEvent,
    WorkflowState,
)
from evitriage.domain.workspace import (
    RepositorySnapshot,
    RunWorkspace,
    WorkspaceAllocation,
)

__all__ = [
    "AnalysisSpec",
    "ArtifactRecord",
    "BuildSpec",
    "CodeQLSpec",
    "ContextRunSummary",
    "DatasetSource",
    "GitSource",
    "LocalSource",
    "NormalizedRunSummary",
    "ProjectMetadata",
    "ProjectSpec",
    "RepositorySnapshot",
    "ResolvedProjectSpec",
    "RunManifest",
    "RunWorkspace",
    "SecuritySpec",
    "StorageSpec",
    "WorkflowEvent",
    "WorkflowState",
    "WorkspaceAllocation",
    "canonical_project_spec_json",
    "compute_project_spec_digest",
]
