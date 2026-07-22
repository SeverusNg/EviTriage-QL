"""Typed, machine-readable application errors."""

from __future__ import annotations

from collections.abc import Mapping
from typing import ClassVar


class EviTriageError(Exception):
    """Base class for an expected EviTriage failure."""

    code: ClassVar[str] = "EVITRIAGE_ERROR"
    exit_code: ClassVar[int] = 1

    def __init__(
        self,
        message: str,
        *,
        details: Mapping[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, object]:
        """Return a stable representation suitable for CLI JSON output."""
        return {
            "error": {
                "code": self.code,
                "message": self.message,
                "details": self.details,
            }
        }


class ConfigurationError(EviTriageError):
    """Configuration is malformed or violates a trusted policy."""

    code = "CONFIGURATION_ERROR"
    exit_code = 2


class ProjectNotFoundError(ConfigurationError):
    """A requested project configuration cannot be located."""

    code = "PROJECT_NOT_FOUND"


class PathSafetyError(EviTriageError):
    """A path escapes an explicitly managed root or is otherwise unsafe."""

    code = "PATH_SAFETY_ERROR"
    exit_code = 3


class WorkspaceError(EviTriageError):
    """Workspace allocation or lifecycle operation failed."""

    code = "WORKSPACE_ERROR"
    exit_code = 4


class WorkspaceConflictError(WorkspaceError):
    """An existing workspace conflicts with the requested allocation."""

    code = "WORKSPACE_CONFLICT"


class StorageError(EviTriageError):
    """Persistent metadata storage failed."""

    code = "STORAGE_ERROR"
    exit_code = 5


class WorkflowError(EviTriageError):
    """A run attempted an invalid state transition or artifact operation."""

    code = "WORKFLOW_ERROR"
    exit_code = 6


class FeatureNotAvailableError(EviTriageError):
    """A versioned feature is deliberately unavailable in this release."""

    code = "FEATURE_NOT_AVAILABLE"
    exit_code = 7


class ModelError(EviTriageError):
    """A bounded structured-model invocation could not be completed."""

    code = "MODEL_FAILED"
    exit_code = 8


class ModelResponseError(ModelError):
    """A model response violated its schema or closed evidence boundary."""

    code = "MODEL_RESPONSE_INVALID"


class ReplayMissError(ModelError):
    """An offline replay cache has no response for the canonical request."""

    code = "MODEL_REPLAY_MISS"


class PolicyRejectedError(EviTriageError):
    """A decision candidate could not be evaluated inside the evidence boundary."""

    code = "POLICY_REJECTED"
    exit_code = 9
