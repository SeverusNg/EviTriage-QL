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


class FeatureNotAvailableError(EviTriageError):
    """A versioned feature is deliberately unavailable in this release."""

    code = "FEATURE_NOT_AVAILABLE"
    exit_code = 6
