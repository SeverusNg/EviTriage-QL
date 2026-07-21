"""Typed failures raised at the untrusted SARIF boundary."""

from __future__ import annotations

from typing import ClassVar

from evitriage.errors import EviTriageError, PathSafetyError


class InvalidSarifError(EviTriageError):
    """The input is not supported, valid SARIF 2.1.0."""

    code: ClassVar[str] = "INVALID_SARIF"
    exit_code: ClassVar[int] = 7


class UnsafeSarifUriError(PathSafetyError):
    """A SARIF location cannot be safely bound to the source snapshot."""

    code: ClassVar[str] = "UNSAFE_SARIF_URI"


__all__ = ["InvalidSarifError", "UnsafeSarifUriError"]
