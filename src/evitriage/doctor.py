"""Deterministic local environment diagnostics."""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from evitriage import __version__
from evitriage.config import load_system_config
from evitriage.errors import ConfigurationError

CheckStatus = Literal["ok", "warning", "error"]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One required or optional environment check."""

    name: str
    status: CheckStatus
    required: bool
    detail: str

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return asdict(self)


def _python_check() -> DoctorCheck:
    supported = (3, 12) <= sys.version_info[:2] < (3, 14)
    return DoctorCheck(
        name="python",
        status="ok" if supported else "error",
        required=True,
        detail=".".join(str(part) for part in sys.version_info[:3]),
    )


def _executable_check(
    name: str,
    *,
    arguments: tuple[str, ...],
    required: bool,
) -> DoctorCheck:
    executable = shutil.which(name)
    if executable is None:
        return DoctorCheck(
            name=name,
            status="error" if required else "warning",
            required=required,
            detail="not found on PATH",
        )
    try:
        completed = subprocess.run(  # noqa: S603 - executable is resolved from a fixed allowlist
            [executable, *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return DoctorCheck(
            name=name,
            status="error" if required else "warning",
            required=required,
            detail=f"version probe failed: {type(error).__name__}",
        )
    output = (completed.stdout or completed.stderr).strip().splitlines()
    detail = output[0][:300] if output else f"exit code {completed.returncode}"
    healthy = completed.returncode == 0
    return DoctorCheck(
        name=name,
        status="ok" if healthy else ("error" if required else "warning"),
        required=required,
        detail=detail,
    )


def _writable_directory_check(name: str, path: Path) -> DoctorCheck:
    try:
        path.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            raise OSError("managed root must not be a symlink")
        path.chmod(0o700, follow_symlinks=False)
        with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=path) as probe:
            probe.write(b"ok")
            probe.flush()
    except OSError as error:
        return DoctorCheck(name=name, status="error", required=True, detail=str(error))
    return DoctorCheck(name=name, status="ok", required=True, detail=str(path.resolve()))


def _sqlite_check() -> DoctorCheck:
    try:
        connection = sqlite3.connect(":memory:")
        try:
            version = connection.execute("select sqlite_version()").fetchone()[0]
        finally:
            connection.close()
    except sqlite3.Error as error:
        return DoctorCheck(name="sqlite", status="error", required=True, detail=str(error))
    return DoctorCheck(name="sqlite", status="ok", required=True, detail=str(version))


def _system_config_check(repository_root: Path) -> DoctorCheck:
    path = repository_root / "configs" / "system" / "v0.1.yaml"
    try:
        configuration = load_system_config(path)
    except ConfigurationError as error:
        return DoctorCheck(
            name="system_config",
            status="error",
            required=True,
            detail=error.message,
        )
    return DoctorCheck(
        name="system_config",
        status="ok",
        required=True,
        detail=(
            f"digest={configuration.digest}; codeql={configuration.codeql.required_cli_version}"
        ),
    )


def run_doctor(repository_root: Path) -> dict[str, object]:
    """Inspect required foundations and optional real CodeQL scan tools."""
    root = repository_root.resolve(strict=True)
    checks = [
        _python_check(),
        _executable_check("uv", arguments=("--version",), required=True),
        _sqlite_check(),
        _system_config_check(root),
        _writable_directory_check("workspace_root", root / "workspaces"),
        _writable_directory_check("artifact_root", root / "artifacts"),
        _executable_check("java", arguments=("-version",), required=False),
        _executable_check("javac", arguments=("-version",), required=False),
        _executable_check("codeql", arguments=("version", "--format=terse"), required=False),
    ]
    failed = any(check.required and check.status == "error" for check in checks)
    return {
        "schema_version": "1.0",
        "status": "error" if failed else "ok",
        "evitriage_version": __version__,
        "checked_at": datetime.now(UTC).isoformat(),
        "repository_root": str(root),
        "checks": [check.as_dict() for check in checks],
    }
