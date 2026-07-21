"""Constrained CodeQL database creation and SARIF analysis.

This adapter is deliberately the only layer that starts CodeQL.  It accepts
already-validated domain specifications and a managed :class:`RunWorkspace`,
then records every tool invocation as an artifact.  It never treats a missing
tool, timeout, or non-zero process exit as a successful scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from evitriage.domain.project import BuildSpec, CodeQLSpec
from evitriage.domain.workspace import RunWorkspace
from evitriage.errors import EviTriageError, PathSafetyError
from evitriage.observability import redact
from evitriage.sarif.ingest import parse_sarif_bytes, read_sarif_bytes

_ARTIFACT_DIRECTORY = "codeql"
_SARIF_NAME = "results.sarif"
_MAXIMUM_LOG_CHARACTERS = 1_000_000
_BUILTIN_QUERY_SUITE_ALIASES = {
    ("java-kotlin", "security-extended"): (
        "codeql/java-queries:codeql-suites/java-security-extended.qls"
    ),
}
_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "USERPROFILE",
        "WINDIR",
    }
)


class CodeQLToolUnavailableError(EviTriageError):
    """CodeQL or Java required for a real scan was not discoverable."""

    code = "CODEQL_TOOL_UNAVAILABLE"
    exit_code = 7


class CodeQLVersionMismatchError(EviTriageError):
    """The discovered CodeQL version does not match the pinned ProjectSpec."""

    code = "CODEQL_VERSION_MISMATCH"
    exit_code = 7


class CodeQLJavaVersionMismatchError(EviTriageError):
    """The discovered Java major version does not match the build plan."""

    code = "CODEQL_JAVA_VERSION_MISMATCH"
    exit_code = 7


class CodeQLTimeoutError(EviTriageError):
    """A CodeQL command exceeded its explicit timeout."""

    code = "CODEQL_TIMEOUT"
    exit_code = 7


class CodeQLCommandError(EviTriageError):
    """A CodeQL command exited unsuccessfully."""

    code = "CODEQL_COMMAND_FAILED"
    exit_code = 7


class CodeQLBuildPlanError(EviTriageError):
    """The Gate B runner was not given a safe Maven-wrapper build plan."""

    code = "CODEQL_INVALID_BUILD_PLAN"
    exit_code = 7


@dataclass(frozen=True, slots=True)
class CodeQLCommandRecord:
    """Auditable outcome for one argv-based external tool invocation."""

    name: str
    argv: tuple[str, ...]
    cwd: Path
    started_at: datetime
    duration_seconds: float
    exit_code: int | None
    stdout_path: Path
    stderr_path: Path
    stdout_sha256: str
    stderr_sha256: str
    timed_out: bool = False

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-safe, immutable audit representation."""

        return {
            "name": self.name,
            "argv": list(self.argv),
            "cwd": str(self.cwd),
            "started_at": self.started_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "exit_code": self.exit_code,
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "timed_out": self.timed_out,
        }


@dataclass(frozen=True, slots=True)
class CodeQLRunResult:
    """Successful, real CodeQL database-create plus SARIF-analyze result."""

    schema_version: Literal["1.0"]
    status: Literal["succeeded"]
    codeql_version: str
    java_version: str
    javac_version: str
    maven_distribution_version: str
    maven_distribution_url: str
    maven_distribution_sha256: str
    database_path: Path
    sarif_path: Path
    sarif_sha256: str
    commands: tuple[CodeQLCommandRecord, ...]
    started_at: datetime
    completed_at: datetime
    duration_seconds: float

    def as_dict(self) -> dict[str, object]:
        """Return the manifest-ready real scan metadata."""

        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "codeql_version": self.codeql_version,
            "java_version": self.java_version,
            "javac_version": self.javac_version,
            "maven_distribution_version": self.maven_distribution_version,
            "maven_distribution_url": self.maven_distribution_url,
            "maven_distribution_sha256": self.maven_distribution_sha256,
            "database_path": str(self.database_path),
            "sarif_path": str(self.sarif_path),
            "sarif_sha256": self.sarif_sha256,
            "commands": [record.as_dict() for record in self.commands],
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": self.duration_seconds,
        }


class CodeQLCommandBuilder:
    """Build CodeQL argv vectors from trusted domain values only.

    The one CodeQL argument that is itself a command, ``--command``, is
    produced solely from :class:`BuildSpec`'s immutable, validated argv.
    Nothing sourced from repository text is concatenated into any command.
    """

    def __init__(self, executable: str) -> None:
        if not executable or "\x00" in executable:
            raise ValueError("CodeQL executable must be a non-empty NUL-free path")
        self.executable = executable

    def version(self) -> tuple[str, ...]:
        """Return the fixed argv used to query CodeQL's terse version."""

        return (self.executable, "version", "--format=terse")

    def java_version(self, java_executable: str) -> tuple[str, ...]:
        """Return the fixed argv used to query the selected Java executable."""

        return (java_executable, "-version")

    def javac_version(self, javac_executable: str) -> tuple[str, ...]:
        """Return the fixed argv used to verify that a matching JDK is present."""

        return (javac_executable, "-version")

    def database_create(
        self,
        *,
        spec: CodeQLSpec,
        build: BuildSpec,
        database_path: Path,
        source_root: Path,
    ) -> tuple[str, ...]:
        """Build the database-create argv without invoking a shell."""

        build_command = _quote_argv_for_codeql(build.argv)
        return (
            self.executable,
            "database",
            "create",
            str(database_path),
            f"--language={spec.language}",
            f"--source-root={source_root}",
            f"--command={build_command}",
            "--threads=0",
        )

    def database_analyze(
        self,
        *,
        spec: CodeQLSpec,
        database_path: Path,
        sarif_path: Path,
    ) -> tuple[str, ...]:
        """Build the SARIF analysis argv using pinned suites and packs."""

        argv: list[str] = [
            self.executable,
            "database",
            "analyze",
            str(database_path),
            *(_resolve_query_suite(spec.language, suite) for suite in spec.query_suites),
            *spec.query_packs,
            "--format=sarif-latest",
            f"--output={sarif_path}",
        ]
        query_help = "always" if spec.include_query_help else "never"
        argv.extend((f"--sarif-include-query-help={query_help}", "--threads=0"))
        for pack in spec.model_packs:
            argv.append(f"--model-packs={pack}")
        return tuple(argv)


class CodeQLRunner:
    """Execute a real CodeQL scan inside a validated managed workspace."""

    def __init__(
        self,
        *,
        codeql_executable: str = "codeql",
        java_executable: str = "java",
        javac_executable: str = "javac",
    ) -> None:
        self._codeql_executable = codeql_executable
        self._java_executable = java_executable
        self._javac_executable = javac_executable

    def scan(
        self,
        *,
        codeql: CodeQLSpec,
        build: BuildSpec,
        workspace: RunWorkspace,
    ) -> CodeQLRunResult:
        """Create a database then analyze it into a managed SARIF artifact.

        A result is returned only after both CodeQL stages exit zero and the
        SARIF file is a regular managed artifact.  Otherwise a typed error
        contains structured command/audit details and no success surrogate.
        """

        paths = _validated_paths(workspace, build)
        maven_pin = _validate_maven_wrapper(build, paths.build_working_directory, paths.build_root)
        codeql_path = _find_tool(self._codeql_executable, "codeql")
        java_path = _find_tool(self._java_executable, "java")
        javac_path = _find_tool(self._javac_executable, "javac")
        _require_same_jdk(java_path, javac_path)
        environment = _subprocess_environment(java_path, workspace.temporary)
        builder = CodeQLCommandBuilder(codeql_path)
        started_at = datetime.now(UTC)
        started_clock = time.monotonic()
        records: list[CodeQLCommandRecord] = []

        codeql_version_record = self._run_command(
            name="codeql-version",
            argv=builder.version(),
            cwd=paths.build_root,
            timeout_seconds=30,
            artifacts_directory=paths.artifacts_directory,
            environment=environment,
        )
        records.append(codeql_version_record)
        _require_success(codeql_version_record)
        codeql_version = _terse_version(codeql_version_record.stdout_path, "codeql")
        if codeql_version != codeql.cli_version:
            raise CodeQLVersionMismatchError(
                "CodeQL version does not match the ProjectSpec pin",
                details={
                    "expected": codeql.cli_version,
                    "observed": codeql_version,
                    "command": codeql_version_record.as_dict(),
                },
            )

        java_version_record = self._run_command(
            name="java-version",
            argv=builder.java_version(java_path),
            cwd=paths.build_root,
            timeout_seconds=30,
            artifacts_directory=paths.artifacts_directory,
            environment=environment,
        )
        records.append(java_version_record)
        _require_success(java_version_record)
        java_version = _java_version(java_version_record)
        observed_java_major = _java_major_version(java_version)
        expected_java_major = _configured_java_major(build.jdk)
        if observed_java_major != expected_java_major:
            raise CodeQLJavaVersionMismatchError(
                "Java version does not match the ProjectSpec build pin",
                details={
                    "expected_major": expected_java_major,
                    "observed_major": observed_java_major,
                    "observed": java_version,
                    "command": java_version_record.as_dict(),
                },
            )

        javac_version_record = self._run_command(
            name="javac-version",
            argv=builder.javac_version(javac_path),
            cwd=paths.build_root,
            timeout_seconds=30,
            artifacts_directory=paths.artifacts_directory,
            environment=environment,
        )
        records.append(javac_version_record)
        _require_success(javac_version_record)
        javac_version = _java_version(javac_version_record)
        observed_javac_major = _java_major_version(javac_version)
        if observed_javac_major != expected_java_major:
            raise CodeQLJavaVersionMismatchError(
                "javac version does not match the ProjectSpec build pin",
                details={
                    "expected_major": expected_java_major,
                    "observed_major": observed_javac_major,
                    "observed": javac_version,
                    "command": javac_version_record.as_dict(),
                },
            )

        create_record = self._run_command(
            name="database-create",
            argv=builder.database_create(
                spec=codeql,
                build=build,
                database_path=paths.database_path,
                source_root=paths.build_root,
            ),
            cwd=paths.build_working_directory,
            timeout_seconds=build.timeout_seconds,
            artifacts_directory=paths.artifacts_directory,
            environment=environment,
        )
        records.append(create_record)
        _require_success(create_record)
        _validate_managed_directory(paths.database_path, paths.workspace_root)

        analyze_record = self._run_command(
            name="database-analyze",
            argv=builder.database_analyze(
                spec=codeql,
                database_path=paths.database_path,
                sarif_path=paths.sarif_path,
            ),
            cwd=paths.build_root,
            timeout_seconds=build.timeout_seconds,
            artifacts_directory=paths.artifacts_directory,
            environment=environment,
        )
        records.append(analyze_record)
        _require_success(analyze_record)
        _validate_regular_managed_file(paths.sarif_path, paths.artifact_root)
        sarif_bytes = read_sarif_bytes(paths.sarif_path)
        parse_sarif_bytes(sarif_bytes)
        sarif_sha256 = hashlib.sha256(sarif_bytes).hexdigest()

        completed_at = datetime.now(UTC)
        result = CodeQLRunResult(
            schema_version="1.0",
            status="succeeded",
            codeql_version=codeql_version,
            java_version=java_version,
            javac_version=javac_version,
            maven_distribution_version=maven_pin.version,
            maven_distribution_url=maven_pin.distribution_url,
            maven_distribution_sha256=maven_pin.sha256,
            database_path=paths.database_path,
            sarif_path=paths.sarif_path,
            sarif_sha256=sarif_sha256,
            commands=tuple(records),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=time.monotonic() - started_clock,
        )
        _write_json_artifact(
            paths.artifacts_directory / "run.json",
            result.as_dict(),
            paths.artifact_root,
        )
        return result

    @staticmethod
    def _run_command(
        *,
        name: str,
        argv: tuple[str, ...],
        cwd: Path,
        timeout_seconds: int,
        artifacts_directory: Path,
        environment: Mapping[str, str],
    ) -> CodeQLCommandRecord:
        start = datetime.now(UTC)
        started_clock = time.monotonic()
        stdout = ""
        stderr = ""
        exit_code: int | None = None
        timed_out = False
        try:
            completed = subprocess.run(  # noqa: S603 - argv is built from validated specs only
                list(argv),
                cwd=cwd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                shell=False,
                env=dict(environment),
                encoding="utf-8",
                errors="replace",
            )
            stdout = _bounded_process_output(completed.stdout)
            stderr = _bounded_process_output(completed.stderr)
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as error:
            timed_out = True
            stdout = _bounded_process_output(_coerce_process_output(error.stdout))
            stderr = _bounded_process_output(_coerce_process_output(error.stderr))
        except OSError as error:
            stderr = f"failed to start process: {type(error).__name__}"

        stdout_path = artifacts_directory / f"{name}.stdout.log"
        stderr_path = artifacts_directory / f"{name}.stderr.log"
        artifact_root = artifacts_directory.parent
        _write_text_artifact(stdout_path, _redacted_process_output(stdout), artifact_root)
        _write_text_artifact(stderr_path, _redacted_process_output(stderr), artifact_root)
        record = CodeQLCommandRecord(
            name=name,
            argv=argv,
            cwd=cwd,
            started_at=start,
            duration_seconds=time.monotonic() - started_clock,
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stdout_sha256=_sha256_file(stdout_path),
            stderr_sha256=_sha256_file(stderr_path),
            timed_out=timed_out,
        )
        _write_json_artifact(
            artifacts_directory / f"{name}.command.json",
            record.as_dict(),
            artifacts_directory.parent,
        )
        return record


@dataclass(frozen=True, slots=True)
class _ManagedPaths:
    workspace_root: Path
    artifact_root: Path
    build_root: Path
    build_working_directory: Path
    database_path: Path
    artifacts_directory: Path
    sarif_path: Path


@dataclass(frozen=True, slots=True)
class _MavenWrapperPin:
    version: str
    distribution_url: str
    sha256: str


def _validated_paths(workspace: RunWorkspace, build: BuildSpec) -> _ManagedPaths:
    workspace_root = _validate_managed_directory(workspace.workspace_root, workspace.workspace_root)
    artifact_root = _validate_managed_directory(workspace.artifact_root, workspace.artifact_root)
    if _paths_overlap(workspace_root, artifact_root):
        raise PathSafetyError("workspace and artifact roots must not overlap")
    build_root = _validate_managed_directory(workspace.build_copy, workspace_root)
    database_root = _validate_managed_directory(workspace.codeql_database, workspace_root)
    artifact_run_root = _validate_managed_directory(workspace.artifact_run_root, artifact_root)
    build_working_directory = build_root / Path(build.working_directory)
    _validate_managed_directory(build_working_directory, build_root)

    artifacts_directory = artifact_run_root / _ARTIFACT_DIRECTORY
    _ensure_managed_directory(artifacts_directory, artifact_root)
    database_path = database_root / "database"
    _assert_managed_child(database_path, workspace_root)
    if database_path.exists() or database_path.is_symlink():
        raise PathSafetyError(f"refusing to overwrite an existing CodeQL database: {database_path}")
    sarif_path = artifacts_directory / _SARIF_NAME
    if sarif_path.exists() or sarif_path.is_symlink():
        raise PathSafetyError(f"refusing to overwrite an existing SARIF artifact: {sarif_path}")
    return _ManagedPaths(
        workspace_root=workspace_root,
        artifact_root=artifact_root,
        build_root=build_root,
        build_working_directory=build_working_directory,
        database_path=database_path,
        artifacts_directory=artifacts_directory,
        sarif_path=sarif_path,
    )


def _validate_maven_wrapper(
    build: BuildSpec, working_directory: Path, build_root: Path
) -> _MavenWrapperPin:
    """Require a checked-in, non-symlink Maven wrapper for real Gate B scans."""

    supported_wrappers = {"./mvnw", "./mvnw.cmd"}
    if build.argv[0] not in supported_wrappers:
        raise CodeQLBuildPlanError(
            "Gate B CodeQL scans require a checked-in Maven wrapper, not a host Maven binary",
            details={"executable": build.argv[0], "allowed": sorted(supported_wrappers)},
        )
    wrapper = working_directory / build.argv[0][2:]
    _assert_managed_child(wrapper, build_root)
    _reject_symlink_components(wrapper)
    try:
        metadata = wrapper.stat(follow_symlinks=False)
    except OSError as error:
        raise CodeQLBuildPlanError(f"Maven wrapper is unavailable: {wrapper}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise CodeQLBuildPlanError(f"Maven wrapper is not a regular file: {wrapper}")
    if os.name != "nt" and not metadata.st_mode & stat.S_IXUSR:
        raise CodeQLBuildPlanError(f"Maven wrapper is not owner-executable: {wrapper}")

    properties_path = working_directory / ".mvn" / "wrapper" / "maven-wrapper.properties"
    _assert_managed_child(properties_path, build_root)
    _reject_symlink_components(properties_path)
    try:
        properties_metadata = properties_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(properties_metadata.st_mode) or properties_metadata.st_size > 64 * 1024:
            raise CodeQLBuildPlanError(
                f"Maven wrapper properties must be a bounded regular file: {properties_path}"
            )
        raw_properties = properties_path.read_text(encoding="utf-8")
    except UnicodeError as error:
        raise CodeQLBuildPlanError("Maven wrapper properties must be UTF-8") from error
    except OSError as error:
        raise CodeQLBuildPlanError(
            f"Maven wrapper properties are unavailable: {properties_path}"
        ) from error
    properties: dict[str, str] = {}
    for raw_line in raw_properties.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if "=" not in line:
            raise CodeQLBuildPlanError("invalid Maven wrapper property line")
        key, value = (part.strip() for part in line.split("=", maxsplit=1))
        if not key or not value or key in properties:
            raise CodeQLBuildPlanError("invalid or duplicate Maven wrapper property")
        properties[key] = value
    distribution_url = properties.get("distributionUrl", "")
    distribution_sha256 = properties.get("distributionSha256Sum", "").lower()
    if not distribution_url.startswith("https://") or re.search(
        r"(?i)^https://[^/@\s]+@", distribution_url
    ):
        raise CodeQLBuildPlanError("Maven wrapper distributionUrl must be credential-free HTTPS")
    if not re.fullmatch(r"[0-9a-f]{64}", distribution_sha256):
        raise CodeQLBuildPlanError(
            "Maven wrapper distributionSha256Sum must pin a lowercase SHA-256"
        )
    version_match = re.search(
        r"/apache-maven/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)/"
        r"apache-maven-(?P=version)-bin\.(?:zip|tar\.gz)$",
        distribution_url,
    )
    if version_match is None:
        raise CodeQLBuildPlanError(
            "Maven wrapper distributionUrl must pin one exact Apache Maven release"
        )
    return _MavenWrapperPin(
        version=version_match.group("version"),
        distribution_url=distribution_url,
        sha256=distribution_sha256,
    )


def _find_tool(configured: str, tool_name: str) -> str:
    path = shutil.which(configured)
    if path is None:
        raise CodeQLToolUnavailableError(
            f"required tool is not available: {tool_name}",
            details={"tool": tool_name, "configured": configured},
        )
    return path


def _subprocess_environment(java_executable: str, temporary_root: Path) -> dict[str, str]:
    """Return a minimal tool environment without ambient credentials or proxies."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if key in _ENVIRONMENT_ALLOWLIST and "\x00" not in value
    }
    java_path = Path(java_executable).resolve(strict=False)
    java_bin = java_path.parent
    inherited_path = environment.get("PATH", os.defpath)
    environment["PATH"] = os.pathsep.join((str(java_bin), inherited_path))
    if java_bin.name.lower() == "bin":
        environment["JAVA_HOME"] = str(java_bin.parent)
    temporary = str(temporary_root)
    environment.update({"TMPDIR": temporary, "TEMP": temporary, "TMP": temporary})
    return environment


def _require_same_jdk(java_executable: str, javac_executable: str) -> None:
    java_bin = Path(java_executable).resolve(strict=False).parent
    javac_bin = Path(javac_executable).resolve(strict=False).parent
    if java_bin != javac_bin:
        raise CodeQLBuildPlanError(
            "java and javac must resolve from the same pinned JDK",
            details={"java_bin": str(java_bin), "javac_bin": str(javac_bin)},
        )


def _require_success(record: CodeQLCommandRecord) -> None:
    if record.timed_out:
        raise CodeQLTimeoutError(
            f"CodeQL command timed out: {record.name}",
            details={"command": record.as_dict()},
        )
    if record.exit_code is None:
        raise CodeQLCommandError(
            f"CodeQL command could not be started: {record.name}",
            details={"command": record.as_dict()},
        )
    if record.exit_code != 0:
        raise CodeQLCommandError(
            f"CodeQL command exited unsuccessfully: {record.name}",
            details={"command": record.as_dict()},
        )


def _quote_argv_for_codeql(argv: tuple[str, ...]) -> str:
    """Quote a validated argv for CodeQL's documented ``--command`` string."""

    if os.name == "nt":
        return subprocess.list2cmdline(list(argv))
    return shlex_join(argv)


def _resolve_query_suite(language: str, suite: str) -> str:
    """Resolve blueprint suite aliases to bundle-pinned CodeQL pack suites."""

    resolved = _BUILTIN_QUERY_SUITE_ALIASES.get((language, suite))
    if resolved is not None:
        return resolved
    if suite == "security-extended":
        raise CodeQLBuildPlanError(
            "security-extended is not mapped for the configured CodeQL language",
            details={"language": language, "query_suite": suite},
        )
    return suite


def shlex_join(argv: tuple[str, ...]) -> str:
    """Use POSIX-safe quoting without permitting a shell process in this adapter."""

    # Import lazily so the platform-specific decision remains next to its use.
    import shlex

    return shlex.join(argv)


def _terse_version(path: Path, tool_name: str) -> str:
    value = path.read_text(encoding="utf-8").strip().splitlines()
    if not value or not value[0].strip():
        raise CodeQLCommandError(f"{tool_name} version command produced no version")
    return value[0].strip()


def _java_version(record: CodeQLCommandRecord) -> str:
    for path in (record.stdout_path, record.stderr_path):
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            return lines[0].strip()
    raise CodeQLCommandError("java version command produced no version")


def _java_major_version(version_line: str) -> int:
    match = re.search(r'(?:version\s+)?"?(?P<first>[0-9]+)(?:\.(?P<second>[0-9]+))?', version_line)
    if match is None:
        raise CodeQLCommandError(
            "java version command produced an unrecognized version",
            details={"observed": version_line},
        )
    first = int(match.group("first"))
    second = match.group("second")
    return int(second) if first == 1 and second is not None else first


def _configured_java_major(configured: str) -> int:
    match = re.match(r"^(?:1\.)?(?P<major>[1-9][0-9]*)", configured)
    if match is None:
        raise CodeQLBuildPlanError(
            "build.jdk must begin with a Java major version",
            details={"configured": configured},
        )
    return int(match.group("major"))


def _coerce_process_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _bounded_process_output(value: str | None) -> str:
    if value is None:
        return ""
    if len(value) <= _MAXIMUM_LOG_CHARACTERS:
        return value
    omitted = len(value) - _MAXIMUM_LOG_CHARACTERS
    return (
        value[:_MAXIMUM_LOG_CHARACTERS]
        + f"\n[EVITRIAGE OUTPUT TRUNCATED: {omitted} CHARACTERS OMITTED]\n"
    )


def _redacted_process_output(value: str) -> str:
    redacted = redact(value)
    return redacted if isinstance(redacted, str) else value


def _write_text_artifact(path: Path, data: str, root: Path) -> None:
    _assert_managed_child(path, root)
    if path.exists() or path.is_symlink():
        raise PathSafetyError(f"refusing to overwrite CodeQL artifact: {path}")
    try:
        with path.open("x", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
    except OSError as error:
        raise CodeQLCommandError(f"cannot write CodeQL artifact: {path}") from error


def _write_json_artifact(path: Path, value: dict[str, object], root: Path) -> None:
    data = json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
    _write_text_artifact(path, data, root)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    except OSError as error:
        raise CodeQLCommandError(f"cannot hash CodeQL artifact: {path}") from error
    return digest.hexdigest()


def _validate_managed_directory(path: Path, root: Path) -> Path:
    _assert_managed_child(path, root, allow_root=True)
    _reject_symlink_components(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise PathSafetyError(f"managed path is unavailable: {path}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise PathSafetyError(f"managed path is not a directory: {path}")
    return path.resolve(strict=True)


def _validate_regular_managed_file(path: Path, root: Path) -> None:
    _assert_managed_child(path, root)
    _reject_symlink_components(path)
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise CodeQLCommandError(f"expected CodeQL artifact is unavailable: {path}") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise PathSafetyError(f"CodeQL artifact is not a regular file: {path}")


def _ensure_managed_directory(path: Path, root: Path) -> None:
    _assert_managed_child(path, root)
    if path.exists() or path.is_symlink():
        _validate_managed_directory(path, root)
        return
    try:
        path.mkdir(mode=0o700)
    except OSError as error:
        raise CodeQLCommandError(f"cannot create CodeQL artifact directory: {path}") from error
    _validate_managed_directory(path, root)
    try:
        path.chmod(0o700, follow_symlinks=False)
    except OSError as error:
        raise CodeQLCommandError(f"cannot secure CodeQL artifact directory: {path}") from error


def _assert_managed_child(path: Path, root: Path, *, allow_root: bool = False) -> None:
    if not path.is_absolute() or not root.is_absolute() or ".." in path.parts:
        raise PathSafetyError(f"managed path is not a safe absolute path: {path}")
    if path == root:
        if allow_root:
            return
        raise PathSafetyError(f"managed path must be below its root: {path}")
    if not path.is_relative_to(root):
        raise PathSafetyError(f"managed path escapes its root: {path}")


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            raise PathSafetyError(f"managed path component does not exist: {current}") from None
        except OSError as error:
            raise PathSafetyError(f"cannot inspect managed path component: {current}") from error
        if stat.S_ISLNK(metadata.st_mode):
            raise PathSafetyError(f"managed path contains a symbolic link: {current}")


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first.is_relative_to(second) or second.is_relative_to(first)


__all__ = [
    "CodeQLBuildPlanError",
    "CodeQLCommandBuilder",
    "CodeQLCommandError",
    "CodeQLCommandRecord",
    "CodeQLJavaVersionMismatchError",
    "CodeQLRunResult",
    "CodeQLRunner",
    "CodeQLTimeoutError",
    "CodeQLToolUnavailableError",
    "CodeQLVersionMismatchError",
]
