from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from evitriage.codeql import (
    CodeQLBuildPlanError,
    CodeQLCommandBuilder,
    CodeQLCommandError,
    CodeQLJavaVersionMismatchError,
    CodeQLRunner,
    CodeQLTimeoutError,
    CodeQLToolUnavailableError,
    CodeQLVersionMismatchError,
)
from evitriage.domain.project import BuildSpec, CodeQLSpec
from evitriage.domain.workspace import RunWorkspace
from evitriage.errors import PathSafetyError
from evitriage.sarif import InvalidSarifError


def _workspace(tmp_path: Path) -> RunWorkspace:
    workspace_root = tmp_path / "workspaces"
    artifact_root = tmp_path / "artifacts"
    build_copy = workspace_root / "build-copies" / "run-one"
    codeql_database = workspace_root / "codeql-databases" / "run-one"
    temporary = workspace_root / "temporary" / "run-one"
    source_snapshot = workspace_root / "sources" / ("a" * 64)
    artifact_run_root = artifact_root / "runs" / "run-one"
    for path in (
        build_copy,
        codeql_database,
        temporary,
        source_snapshot,
        artifact_run_root,
    ):
        path.mkdir(parents=True)
    wrapper = build_copy / "mvnw"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o700)
    wrapper_properties = build_copy / ".mvn" / "wrapper" / "maven-wrapper.properties"
    wrapper_properties.parent.mkdir(parents=True)
    wrapper_properties.write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/"
        "apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n"
        "distributionSha256Sum="
        "4ec3f26fb1a692473aea0235c300bd20f0f9fe741947c82c1234cefd76ac3a3c\n",
        encoding="utf-8",
    )
    return RunWorkspace(
        run_id="run-one",
        project_id="project-one",
        snapshot_id="a" * 64,
        workspace_root=workspace_root,
        artifact_root=artifact_root,
        source_snapshot=source_snapshot,
        build_copy=build_copy,
        codeql_database=codeql_database,
        temporary=temporary,
        artifact_run_root=artifact_run_root,
    )


def _codeql_spec(*, version: str = "2.26.1") -> CodeQLSpec:
    return CodeQLSpec(
        cli_version=version,
        language="java-kotlin",
        query_suites=("security-extended",),
        query_packs=("acme/java-queries@1.2.3",),
        model_packs=("acme/java-models@1.2.3",),
        include_query_help=True,
    )


def _build_spec(*, executable: str = "./mvnw") -> BuildSpec:
    return BuildSpec(
        adapter="maven",
        jdk="17",
        command=(executable, "--offline", "-q", "-DskipTests", "package"),
        timeout_seconds=60,
    )


def _install_fake_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    def which(value: str) -> str | None:
        return {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
            "javac": "/tools/javac",
        }.get(value)

    monkeypatch.setattr("evitriage.codeql.runner.shutil.which", which)


def _successful_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    assert kwargs["shell"] is False
    assert kwargs["check"] is False
    assert kwargs["capture_output"] is True
    assert kwargs["encoding"] == "utf-8"
    assert kwargs["errors"] == "replace"
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert "GITHUB_TOKEN" not in environment
    assert "HTTPS_PROXY" not in environment
    assert environment.get("JAVA_HOME") != "/attacker-controlled-jdk"
    assert isinstance(kwargs["cwd"], Path)
    if arguments[1:3] == ["version", "--format=terse"]:
        return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
    if arguments[0] == "/tools/java":
        return subprocess.CompletedProcess(
            arguments,
            0,
            stdout="",
            stderr='openjdk version "17.0.10"\n',
        )
    if arguments[0] == "/tools/javac":
        return subprocess.CompletedProcess(arguments, 0, stdout="javac 17.0.10\n", stderr="")
    if arguments[1:3] == ["database", "create"]:
        Path(arguments[3]).mkdir()
        return subprocess.CompletedProcess(arguments, 0, stdout="database created\n", stderr="")
    if arguments[1:3] == ["database", "analyze"]:
        output_argument = next(
            argument for argument in arguments if argument.startswith("--output=")
        )
        Path(output_argument.removeprefix("--output=")).write_text(
            '{"version":"2.1.0","runs":[]}\n', encoding="utf-8"
        )
        return subprocess.CompletedProcess(arguments, 0, stdout="analysis complete\n", stderr="")
    raise AssertionError(arguments)


def test_command_builder_uses_argv_and_quotes_only_the_codeql_command_value() -> None:
    builder = CodeQLCommandBuilder("/tools/codeql")
    build = _build_spec()
    build = build.model_copy(update={"command": ("./mvnw", "-Dmessage=two words", "package")})

    create = builder.database_create(
        spec=_codeql_spec(),
        build=build,
        database_path=Path("/managed/database"),
        source_root=Path("/managed/build"),
    )
    analyze = builder.database_analyze(
        spec=_codeql_spec(),
        database_path=Path("/managed/database"),
        sarif_path=Path("/managed/results.sarif"),
    )

    assert create[:4] == ("/tools/codeql", "database", "create", "/managed/database")
    assert "--command=./mvnw '-Dmessage=two words' package" in create
    assert "--threads=0" in create
    assert "security-extended" in analyze
    assert "--sarif-include-query-help=always" in analyze
    assert "--threads=0" in analyze
    assert "acme/java-queries@1.2.3" in analyze
    assert not any(argument.startswith("--additional-packs=") for argument in analyze)
    assert "--model-packs=acme/java-models@1.2.3" in analyze


def test_runner_records_real_command_metadata_and_sarif_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-reach-tools")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    monkeypatch.setenv("JAVA_HOME", "/attacker-controlled-jdk")
    calls: list[list[str]] = []

    def fake_run(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return _successful_run(arguments, **kwargs)

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", fake_run)
    workspace = _workspace(tmp_path)

    result = CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)

    assert result.status == "succeeded"
    assert result.codeql_version == "2.26.1"
    assert result.java_version.startswith("openjdk version")
    assert result.javac_version.startswith("javac 17")
    assert result.maven_distribution_version == "3.9.9"
    assert result.maven_distribution_url.startswith("https://repo.maven.apache.org/")
    assert result.sarif_path.is_file()
    assert len(result.sarif_sha256) == 64
    assert result.database_path == workspace.codeql_database / "database"
    assert [record.name for record in result.commands] == [
        "codeql-version",
        "java-version",
        "javac-version",
        "database-create",
        "database-analyze",
    ]
    assert all(record.exit_code == 0 for record in result.commands)
    assert all(
        record.stdout_path.is_file() and record.stderr_path.is_file() for record in result.commands
    )
    assert (workspace.artifact_run_root / "codeql" / "run.json").is_file()
    assert calls[3][0:3] == ["/tools/codeql", "database", "create"]
    assert calls[3][3] == str(workspace.codeql_database / "database")
    assert f"--source-root={workspace.build_copy}" in calls[3]
    assert calls[4][0:3] == ["/tools/codeql", "database", "analyze"]


def test_runner_fails_structurally_when_codeql_or_java_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("evitriage.codeql.runner.shutil.which", lambda _: None)

    with pytest.raises(CodeQLToolUnavailableError) as raised:
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=_build_spec(),
            workspace=_workspace(tmp_path),
        )

    assert raised.value.code == "CODEQL_TOOL_UNAVAILABLE"
    assert raised.value.details["tool"] == "codeql"


def test_runner_reports_java_as_the_missing_required_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "evitriage.codeql.runner.shutil.which",
        lambda value: "/tools/codeql" if value == "codeql" else None,
    )

    with pytest.raises(CodeQLToolUnavailableError) as raised:
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=_build_spec(),
            workspace=_workspace(tmp_path),
        )

    assert raised.value.details["tool"] == "java"


def test_runner_reports_javac_as_the_missing_required_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "evitriage.codeql.runner.shutil.which",
        lambda value: {
            "codeql": "/tools/codeql",
            "java": "/tools/java",
        }.get(value),
    )

    with pytest.raises(CodeQLToolUnavailableError) as raised:
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=_build_spec(),
            workspace=_workspace(tmp_path),
        )

    assert raised.value.details["tool"] == "javac"


def test_runner_requires_java_and_javac_from_one_jdk(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        "evitriage.codeql.runner.shutil.which",
        lambda value: {
            "codeql": "/tools/codeql",
            "java": "/jdk-17/bin/java",
            "javac": "/different-jdk/bin/javac",
        }.get(value),
    )
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("ran"),
    )

    with pytest.raises(CodeQLBuildPlanError, match="same pinned JDK"):
        CodeQLRunner().scan(
            codeql=_codeql_spec(), build=_build_spec(), workspace=_workspace(tmp_path)
        )


def test_runner_rejects_host_maven_before_running_any_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)
    called = False

    def fail_if_called(*_: object, **__: object) -> subprocess.CompletedProcess[str]:
        nonlocal called
        called = True
        raise AssertionError("subprocess must not run a host Maven plan")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", fail_if_called)

    with pytest.raises(CodeQLBuildPlanError):
        unsafe_build = _build_spec().model_copy(
            update={"command": ("mvn", "--offline", "-q", "package")}
        )
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=unsafe_build,
            workspace=_workspace(tmp_path),
        )

    assert not called


def test_runner_rejects_wrapper_symlink_escape_before_running_any_tool(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)
    workspace = _workspace(tmp_path)
    wrapper = workspace.build_copy / "mvnw"
    wrapper.unlink()
    outside = tmp_path / "outside-wrapper"
    outside.write_text("not a wrapper", encoding="utf-8")
    wrapper.symlink_to(outside)
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("ran"),
    )

    with pytest.raises(PathSafetyError, match="symbolic link"):
        CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)


def test_runner_requires_a_pinned_maven_distribution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    workspace = _workspace(tmp_path)
    properties = workspace.build_copy / ".mvn/wrapper/maven-wrapper.properties"
    properties.write_text(
        "distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/"
        "apache-maven/3.9.9/apache-maven-3.9.9-bin.zip\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("ran"),
    )

    with pytest.raises(CodeQLBuildPlanError, match="distributionSha256Sum"):
        CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)


def test_runner_reports_version_mismatch_and_nonzero_exits_without_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)

    def mismatched(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(arguments, 0, stdout="2.25.0\n", stderr="")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", mismatched)
    with pytest.raises(CodeQLVersionMismatchError) as mismatch:
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=_build_spec(),
            workspace=_workspace(tmp_path),
        )
    assert mismatch.value.details["expected"] == "2.26.1"
    assert mismatch.value.details["observed"] == "2.25.0"

    _install_fake_tools(monkeypatch)
    workspace = _workspace(tmp_path / "nonzero")

    def nonzero(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        if arguments[0] == "/tools/java":
            return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="java 17\n")
        if arguments[0] == "/tools/javac":
            return subprocess.CompletedProcess(arguments, 0, stdout="javac 17\n", stderr="")
        return subprocess.CompletedProcess(arguments, 23, stdout="", stderr="analysis failed\n")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", nonzero)
    with pytest.raises(CodeQLCommandError) as failed:
        CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)
    command = failed.value.details["command"]
    assert isinstance(command, dict)
    assert command["exit_code"] == 23
    assert command["name"] == "database-create"


def test_runner_reports_timeout_with_a_structured_command_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)

    def timeout(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(arguments, timeout=30, output=b"partial", stderr=b"late")

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", timeout)
    workspace = _workspace(tmp_path)

    with pytest.raises(CodeQLTimeoutError) as raised:
        CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)

    command = raised.value.details["command"]
    assert isinstance(command, dict)
    assert command["timed_out"] is True
    assert command["exit_code"] is None
    stdout_path = workspace.artifact_run_root / "codeql" / "codeql-version.stdout.log"
    assert stdout_path.read_text() == "partial"


def test_runner_rejects_unpinned_java_and_invalid_sarif(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)

    def java_21(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if arguments[1:3] == ["version", "--format=terse"]:
            return subprocess.CompletedProcess(arguments, 0, stdout="2.26.1\n", stderr="")
        return subprocess.CompletedProcess(
            arguments, 0, stdout="", stderr='openjdk version "21.0.2"\n'
        )

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", java_21)
    with pytest.raises(CodeQLJavaVersionMismatchError) as mismatch:
        CodeQLRunner().scan(
            codeql=_codeql_spec(), build=_build_spec(), workspace=_workspace(tmp_path / "jdk")
        )
    assert mismatch.value.details["expected_major"] == 17
    assert mismatch.value.details["observed_major"] == 21

    def invalid_sarif(arguments: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        completed = _successful_run(arguments, **kwargs)
        if arguments[1:3] == ["database", "analyze"]:
            output = next(item for item in arguments if item.startswith("--output="))
            Path(output.removeprefix("--output=")).write_text(
                '{"version":"2.0.0","runs":[]}\n', encoding="utf-8"
            )
        return completed

    monkeypatch.setattr("evitriage.codeql.runner.subprocess.run", invalid_sarif)
    with pytest.raises(InvalidSarifError, match=r"SARIF 2\.1\.0"):
        CodeQLRunner().scan(
            codeql=_codeql_spec(),
            build=_build_spec(),
            workspace=_workspace(tmp_path / "sarif"),
        )


def test_runner_refuses_existing_sarif_artifact_before_invocation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_fake_tools(monkeypatch)
    workspace = _workspace(tmp_path)
    artifact_directory = workspace.artifact_run_root / "codeql"
    artifact_directory.mkdir()
    (artifact_directory / "results.sarif").write_text("old", encoding="utf-8")
    monkeypatch.setattr(
        "evitriage.codeql.runner.subprocess.run",
        lambda *_args, **_kwargs: pytest.fail("ran"),
    )

    with pytest.raises(PathSafetyError, match="overwrite"):
        CodeQLRunner().scan(codeql=_codeql_spec(), build=_build_spec(), workspace=workspace)
