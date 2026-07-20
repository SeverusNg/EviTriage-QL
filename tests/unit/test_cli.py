from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import typer
import yaml
from typer._click.exceptions import ClickException as TyperClickException
from typer.testing import CliRunner

import evitriage.cli as cli_module
from evitriage.cli import app, find_repository_root
from evitriage.errors import ConfigurationError, PathSafetyError

runner = CliRunner()


def test_find_repository_root_honors_explicit_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "evitriage-ql"\n', encoding="utf-8")
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(tmp_path))

    assert find_repository_root() == tmp_path.resolve()


def test_find_repository_root_walks_from_a_file_and_reports_missing_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    nested = repository / "nested"
    nested.mkdir(parents=True)
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "evitriage-ql"\n', encoding="utf-8"
    )
    starting_file = nested / "input.txt"
    starting_file.write_text("input", encoding="utf-8")
    monkeypatch.delenv("EVITRIAGE_PROJECT_ROOT", raising=False)

    assert find_repository_root(starting_file) == repository
    with pytest.raises(ConfigurationError, match="cannot locate"):
        find_repository_root(tmp_path)
    with pytest.raises(ConfigurationError, match="cannot resolve"):
        find_repository_root(tmp_path / "missing")


def test_project_validate_cli_emits_sanitized_json(
    monkeypatch: pytest.MonkeyPatch,
    repository_root: Path,
) -> None:
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository_root))

    result = runner.invoke(
        app,
        [
            "project",
            "validate",
            "--config",
            "configs/projects/example-local.yaml",
            "--json",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert payload["project_id"] == "example-local"
    assert len(payload["digest"]) == 64
    serialized = json.dumps(payload)
    assert "api_key" not in serialized
    assert "system_prompt" not in serialized

    human = runner.invoke(
        app,
        [
            "project",
            "validate",
            "--config",
            "configs/projects/example-local.yaml",
        ],
    )
    assert human.exit_code == 0, human.output
    assert "valid project: example-local" in human.stdout
    assert "digest:" in human.stdout


def test_project_validate_cli_rejects_checked_in_id_with_changed_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository_root))
    raw = yaml.safe_load(
        (repository_root / "configs/projects/example-local.yaml").read_text(encoding="utf-8")
    )
    raw["source"]["path"] = "tests/fixtures/java-microbench/command-app"
    collision = tmp_path / "collision.yaml"
    collision.write_text(yaml.safe_dump(raw, sort_keys=False), encoding="utf-8")

    result = runner.invoke(
        app,
        ["project", "validate", "--config", str(collision), "--json"],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, ConfigurationError)
    assert "version the project id explicitly" in str(result.exception)


def test_version_cli() -> None:
    result = runner.invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_doctor_cli_emits_valid_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "evitriage-ql"\n', encoding="utf-8")
    config_dir = tmp_path / "configs" / "system"
    config_dir.mkdir(parents=True)
    shutil.copy2(repository_root / "configs/system/v0.1.yaml", config_dir / "v0.1.yaml")
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(tmp_path))

    result = runner.invoke(app, ["doctor", "--json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert {check["name"] for check in payload["checks"]} >= {
        "python",
        "uv",
        "sqlite",
        "codeql",
    }


def test_doctor_human_output_and_failed_required_check(
    monkeypatch: pytest.MonkeyPatch,
    repository_root: Path,
) -> None:
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(repository_root))
    report: dict[str, object] = {
        "evitriage_version": "0.1.0",
        "status": "ok",
        "checks": [{"name": "python", "status": "ok", "detail": "3.12"}],
    }
    monkeypatch.setattr(cli_module, "run_doctor", lambda _: report)

    human = runner.invoke(app, ["doctor"])
    assert human.exit_code == 0
    assert "EviTriage-QL 0.1.0: ok" in human.stdout
    assert "python: ok" in human.stdout

    report["status"] = "error"
    failed = runner.invoke(app, ["doctor", "--json"])
    assert failed.exit_code == 1
    assert json.loads(failed.stdout)["status"] == "error"


def test_database_migrate_cli_is_real_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    repository_root: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "evitriage-ql"\n', encoding="utf-8")
    shutil.copy2(repository_root / "alembic.ini", tmp_path / "alembic.ini")
    shutil.copytree(repository_root / "migrations", tmp_path / "migrations")
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(tmp_path))

    first = runner.invoke(app, ["db", "migrate", "--json"])
    second = runner.invoke(app, ["db", "migrate", "--json"])

    assert first.exit_code == 0, first.output
    assert second.exit_code == 0, second.output
    payload = json.loads(second.stdout)
    assert payload["revision"] == "0001_gate_a"
    assert set(payload["tables"]) == {
        "alembic_version",
        "projects",
        "runs",
        "workflow_events",
    }
    assert Path(payload["database"]).is_file()
    assert Path(payload["database"]).stat().st_mode & 0o077 == 0

    human = runner.invoke(app, ["db", "migrate"])
    assert human.exit_code == 0, human.output
    assert "database upgraded to 0001_gate_a" in human.stdout


def test_database_migrate_rejects_path_outside_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "evitriage-ql"\n', encoding="utf-8")
    monkeypatch.setenv("EVITRIAGE_PROJECT_ROOT", str(tmp_path))

    result = runner.invoke(
        app,
        ["db", "migrate", "--database", "outside.sqlite", "--json"],
    )

    assert result.exit_code != 0
    assert isinstance(result.exception, PathSafetyError)

    artifacts = tmp_path / "artifacts"
    real = artifacts / "real"
    real.mkdir(parents=True)
    (artifacts / "linked").symlink_to(real, target_is_directory=True)
    linked = runner.invoke(
        app,
        [
            "db",
            "migrate",
            "--database",
            "artifacts/linked/database.sqlite",
            "--json",
        ],
    )
    assert linked.exit_code != 0
    assert isinstance(linked.exception, PathSafetyError)


def test_main_serializes_expected_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise ConfigurationError("invalid", details={"api_key": "must-hide"})

    monkeypatch.setattr(cli_module, "app", fail)
    monkeypatch.setattr("sys.argv", ["evitriage", "--json"])

    with pytest.raises(SystemExit) as raised:
        cli_module.main()

    assert raised.value.code == 2
    payload = json.loads(capsys.readouterr().err)
    assert payload["error"]["code"] == "CONFIGURATION_ERROR"
    assert payload["error"]["details"]["api_key"] == "[REDACTED]"


def test_main_handles_human_errors_usage_errors_and_typer_exits(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_domain(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise ConfigurationError("invalid human input")

    monkeypatch.setattr(cli_module, "app", fail_domain)
    monkeypatch.setattr("sys.argv", ["evitriage"])
    with pytest.raises(SystemExit) as domain_exit:
        cli_module.main()
    assert domain_exit.value.code == 2
    assert "CONFIGURATION_ERROR: invalid human input" in capsys.readouterr().err

    def fail_usage(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise TyperClickException("bad usage")

    monkeypatch.setattr(cli_module, "app", fail_usage)
    with pytest.raises(SystemExit) as usage_exit:
        cli_module.main()
    assert usage_exit.value.code != 0
    assert "bad usage" in capsys.readouterr().err

    def exit_normally(*, standalone_mode: bool) -> None:
        assert standalone_mode is False
        raise typer.Exit(7)

    monkeypatch.setattr(cli_module, "app", exit_normally)
    with pytest.raises(SystemExit) as typer_exit:
        cli_module.main()
    assert typer_exit.value.code == 7
