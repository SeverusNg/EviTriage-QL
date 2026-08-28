"""Command-line entry point for the auditable EviTriage workflow."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated, Literal

import typer
import yaml
from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig
from alembic.util.exc import CommandError as AlembicCommandError
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError
from typer._click.exceptions import ClickException as TyperClickException

from evitriage import __version__
from evitriage.config import load_llm_profile
from evitriage.credentials import (
    CredentialProviderSelection,
    CredentialResolver,
    PassCredentialProvider,
    store_deepseek_credential,
)
from evitriage.doctor import run_doctor
from evitriage.domain.run import ContextRunSummary
from evitriage.domain.triage import TriageRunSummary
from evitriage.errors import (
    ConfigurationError,
    EviTriageError,
    PathSafetyError,
    StorageError,
)
from evitriage.experiment_cli import register_experiment_commands
from evitriage.llm import DeepSeekLLM, ReplayLLM, StructuredLLM
from evitriage.observability import configure_logging, redact
from evitriage.pipeline import (
    run_codeql_scan,
    run_codeql_triage,
    run_sarif_ingest,
    run_sarif_triage,
)
from evitriage.projects.registry import ProjectRegistry
from evitriage.storage.database import Database

app = typer.Typer(
    name="evitriage",
    help="Evidence-grounded secondary triage for CodeQL alerts.",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
project_app = typer.Typer(help="Validate trusted project boundaries.", no_args_is_help=True)
db_app = typer.Typer(help="Manage the local metadata database.", no_args_is_help=True)
credentials_app = typer.Typer(help="Manage repository-external encrypted credentials.")
experiment_app = typer.Typer(help="Run manifest-bound existing-SARIF experiments.")
app.add_typer(project_app, name="project")
app.add_typer(db_app, name="db")
app.add_typer(credentials_app, name="credentials")
app.add_typer(experiment_app, name="experiment")


def _emit_json(payload: object, *, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    typer.echo(
        json.dumps(redact(payload), ensure_ascii=False, sort_keys=True),
        file=stream,
    )


def find_repository_root(start: Path | None = None) -> Path:
    """Find the nearest checkout root containing this project's pyproject file."""
    configured = os.environ.get("EVITRIAGE_PROJECT_ROOT")
    candidate = Path(configured) if configured else (start or Path.cwd())
    try:
        candidate = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ConfigurationError(f"cannot resolve repository root start: {candidate}") from error
    if candidate.is_file():
        candidate = candidate.parent
    for directory in (candidate, *candidate.parents):
        pyproject = directory / "pyproject.toml"
        if pyproject.is_file() and 'name = "evitriage-ql"' in pyproject.read_text(encoding="utf-8"):
            return directory
    raise ConfigurationError(
        "cannot locate EviTriage-QL repository root; run inside the checkout or set "
        "EVITRIAGE_PROJECT_ROOT"
    )


@app.callback()
def root(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable debug-level structured logs."),
    ] = False,
) -> None:
    """Configure process-wide, non-secret structured diagnostics."""
    configure_logging(verbose=verbose)


@credentials_app.command("set-deepseek")
def credentials_set_deepseek(
    provider: Annotated[
        Literal["systemd-creds", "pass"],
        typer.Option(
            "--provider",
            help="Persistent backend: TPM2/systemd-creds or pass/GPG.",
        ),
    ] = "systemd-creds",
    replace: Annotated[
        bool,
        typer.Option("--replace", help="Replace an existing encrypted credential during rotation."),
    ] = False,
) -> None:
    """Prompt twice and encrypt a DeepSeek key without a plaintext file."""

    api_key = typer.prompt(
        "New DeepSeek API Key",
        hide_input=True,
        confirmation_prompt=True,
    )
    if provider == "systemd-creds":
        path = store_deepseek_credential(api_key, replace=replace)
        typer.echo(f"encrypted DeepSeek credential installed: {path}")
    else:
        PassCredentialProvider().store_secret(api_key, replace=replace)
        typer.echo("encrypted DeepSeek credential installed via pass")


@credentials_app.command("status")
def credentials_status(
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit credential presence without exposing its value."),
    ] = False,
) -> None:
    """Report provider availability and auto selection without loading a secret."""

    credential_status = CredentialResolver().status()
    payload: dict[str, object] = {
        "deepseek": credential_status,
        "status": "ok",
    }
    if as_json:
        _emit_json(payload)
    else:
        typer.echo(
            "DeepSeek credential provider: "
            f"{credential_status['selected_provider'] or 'none'} "
            f"({credential_status['selection_status']})"
        )


@app.command()
def doctor(
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit one machine-readable JSON object."),
    ] = False,
) -> None:
    """Check required foundations and optional CodeQL/JDK scan readiness."""
    report = run_doctor(find_repository_root())
    if as_json:
        _emit_json(report)
    else:
        typer.echo(f"EviTriage-QL {report['evitriage_version']}: {report['status']}")
        checks = report["checks"]
        if isinstance(checks, list):
            for check in checks:
                if isinstance(check, dict):
                    typer.echo(
                        f"- {check.get('name')}: {check.get('status')} ({check.get('detail')})"
                    )
    if report["status"] != "ok":
        raise typer.Exit(code=1)


@project_app.command("validate")
def project_validate(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            exists=False,
            file_okay=True,
            dir_okay=False,
            readable=True,
            resolve_path=False,
            help="ProjectSpec YAML path, relative to the repository root or absolute.",
        ),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit the resolved, sanitized config as JSON."),
    ] = False,
    allowed_source_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--allowed-source-root",
            help=(
                "Trusted local source root; repeat to allow sources outside the checkout. "
                "Defaults to the repository root."
            ),
        ),
    ] = None,
) -> None:
    """Strictly validate and resolve a ProjectSpec without executing repository code."""
    repository_root = find_repository_root()
    allowed_roots = tuple(allowed_source_root) if allowed_source_root else None
    resolved = ProjectRegistry(repository_root, allowed_source_roots=allowed_roots).validate_path(
        config
    )
    payload: dict[str, object] = {
        "status": "ok",
        "schema_version": resolved.spec.schema_version,
        "project_id": resolved.project_id,
        "config_path": resolved.config_path,
        "digest": resolved.digest,
        "resolved": resolved.sanitized,
    }
    if as_json:
        _emit_json(payload)
    else:
        typer.echo(f"valid project: {resolved.project_id}")
        typer.echo(f"digest: {resolved.digest}")
        typer.echo(yaml.safe_dump(resolved.sanitized, sort_keys=True).rstrip())


def _operator_input_path(repository_root: Path, requested: Path) -> Path:
    """Anchor a relative operator input without resolving away a final symlink."""

    candidate = requested if requested.is_absolute() else repository_root / requested
    return Path(os.path.abspath(candidate))


register_experiment_commands(
    experiment_app,
    repository_root=lambda: find_repository_root(),
    operator_path=lambda root, requested: _operator_input_path(root, requested),
    emit_json=lambda payload: _emit_json(payload),
)


def _emit_run_summary(payload: ContextRunSummary | TriageRunSummary, *, as_json: bool) -> None:
    serialized = payload.model_dump(mode="json")
    if as_json:
        _emit_json(serialized)
        return
    typer.echo(f"run: {serialized.get('run_id')}")
    typer.echo(f"state: {serialized.get('state')}")
    typer.echo(f"alerts: {serialized.get('alert_count')}")
    typer.echo(f"artifacts: {serialized.get('artifact_run_root')}")


def _execute_sarif_command(
    *,
    command_name: Literal["ingest-sarif", "normalize"],
    project_config: Path,
    sarif: Path,
    as_json: bool,
    allowed_source_root: list[Path] | None,
) -> None:
    repository_root = find_repository_root()
    allowed_roots = tuple(allowed_source_root) if allowed_source_root else None
    summary = run_sarif_ingest(
        repository_root,
        project_config=project_config,
        sarif_path=_operator_input_path(repository_root, sarif),
        allowed_source_roots=allowed_roots,
        command=command_name,
    )
    _emit_run_summary(summary, as_json=as_json)


@app.command("ingest-sarif")
def ingest_sarif_command(
    project_config: Annotated[
        Path,
        typer.Option(
            "--project-config",
            help="Validated local ProjectSpec used to bind SARIF paths to a source snapshot.",
        ),
    ],
    sarif: Annotated[
        Path,
        typer.Option(
            "--sarif",
            help="Existing SARIF 2.1.0 file; relative paths are anchored at the checkout root.",
        ),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit one machine-readable run summary."),
    ] = False,
    allowed_source_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--allowed-source-root",
            help="Trusted local source root; repeat for sources outside the checkout.",
        ),
    ] = None,
) -> None:
    """Ingest SARIF and build normalized Gate C context/evidence offline."""

    _execute_sarif_command(
        command_name="ingest-sarif",
        project_config=project_config,
        sarif=sarif,
        as_json=as_json,
        allowed_source_root=allowed_source_root,
    )


@app.command("normalize")
def normalize_command(
    project_config: Annotated[
        Path,
        typer.Option("--project-config", help="Validated local ProjectSpec."),
    ],
    sarif: Annotated[
        Path,
        typer.Option("--sarif", help="SARIF 2.1.0 input to normalize."),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit one machine-readable run summary."),
    ] = False,
    allowed_source_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--allowed-source-root",
            help="Trusted local source root; repeat for sources outside the checkout.",
        ),
    ] = None,
) -> None:
    """Normalize SARIF and build the shared Gate C context/evidence artifacts."""

    _execute_sarif_command(
        command_name="normalize",
        project_config=project_config,
        sarif=sarif,
        as_json=as_json,
        allowed_source_root=allowed_source_root,
    )


@app.command("triage")
def triage_command(
    project_config: Annotated[
        Path,
        typer.Option("--project-config", help="Validated local ProjectSpec."),
    ],
    sarif: Annotated[
        Path | None,
        typer.Option("--sarif", help="Existing SARIF 2.1.0 input to triage."),
    ] = None,
    scan: Annotated[
        bool,
        typer.Option("--scan", help="Run CodeQL first, then continue through triage/report."),
    ] = False,
    replay_cache: Annotated[
        Path | None,
        typer.Option(
            "--replay-cache",
            help="Required only for Replay; directory of request-hash JSON responses.",
        ),
    ] = None,
    evidence_supplement: Annotated[
        Path | None,
        typer.Option(
            "--evidence-supplement",
            help=(
                "Optional trusted human/test/verifier evidence JSON bound to the exact "
                "source and SARIF identities."
            ),
        ),
    ] = None,
    llm_profile: Annotated[
        Path,
        typer.Option(
            "--llm-profile",
            help="Trusted Replay/DeepSeek profile matching ProjectSpec analysis.llm_profile.",
        ),
    ] = Path("configs/llm/replay-v0.1.yaml"),
    credential_provider: Annotated[
        CredentialProviderSelection,
        typer.Option(
            "--credential-provider",
            help=("DeepSeek credential source. Auto uses environment, systemd-creds, then pass."),
        ),
    ] = "auto",
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit one machine-readable Gate D run summary."),
    ] = False,
    allowed_source_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--allowed-source-root",
            help="Trusted local source root; repeat for sources outside the checkout.",
        ),
    ] = None,
) -> None:
    """Run bounded Replay or DeepSeek Analyst/Rebuttal/Judge triage."""

    repository_root = find_repository_root()
    if (sarif is None) == (not scan):
        raise ConfigurationError("triage requires exactly one of --sarif or --scan")
    profile = load_llm_profile(_operator_input_path(repository_root, llm_profile))
    llm: StructuredLLM
    if profile.provider == "replay":
        if credential_provider != "auto":
            raise ConfigurationError(
                "--credential-provider can be selected only with a DeepSeek profile"
            )
        if replay_cache is None:
            raise ConfigurationError("--replay-cache is required for a Replay profile")
        llm = ReplayLLM(profile, _operator_input_path(repository_root, replay_cache))
    elif profile.provider == "deepseek":
        if replay_cache is not None:
            raise ConfigurationError("--replay-cache cannot be used with a DeepSeek profile")
        credential = CredentialResolver().resolve(credential_provider)
        llm = DeepSeekLLM(profile, api_key=credential.secret)
    else:
        raise ConfigurationError("FakeLLM is available only to tests, not the triage CLI")
    allowed_roots = tuple(allowed_source_root) if allowed_source_root else None
    supplement_path = (
        _operator_input_path(repository_root, evidence_supplement)
        if evidence_supplement is not None
        else None
    )
    if scan:
        summary = run_codeql_triage(
            repository_root,
            project_config=project_config,
            profile=profile,
            llm=llm,
            evidence_supplement_path=supplement_path,
            allowed_source_roots=allowed_roots,
        )
    else:
        if sarif is None:  # pragma: no cover - guarded by the exclusive input check
            raise ConfigurationError("triage requires --sarif when --scan is absent")
        summary = run_sarif_triage(
            repository_root,
            project_config=project_config,
            sarif_path=_operator_input_path(repository_root, sarif),
            profile=profile,
            llm=llm,
            evidence_supplement_path=supplement_path,
            allowed_source_roots=allowed_roots,
        )
    _emit_run_summary(summary, as_json=as_json)


@app.command("scan")
def scan_command(
    project_config: Annotated[
        Path,
        typer.Option("--project-config", help="Validated local ProjectSpec to scan."),
    ],
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit one machine-readable run summary."),
    ] = False,
    allowed_source_root: Annotated[
        list[Path] | None,
        typer.Option(
            "--allowed-source-root",
            help="Trusted local source root; repeat for sources outside the checkout.",
        ),
    ] = None,
) -> None:
    """Run CodeQL, normalization, and Gate C context/evidence extraction."""

    repository_root = find_repository_root()
    allowed_roots = tuple(allowed_source_root) if allowed_source_root else None
    summary = run_codeql_scan(
        repository_root,
        project_config=project_config,
        allowed_source_roots=allowed_roots,
    )
    _emit_run_summary(summary, as_json=as_json)


def _managed_database_path(repository_root: Path, requested: Path) -> Path:
    requested_artifact_root = repository_root / "artifacts"
    if requested_artifact_root.is_symlink():
        raise PathSafetyError("managed artifact root must not be a symbolic link")
    requested_artifact_root.mkdir(parents=True, exist_ok=True)
    requested_artifact_root.chmod(0o700, follow_symlinks=False)
    artifact_root = requested_artifact_root.resolve(strict=True)
    candidate = requested if requested.is_absolute() else repository_root / requested
    absolute_candidate = Path(os.path.abspath(candidate))
    current = Path(absolute_candidate.anchor)
    for part in absolute_candidate.parts[1:]:
        current /= part
        if current.is_symlink():
            raise PathSafetyError(f"database path contains a symbolic link: {current}")
        if not current.exists():
            break
    database_path = candidate.resolve(strict=False)
    if database_path == artifact_root or not database_path.is_relative_to(artifact_root):
        raise PathSafetyError(
            "Gate A database must be a file below the managed artifact root",
            details={"path": str(database_path), "artifact_root": str(artifact_root)},
        )
    database_path.parent.mkdir(parents=True, exist_ok=True)
    database_path.parent.chmod(0o700, follow_symlinks=False)
    return database_path


@db_app.command("migrate")
def db_migrate(
    database: Annotated[
        Path,
        typer.Option(
            "--database",
            help="SQLite file below artifacts/, relative to the repository root by default.",
        ),
    ] = Path("artifacts/evitriage.db"),
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit migration metadata as JSON."),
    ] = False,
) -> None:
    """Upgrade the managed SQLite metadata database to the latest revision."""
    repository_root = find_repository_root()
    database_path = _managed_database_path(repository_root, database)
    configuration = AlembicConfig(str(repository_root / "alembic.ini"))
    configuration.set_main_option(
        "sqlalchemy.url", f"sqlite+pysqlite:///{database_path.as_posix()}"
    )
    try:
        alembic_command.upgrade(configuration, "head")
        database_path.chmod(0o600, follow_symlinks=False)
        storage = Database.from_path(database_path)
        try:
            table_names = sorted(inspect(storage.engine).get_table_names())
        finally:
            storage.dispose()
    except (OSError, SQLAlchemyError, AlembicCommandError) as error:
        raise StorageError(f"database migration failed: {error}") from error
    payload: dict[str, object] = {
        "status": "ok",
        "database": str(database_path),
        "revision": "0001_gate_a",
        "tables": table_names,
    }
    if as_json:
        _emit_json(payload)
    else:
        typer.echo(f"database upgraded to 0001_gate_a: {database_path}")


@app.command("version")
def version() -> None:
    """Print the package version."""
    typer.echo(__version__)


def main() -> None:
    """Run Typer with stable handling for expected operational errors."""
    try:
        app(standalone_mode=False)
    except EviTriageError as error:
        if "--json" in sys.argv:
            _emit_json(error.as_dict(), error=True)
        else:
            typer.echo(f"{error.code}: {error.message}", err=True)
        raise SystemExit(error.exit_code) from error
    except TyperClickException as error:
        if "--json" in sys.argv:
            _emit_json(
                {
                    "error": {
                        "code": "CLI_USAGE_ERROR",
                        "message": error.format_message(),
                        "details": {},
                    }
                },
                error=True,
            )
        else:
            error.show()
        raise SystemExit(error.exit_code) from error
    except typer.Exit as error:
        raise SystemExit(error.exit_code) from error


if __name__ == "__main__":
    main()
