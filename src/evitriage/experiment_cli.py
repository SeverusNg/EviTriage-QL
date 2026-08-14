"""Typer command callbacks for manifest-driven existing-SARIF experiments."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from evitriage.config import load_llm_profile
from evitriage.credentials import CredentialProviderSelection, CredentialResolver
from evitriage.errors import ConfigurationError
from evitriage.experiment_artifacts import (
    evaluate_frozen_experiment,
    finalize_experiment_artifacts,
)
from evitriage.experiments import (
    load_experiment_manifest,
    preflight_existing_sarif_experiment,
    run_existing_sarif_experiment,
)
from evitriage.llm import DeepSeekLLM, ReplayLLM, StructuredLLM


def register_experiment_commands(
    experiment_app: typer.Typer,
    *,
    repository_root: Callable[[], Path],
    operator_path: Callable[[Path, Path], Path],
    emit_json: Callable[[object], None],
) -> None:
    """Attach commands while reusing the root CLI's path and JSON boundaries."""

    @experiment_app.command("preflight")
    def preflight_command(
        manifest_path: Annotated[Path, typer.Option("--manifest")],
        as_json: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Validate all inputs without loading an LLM profile or credential."""

        root = repository_root()
        manifest = load_experiment_manifest(operator_path(root, manifest_path))
        result = preflight_existing_sarif_experiment(root, manifest)
        if as_json:
            emit_json(result.model_dump(mode="json"))
        else:
            typer.echo(f"preflight: {result.status}")
            typer.echo(f"triage alerts: {result.triage_alert_count}")
            typer.echo(f"model calls: {result.minimum_model_calls}-{result.maximum_model_calls}")

    @experiment_app.command("run")
    def run_command(
        manifest_path: Annotated[Path, typer.Option("--manifest")],
        dry_run: Annotated[bool, typer.Option("--dry-run")] = False,
        replay_cache: Annotated[Path | None, typer.Option("--replay-cache")] = None,
        credential_provider: Annotated[
            CredentialProviderSelection, typer.Option("--credential-provider")
        ] = "auto",
        as_json: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Preflight globally, then triage each independent case sequentially."""

        root = repository_root()
        manifest = load_experiment_manifest(operator_path(root, manifest_path))
        preflight = preflight_existing_sarif_experiment(root, manifest)
        if dry_run:
            result = run_existing_sarif_experiment(root, manifest, llm=None, dry_run=True)
        else:
            profile = load_llm_profile(operator_path(root, Path(manifest.llm_profile)))
            llm: StructuredLLM
            if profile.provider == "replay":
                if credential_provider != "auto":
                    raise ConfigurationError("--credential-provider is valid only for DeepSeek")
                if replay_cache is None:
                    raise ConfigurationError("--replay-cache is required for Replay")
                llm = ReplayLLM(profile, operator_path(root, replay_cache))
            elif profile.provider == "deepseek":
                if replay_cache is not None:
                    raise ConfigurationError("--replay-cache cannot be used with DeepSeek")
                # Global source/SARIF/spec preflight has completed before this
                # credential access. Network starts only in DeepSeekLLM.complete.
                credential = CredentialResolver().resolve(credential_provider)
                llm = DeepSeekLLM(profile, api_key=credential.secret)
            else:
                raise ConfigurationError("FakeLLM is test-only")
            result = run_existing_sarif_experiment(root, manifest, llm=llm, dry_run=False)
            finalize_experiment_artifacts(root, manifest, preflight, result)
        if as_json:
            emit_json(result.model_dump(mode="json"))
        else:
            typer.echo(f"experiment: {result.status}")
            typer.echo(f"alerts: {result.decided_alert_count}/{result.triage_alert_count}")
        if result.status == "incomplete":
            raise typer.Exit(code=1)

    @experiment_app.command("evaluate")
    def evaluate_command(
        manifest_path: Annotated[Path, typer.Option("--manifest")],
        as_json: Annotated[bool, typer.Option("--json")] = False,
    ) -> None:
        """Read the human baseline only after automatic decisions are immutable."""

        root = repository_root()
        manifest = load_experiment_manifest(operator_path(root, manifest_path))
        result = evaluate_frozen_experiment(root, manifest)
        if as_json:
            emit_json(result.model_dump(mode="json"))
        else:
            typer.echo(f"aligned: {result.aligned_count}")
            typer.echo(f"agreement: {result.agreement:.6f}")


__all__ = ["register_experiment_commands"]
