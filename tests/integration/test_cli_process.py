from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.integration
def test_console_entrypoint_returns_structured_configuration_error(
    tmp_path: Path,
    repository_root: Path,
) -> None:
    invalid = tmp_path / "invalid-project.yaml"
    invalid.write_text("schema_version: '1.0'\napi_key: must-not-leak\n", encoding="utf-8")
    environment = os.environ.copy()
    environment["EVITRIAGE_PROJECT_ROOT"] = str(repository_root)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "project",
            "validate",
            "--config",
            str(invalid),
            "--json",
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stderr)
    assert payload["error"]["code"] == "CONFIGURATION_ERROR"
    assert "must-not-leak" not in completed.stderr
    assert "Traceback" not in completed.stderr


@pytest.mark.integration
def test_console_json_mode_structures_cli_usage_errors(repository_root: Path) -> None:
    environment = os.environ.copy()
    environment["EVITRIAGE_PROJECT_ROOT"] = str(repository_root)

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "evitriage.cli",
            "project",
            "validate",
            "--json",
        ],
        cwd=repository_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        shell=False,
    )

    assert completed.returncode == 2
    payload = json.loads(completed.stderr)
    assert payload["error"]["code"] == "CLI_USAGE_ERROR"
    assert "config" in payload["error"]["message"]
