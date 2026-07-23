from __future__ import annotations

import json
import logging
from io import StringIO
from pathlib import Path

import pytest

from evitriage.errors import ConfigurationError
from evitriage.observability import configure_logging, redact
from evitriage.secret_scan import detect_secret_rules, scan_repository


def test_typed_error_has_stable_machine_representation() -> None:
    error = ConfigurationError("bad project", details={"field": "source.path"})

    assert error.exit_code == 2
    assert error.as_dict() == {
        "error": {
            "code": "CONFIGURATION_ERROR",
            "message": "bad project",
            "details": {"field": "source.path"},
        }
    }


@pytest.mark.security
def test_redaction_handles_nested_secrets_and_bearer_values() -> None:
    value = {
        "api_key": "top-secret",
        "nested": [
            {"password": "hidden"},
            "Bearer abc.def",
            "password=hunter2 token:secret-value",
            "https://user:token@example.invalid/repository.git",
        ],
        "safe": "visible",
    }

    assert redact(value) == {
        "api_key": "[REDACTED]",
        "nested": [
            {"password": "[REDACTED]"},
            "Bearer [REDACTED]",
            "password=[REDACTED] token:[REDACTED]",
            "https://[REDACTED]@example.invalid/repository.git",
        ],
        "safe": "visible",
    }


def test_json_logger_redacts_structured_fields() -> None:
    stream = StringIO()
    configure_logging(stream=stream)

    logging.getLogger("evitriage.test").info(
        "configured",
        extra={"structured_fields": {"token": "secret", "project": "demo"}},
    )

    event = json.loads(stream.getvalue())
    assert event["message"] == "configured"
    assert event["fields"] == {"project": "demo", "token": "[REDACTED]"}


def test_secret_scan_detects_values_without_flagging_environment_references(
    repository_root: Path,
) -> None:
    assignment = b"DEEPSEEK_API_" + b"KEY=" + b"sk-" + (b"x" * 24)
    private_key = b"-----BEGIN " + b"PRIVATE KEY-----"

    assert set(detect_secret_rules(assignment)) == {
        "api-key-shaped-token",
        "deepseek-environment-assignment",
    }
    assert detect_secret_rules(private_key) == ("private-key-block",)
    assert detect_secret_rules(b"read -s DEEPSEEK_API_KEY; export DEEPSEEK_API_KEY") == ()
    assert scan_repository(repository_root) == ()
