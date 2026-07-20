from __future__ import annotations

import json
import logging
from io import StringIO

from evitriage.errors import ConfigurationError
from evitriage.observability import configure_logging, redact


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


def test_redaction_handles_nested_secrets_and_bearer_values() -> None:
    value = {
        "api_key": "top-secret",
        "nested": [{"password": "hidden"}, "Bearer abc.def"],
        "safe": "visible",
    }

    assert redact(value) == {
        "api_key": "[REDACTED]",
        "nested": [{"password": "[REDACTED]"}, "Bearer [REDACTED]"],
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
