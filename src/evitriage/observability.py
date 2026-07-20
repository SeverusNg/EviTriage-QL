"""Structured logging and conservative secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|password|passwd|secret|token|credential)",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)bearer\s+[a-z0-9._~+/=-]+")


def redact(value: object) -> object:
    """Recursively redact values associated with common secret names."""
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            redacted[key] = "[REDACTED]" if _SECRET_KEY.search(key) else redact(item)
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _BEARER.sub("Bearer [REDACTED]", value)
    return value


def _json_default(value: object) -> str:
    if isinstance(value, (datetime, Path)):
        return value.isoformat() if isinstance(value, datetime) else str(value)
    return repr(value)


class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "structured_fields", None)
        if isinstance(fields, Mapping):
            payload["fields"] = redact(fields)
        if record.exc_info is not None:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(redact(payload), sort_keys=True, default=_json_default)


def configure_logging(*, verbose: bool = False, stream: TextIO | None = None) -> None:
    """Configure the package logger without altering unrelated loggers."""
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("evitriage")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False
