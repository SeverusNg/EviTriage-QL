"""Bounded file ingestion for untrusted SARIF JSON artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from pydantic import ValidationError

from evitriage.domain.alerts import AlertBundle
from evitriage.sarif.errors import InvalidSarifError
from evitriage.sarif.normalizer import SarifNormalizer
from evitriage.sarif.raw_models import SarifDocument

DEFAULT_MAXIMUM_SARIF_BYTES = 128 * 1024 * 1024


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def parse_sarif_bytes(data: bytes) -> SarifDocument:
    """Parse UTF-8 JSON into the supported strict SARIF 2.1.0 structure."""

    try:
        text = data.decode("utf-8-sig")
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise InvalidSarifError(f"invalid SARIF JSON: {exc}") from exc
    try:
        return SarifDocument.model_validate(decoded, strict=True)
    except ValidationError as exc:
        raise InvalidSarifError(f"invalid SARIF 2.1.0 structure: {exc}") from exc


def read_sarif_bytes(
    path: str | Path, *, maximum_bytes: int = DEFAULT_MAXIMUM_SARIF_BYTES
) -> bytes:
    """Read a regular SARIF file without following a final symbolic link."""

    if maximum_bytes < 1:
        raise ValueError("maximum_bytes must be positive")
    source = Path(path).expanduser()
    if source.is_symlink():
        raise InvalidSarifError("SARIF input must not be a symbolic link")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise InvalidSarifError(f"cannot open SARIF input {source}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InvalidSarifError("SARIF input must be a regular file")
        if metadata.st_size > maximum_bytes:
            raise InvalidSarifError(f"SARIF input exceeds maximum size ({maximum_bytes} bytes)")
        chunks: list[bytes] = []
        observed = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
            observed += len(chunk)
            if observed > maximum_bytes:
                raise InvalidSarifError(f"SARIF input exceeds maximum size ({maximum_bytes} bytes)")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def ingest_sarif(
    path: str | Path,
    *,
    source_root: str | Path,
    run_id: str,
    repository_identity: str,
    commit_sha: str | None = None,
    maximum_bytes: int = DEFAULT_MAXIMUM_SARIF_BYTES,
) -> AlertBundle:
    """Read, validate, and normalize one SARIF artifact."""

    raw = read_sarif_bytes(path, maximum_bytes=maximum_bytes)
    document = parse_sarif_bytes(raw)
    return SarifNormalizer(source_root).normalize(
        document,
        run_id=run_id,
        repository_identity=repository_identity,
        commit_sha=commit_sha,
        raw_sarif_sha256=hashlib.sha256(raw).hexdigest(),
    )


__all__ = [
    "DEFAULT_MAXIMUM_SARIF_BYTES",
    "ingest_sarif",
    "parse_sarif_bytes",
    "read_sarif_bytes",
]
