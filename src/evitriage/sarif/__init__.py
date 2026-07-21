"""Strict SARIF 2.1.0 ingestion and deterministic normalization."""

from evitriage.sarif.errors import InvalidSarifError, UnsafeSarifUriError
from evitriage.sarif.ingest import ingest_sarif, parse_sarif_bytes, read_sarif_bytes
from evitriage.sarif.normalizer import SarifNormalizer
from evitriage.sarif.raw_models import SarifDocument

__all__ = [
    "InvalidSarifError",
    "SarifDocument",
    "SarifNormalizer",
    "UnsafeSarifUriError",
    "ingest_sarif",
    "parse_sarif_bytes",
    "read_sarif_bytes",
]
