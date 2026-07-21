"""Deterministic normalization of untrusted SARIF 2.1.0 results."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from evitriage.domain.alerts import (
    AlertBundle,
    DataFlowPath,
    JsonValue,
    NormalizedAlert,
    PathStep,
    RawResultReference,
    RuleMetadata,
    SourceLocation,
)
from evitriage.sarif.errors import InvalidSarifError, UnsafeSarifUriError
from evitriage.sarif.raw_models import (
    Artifact,
    ArtifactLocation,
    Location,
    Message,
    ReportingDescriptor,
    Result,
    Run,
    SarifDocument,
    ToolComponent,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FULL_COMMIT = re.compile(r"^[0-9a-fA-F]{40}$")
_WINDOWS_DRIVE = re.compile(r"^/?([A-Za-z]):(?:/|$)")
_BAD_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_CWE = re.compile(r"(?i)(?:^|[/_-])cwe[-/](?:cwe-)?0*([1-9][0-9]*)(?:$|[/_-])")
_HASH_DOMAIN_PATH = b"EviTriage-QL normalized SARIF path v1\0"
_HASH_DOMAIN_ALERT = b"EviTriage-QL normalized SARIF alert v1\0"
_MAXIMUM_URI_BASE_DEPTH = 64


@dataclass(frozen=True, slots=True)
class _UriPath:
    flavor: Literal["posix", "windows"]
    absolute: bool
    parts: tuple[str, ...]
    drive: str | None = None


@dataclass(frozen=True, slots=True)
class _BasePath:
    path: _UriPath
    absolute_anchor: _UriPath | None


def _message_text(message: Message | None) -> str | None:
    if message is None:
        return None
    return message.text if message.text is not None else message.markdown


def _stable_sha256(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(domain)
    digest.update(encoded)
    return digest.hexdigest()


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise InvalidSarifError("SARIF properties contain a non-finite number")
        return value
    if isinstance(value, list):
        return [_json_value(item) for item in value]
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        return {key: _json_value(item) for key, item in value.items()}
    raise InvalidSarifError("SARIF properties contain a non-JSON value")


def _json_properties(value: dict[str, object]) -> dict[str, JsonValue]:
    return {key: _json_value(item) for key, item in value.items()}


class _LocationResolver:
    """Map SARIF URIs into a configured snapshot without dereferencing URI paths."""

    def __init__(self, source_root: Path, run: Run) -> None:
        supplied_root = source_root.expanduser()
        if supplied_root.is_symlink():
            raise UnsafeSarifUriError("source_root must not be a symbolic link")
        try:
            self._source_root = supplied_root.resolve(strict=True)
        except OSError as exc:
            raise UnsafeSarifUriError(f"source_root is unavailable: {supplied_root}") from exc
        if not self._source_root.is_dir():
            raise UnsafeSarifUriError(f"source_root is not a directory: {self._source_root}")
        self._run = run
        self._base_cache: dict[str, _BasePath] = {}
        self._hash_cache: dict[str, str | None] = {}

    def source_location(
        self,
        location: Location,
        *,
        related_by_id: dict[int, Location],
    ) -> SourceLocation:
        resolved_location = location
        if resolved_location.physical_location is None:
            if resolved_location.id is None or resolved_location.id not in related_by_id:
                raise InvalidSarifError("SARIF location has no physicalLocation")
            resolved_location = related_by_id[resolved_location.id]
        physical = resolved_location.physical_location
        if physical is None or physical.artifact_location is None:
            raise InvalidSarifError("SARIF physicalLocation has no artifactLocation")
        region = physical.region
        if region is None or region.start_line is None:
            raise InvalidSarifError("SARIF source region requires startLine")

        artifact_location, artifact = self._artifact_location(physical.artifact_location)
        relative_path = self._relative_source_path(artifact_location)
        artifact_sha256 = self._verified_artifact_sha256(relative_path, artifact)
        snippet_message = region.snippet
        if snippet_message is None and physical.context_region is not None:
            snippet_message = physical.context_region.snippet
        try:
            return SourceLocation(
                path=relative_path,
                start_line=region.start_line,
                start_column=region.start_column if region.start_column is not None else 1,
                end_line=region.end_line,
                end_column=region.end_column,
                artifact_sha256=artifact_sha256,
                snippet=_message_text(snippet_message),
            )
        except ValidationError as exc:
            raise InvalidSarifError(f"invalid SARIF source region: {exc}") from exc

    def _artifact_location(
        self, location: ArtifactLocation
    ) -> tuple[ArtifactLocation, Artifact | None]:
        artifact: Artifact | None = None
        if location.index is not None:
            if location.index >= len(self._run.artifacts):
                raise InvalidSarifError(f"artifactLocation index {location.index} is out of range")
            artifact = self._run.artifacts[location.index]
        if location.uri is not None:
            return location, artifact
        if artifact is None or artifact.location is None or artifact.location.uri is None:
            raise InvalidSarifError("artifactLocation requires uri or a valid artifact index")
        base_id = location.uri_base_id or artifact.location.uri_base_id
        return ArtifactLocation(uri=artifact.location.uri, uri_base_id=base_id), artifact

    @staticmethod
    def _asserted_artifact_sha256(artifact: Artifact | None) -> str | None:
        if artifact is None:
            return None
        for key, value in artifact.hashes.items():
            if key.lower().replace("_", "-") in {"sha-256", "sha256"}:
                lowered = value.lower()
                if _SHA256.fullmatch(lowered):
                    return lowered
        return None

    def _verified_artifact_sha256(
        self, relative_path: str, artifact: Artifact | None
    ) -> str | None:
        """Hash an existing snapshot file and reject a conflicting SARIF assertion."""

        if relative_path in self._hash_cache:
            observed = self._hash_cache[relative_path]
        else:
            candidate = self._source_root.joinpath(*relative_path.split("/"))
            self._reject_snapshot_symlinks(candidate)
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(candidate, flags)
            except FileNotFoundError:
                observed = None
            except OSError as exc:
                raise UnsafeSarifUriError(
                    f"cannot inspect SARIF source artifact: {relative_path!r}"
                ) from exc
            else:
                try:
                    metadata = os.fstat(descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise UnsafeSarifUriError(
                            f"SARIF source artifact is not a regular file: {relative_path!r}"
                        )
                    digest = hashlib.sha256()
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                except OSError as exc:
                    raise UnsafeSarifUriError(
                        f"cannot hash SARIF source artifact: {relative_path!r}"
                    ) from exc
                finally:
                    os.close(descriptor)
                observed = digest.hexdigest()
            self._hash_cache[relative_path] = observed

        asserted = self._asserted_artifact_sha256(artifact)
        if asserted is not None and observed is not None and asserted != observed:
            raise InvalidSarifError(
                f"SARIF artifact SHA-256 does not match the source snapshot: {relative_path!r}"
            )
        return observed

    def _relative_source_path(self, location: ArtifactLocation) -> str:
        if location.uri is None:
            raise InvalidSarifError("artifactLocation URI is missing")
        child = self._parse_uri(location.uri)
        anchor: _UriPath | None = None
        if location.uri_base_id is not None:
            base = self._resolve_base(location.uri_base_id, active=())
            child = self._join(base.path, child)
            anchor = base.absolute_anchor

        if child.absolute:
            if anchor is not None:
                relative_parts = self._relative_parts(child, anchor)
            elif child.flavor == "posix":
                source_anchor = self._parse_uri(self._source_root.as_posix())
                relative_parts = self._relative_parts(child, source_anchor)
            else:
                raise UnsafeSarifUriError(
                    "absolute Windows URI requires a declared source URI base"
                )
        else:
            relative_parts = child.parts
        if not relative_parts:
            raise UnsafeSarifUriError("SARIF URI resolves to the source root, not a file")

        candidate = self._source_root.joinpath(*relative_parts)
        self._reject_snapshot_symlinks(candidate)
        try:
            candidate.resolve(strict=False).relative_to(self._source_root)
        except (OSError, ValueError) as exc:
            raise UnsafeSarifUriError(
                f"SARIF URI escapes the configured source snapshot: {location.uri!r}"
            ) from exc
        return "/".join(relative_parts)

    def _resolve_base(self, base_id: str, *, active: tuple[str, ...]) -> _BasePath:
        if len(active) >= _MAXIMUM_URI_BASE_DEPTH:
            raise InvalidSarifError(
                f"SARIF uriBaseId chain exceeds maximum depth ({_MAXIMUM_URI_BASE_DEPTH})"
            )
        if base_id in self._base_cache:
            return self._base_cache[base_id]
        if base_id in active:
            raise InvalidSarifError(f"cyclic SARIF uriBaseId reference: {base_id!r}")
        if base_id not in self._run.original_uri_base_ids:
            raise InvalidSarifError(f"unknown SARIF uriBaseId: {base_id!r}")
        location = self._run.original_uri_base_ids[base_id]
        if location.uri is None:
            raise InvalidSarifError(f"SARIF URI base {base_id!r} has no uri")
        path = self._parse_uri(location.uri)
        anchor: _UriPath | None = path if path.absolute else None
        if location.uri_base_id is not None:
            parent = self._resolve_base(location.uri_base_id, active=(*active, base_id))
            path = self._join(parent.path, path)
            anchor = parent.absolute_anchor
        value = _BasePath(path=path, absolute_anchor=anchor)
        self._base_cache[base_id] = value
        return value

    @staticmethod
    def _parse_uri(value: str) -> _UriPath:
        if not value or _BAD_PERCENT_ESCAPE.search(value):
            raise UnsafeSarifUriError(f"invalid SARIF URI: {value!r}")
        normalized_input = value.replace("\\", "/")
        is_windows_path = _WINDOWS_DRIVE.match(normalized_input) is not None
        try:
            parsed = urlsplit(normalized_input if not is_windows_path else "")
        except ValueError as exc:
            raise UnsafeSarifUriError(f"invalid SARIF URI: {value!r}") from exc
        if is_windows_path:
            raw_path = normalized_input
        else:
            if parsed.scheme not in {"", "file"}:
                raise UnsafeSarifUriError(f"SARIF URI scheme is not allowed: {parsed.scheme!r}")
            if parsed.query or parsed.fragment:
                raise UnsafeSarifUriError("SARIF source URI must not contain query or fragment")
            if (parsed.scheme == "" and parsed.netloc) or (
                parsed.scheme == "file" and parsed.netloc not in {"", "localhost"}
            ):
                raise UnsafeSarifUriError("remote/UNC file URI authorities are not allowed")
            raw_path = parsed.path
        try:
            decoded = unquote(raw_path, encoding="utf-8", errors="strict").replace("\\", "/")
        except UnicodeError as exc:
            raise UnsafeSarifUriError(f"SARIF URI is not valid UTF-8: {value!r}") from exc
        if any(ord(character) < 32 or ord(character) == 127 for character in decoded):
            raise UnsafeSarifUriError("SARIF URI contains control characters")

        drive_match = _WINDOWS_DRIVE.match(decoded)
        drive = drive_match.group(1).upper() if drive_match else None
        if drive_match:
            flavor: Literal["posix", "windows"] = "windows"
            absolute = decoded.startswith(
                (f"{drive_match.group(1)}:/", f"/{drive_match.group(1)}:/")
            )
            path_without_root = decoded[drive_match.end() :]
        else:
            flavor = "posix"
            absolute = decoded.startswith("/")
            path_without_root = decoded.lstrip("/")
        parts: list[str] = []
        for part in path_without_root.split("/"):
            if part in {"", "."}:
                continue
            if part == "..":
                raise UnsafeSarifUriError("SARIF URI contains parent traversal")
            if ":" in part:
                raise UnsafeSarifUriError("SARIF URI contains an unsafe colon")
            parts.append(part)
        return _UriPath(flavor=flavor, absolute=absolute, parts=tuple(parts), drive=drive)

    @staticmethod
    def _join(base: _UriPath, child: _UriPath) -> _UriPath:
        if child.absolute:
            return child
        return _UriPath(
            flavor=base.flavor,
            absolute=base.absolute,
            parts=(*base.parts, *child.parts),
            drive=base.drive,
        )

    @staticmethod
    def _relative_parts(path: _UriPath, anchor: _UriPath) -> tuple[str, ...]:
        if (
            not path.absolute
            or not anchor.absolute
            or path.flavor != anchor.flavor
            or path.drive != anchor.drive
            or path.parts[: len(anchor.parts)] != anchor.parts
        ):
            raise UnsafeSarifUriError("SARIF URI is outside its declared source base")
        return path.parts[len(anchor.parts) :]

    def _reject_snapshot_symlinks(self, candidate: Path) -> None:
        current = self._source_root
        relative = candidate.relative_to(self._source_root)
        for part in relative.parts:
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                return
            except OSError as exc:
                raise UnsafeSarifUriError(
                    f"cannot inspect source path component: {current}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise UnsafeSarifUriError(f"SARIF URI traverses a symbolic link: {current}")


class SarifNormalizer:
    """Normalize a parsed SARIF document into immutable alert domain records."""

    def __init__(
        self,
        source_root: str | Path,
        *,
        maximum_results: int = 100_000,
        maximum_path_steps: int = 100_000,
    ) -> None:
        if maximum_results < 1 or maximum_path_steps < 1:
            raise ValueError("SARIF normalization limits must be positive")
        self._source_root = Path(source_root)
        self._maximum_results = maximum_results
        self._maximum_path_steps = maximum_path_steps

    def normalize(
        self,
        document: SarifDocument,
        *,
        run_id: str,
        repository_identity: str,
        raw_sarif_sha256: str,
        commit_sha: str | None = None,
    ) -> AlertBundle:
        """Normalize all results from all runs without deduplicating occurrences."""

        if not _SHA256.fullmatch(raw_sarif_sha256):
            raise InvalidSarifError("raw_sarif_sha256 must be a lowercase SHA-256 digest")
        normalized_commit = commit_sha.lower() if commit_sha is not None else None
        if normalized_commit is not None and not _FULL_COMMIT.fullmatch(normalized_commit):
            raise InvalidSarifError("commit_sha must be a full 40-character Git SHA")
        result_count = sum(len(run.results) for run in document.runs)
        if result_count > self._maximum_results:
            raise InvalidSarifError(f"SARIF exceeds maximum result count ({self._maximum_results})")

        alerts: list[NormalizedAlert] = []
        path_step_count = 0
        for run_index, sarif_run in enumerate(document.runs):
            resolver = _LocationResolver(self._source_root, sarif_run)
            rules_by_id = self._rules_by_id(sarif_run.tool.driver)
            for result_index, result in enumerate(sarif_run.results):
                rule_descriptor = self._resolve_rule(result, sarif_run.tool.driver, rules_by_id)
                related_by_id = self._related_by_id(result)
                locations = tuple(
                    resolver.source_location(location, related_by_id=related_by_id)
                    for location in result.locations
                )
                if not locations:
                    raise InvalidSarifError(
                        f"result {run_index}:{result_index} has no physical location"
                    )
                related_locations = tuple(
                    resolver.source_location(location, related_by_id=related_by_id)
                    for location in result.related_locations
                )
                try:
                    paths, added_steps = self._normalize_paths(
                        result, resolver=resolver, related_by_id=related_by_id
                    )
                except ValidationError as exc:
                    raise InvalidSarifError(
                        f"invalid path in result {run_index}:{result_index}: {exc}"
                    ) from exc
                path_step_count += added_steps
                if path_step_count > self._maximum_path_steps:
                    raise InvalidSarifError(
                        f"SARIF exceeds maximum path step count ({self._maximum_path_steps})"
                    )
                fingerprints = self._fingerprints(result.fingerprints, "fingerprint")
                partial_fingerprints = self._fingerprints(
                    result.partial_fingerprints, "partial fingerprint"
                )
                rule = self._rule_metadata(
                    descriptor=rule_descriptor,
                    driver=sarif_run.tool.driver,
                    result=result,
                )
                message = _message_text(result.message)
                if not message:
                    raise InvalidSarifError(
                        f"result {run_index}:{result_index} has an empty message"
                    )
                alert_payload = {
                    "rule_id": rule.rule_id,
                    "message": message,
                    "primary_location": locations[0].model_dump(mode="json"),
                    "fingerprints": fingerprints,
                    "partial_fingerprints": partial_fingerprints,
                    "path_fingerprints": [path.path_fingerprint for path in paths],
                }
                try:
                    alert = NormalizedAlert(
                        run_id=run_id,
                        repository_identity=repository_identity,
                        commit_sha=normalized_commit,
                        rule=rule,
                        message=message,
                        level=result.level or rule.severity,
                        primary_location=locations[0],
                        additional_locations=locations[1:],
                        related_locations=related_locations,
                        paths=paths,
                        has_code_flows=bool(result.code_flows),
                        fingerprints=fingerprints,
                        partial_fingerprints=partial_fingerprints,
                        result_properties=_json_properties(result.properties),
                        alert_fingerprint=_stable_sha256(_HASH_DOMAIN_ALERT, alert_payload),
                        raw_result_reference=RawResultReference(
                            raw_sarif_sha256=raw_sarif_sha256,
                            run_index=run_index,
                            result_index=result_index,
                        ),
                    )
                except (ValidationError, ValueError, TypeError) as exc:
                    raise InvalidSarifError(
                        f"result {run_index}:{result_index} cannot be normalized: {exc}"
                    ) from exc
                alerts.append(alert)
        try:
            return AlertBundle(
                run_id=run_id,
                repository_identity=repository_identity,
                commit_sha=normalized_commit,
                raw_sarif_sha256=raw_sarif_sha256,
                alerts=tuple(alerts),
            )
        except ValidationError as exc:
            raise InvalidSarifError(f"invalid alert bundle metadata: {exc}") from exc

    @staticmethod
    def _rules_by_id(driver: ToolComponent) -> dict[str, ReportingDescriptor]:
        rules: dict[str, ReportingDescriptor] = {}
        for rule in driver.rules:
            if rule.id in rules:
                raise InvalidSarifError(f"duplicate SARIF rule id: {rule.id!r}")
            rules[rule.id] = rule
        return rules

    @staticmethod
    def _resolve_rule(
        result: Result,
        driver: ToolComponent,
        rules_by_id: dict[str, ReportingDescriptor],
    ) -> ReportingDescriptor:
        indexed: ReportingDescriptor | None = None
        if result.rule_index is not None:
            if result.rule_index >= len(driver.rules):
                raise InvalidSarifError(f"result ruleIndex {result.rule_index} is out of range")
            indexed = driver.rules[result.rule_index]
        if result.rule_id is not None and indexed is not None and indexed.id != result.rule_id:
            raise InvalidSarifError("result ruleId and ruleIndex resolve to different rules")
        if result.rule_id is not None:
            return rules_by_id.get(result.rule_id) or ReportingDescriptor(id=result.rule_id)
        if indexed is not None:
            return indexed
        raise InvalidSarifError("SARIF result requires ruleId or ruleIndex")

    @staticmethod
    def _related_by_id(result: Result) -> dict[int, Location]:
        related: dict[int, Location] = {}
        for location in result.related_locations:
            if location.id is None:
                continue
            if location.id in related:
                raise InvalidSarifError(f"duplicate relatedLocation id: {location.id}")
            related[location.id] = location
        return related

    def _normalize_paths(
        self,
        result: Result,
        *,
        resolver: _LocationResolver,
        related_by_id: dict[int, Location],
    ) -> tuple[tuple[DataFlowPath, ...], int]:
        paths: list[DataFlowPath] = []
        step_count = 0
        for code_flow in result.code_flows:
            if not code_flow.thread_flows:
                raise InvalidSarifError("codeFlow contains no threadFlows")
            for thread_flow in code_flow.thread_flows:
                if not thread_flow.locations:
                    raise InvalidSarifError("threadFlow contains no threadFlowLocations")
                steps: list[PathStep] = []
                final_index = len(thread_flow.locations) - 1
                for index, raw_step in enumerate(thread_flow.locations):
                    kinds = tuple(raw_step.kinds)
                    steps.append(
                        PathStep(
                            index=index,
                            location=resolver.source_location(
                                raw_step.location, related_by_id=related_by_id
                            ),
                            message=_message_text(raw_step.location.message),
                            step_kind=self._step_kind(kinds, index, final_index),
                            kinds=kinds,
                            nesting_level=raw_step.nesting_level,
                            execution_order=raw_step.execution_order,
                            importance=raw_step.importance,
                        )
                    )
                step_count += len(steps)
                fingerprint_payload = [
                    {
                        "location": step.location.model_dump(mode="json"),
                        "message": step.message,
                        "kinds": step.kinds,
                        "step_kind": step.step_kind,
                    }
                    for step in steps
                ]
                paths.append(
                    DataFlowPath(
                        ordinal=len(paths),
                        steps=tuple(steps),
                        path_fingerprint=_stable_sha256(_HASH_DOMAIN_PATH, fingerprint_payload),
                        completeness="complete" if len(steps) >= 2 else "partial",
                        message=_message_text(thread_flow.message)
                        or _message_text(code_flow.message),
                    )
                )
        return tuple(paths), step_count

    @staticmethod
    def _step_kind(
        kinds: tuple[str, ...], index: int, final_index: int
    ) -> Literal["source", "sink", "intermediate", "unknown"]:
        lowered = {kind.lower() for kind in kinds}
        if "source" in lowered:
            return "source"
        if "sink" in lowered:
            return "sink"
        if index == 0:
            return "source"
        if index == final_index:
            return "sink"
        return "intermediate" if final_index > 0 else "unknown"

    @staticmethod
    def _fingerprints(values: dict[str, str], label: str) -> dict[str, str]:
        fingerprints: dict[str, str] = {}
        for key, value in sorted(values.items()):
            if not key or not value:
                raise InvalidSarifError(f"{label} keys and values must be non-empty")
            if any(ord(character) < 32 or ord(character) == 127 for character in key + value):
                raise InvalidSarifError(f"{label} contains control characters")
            fingerprints[key] = value
        return fingerprints

    @staticmethod
    def _rule_metadata(
        *,
        descriptor: ReportingDescriptor,
        driver: ToolComponent,
        result: Result,
    ) -> RuleMetadata:
        tags_value = descriptor.properties.get("tags", ())
        tags = (
            tuple(value for value in tags_value if isinstance(value, str))
            if isinstance(tags_value, (list, tuple))
            else ()
        )
        cwes: set[str] = set()
        for tag in tags:
            match = _CWE.search(f"/{tag}/")
            if match:
                cwes.add(f"CWE-{int(match.group(1))}")
        severity = result.level
        if severity is None and descriptor.default_configuration is not None:
            severity = descriptor.default_configuration.level
        if severity is None:
            candidate = descriptor.properties.get("problem.severity")
            severity = candidate if isinstance(candidate, str) and candidate else None
        security_severity = SarifNormalizer._security_severity(
            descriptor.properties.get("security-severity")
        )
        description = _message_text(descriptor.full_description) or _message_text(
            descriptor.short_description
        )
        try:
            return RuleMetadata(
                rule_id=descriptor.id,
                name=descriptor.name,
                description=description,
                cwe_ids=tuple(sorted(cwes, key=lambda value: int(value[4:]))),
                severity=severity,
                security_severity=security_severity,
                query_help_uri=descriptor.help_uri,
                # SARIF's tool driver identifies CodeQL itself, not the query
                # pack that produced a result.  Preserve unknown provenance as
                # null rather than fabricating a pack identity from CLI data.
                query_pack=None,
                query_pack_version=None,
                tags=tuple(sorted(set(tags))),
            )
        except ValidationError as exc:
            raise InvalidSarifError(f"invalid SARIF rule metadata: {exc}") from exc

    @staticmethod
    def _security_severity(value: object) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float, str)):
            try:
                parsed = float(value)
            except ValueError:
                return None
            if math.isfinite(parsed) and 0 <= parsed <= 10:
                return parsed
        return None


__all__ = ["SarifNormalizer"]
