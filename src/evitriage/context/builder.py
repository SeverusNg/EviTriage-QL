"""Bounded Java Level 0/1 context extraction from normalized alerts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from evitriage.domain.alerts import AlertBundle, ColumnKind, NormalizedAlert, SourceLocation
from evitriage.domain.context import (
    ContextCandidate,
    ContextOmission,
    ContextOmissionCode,
    ContextPolicyName,
    ContextReference,
    LevelZeroContext,
    SliceArtifact,
    SliceContent,
    SourceSlice,
)
from evitriage.errors import FeatureNotAvailableError, PathSafetyError

_CONTEXT_VERSION: Literal["1.0"] = "1.0"
_DEFAULT_MAXIMUM_SOURCE_BYTES = 1024 * 1024
_DEFAULT_MAXIMUM_TOKEN_BUDGET = 24_000
_CONTROL_KEYWORDS = frozenset(
    {"catch", "do", "else", "for", "if", "new", "switch", "synchronized", "try", "while"}
)
_CONTROL_HEADER_PATTERN = re.compile(
    r"^(?:catch|do|else|finally|for|if|switch|synchronized|try|while)\b"
)
_GUARD_PATTERN = re.compile(r"\b(?:if|switch|while)\s*\(")
_SANITIZER_PATTERN = re.compile(
    r"\b(?:canonicali[sz]e|encode|escape|normalize|sanitize|validate)[A-Za-z0-9_$]*\s*\(",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class _SourceDocument:
    path: str
    text: str
    lines: tuple[str, ...]
    artifact_sha256: str


@dataclass(frozen=True, slots=True)
class _Selection:
    start_line: int
    end_line: int
    selection: Literal["fixed_window", "enclosing_function"]
    enclosing_symbol: str | None
    omission: ContextOmission | None = None


@dataclass(frozen=True, slots=True)
class _ReadFailure:
    code: ContextOmissionCode
    detail: str


class ContextPolicy(Protocol):
    """Select a bounded range from a source document for one location."""

    name: ContextPolicyName

    def select(self, document: _SourceDocument, location: SourceLocation) -> _Selection:
        """Return the selected source range and any precision loss."""


class FixedWindowPolicy:
    """Select a deterministic line window around every referenced location."""

    name: ContextPolicyName = "fixed_window"

    def __init__(self, *, radius: int = 5) -> None:
        if radius < 0 or radius > 100:
            raise ValueError("fixed-window radius must be between 0 and 100")
        self._radius = radius

    def select(self, document: _SourceDocument, location: SourceLocation) -> _Selection:
        return _Selection(
            start_line=max(1, location.start_line - self._radius),
            end_line=min(
                len(document.lines), (location.end_line or location.start_line) + self._radius
            ),
            selection="fixed_window",
            enclosing_symbol=None,
        )


class PathFunctionSlicePolicy:
    """Select the smallest lexical Java callable containing a path location."""

    name: ContextPolicyName = "path_function_slice"

    def __init__(self, *, fallback_radius: int = 5) -> None:
        self._fallback = FixedWindowPolicy(radius=fallback_radius)

    def select(self, document: _SourceDocument, location: SourceLocation) -> _Selection:
        function = _enclosing_java_function(document.text, location.start_line)
        if function is not None:
            start_line, end_line, symbol = function
            return _Selection(
                start_line=start_line,
                end_line=end_line,
                selection="enclosing_function",
                enclosing_symbol=symbol,
            )
        fallback = self._fallback.select(document, location)
        return _Selection(
            start_line=fallback.start_line,
            end_line=fallback.end_line,
            selection=fallback.selection,
            enclosing_symbol=None,
            omission=ContextOmission(
                code="function_boundary_unresolved",
                path=document.path,
                detail=(
                    f"no lexical Java callable enclosed line {location.start_line}; "
                    "a bounded fixed window was retained"
                ),
            ),
        )


class ContextBuilder:
    """Read only normalized locations and safely extract bounded source context."""

    def __init__(
        self,
        source_root: Path,
        *,
        maximum_token_budget: int = _DEFAULT_MAXIMUM_TOKEN_BUDGET,
        maximum_source_bytes: int = _DEFAULT_MAXIMUM_SOURCE_BYTES,
    ) -> None:
        if maximum_token_budget < 1:
            raise ValueError("maximum_token_budget must be positive")
        if maximum_source_bytes < 1:
            raise ValueError("maximum_source_bytes must be positive")
        if not source_root.is_absolute() or source_root.is_symlink():
            raise PathSafetyError("context source root must be an absolute non-symlink directory")
        try:
            canonical_root = source_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PathSafetyError(f"cannot resolve context source root: {source_root}") from exc
        if not canonical_root.is_dir():
            raise PathSafetyError("context source root must be a directory")
        self._source_root = canonical_root
        self._maximum_token_budget = maximum_token_budget
        self._maximum_source_bytes = maximum_source_bytes
        self._cache: dict[str, _SourceDocument | _ReadFailure] = {}

    def build(
        self,
        bundle: AlertBundle,
        *,
        policy_name: str,
    ) -> tuple[SliceArtifact, ...]:
        """Build one context artifact per normalized result occurrence."""

        policy = self._resolve_policy(policy_name)
        return tuple(self._build_alert(alert, policy) for alert in bundle.alerts)

    @staticmethod
    def _resolve_policy(policy_name: str) -> ContextPolicy:
        if policy_name == "fixed_window":
            return FixedWindowPolicy()
        if policy_name == "path_function_slice":
            return PathFunctionSlicePolicy()
        if policy_name == "adaptive_slice":
            raise FeatureNotAvailableError(
                "adaptive_slice is reserved for V0.3+ and is not executable in Gate C",
                details={"context_policy": policy_name},
            )
        raise FeatureNotAvailableError(
            "unknown context policy",
            details={"context_policy": policy_name},
        )

    def _build_alert(self, alert: NormalizedAlert, policy: ContextPolicy) -> SliceArtifact:
        level_zero = LevelZeroContext(
            rule=alert.rule,
            message=alert.message,
            primary_location=alert.primary_location,
            additional_locations=alert.additional_locations,
            related_locations=alert.related_locations,
            paths=alert.paths,
        )
        level_zero_text = json.dumps(
            level_zero.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        references = _alert_references(alert)
        omissions: list[ContextOmission] = []
        selected: dict[
            tuple[str, int, int, str],
            tuple[_SourceDocument, _Selection, list[ContextReference]],
        ] = {}
        for reference in references:
            observed = self._read_source(reference.location.path)
            if isinstance(observed, _ReadFailure):
                omissions.append(
                    ContextOmission(
                        code=observed.code,
                        path=reference.location.path,
                        detail=observed.detail,
                    )
                )
                continue
            coordinate_error = _coordinate_error(observed, reference.location)
            if coordinate_error is not None:
                omissions.append(
                    ContextOmission(
                        code="coordinate_out_of_bounds",
                        path=reference.location.path,
                        detail=coordinate_error,
                    )
                )
                continue
            if (
                reference.location.artifact_sha256 is not None
                and reference.location.artifact_sha256 != observed.artifact_sha256
            ):
                omissions.append(
                    ContextOmission(
                        code="source_digest_mismatch",
                        path=reference.location.path,
                        detail="normalized source digest no longer matches the snapshot file",
                    )
                )
                continue
            selection = policy.select(observed, reference.location)
            if selection.omission is not None:
                omissions.append(selection.omission)
            key = (
                observed.path,
                selection.start_line,
                selection.end_line,
                selection.selection,
            )
            existing = selected.get(key)
            if existing is None:
                selected[key] = (observed, selection, [reference])
            else:
                existing[2].append(reference)

        source_slices: list[SourceSlice] = []
        token_estimate = _estimate_tokens(level_zero_text)
        if token_estimate > self._maximum_token_budget:
            omissions.append(
                ContextOmission(
                    code="token_budget_exceeded",
                    path=alert.primary_location.path,
                    detail=(
                        f"Level 0 metadata alone estimates {token_estimate} tokens, exceeding "
                        f"the {self._maximum_token_budget}-token budget"
                    ),
                )
            )
        for document, selection, slice_references in selected.values():
            content = "".join(document.lines[selection.start_line - 1 : selection.end_line])
            estimated = _estimate_tokens(content)
            if token_estimate + estimated > self._maximum_token_budget:
                omissions.append(
                    ContextOmission(
                        code="token_budget_exceeded",
                        path=document.path,
                        detail=(
                            f"omitted lines {selection.start_line}-{selection.end_line}; "
                            f"estimated {estimated} tokens with "
                            f"{max(0, self._maximum_token_budget - token_estimate)} "
                            "remaining"
                        ),
                    )
                )
                continue
            source_slices.append(
                _source_slice(
                    document,
                    selection=selection,
                    content=content,
                    references=tuple(slice_references),
                )
            )
            token_estimate += estimated

        guards, sanitizers = _lexical_candidates(tuple(source_slices))
        content_model = SliceContent(
            alert_fingerprint=alert.alert_fingerprint,
            raw_result_reference=alert.raw_result_reference,
            context_policy=policy.name,
            context_version=_CONTEXT_VERSION,
            level_zero=level_zero,
            source_slices=tuple(source_slices),
            guards=guards,
            candidate_sanitizers=sanitizers,
            token_estimate=token_estimate,
            maximum_token_budget=self._maximum_token_budget,
            completeness="partial" if omissions else "complete",
            omitted=tuple(_deduplicate_omissions(omissions)),
        )
        serialized = json.dumps(
            content_model.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return SliceArtifact(
            slice_sha256=hashlib.sha256(serialized).hexdigest(),
            content=content_model,
        )

    def _read_source(self, relative_path: str) -> _SourceDocument | _ReadFailure:
        cached = self._cache.get(relative_path)
        if cached is not None:
            return cached
        target = self._source_root.joinpath(*relative_path.split("/"))
        current = self._source_root
        for component in relative_path.split("/"):
            current /= component
            if current.is_symlink():
                failure = _ReadFailure("source_not_regular", "source path crosses a symbolic link")
                self._cache[relative_path] = failure
                return failure
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags)
        except FileNotFoundError:
            failure = _ReadFailure("source_file_missing", "referenced snapshot file is absent")
            self._cache[relative_path] = failure
            return failure
        except OSError as exc:
            failure = _ReadFailure("source_not_regular", f"cannot safely open source file: {exc}")
            self._cache[relative_path] = failure
            return failure
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                result: _SourceDocument | _ReadFailure = _ReadFailure(
                    "source_not_regular", "referenced source is not a regular file"
                )
            elif metadata.st_size > self._maximum_source_bytes:
                result = _ReadFailure(
                    "source_too_large",
                    f"source size {metadata.st_size} exceeds {self._maximum_source_bytes} bytes",
                )
            else:
                chunks: list[bytes] = []
                remaining = self._maximum_source_bytes + 1
                while remaining > 0 and (chunk := os.read(descriptor, min(1024 * 1024, remaining))):
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                if len(raw) > self._maximum_source_bytes:
                    result = _ReadFailure("source_too_large", "source grew beyond its size limit")
                elif b"\x00" in raw:
                    result = _ReadFailure("binary_source", "NUL byte marks source as binary")
                else:
                    try:
                        # SARIF text coordinates do not count an encoding BOM.
                        # utf-8-sig accepts ordinary UTF-8 unchanged and removes
                        # only a leading UTF-8 BOM from coordinate/content text.
                        text = raw.decode("utf-8-sig", errors="strict")
                    except UnicodeDecodeError:
                        result = _ReadFailure(
                            "unsupported_encoding", "Gate C accepts UTF-8 source text only"
                        )
                    else:
                        lines = tuple(text.splitlines(keepends=True))
                        if not lines:
                            lines = ("",)
                        result = _SourceDocument(
                            path=relative_path,
                            text=text,
                            lines=lines,
                            artifact_sha256=hashlib.sha256(raw).hexdigest(),
                        )
        finally:
            os.close(descriptor)
        self._cache[relative_path] = result
        return result


def _alert_references(alert: NormalizedAlert) -> tuple[ContextReference, ...]:
    references: list[ContextReference] = [
        ContextReference(kind="primary", location=alert.primary_location)
    ]
    references.extend(
        ContextReference(kind="additional", location=location)
        for location in alert.additional_locations
    )
    references.extend(
        ContextReference(kind="related", location=location) for location in alert.related_locations
    )
    for path in alert.paths:
        for step in path.steps:
            kind: Literal["source", "sink", "path_step"]
            if step.index == 0:
                kind = "source"
            elif step.index == len(path.steps) - 1:
                kind = "sink"
            else:
                kind = "path_step"
            references.append(
                ContextReference(
                    kind=kind,
                    location=step.location,
                    path_ordinal=path.ordinal,
                    step_index=step.index,
                )
            )
    return tuple(references)


def _coordinate_error(document: _SourceDocument, location: SourceLocation) -> str | None:
    line_count = len(document.lines)
    end_line = location.end_line or location.start_line
    if location.start_line > line_count or end_line > line_count:
        return (
            f"declared lines {location.start_line}-{end_line} exceed file line count {line_count}"
        )
    start_length = _column_length(
        document.lines[location.start_line - 1].rstrip("\r\n"), location.column_kind
    )
    if location.start_column > start_length + 1:
        return (
            f"declared start column {location.start_column} exceeds line length "
            f"{start_length} {location.column_kind}"
        )
    if location.end_column is not None:
        end_length = _column_length(
            document.lines[end_line - 1].rstrip("\r\n"), location.column_kind
        )
        if location.end_column > end_length + 1:
            return (
                f"declared end column {location.end_column} exceeds line length "
                f"{end_length} {location.column_kind}"
            )
    return None


def _column_length(content: str, column_kind: ColumnKind) -> int:
    if column_kind == "utf16CodeUnits":
        return len(content.encode("utf-16-le")) // 2
    return len(content)


def _source_slice(
    document: _SourceDocument,
    *,
    selection: _Selection,
    content: str,
    references: tuple[ContextReference, ...],
) -> SourceSlice:
    content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
    identity = {
        "artifact_sha256": document.artifact_sha256,
        "content_sha256": content_sha256,
        "end_line": selection.end_line,
        "path": document.path,
        "selection": selection.selection,
        "start_line": selection.start_line,
    }
    slice_id = (
        "slice_"
        + hashlib.sha256(
            json.dumps(identity, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()
    )
    return SourceSlice(
        slice_id=slice_id,
        selection=selection.selection,
        path=document.path,
        start_line=selection.start_line,
        end_line=selection.end_line,
        artifact_sha256=document.artifact_sha256,
        content_sha256=content_sha256,
        content=content,
        enclosing_symbol=selection.enclosing_symbol,
        references=references,
    )


def _estimate_tokens(content: str) -> int:
    if not content:
        return 0
    return max(1, (len(content.encode("utf-8")) + 3) // 4)


def _deduplicate_omissions(omissions: list[ContextOmission]) -> list[ContextOmission]:
    observed: set[tuple[str, str, str]] = set()
    result: list[ContextOmission] = []
    for omission in omissions:
        identity = (omission.code, omission.path, omission.detail)
        if identity not in observed:
            observed.add(identity)
            result.append(omission)
    return result


def _lexical_candidates(
    slices: tuple[SourceSlice, ...],
) -> tuple[tuple[ContextCandidate, ...], tuple[ContextCandidate, ...]]:
    guards: list[ContextCandidate] = []
    sanitizers: list[ContextCandidate] = []
    observed: set[tuple[str, int, str]] = set()
    for source_slice in slices:
        sanitized = _strip_java_comments_and_literals(source_slice.content)
        original_lines = source_slice.content.splitlines()
        sanitized_lines = sanitized.splitlines()
        for offset, sanitized_line in enumerate(sanitized_lines):
            line_number = source_slice.start_line + offset
            excerpt = original_lines[offset].strip() if offset < len(original_lines) else ""
            if not excerpt:
                continue
            patterns: tuple[tuple[Literal["guard", "sanitizer"], re.Pattern[str]], ...] = (
                ("guard", _GUARD_PATTERN),
                ("sanitizer", _SANITIZER_PATTERN),
            )
            for kind, pattern in patterns:
                if pattern.search(sanitized_line) is None:
                    continue
                identity = (source_slice.path, line_number, kind)
                if identity in observed:
                    continue
                observed.add(identity)
                candidate = ContextCandidate(
                    kind=kind,
                    location=SourceLocation(
                        path=source_slice.path,
                        column_kind="unicodeCodePoints",
                        start_line=line_number,
                        start_column=1,
                        end_line=line_number,
                        end_column=len(original_lines[offset].rstrip("\r\n")) + 1,
                        artifact_sha256=source_slice.artifact_sha256,
                    ),
                    excerpt=excerpt,
                )
                (guards if kind == "guard" else sanitizers).append(candidate)
    return tuple(guards), tuple(sanitizers)


def _enclosing_java_function(text: str, target_line: int) -> tuple[int, int, str] | None:
    sanitized = _strip_java_comments_and_literals(text)
    line_starts = [0]
    line_starts.extend(match.end() for match in re.finditer("\n", sanitized))

    def line_number(offset: int) -> int:
        # Number of newlines before offset plus one.  Files are deliberately
        # bounded, so this simple search keeps the extractor dependency-free.
        low = 0
        high = len(line_starts)
        while low < high:
            middle = (low + high) // 2
            if line_starts[middle] <= offset:
                low = middle + 1
            else:
                high = middle
        return low

    stack: list[int] = []
    candidates: list[tuple[int, int, str]] = []
    for offset, character in enumerate(sanitized):
        if character == "{":
            stack.append(offset)
            continue
        if character != "}" or not stack:
            continue
        opening = stack.pop()
        delimiter = max(
            sanitized.rfind(";", 0, opening),
            sanitized.rfind("{", 0, opening),
            sanitized.rfind("}", 0, opening),
        )
        header_start = delimiter + 1
        while header_start < opening and sanitized[header_start].isspace():
            header_start += 1
        header = " ".join(sanitized[header_start:opening].split())
        if _CONTROL_HEADER_PATTERN.match(header):
            continue
        names = re.findall(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*\(", header)
        if not names:
            continue
        symbol = names[-1]
        if symbol in _CONTROL_KEYWORDS or "->" in header:
            continue
        if re.search(r"\b(?:class|enum|interface|record)\b", header):
            continue
        start_line = line_number(header_start)
        end_line = line_number(offset)
        if start_line <= target_line <= end_line:
            candidates.append((start_line, end_line, symbol))
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item[1] - item[0], item[0], item[2]))


def _strip_java_comments_and_literals(text: str) -> str:
    output = list(text)
    index = 0
    state = "code"
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if character == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line_comment"
                continue
            if character == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block_comment"
                continue
            if text.startswith('"""', index):
                output[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "text_block"
                continue
            if character == '"':
                output[index] = " "
                index += 1
                state = "string"
                continue
            if character == "'":
                output[index] = " "
                index += 1
                state = "character"
                continue
            index += 1
            continue
        if character == "\n":
            if state == "line_comment":
                state = "code"
            index += 1
            continue
        output[index] = " "
        if state == "block_comment" and character == "*" and following == "/":
            output[index + 1] = " "
            index += 2
            state = "code"
        elif state == "text_block" and text.startswith('"""', index):
            output[index : index + 3] = [" ", " ", " "]
            index += 3
            state = "code"
        elif state in {"string", "character"} and character == "\\":
            if index + 1 < len(text):
                output[index + 1] = " " if text[index + 1] != "\n" else "\n"
            index += 2
        elif (state == "string" and character == '"') or (
            state == "character" and character == "'"
        ):
            index += 1
            state = "code"
        else:
            index += 1
    return "".join(output)


__all__ = [
    "ContextBuilder",
    "ContextPolicy",
    "FixedWindowPolicy",
    "PathFunctionSlicePolicy",
]
