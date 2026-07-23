"""Provider-neutral structured LLM protocol and offline Gate D adapters."""

from __future__ import annotations

import errno
import hashlib
import http.client
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, NoReturn, Protocol, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

from evitriage.domain.alerts import Sha256
from evitriage.domain.triage import AgentRole, TriageTarget
from evitriage.errors import ConfigurationError, ModelError, ModelResponseError, ReplayMissError
from evitriage.observability import redact_mapping

_MAXIMUM_REPLAY_BYTES = 2 * 1024 * 1024
_MAXIMUM_PROVIDER_RESPONSE_BYTES = 2 * 1024 * 1024
_MAXIMUM_PROVIDER_REQUEST_BYTES = 4 * 1024 * 1024
_DEEPSEEK_API_HOST = "api.deepseek.com"
_DEEPSEEK_API_PATH = "/chat/completions"
_DEEPSEEK_TIMEOUT_SECONDS = 120
_DEEPSEEK_MODELS = frozenset({"deepseek-v4-flash", "deepseek-v4-pro"})
_ResponseModelT = TypeVar("_ResponseModelT", bound=BaseModel)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LLMProfile(_StrictModel):
    """Trusted model, decoding, and data-transfer identity for Gate D+."""

    schema_version: Literal["1.0"] = "1.0"
    id: Annotated[
        str,
        Field(min_length=1, max_length=100, pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$"),
    ]
    provider: Literal["fake", "replay", "deepseek"]
    model_id: Annotated[str, Field(min_length=1, max_length=200)]
    temperature: Annotated[float, Field(ge=0, le=0)] = 0.0
    maximum_output_tokens: Annotated[int, Field(ge=1, le=1_000_000)] = 8192
    data_policy: Literal["offline_only", "remote_llm_allowed"] = "offline_only"

    @model_validator(mode="after")
    def validate_provider_policy(self) -> Self:
        if self.provider == "deepseek":
            if self.model_id not in _DEEPSEEK_MODELS:
                raise ValueError("DeepSeek profiles must select a supported V4 model")
            if self.data_policy != "remote_llm_allowed":
                raise ValueError("DeepSeek profiles require data_policy=remote_llm_allowed")
        elif self.data_policy != "offline_only":
            raise ValueError("Fake and Replay profiles require data_policy=offline_only")
        return self

    @property
    def digest(self) -> Sha256:
        """Return the canonical identity of every trusted profile field."""

        return hashlib.sha256(_canonical_json_bytes(self.model_dump(mode="json"))).hexdigest()


class InvocationContext(_StrictModel):
    """Operational context that cannot grant tools or widen the data policy."""

    run_id: Annotated[str, Field(min_length=1, max_length=128)]
    target: TriageTarget
    agent_role: AgentRole
    attempt: Annotated[int, Field(ge=0, le=1)]
    profile: LLMProfile


class StructuredLLM(Protocol):
    """Provider-neutral interface for one strict structured completion."""

    def complete(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[_ResponseModelT],
        invocation_context: InvocationContext,
    ) -> _ResponseModelT:
        """Return one response validated against ``response_model``."""
        ...


@dataclass(frozen=True, slots=True)
class ScriptedResponse:
    """One ordered FakeLLM response with an expected role."""

    agent_role: AgentRole
    payload: JsonValue | bytes


@dataclass(frozen=True, slots=True)
class FakeInvocation:
    """Captured FakeLLM request metadata for deterministic test assertions."""

    agent_role: AgentRole
    attempt: int
    request_sha256: str
    system_prompt: str
    canonical_user_payload: str
    response_model: str


def canonical_request_sha256(
    *,
    system_prompt: str,
    user_payload: Mapping[str, object],
    response_model: type[BaseModel],
    invocation_context: InvocationContext,
) -> Sha256:
    """Hash prompt, payload, schema, role, model/profile, and decoding parameters."""

    envelope = {
        "agent_role": invocation_context.agent_role,
        "profile": invocation_context.profile.model_dump(mode="json"),
        "response_schema": response_model.model_json_schema(),
        "system_prompt": system_prompt,
        "user_payload": dict(user_payload),
    }
    try:
        serialized = _canonical_json_bytes(envelope)
    except (TypeError, ValueError) as error:
        raise ModelError(
            "structured model request is not canonical JSON",
            details={"reason": type(error).__name__},
        ) from error
    return hashlib.sha256(serialized).hexdigest()


class FakeLLM:
    """Offline ordered fixture adapter with the same strict parsing as replay."""

    def __init__(self, profile: LLMProfile, responses: Sequence[ScriptedResponse]) -> None:
        if profile.provider != "fake":
            raise ConfigurationError("FakeLLM requires a profile with provider=fake")
        self._profile = profile
        self._responses = tuple(responses)
        self._cursor = 0
        self._invocations: list[FakeInvocation] = []

    @property
    def invocations(self) -> tuple[FakeInvocation, ...]:
        """Return captured requests without exposing response content."""

        return tuple(self._invocations)

    def complete(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[_ResponseModelT],
        invocation_context: InvocationContext,
    ) -> _ResponseModelT:
        """Consume exactly one role-matched scripted response."""

        _require_profile(invocation_context, self._profile)
        request_sha256 = canonical_request_sha256(
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_model=response_model,
            invocation_context=invocation_context,
        )
        try:
            canonical_payload = _canonical_json_bytes(dict(user_payload)).decode("utf-8")
        except (TypeError, ValueError) as error:
            raise ModelError("FakeLLM payload is not canonical JSON") from error
        self._invocations.append(
            FakeInvocation(
                agent_role=invocation_context.agent_role,
                attempt=invocation_context.attempt,
                request_sha256=request_sha256,
                system_prompt=system_prompt,
                canonical_user_payload=canonical_payload,
                response_model=response_model.__name__,
            )
        )
        if self._cursor >= len(self._responses):
            raise ModelError(
                "FakeLLM scripted responses are exhausted",
                details={"call_index": self._cursor},
            )
        scripted = self._responses[self._cursor]
        self._cursor += 1
        if scripted.agent_role != invocation_context.agent_role:
            raise ModelError(
                "FakeLLM scripted role does not match the invocation",
                details={
                    "expected_role": scripted.agent_role,
                    "actual_role": invocation_context.agent_role,
                    "call_index": self._cursor - 1,
                },
            )
        if isinstance(scripted.payload, bytes):
            raw = scripted.payload
        else:
            try:
                raw = _canonical_json_bytes(scripted.payload)
            except (TypeError, ValueError) as error:
                raise ModelResponseError(
                    "FakeLLM response is not JSON",
                    details={"reason": type(error).__name__},
                ) from error
        return _validate_response(raw, response_model)


class ReplayLLM:
    """Read-only, no-follow adapter for request-hash-addressed JSON responses."""

    def __init__(self, profile: LLMProfile, cache_root: Path) -> None:
        if profile.provider != "replay":
            raise ConfigurationError("ReplayLLM requires a profile with provider=replay")
        if cache_root.is_symlink():
            raise ConfigurationError("ReplayLLM cache root must not be a symbolic link")
        try:
            canonical = cache_root.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ConfigurationError(
                f"ReplayLLM cache root does not exist: {cache_root}"
            ) from error
        if not canonical.is_dir():
            raise ConfigurationError(f"ReplayLLM cache root is not a directory: {canonical}")
        self._profile = profile
        self._cache_root = canonical

    def complete(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[_ResponseModelT],
        invocation_context: InvocationContext,
    ) -> _ResponseModelT:
        """Load ``<request_sha256>.json`` and strictly validate its content."""

        _require_profile(invocation_context, self._profile)
        request_sha256 = canonical_request_sha256(
            system_prompt=system_prompt,
            user_payload=user_payload,
            response_model=response_model,
            invocation_context=invocation_context,
        )
        path = self._cache_root / f"{request_sha256}.json"
        raw = self._read_regular_file(path, request_sha256=request_sha256)
        return _validate_response(raw, response_model)

    @staticmethod
    def _read_regular_file(path: Path, *, request_sha256: str) -> bytes:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        elif path.is_symlink():  # pragma: no cover - supported platforms expose O_NOFOLLOW
            raise ModelError(
                "ReplayLLM cache entry must not be a symbolic link",
                details={"request_sha256": request_sha256},
            )
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError as error:
            raise ReplayMissError(
                "no ReplayLLM cache entry matches the canonical request",
                details={"request_sha256": request_sha256},
            ) from error
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ModelError(
                    "ReplayLLM cache entry must not be a symbolic link",
                    details={"request_sha256": request_sha256},
                ) from error
            raise ModelError(
                "cannot open ReplayLLM cache entry",
                details={"request_sha256": request_sha256, "reason": type(error).__name__},
            ) from error
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise ModelError(
                    "ReplayLLM cache entry is not a regular file",
                    details={"request_sha256": request_sha256},
                )
            if metadata.st_size > _MAXIMUM_REPLAY_BYTES:
                raise ModelError(
                    "ReplayLLM cache entry exceeds the size limit",
                    details={
                        "request_sha256": request_sha256,
                        "maximum_bytes": _MAXIMUM_REPLAY_BYTES,
                    },
                )
            chunks: list[bytes] = []
            remaining = _MAXIMUM_REPLAY_BYTES + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(64 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAXIMUM_REPLAY_BYTES:
                raise ModelError(
                    "ReplayLLM cache entry exceeds the size limit",
                    details={
                        "request_sha256": request_sha256,
                        "maximum_bytes": _MAXIMUM_REPLAY_BYTES,
                    },
                )
            return raw
        except OSError as error:
            raise ModelError(
                "cannot read ReplayLLM cache entry",
                details={"request_sha256": request_sha256, "reason": type(error).__name__},
            ) from error
        finally:
            os.close(descriptor)


class DeepSeekLLM:
    """Restricted DeepSeek V4 JSON adapter using the official HTTPS endpoint."""

    def __init__(self, profile: LLMProfile, *, api_key: str) -> None:
        if profile.provider != "deepseek":
            raise ConfigurationError("DeepSeekLLM requires a profile with provider=deepseek")
        self._profile = profile
        self._api_key = api_key

    def complete(
        self,
        *,
        system_prompt: str,
        user_payload: Mapping[str, object],
        response_model: type[_ResponseModelT],
        invocation_context: InvocationContext,
    ) -> _ResponseModelT:
        """Call DeepSeek V4 once and strictly validate its JSON content."""

        _require_profile(invocation_context, self._profile)
        request_content = {
            "response_schema": response_model.model_json_schema(),
            # Keep the provider boundary safe even when an adapter is invoked by a
            # caller other than the standard triage workflow.
            "task_payload": redact_mapping(user_payload),
        }
        try:
            user_content = _canonical_json_bytes(request_content).decode("utf-8")
            request_body = _canonical_json_bytes(
                {
                    "max_tokens": self._profile.maximum_output_tokens,
                    "messages": [
                        {"content": system_prompt, "role": "system"},
                        {"content": user_content, "role": "user"},
                    ],
                    "model": self._profile.model_id,
                    "response_format": {"type": "json_object"},
                    "stream": False,
                    "temperature": self._profile.temperature,
                    "thinking": {"type": "disabled"},
                }
            )
        except (TypeError, ValueError) as error:
            raise ModelError(
                "DeepSeek request is not canonical JSON",
                details={"reason": type(error).__name__},
            ) from error
        if len(request_body) > _MAXIMUM_PROVIDER_REQUEST_BYTES:
            raise ModelError(
                "DeepSeek request exceeds the provider size limit",
                details={"maximum_bytes": _MAXIMUM_PROVIDER_REQUEST_BYTES},
            )
        raw = self._post(request_body)
        content = _deepseek_response_content(raw)
        return _validate_response(content.encode("utf-8"), response_model)

    def _post(self, request_body: bytes) -> bytes:
        connection = http.client.HTTPSConnection(
            _DEEPSEEK_API_HOST,
            443,
            timeout=_DEEPSEEK_TIMEOUT_SECONDS,
        )
        try:
            connection.request(
                "POST",
                _DEEPSEEK_API_PATH,
                body=request_body,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
            )
            response = connection.getresponse()
            raw = response.read(_MAXIMUM_PROVIDER_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as error:
            raise ModelError(
                "DeepSeek HTTPS request failed",
                details={"reason": type(error).__name__},
            ) from error
        finally:
            connection.close()
        if len(raw) > _MAXIMUM_PROVIDER_RESPONSE_BYTES:
            raise ModelError(
                "DeepSeek response exceeds the provider size limit",
                details={"maximum_bytes": _MAXIMUM_PROVIDER_RESPONSE_BYTES},
            )
        if response.status != 200:
            raise ModelError(
                "DeepSeek API returned a non-success status",
                details={"http_status": response.status},
            )
        return raw


class _DeepSeekMessage(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    content: str


class _DeepSeekChoice(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    finish_reason: str
    message: _DeepSeekMessage


class _DeepSeekResponse(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True, strict=True)

    choices: Annotated[list[_DeepSeekChoice], Field(min_length=1, max_length=1)]


def _deepseek_response_content(raw: bytes) -> str:
    response_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
        response = _DeepSeekResponse.model_validate(decoded, strict=True)
    except (UnicodeError, ValueError, ValidationError) as error:
        raise ModelResponseError(
            "DeepSeek response envelope is invalid",
            details={
                "response_sha256": response_sha256,
                "reason": type(error).__name__,
            },
        ) from error
    choice = response.choices[0]
    if choice.finish_reason != "stop":
        raise ModelResponseError(
            "DeepSeek response did not finish normally",
            details={
                "response_sha256": response_sha256,
                "finish_reason": choice.finish_reason,
            },
        )
    return choice.message.content


def _require_profile(context: InvocationContext, configured: LLMProfile) -> None:
    if context.profile != configured:
        raise ModelError("invocation profile does not match the configured LLM adapter")


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> NoReturn:
    raise ValueError(f"non-finite JSON number: {value}")


def _validate_response[ResponseT: BaseModel](
    raw: bytes,
    response_model: type[ResponseT],
) -> ResponseT:
    response_sha256 = hashlib.sha256(raw).hexdigest()
    try:
        decoded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
        if not isinstance(decoded, dict):
            raise ValueError("structured response root must be a JSON object")
        return response_model.model_validate_json(raw, strict=True)
    except (UnicodeError, ValueError, ValidationError) as error:
        details: dict[str, object] = {
            "response_sha256": response_sha256,
            "response_model": response_model.__name__,
            "reason": type(error).__name__,
        }
        if isinstance(error, ValidationError):
            details["issues"] = [
                {
                    "type": str(issue["type"]),
                    "location": [str(part) for part in issue["loc"]],
                    "message": str(issue["msg"]),
                }
                for issue in error.errors(
                    include_url=False,
                    include_context=False,
                    include_input=False,
                )
            ]
        raise ModelResponseError("structured model response is invalid", details=details) from error


__all__ = [
    "DeepSeekLLM",
    "FakeInvocation",
    "FakeLLM",
    "InvocationContext",
    "LLMProfile",
    "ReplayLLM",
    "ScriptedResponse",
    "StructuredLLM",
    "canonical_request_sha256",
]
