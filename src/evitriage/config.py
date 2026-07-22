"""Strict trusted-system configuration for the v0.1 runtime."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal, cast

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)
from yaml.nodes import MappingNode

from evitriage.errors import ConfigurationError
from evitriage.llm import LLMProfile


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    loader.flatten_mapping(node)
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as error:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from error
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _FrozenStrictConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _list_to_tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class SystemCodeQLConfig(_FrozenStrictConfig):
    required_cli_version: Annotated[
        str,
        Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$"),
    ]
    include_query_help: bool
    timeout_seconds: Annotated[int, Field(ge=1, le=86_400)]


class ContextConfig(_FrozenStrictConfig):
    policy: Literal["path_function_slice"]
    maximum_token_budget: Annotated[int, Field(ge=1, le=1_000_000)]
    include_tests: bool
    include_config: bool


class AgentConfig(_FrozenStrictConfig):
    workflow: Literal["evidence_three_agent"]
    llm_profile: Annotated[
        str,
        Field(
            min_length=1,
            max_length=100,
            pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$",
        ),
    ]
    temperature: Annotated[float, Field(ge=0, le=2)]
    maximum_schema_repairs_per_agent: Annotated[int, Field(ge=0, le=1)]
    maximum_model_calls_per_alert: Annotated[int, Field(ge=3, le=6)]
    require_evidence_ids: Literal[True]
    allow_repository_instructions: Literal[False]


class DecisionPolicyConfig(_FrozenStrictConfig):
    labels: Annotated[
        tuple[Literal["TP", "FP", "NMC"], ...],
        Field(min_length=3, max_length=3),
        BeforeValidator(_list_to_tuple),
    ]
    auto_dismiss: Literal[False]
    fp_requires_decisive_rebuttal: Literal[True]
    conflict_or_missing_evidence: Literal["NMC"]

    @field_validator("labels")
    @classmethod
    def validate_label_contract(
        cls,
        value: tuple[Literal["TP", "FP", "NMC"], ...],
    ) -> tuple[Literal["TP", "FP", "NMC"], ...]:
        if value != ("TP", "FP", "NMC"):
            raise ValueError("policy.labels must be exactly [TP, FP, NMC]")
        return value


class VerificationConfig(_FrozenStrictConfig):
    enabled: Literal[False]


class ReproducibilityConfig(_FrozenStrictConfig):
    cache_llm_responses: bool
    persist_prompts: bool
    persist_tool_versions: bool
    seed: Annotated[int, Field(ge=0, le=2**63 - 1)]


class SystemConfig(_FrozenStrictConfig):
    """Versioned, trusted settings that projects are not allowed to override."""

    schema_version: Literal["1.0"]
    codeql: SystemCodeQLConfig
    context: ContextConfig
    agents: AgentConfig
    policy: DecisionPolicyConfig
    verification: VerificationConfig
    reproducibility: ReproducibilityConfig

    @property
    def digest(self) -> str:
        payload = json.dumps(
            self.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_system_config(path: Path) -> SystemConfig:
    """Read one UTF-8 YAML document and validate the complete system schema."""

    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"system config does not exist: {path}") from exc
    if not canonical.is_file():
        raise ConfigurationError(f"system config is not a file: {canonical}")
    try:
        raw = yaml.load(
            canonical.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,  # noqa: S506 - subclasses yaml.SafeLoader
        )
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"cannot parse system config {canonical}",
            details={"parser_error": type(exc).__name__},
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"cannot read system config {canonical}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"system config must contain a YAML mapping: {canonical}")
    try:
        return SystemConfig.model_validate(cast(dict[str, object], raw))
    except ValidationError as exc:
        raise ConfigurationError(
            f"invalid system config in {canonical}",
            details={
                "issues": [
                    {
                        "type": str(issue["type"]),
                        "location": [str(part) for part in issue["loc"]],
                        "message": str(issue["msg"]),
                    }
                    for issue in exc.errors(
                        include_url=False,
                        include_context=False,
                        include_input=False,
                    )
                ]
            },
        ) from exc


def load_llm_profile(path: Path) -> LLMProfile:
    """Read one trusted offline LLM profile with duplicate-key rejection."""

    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ConfigurationError(f"LLM profile does not exist: {path}") from exc
    if not canonical.is_file():
        raise ConfigurationError(f"LLM profile is not a file: {canonical}")
    try:
        raw = yaml.load(
            canonical.read_text(encoding="utf-8"),
            Loader=_UniqueKeySafeLoader,  # noqa: S506 - subclasses yaml.SafeLoader
        )
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"cannot parse LLM profile {canonical}",
            details={"parser_error": type(exc).__name__},
        ) from exc
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"cannot read LLM profile {canonical}") from exc
    if not isinstance(raw, dict):
        raise ConfigurationError(f"LLM profile must contain a YAML mapping: {canonical}")
    try:
        return LLMProfile.model_validate(cast(dict[str, object], raw))
    except ValidationError as exc:
        raise ConfigurationError(
            f"invalid LLM profile in {canonical}",
            details={
                "issues": [
                    {
                        "type": str(issue["type"]),
                        "location": [str(part) for part in issue["loc"]],
                        "message": str(issue["msg"]),
                    }
                    for issue in exc.errors(
                        include_url=False,
                        include_context=False,
                        include_input=False,
                    )
                ]
            },
        ) from exc


__all__ = [
    "AgentConfig",
    "ContextConfig",
    "DecisionPolicyConfig",
    "ReproducibilityConfig",
    "SystemCodeQLConfig",
    "SystemConfig",
    "VerificationConfig",
    "load_llm_profile",
    "load_system_config",
]
