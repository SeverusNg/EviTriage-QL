"""Strict structural models for the SARIF 2.1.0 subset consumed by Gate B."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, model_validator


def _as_tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


class SarifInputModel(BaseModel):
    """SARIF allows extension properties; unsupported fields are ignored."""

    model_config = ConfigDict(extra="ignore", frozen=True, strict=True, populate_by_name=True)


class Message(SarifInputModel):
    text: str | None = None
    markdown: str | None = None

    @model_validator(mode="after")
    def require_content(self) -> Self:
        if self.text is None and self.markdown is None:
            raise ValueError("message requires text or markdown")
        return self


class ArtifactLocation(SarifInputModel):
    uri: str | None = None
    uri_base_id: str | None = Field(default=None, alias="uriBaseId")
    index: int | None = Field(default=None, ge=0)


class Artifact(SarifInputModel):
    location: ArtifactLocation | None = None
    hashes: dict[str, str] = Field(default_factory=dict)


class Region(SarifInputModel):
    start_line: int | None = Field(default=None, alias="startLine", ge=1)
    start_column: int | None = Field(default=None, alias="startColumn", ge=1)
    end_line: int | None = Field(default=None, alias="endLine", ge=1)
    end_column: int | None = Field(default=None, alias="endColumn", ge=1)
    snippet: Message | None = None


class PhysicalLocation(SarifInputModel):
    artifact_location: ArtifactLocation | None = Field(default=None, alias="artifactLocation")
    region: Region | None = None
    context_region: Region | None = Field(default=None, alias="contextRegion")


class Location(SarifInputModel):
    id: int | None = Field(default=None, ge=0)
    physical_location: PhysicalLocation | None = Field(default=None, alias="physicalLocation")
    message: Message | None = None


class ThreadFlowLocation(SarifInputModel):
    location: Location
    kinds: Annotated[tuple[str, ...], BeforeValidator(_as_tuple)] = ()
    nesting_level: int | None = Field(default=None, alias="nestingLevel", ge=0)
    execution_order: int | None = Field(default=None, alias="executionOrder", ge=0)
    importance: Literal["important", "essential", "unimportant"] | None = None


class ThreadFlow(SarifInputModel):
    locations: Annotated[tuple[ThreadFlowLocation, ...], BeforeValidator(_as_tuple)] = ()
    message: Message | None = None


class CodeFlow(SarifInputModel):
    thread_flows: Annotated[tuple[ThreadFlow, ...], BeforeValidator(_as_tuple)] = Field(
        default=(), alias="threadFlows"
    )
    message: Message | None = None


class ReportingConfiguration(SarifInputModel):
    level: str | None = None


class ReportingDescriptor(SarifInputModel):
    id: str
    name: str | None = None
    short_description: Message | None = Field(default=None, alias="shortDescription")
    full_description: Message | None = Field(default=None, alias="fullDescription")
    help_uri: str | None = Field(default=None, alias="helpUri")
    default_configuration: ReportingConfiguration | None = Field(
        default=None, alias="defaultConfiguration"
    )
    properties: dict[str, object] = Field(default_factory=dict)


class ToolComponent(SarifInputModel):
    name: str
    version: str | None = None
    semantic_version: str | None = Field(default=None, alias="semanticVersion")
    rules: Annotated[tuple[ReportingDescriptor, ...], BeforeValidator(_as_tuple)] = ()


class Tool(SarifInputModel):
    driver: ToolComponent


class Result(SarifInputModel):
    rule_id: str | None = Field(default=None, alias="ruleId")
    rule_index: int | None = Field(default=None, alias="ruleIndex", ge=0)
    message: Message
    level: str | None = None
    locations: Annotated[tuple[Location, ...], BeforeValidator(_as_tuple)] = ()
    related_locations: Annotated[tuple[Location, ...], BeforeValidator(_as_tuple)] = Field(
        default=(), alias="relatedLocations"
    )
    code_flows: Annotated[tuple[CodeFlow, ...], BeforeValidator(_as_tuple)] = Field(
        default=(), alias="codeFlows"
    )
    fingerprints: dict[str, str] = Field(default_factory=dict)
    partial_fingerprints: dict[str, str] = Field(default_factory=dict, alias="partialFingerprints")
    properties: dict[str, object] = Field(default_factory=dict)


class Run(SarifInputModel):
    tool: Tool
    results: Annotated[tuple[Result, ...], BeforeValidator(_as_tuple)] = ()
    artifacts: Annotated[tuple[Artifact, ...], BeforeValidator(_as_tuple)] = ()
    original_uri_base_ids: dict[str, ArtifactLocation] = Field(
        default_factory=dict, alias="originalUriBaseIds"
    )


class SarifDocument(SarifInputModel):
    version: Literal["2.1.0"]
    schema_uri: str | None = Field(default=None, alias="$schema")
    runs: Annotated[tuple[Run, ...], BeforeValidator(_as_tuple)]


__all__ = [
    "Artifact",
    "ArtifactLocation",
    "CodeFlow",
    "Location",
    "Message",
    "PhysicalLocation",
    "Region",
    "ReportingDescriptor",
    "Result",
    "Run",
    "SarifDocument",
    "ThreadFlow",
    "ThreadFlowLocation",
    "ToolComponent",
]
