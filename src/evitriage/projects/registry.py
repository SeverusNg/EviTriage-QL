"""Load and safely resolve project configurations."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from threading import RLock
from typing import Any, cast

import yaml
from pydantic import ValidationError
from yaml.nodes import MappingNode

from evitriage.domain.project import (
    LocalSource,
    ProjectSpec,
    ResolvedProjectSpec,
    StorageSpec,
    compute_project_spec_digest,
)
from evitriage.errors import ConfigurationError, PathSafetyError

_MAX_CONFIG_BYTES = 1024 * 1024
_SAFE_SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    result: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in result
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
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


def _is_within(path: Path, root: Path) -> bool:
    """Return true when *path* is *root* or one of its descendants."""

    return path == root or path.is_relative_to(root)


def _source_fingerprint(spec: ProjectSpec) -> str:
    payload = json.dumps(
        spec.source.model_dump(mode="json", exclude_none=False),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ProjectRegistry:
    """Strict registry for repository-relative ProjectSpec files.

    Relative local and storage paths are always interpreted relative to the
    repository root, never relative to the caller's current directory or the
    YAML file.  This keeps CLI and programmatic loading on one deterministic
    path and makes checked-in example configs portable.
    """

    def __init__(
        self,
        repository_root: Path,
        projects_dir: Path | None = None,
        allowed_source_roots: tuple[Path, ...] | None = None,
        allowed_workspace_roots: tuple[Path, ...] | None = None,
        allowed_artifact_roots: tuple[Path, ...] | None = None,
    ) -> None:
        try:
            canonical_repository_root = repository_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(
                f"repository root does not exist or cannot be resolved: {repository_root}"
            ) from exc
        if not canonical_repository_root.is_dir():
            raise ConfigurationError(
                f"repository root is not a directory: {canonical_repository_root}"
            )

        self.repository_root = canonical_repository_root
        raw_projects_dir = projects_dir or Path("configs/projects")
        if not raw_projects_dir.is_absolute():
            raw_projects_dir = self.repository_root / raw_projects_dir
        try:
            self.projects_dir = raw_projects_dir.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(
                f"projects directory cannot be resolved: {raw_projects_dir}"
            ) from exc

        roots = (
            allowed_source_roots if allowed_source_roots is not None else (self.repository_root,)
        )
        canonical_roots: list[Path] = []
        for root in roots:
            candidate = root if root.is_absolute() else self.repository_root / root
            try:
                canonical = candidate.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise PathSafetyError(
                    f"allowed source root does not exist or cannot be resolved: {candidate}"
                ) from exc
            if not canonical.is_dir():
                raise PathSafetyError(f"allowed source root is not a directory: {canonical}")
            if canonical not in canonical_roots:
                canonical_roots.append(canonical)
        if not canonical_roots:
            raise PathSafetyError("at least one allowed source root is required")
        self.allowed_source_roots = tuple(canonical_roots)
        workspace_policy_roots = (
            allowed_workspace_roots
            if allowed_workspace_roots is not None
            else (self.repository_root / "workspaces",)
        )
        artifact_policy_roots = (
            allowed_artifact_roots
            if allowed_artifact_roots is not None
            else (self.repository_root / "artifacts",)
        )
        self.allowed_workspace_roots = self._resolve_policy_roots(
            workspace_policy_roots,
            label="workspace",
            reject_root_symlinks=allowed_workspace_roots is None,
        )
        self.allowed_artifact_roots = self._resolve_policy_roots(
            artifact_policy_roots,
            label="artifact",
            reject_root_symlinks=allowed_artifact_roots is None,
        )

        self._source_by_id: dict[str, str] = {}
        self._config_by_id: dict[str, Path] = {}
        self._lock = RLock()

    def validate_path(self, path: Path) -> ResolvedProjectSpec:
        """Validate and resolve one YAML config through the registry path."""

        return self.load_path(path)

    def load_path(self, path: Path) -> ResolvedProjectSpec:
        """Load one config, canonicalize paths, and calculate a stable digest."""

        config_path = self._resolve_config_path(path)
        raw = self._read_yaml(config_path)
        spec = self._validate_mapping(raw, config_path)

        resolved_spec = self._resolve_spec_paths(spec)
        digest = compute_project_spec_digest(resolved_spec)
        resolved = ResolvedProjectSpec(
            spec=resolved_spec,
            config_path=str(config_path),
            digest=digest,
        )
        self._enforce_checked_in_source_identity(resolved, config_path)
        self._register_identity(resolved, config_path)
        return resolved

    def load(self, project_id: str) -> ResolvedProjectSpec:
        """Load a checked-in project config by its declared project id."""

        if len(project_id) > 63 or _SAFE_SLUG.fullmatch(project_id) is None:
            raise ConfigurationError(f"unsafe project id: {project_id!r}")
        if not self.projects_dir.is_dir():
            raise ConfigurationError(f"projects directory does not exist: {self.projects_dir}")

        matches: list[ResolvedProjectSpec] = []
        candidates = sorted(
            (*self.projects_dir.glob("*.yaml"), *self.projects_dir.glob("*.yml")),
            key=lambda candidate: candidate.name,
        )
        for candidate in candidates:
            raw = self._read_yaml(candidate.resolve(strict=True))
            project_section = raw.get("project")
            declared_id = project_section.get("id") if isinstance(project_section, dict) else None
            if declared_id == project_id:
                matches.append(self.load_path(candidate))

        if not matches:
            raise ConfigurationError(
                f"project id {project_id!r} was not found in {self.projects_dir}"
            )
        # Identical duplicate declarations are still ambiguous to humans.  A
        # differing source is already rejected by _register_identity with a
        # more specific error; reject identical duplicates here as well.
        if len(matches) > 1:
            paths = ", ".join(match.config_path for match in matches)
            raise ConfigurationError(
                f"project id {project_id!r} is declared by multiple configs: {paths}"
            )
        return matches[0]

    def list_ids(self) -> tuple[str, ...]:
        """Return declared ids after validating every registry entry."""

        if not self.projects_dir.is_dir():
            raise ConfigurationError(f"projects directory does not exist: {self.projects_dir}")
        ids: list[str] = []
        for candidate in sorted(
            (*self.projects_dir.glob("*.yaml"), *self.projects_dir.glob("*.yml")),
            key=lambda item: item.name,
        ):
            resolved = self.load_path(candidate)
            ids.append(resolved.project_id)
        if len(ids) != len(set(ids)):
            raise ConfigurationError("duplicate project ids are not allowed")
        return tuple(ids)

    def _resolve_config_path(self, path: Path) -> Path:
        candidate = path if path.is_absolute() else self.repository_root / path
        try:
            canonical = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError(
                f"project config does not exist or cannot be resolved: {candidate}"
            ) from exc
        if not canonical.is_file():
            raise ConfigurationError(f"project config is not a file: {canonical}")
        if canonical.suffix.lower() not in {".yaml", ".yml"}:
            raise ConfigurationError("project config must be a .yaml or .yml file")
        try:
            size = canonical.stat().st_size
        except OSError as exc:
            raise ConfigurationError(f"cannot stat project config: {canonical}") from exc
        if size > _MAX_CONFIG_BYTES:
            raise ConfigurationError(
                f"project config exceeds {_MAX_CONFIG_BYTES} bytes: {canonical}"
            )
        return canonical

    @staticmethod
    def _read_yaml(config_path: Path) -> dict[str, Any]:
        try:
            text = config_path.read_text(encoding="utf-8")
            loader = _UniqueKeySafeLoader(text)
            try:
                value = loader.get_single_data()
            finally:
                loader.dispose()  # type: ignore[no-untyped-call]
        except yaml.YAMLError as exc:
            raise ConfigurationError(
                f"cannot parse project config {config_path}",
                details={"parser_error": type(exc).__name__},
            ) from exc
        except (OSError, UnicodeError) as exc:
            raise ConfigurationError(f"cannot read project config {config_path}") from exc
        if not isinstance(value, dict):
            raise ConfigurationError(f"project config must contain a YAML mapping: {config_path}")
        return cast(dict[str, Any], value)

    @staticmethod
    def _validate_mapping(raw: dict[str, Any], config_path: Path) -> ProjectSpec:
        try:
            return ProjectSpec.model_validate(raw)
        except ValidationError as exc:
            raise ConfigurationError(
                f"invalid ProjectSpec in {config_path}",
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

    def _resolve_spec_paths(self, spec: ProjectSpec) -> ProjectSpec:
        source = spec.source
        canonical_source: Path | None = None
        if isinstance(source, LocalSource):
            canonical_source = self._resolve_local_source(source.path)
            source = source.model_copy(update={"path": str(canonical_source)})

        workspace_root = self._resolve_managed_root(
            spec.storage.workspace_root,
            field_name="storage.workspace_root",
            allowed_roots=self.allowed_workspace_roots,
        )
        artifact_root = self._resolve_managed_root(
            spec.storage.artifact_root,
            field_name="storage.artifact_root",
            allowed_roots=self.allowed_artifact_roots,
        )
        if _is_within(workspace_root, artifact_root) or _is_within(artifact_root, workspace_root):
            raise PathSafetyError(
                "workspace and artifact roots must be distinct, non-overlapping trees"
            )
        if canonical_source is not None and (
            _is_within(canonical_source, workspace_root)
            or _is_within(workspace_root, canonical_source)
            or _is_within(canonical_source, artifact_root)
            or _is_within(artifact_root, canonical_source)
        ):
            raise PathSafetyError("local source must not overlap managed storage roots")
        storage = StorageSpec(
            workspace_root=str(workspace_root),
            artifact_root=str(artifact_root),
        )
        return spec.model_copy(update={"source": source, "storage": storage})

    def _resolve_local_source(self, path_text: str) -> Path:
        path = Path(path_text)
        if ".." in Path(path_text.replace("\\", "/")).parts:
            raise PathSafetyError("source.path must not contain parent traversal")
        candidate = path if path.is_absolute() else self.repository_root / path
        try:
            canonical = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PathSafetyError(
                f"local source does not exist or cannot be resolved: {candidate}"
            ) from exc
        if not canonical.is_dir():
            raise PathSafetyError(f"local source is not a directory: {canonical}")
        if not any(_is_within(canonical, root) for root in self.allowed_source_roots):
            allowed = ", ".join(str(root) for root in self.allowed_source_roots)
            raise PathSafetyError(f"local source escapes allowed roots ({allowed}): {canonical}")
        return canonical

    def _resolve_managed_root(
        self,
        path_text: str,
        *,
        field_name: str,
        allowed_roots: tuple[Path, ...],
    ) -> Path:
        path = Path(path_text)
        if ".." in Path(path_text.replace("\\", "/")).parts:
            raise PathSafetyError(f"{field_name} must not contain parent traversal")
        candidate = path if path.is_absolute() else self.repository_root / path
        self._reject_symlink_components(candidate, field_name=field_name)
        try:
            canonical = candidate.resolve(strict=False)
        except (OSError, RuntimeError) as exc:
            raise PathSafetyError(f"{field_name} cannot be resolved: {candidate}") from exc
        if not any(_is_within(canonical, root) for root in allowed_roots):
            allowed = ", ".join(str(root) for root in allowed_roots)
            raise PathSafetyError(
                f"{field_name} escapes trusted managed roots ({allowed}): {canonical}"
            )
        return canonical

    def _resolve_policy_roots(
        self,
        roots: tuple[Path, ...],
        *,
        label: str,
        reject_root_symlinks: bool,
    ) -> tuple[Path, ...]:
        resolved: list[Path] = []
        for root in roots:
            candidate = root if root.is_absolute() else self.repository_root / root
            if reject_root_symlinks:
                self._reject_symlink_components(
                    candidate,
                    field_name=f"trusted {label} root",
                )
            try:
                canonical = candidate.resolve(strict=False)
            except (OSError, RuntimeError) as exc:
                raise PathSafetyError(
                    f"trusted {label} root cannot be resolved: {candidate}"
                ) from exc
            if canonical.exists() and not canonical.is_dir():
                raise PathSafetyError(f"trusted {label} root is not a directory: {canonical}")
            if canonical not in resolved:
                resolved.append(canonical)
        if not resolved:
            raise PathSafetyError(f"at least one trusted {label} root is required")
        return tuple(resolved)

    @staticmethod
    def _reject_symlink_components(path: Path, *, field_name: str) -> None:
        """Reject a lexical path containing an existing symbolic-link component."""

        absolute = Path(os.path.abspath(path))
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            try:
                if current.is_symlink():
                    raise PathSafetyError(
                        f"{field_name} contains a symbolic-link component: {current}"
                    )
                if not current.exists():
                    break
            except OSError as exc:
                raise PathSafetyError(
                    f"{field_name} cannot be inspected safely: {current}"
                ) from exc

    def _register_identity(
        self,
        resolved: ResolvedProjectSpec,
        config_path: Path,
    ) -> None:
        source_identity = _source_fingerprint(resolved.spec)
        with self._lock:
            existing = self._source_by_id.get(resolved.project_id)
            if existing is not None and existing != source_identity:
                previous_path = self._config_by_id[resolved.project_id]
                raise ConfigurationError(
                    "project id "
                    f"{resolved.project_id!r} points to different sources in "
                    f"{previous_path} and {config_path}; version the project id explicitly"
                )
            self._source_by_id[resolved.project_id] = source_identity
            self._config_by_id.setdefault(resolved.project_id, config_path)

    def _enforce_checked_in_source_identity(
        self,
        resolved: ResolvedProjectSpec,
        config_path: Path,
    ) -> None:
        """Compare an arbitrary config with the repository's declared identity.

        The comparison is intentionally repeated for each fresh Registry instance,
        so a standalone CLI invocation cannot reuse an existing project id for a
        different source merely by avoiding an earlier in-memory registration.
        """

        if not self.projects_dir.is_dir():
            return
        source_identity = _source_fingerprint(resolved.spec)
        candidates = sorted(
            (*self.projects_dir.glob("*.yaml"), *self.projects_dir.glob("*.yml")),
            key=lambda candidate: candidate.name,
        )
        for candidate in candidates:
            canonical = candidate.resolve(strict=True)
            if canonical == config_path:
                continue
            raw = self._read_yaml(canonical)
            project_section = raw.get("project")
            declared_id = project_section.get("id") if isinstance(project_section, dict) else None
            if declared_id != resolved.project_id:
                continue
            checked_in_spec = self._resolve_spec_paths(self._validate_mapping(raw, canonical))
            if _source_fingerprint(checked_in_spec) != source_identity:
                raise ConfigurationError(
                    "project id "
                    f"{resolved.project_id!r} points to different sources in "
                    f"{canonical} and {config_path}; version the project id explicitly"
                )


__all__ = ["ProjectRegistry"]
