"""Safe, content-addressed workspaces for untrusted local source trees."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from typing import Protocol

from evitriage.domain.workspace import (
    RepositorySnapshot,
    RunWorkspace,
    WorkspaceAllocation,
)
from evitriage.errors import PathSafetyError, WorkspaceConflictError, WorkspaceError

_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DESCRIPTOR_NAME = ".evitriage-workspace.json"
_RESOLVED_SPEC_NAME = "project-spec.resolved.yaml"
_TREE_HASH_DOMAIN = b"EviTriage-QL source tree v1\0"


class _Digest(Protocol):
    """Structural type shared by hashlib digest implementations."""

    def update(self, data: bytes, /) -> None:
        """Add bytes to the digest state."""


class WorkspaceManager:
    """Allocate isolated run directories beneath two explicitly managed roots.

    Local input is copied twice: first into a shared, content-addressed,
    read-only snapshot and then into a run-specific writable build copy.  The
    input directory is only ever opened for reading.
    """

    def __init__(
        self,
        workspace_root: str | Path,
        artifact_root: str | Path,
        *,
        maximum_files: int = 100_000,
        maximum_total_bytes: int = 2 * 1024 * 1024 * 1024,
        maximum_file_bytes: int = 256 * 1024 * 1024,
        maximum_depth: int = 128,
    ) -> None:
        if maximum_files < 1:
            raise ValueError("maximum_files must be positive")
        if maximum_total_bytes < 1:
            raise ValueError("maximum_total_bytes must be positive")
        if maximum_file_bytes < 1:
            raise ValueError("maximum_file_bytes must be positive")
        if maximum_depth < 1 or maximum_depth > 512:
            raise ValueError("maximum_depth must be between 1 and 512")

        # Validation is deliberately side-effect free.  Roots are materialized
        # only after a source has been checked not to overlap them.
        self._workspace_root = self._normalize_root(workspace_root, "workspace")
        self._artifact_root = self._normalize_root(artifact_root, "artifact")
        if self._paths_overlap(self._workspace_root, self._artifact_root):
            raise PathSafetyError(
                "workspace_root and artifact_root must be distinct, non-overlapping trees"
            )

        self._maximum_files = maximum_files
        self._maximum_total_bytes = maximum_total_bytes
        self._maximum_file_bytes = maximum_file_bytes
        self._maximum_depth = maximum_depth
        self._initialization_lock = RLock()
        self._roots_initialized = False

    @property
    def workspace_root(self) -> Path:
        """Canonical workspace root."""

        return self._workspace_root

    @property
    def artifact_root(self) -> Path:
        """Canonical artifact root."""

        return self._artifact_root

    def prepare(
        self,
        source_path: str | Path,
        project_id: str,
        resolved_yaml: str,
        run_id: str | None = None,
    ) -> WorkspaceAllocation:
        """Snapshot ``source_path`` and allocate an isolated workspace.

        ``resolved_yaml`` must already be validated and redacted by the project
        configuration layer.  Repeating this call with the same ``run_id`` and
        inputs returns the existing allocation; changing an input for an
        existing run is rejected.
        """

        snapshot = self.snapshot_local_source(source_path)
        return self.create_run(
            project_id=project_id,
            snapshot=snapshot,
            resolved_yaml=resolved_yaml,
            run_id=run_id,
        )

    def snapshot_local_source(self, source_path: str | Path) -> RepositorySnapshot:
        """Create or reuse an immutable snapshot of a local directory."""

        source = self._canonical_source(source_path)
        for managed_root in (self._workspace_root, self._artifact_root):
            if self._paths_overlap(source, managed_root):
                raise PathSafetyError(
                    f"source path must not overlap managed root {managed_root}: {source}"
                )
        self._ensure_roots_initialized()
        digest = self._tree_digest(source)
        snapshot_path = self._managed_child(self._workspace_root, "sources", digest)

        with self._file_lock(f"snapshot-{digest}"):
            if snapshot_path.exists():
                self._validate_existing_directory(snapshot_path, self._workspace_root)
                observed_digest = self._tree_digest(snapshot_path)
                if observed_digest != digest:
                    raise WorkspaceConflictError(
                        f"managed snapshot {snapshot_path} no longer matches its identity"
                    )
            else:
                self._materialize_snapshot(source, snapshot_path, digest)

        created_at = datetime.fromtimestamp(snapshot_path.stat().st_ctime, tz=UTC)
        return RepositorySnapshot(
            snapshot_id=digest,
            origin=str(source),
            checkout_path=snapshot_path,
            source_tree_sha256=digest,
            created_at=created_at,
        )

    def create_run(
        self,
        *,
        project_id: str,
        snapshot: RepositorySnapshot,
        resolved_yaml: str,
        run_id: str | None = None,
    ) -> WorkspaceAllocation:
        """Create a run-specific writable copy from ``snapshot``."""

        self._validate_identifier(project_id, "project_id")
        selected_run_id = run_id or self.new_run_id()
        self._validate_identifier(selected_run_id, "run_id")
        if not _SHA256.fullmatch(snapshot.snapshot_id):
            raise WorkspaceError("snapshot_id is not a SHA-256 digest")
        if snapshot.snapshot_id != snapshot.source_tree_sha256:
            raise WorkspaceConflictError(
                "snapshot_id does not match the recorded source tree identity"
            )

        expected_source_snapshot = self._workspace_root / "sources" / snapshot.snapshot_id
        if snapshot.checkout_path != expected_source_snapshot:
            raise PathSafetyError("snapshot checkout_path is not managed by this manager")
        self._ensure_roots_initialized()
        source_snapshot = self._managed_child(self._workspace_root, "sources", snapshot.snapshot_id)
        self._validate_existing_directory(source_snapshot, self._workspace_root)

        workspace = RunWorkspace(
            run_id=selected_run_id,
            project_id=project_id,
            snapshot_id=snapshot.snapshot_id,
            workspace_root=self._workspace_root,
            artifact_root=self._artifact_root,
            source_snapshot=source_snapshot,
            build_copy=self._managed_child(self._workspace_root, "build-copies", selected_run_id),
            codeql_database=self._managed_child(
                self._workspace_root, "codeql-databases", selected_run_id
            ),
            temporary=self._managed_child(self._workspace_root, "temporary", selected_run_id),
            artifact_run_root=self._managed_child(self._artifact_root, "runs", selected_run_id),
        )
        spec_bytes = resolved_yaml.encode("utf-8")
        spec_digest = hashlib.sha256(spec_bytes).hexdigest()

        with self._file_lock(f"run-{selected_run_id}"):
            allocation = self._create_or_reuse_run(
                workspace=workspace,
                snapshot=snapshot,
                resolved_spec=spec_bytes,
                spec_digest=spec_digest,
            )
        return allocation

    def cleanup_run(self, run: str | RunWorkspace | WorkspaceAllocation) -> None:
        """Remove only the exact writable roots owned by one run.

        The shared source snapshot and lock file are intentionally retained.
        A supplied :class:`RunWorkspace` must exactly match the paths this
        manager derives for its run ID; callers cannot use it as an arbitrary
        recursive-delete request.
        """

        workspace: RunWorkspace | None
        if isinstance(run, WorkspaceAllocation):
            workspace = run.workspace
            run_id = workspace.run_id
        elif isinstance(run, RunWorkspace):
            workspace = run
            run_id = workspace.run_id
        else:
            workspace = None
            run_id = run
        self._validate_identifier(run_id, "run_id")
        self._ensure_roots_initialized()
        expected = self._workspace_for_id(run_id)
        if workspace is not None:
            for field_name in (
                "workspace_root",
                "artifact_root",
                "build_copy",
                "codeql_database",
                "temporary",
                "artifact_run_root",
            ):
                if getattr(workspace, field_name) != getattr(expected, field_name):
                    raise PathSafetyError(
                        f"refusing cleanup: {field_name} is not the exact managed run path"
                    )

        with self._file_lock(f"run-{run_id}"):
            targets = (
                (expected.build_copy, self._workspace_root, "build-copies"),
                (expected.codeql_database, self._workspace_root, "codeql-databases"),
                (expected.temporary, self._workspace_root, "temporary"),
                (expected.artifact_run_root, self._artifact_root, "runs"),
            )
            for target, root, category in targets:
                self._assert_exact_run_root(target, root, category, run_id)
            self._validate_cleanup_ownership(expected, targets)
            for target, _, _ in targets:
                self._remove_managed_tree(target)

    def _validate_cleanup_ownership(
        self,
        expected: RunWorkspace,
        targets: tuple[tuple[Path, Path, str], ...],
    ) -> None:
        if not any(target.exists() or target.is_symlink() for target, _, _ in targets):
            return
        descriptor_path = expected.artifact_run_root / _DESCRIPTOR_NAME
        if not descriptor_path.is_file() or descriptor_path.is_symlink():
            raise WorkspaceConflictError(
                f"refusing cleanup without a valid ownership descriptor: {descriptor_path}"
            )
        descriptor = self._read_descriptor(descriptor_path)
        if descriptor.get("run_id") != expected.run_id or descriptor.get("status") not in {
            "preparing",
            "ready",
        }:
            raise WorkspaceConflictError("cleanup ownership descriptor has invalid identity")
        paths = descriptor.get("paths")
        expected_paths = {
            "build_copy": str(expected.build_copy),
            "codeql_database": str(expected.codeql_database),
            "temporary": str(expected.temporary),
            "artifact_run_root": str(expected.artifact_run_root),
        }
        if not isinstance(paths, dict) or any(
            paths.get(name) != value for name, value in expected_paths.items()
        ):
            raise WorkspaceConflictError("cleanup ownership descriptor has invalid paths")

    @staticmethod
    def new_run_id() -> str:
        """Return a sortable, filesystem-safe run identifier."""

        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        return f"{timestamp}-{uuid.uuid4().hex[:12]}"

    def _create_or_reuse_run(
        self,
        *,
        workspace: RunWorkspace,
        snapshot: RepositorySnapshot,
        resolved_spec: bytes,
        spec_digest: str,
    ) -> WorkspaceAllocation:
        artifact_run_root = workspace.artifact_run_root
        descriptor_path = artifact_run_root / _DESCRIPTOR_NAME
        expected_descriptor = self._descriptor(
            workspace=workspace,
            snapshot=snapshot,
            spec_digest=spec_digest,
            status="ready",
        )

        if artifact_run_root.exists():
            self._validate_existing_directory(artifact_run_root, self._artifact_root)
            if not descriptor_path.is_file() or descriptor_path.is_symlink():
                raise WorkspaceConflictError(
                    f"run artifact root exists without a valid ownership descriptor: "
                    f"{artifact_run_root}"
                )
            existing = self._read_descriptor(descriptor_path)
            self._validate_descriptor(existing, expected_descriptor)
            if existing.get("status") == "ready":
                self._validate_ready_run(workspace, resolved_spec)
                return WorkspaceAllocation(
                    snapshot=snapshot,
                    workspace=workspace,
                    project_spec_sha256=spec_digest,
                    prepared_at=self._descriptor_time(existing),
                )
        else:
            for target in (
                workspace.build_copy,
                workspace.codeql_database,
                workspace.temporary,
            ):
                if target.exists() or target.is_symlink():
                    raise WorkspaceConflictError(
                        f"run path exists without an ownership descriptor: {target}"
                    )
            self._ensure_directory(artifact_run_root, self._artifact_root)

        preparing_descriptor = dict(expected_descriptor)
        preparing_descriptor["status"] = "preparing"
        preparing_descriptor["prepared_at"] = datetime.now(UTC).isoformat()
        self._atomic_write_json(descriptor_path, preparing_descriptor)

        if workspace.build_copy.exists() and preparing_descriptor["status"] == "preparing":
            self._validate_existing_directory(workspace.build_copy, self._workspace_root)
            if self._tree_digest(workspace.build_copy) != snapshot.source_tree_sha256:
                self._remove_managed_tree(workspace.build_copy)
        if not workspace.build_copy.exists():
            self._materialize_build_copy(
                workspace.source_snapshot,
                workspace.build_copy,
                snapshot.source_tree_sha256,
            )
        else:
            self._validate_existing_directory(workspace.build_copy, self._workspace_root)
        self._ensure_directory(workspace.codeql_database, self._workspace_root)
        self._ensure_directory(workspace.temporary, self._workspace_root)
        self._write_equal_or_new(
            artifact_run_root / _RESOLVED_SPEC_NAME,
            resolved_spec,
            artifact_run_root,
        )

        ready_descriptor = dict(expected_descriptor)
        ready_descriptor["prepared_at"] = preparing_descriptor["prepared_at"]
        self._atomic_write_json(descriptor_path, ready_descriptor)
        return WorkspaceAllocation(
            snapshot=snapshot,
            workspace=workspace,
            project_spec_sha256=spec_digest,
            prepared_at=self._descriptor_time(ready_descriptor),
        )

    def _validate_ready_run(self, workspace: RunWorkspace, resolved_spec: bytes) -> None:
        for path, root in (
            (workspace.build_copy, self._workspace_root),
            (workspace.codeql_database, self._workspace_root),
            (workspace.temporary, self._workspace_root),
        ):
            self._validate_existing_directory(path, root)
        spec_path = workspace.artifact_run_root / _RESOLVED_SPEC_NAME
        self._validate_managed_file(spec_path, workspace.artifact_run_root)
        if spec_path.read_bytes() != resolved_spec:
            raise WorkspaceConflictError(
                f"run {workspace.run_id} already exists with a different resolved spec"
            )

    def _workspace_for_id(self, run_id: str) -> RunWorkspace:
        """Build cleanup-only expected paths without requiring snapshot metadata."""

        zero_digest = "0" * 64
        return RunWorkspace(
            run_id=run_id,
            project_id="cleanup",
            snapshot_id=zero_digest,
            workspace_root=self._workspace_root,
            artifact_root=self._artifact_root,
            source_snapshot=self._managed_child(self._workspace_root, "sources", zero_digest),
            build_copy=self._managed_child(self._workspace_root, "build-copies", run_id),
            codeql_database=self._managed_child(self._workspace_root, "codeql-databases", run_id),
            temporary=self._managed_child(self._workspace_root, "temporary", run_id),
            artifact_run_root=self._managed_child(self._artifact_root, "runs", run_id),
        )

    @staticmethod
    def _descriptor(
        *,
        workspace: RunWorkspace,
        snapshot: RepositorySnapshot,
        spec_digest: str,
        status: str,
    ) -> dict[str, object]:
        return {
            "schema_version": "1.0",
            "status": status,
            "run_id": workspace.run_id,
            "project_id": workspace.project_id,
            "snapshot_id": snapshot.snapshot_id,
            "source_tree_sha256": snapshot.source_tree_sha256,
            "project_spec_sha256": spec_digest,
            "paths": {
                "source_snapshot": str(workspace.source_snapshot),
                "build_copy": str(workspace.build_copy),
                "codeql_database": str(workspace.codeql_database),
                "temporary": str(workspace.temporary),
                "artifact_run_root": str(workspace.artifact_run_root),
            },
        }

    @staticmethod
    def _validate_descriptor(existing: dict[str, object], expected: dict[str, object]) -> None:
        for key in (
            "schema_version",
            "run_id",
            "project_id",
            "snapshot_id",
            "source_tree_sha256",
            "project_spec_sha256",
            "paths",
        ):
            if existing.get(key) != expected.get(key):
                raise WorkspaceConflictError(f"run ownership descriptor differs at {key!r}")
        if existing.get("status") not in {"preparing", "ready"}:
            raise WorkspaceConflictError("run ownership descriptor has an invalid status")

    @staticmethod
    def _descriptor_time(descriptor: dict[str, object]) -> datetime:
        value = descriptor.get("prepared_at")
        if not isinstance(value, str):
            return datetime.now(UTC)
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            raise WorkspaceConflictError("descriptor prepared_at must include a timezone")
        return parsed.astimezone(UTC)

    @staticmethod
    def _read_descriptor(path: Path) -> dict[str, object]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise WorkspaceConflictError(f"invalid run ownership descriptor: {path}") from exc
        if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
            raise WorkspaceConflictError(f"invalid run ownership descriptor: {path}")
        return value

    def _materialize_snapshot(self, source: Path, destination: Path, digest: str) -> None:
        staging = destination.parent / f".staging-{digest}-{uuid.uuid4().hex}"
        self._assert_within(staging, self._workspace_root)
        try:
            shutil.copytree(source, staging, symlinks=True, copy_function=shutil.copy2)
            copied_digest = self._tree_digest(staging)
            if copied_digest != digest:
                raise WorkspaceConflictError(
                    "local source changed while its immutable snapshot was being copied"
                )
            self._make_tree_read_only(staging)
            os.replace(staging, destination)
        except FileExistsError:
            if not destination.is_dir():
                raise WorkspaceConflictError(
                    f"snapshot path already exists and is not a directory: {destination}"
                ) from None
        except OSError as exc:
            raise WorkspaceError(f"failed to create source snapshot: {exc}") from exc
        finally:
            if staging.exists() or staging.is_symlink():
                self._remove_managed_tree(staging)

    def _materialize_build_copy(
        self,
        source: Path,
        destination: Path,
        expected_digest: str,
    ) -> None:
        staging = destination.parent / f".staging-{destination.name}-{uuid.uuid4().hex}"
        self._assert_within(staging, self._workspace_root)
        try:
            observed_digest = self._tree_digest(source)
            if observed_digest != expected_digest:
                raise WorkspaceConflictError(
                    "managed source snapshot no longer matches its recorded identity"
                )
            shutil.copytree(source, staging, symlinks=True, copy_function=shutil.copy2)
            # A managed source snapshot cannot contain links.  Re-scan so an
            # externally tampered snapshot never reaches a writable build tree.
            copied_digest = self._tree_digest(staging)
            if copied_digest != expected_digest:
                raise WorkspaceConflictError(
                    "managed source snapshot changed while creating the build copy"
                )
            self._make_tree_writable(staging)
            os.replace(staging, destination)
        except OSError as exc:
            raise WorkspaceError(f"failed to create writable build copy: {exc}") from exc
        finally:
            if staging.exists() or staging.is_symlink():
                self._remove_managed_tree(staging)

    def _tree_digest(self, root: Path) -> str:
        self._reject_symlink_components(root)

        digest = hashlib.sha256()
        digest.update(_TREE_HASH_DOMAIN)
        counters = [0, 0]  # entries, total regular-file bytes
        self._hash_directory(root, digest, counters)
        return digest.hexdigest()

    def _hash_directory(
        self,
        root: Path,
        digest: _Digest,
        counters: list[int],
    ) -> None:
        """Hash a tree with bounded-memory iterative DFS in lexical order."""

        root_entries = self._scan_directory(root, None, counters)
        stack: list[tuple[Path, Path, int, list[tuple[str, os.stat_result]], int]] = [
            (root, Path(), 0, root_entries, 0)
        ]
        while stack:
            current, relative, depth, entries, index = stack[-1]
            if index >= len(entries):
                stack.pop()
                continue
            entry_name, metadata = entries[index]
            stack[-1] = (current, relative, depth, entries, index + 1)
            child_path = current / entry_name
            child_relative = relative / entry_name
            encoded_name = os.fsencode(child_relative.as_posix())
            mode = metadata.st_mode
            if stat.S_ISDIR(mode):
                digest.update(b"D\0")
                digest.update(encoded_name)
                digest.update(b"\0")
                child_depth = depth + 1
                if child_depth > self._maximum_depth:
                    raise WorkspaceError(
                        f"source exceeds maximum directory depth ({self._maximum_depth}): "
                        f"{child_path}"
                    )
                child_entries = self._scan_directory(child_path, metadata, counters)
                stack.append((child_path, child_relative, child_depth, child_entries, 0))
                continue

            digest.update(b"F\0")
            digest.update(encoded_name)
            digest.update(b"\0X\0" if mode & 0o111 else b"\0-\0")
            digest.update(str(metadata.st_size).encode("ascii"))
            digest.update(b"\0")
            self._hash_file(child_path, metadata, digest)
            digest.update(b"\0")

    def _scan_directory(
        self,
        path: Path,
        expected: os.stat_result | None,
        counters: list[int],
    ) -> list[tuple[str, os.stat_result]]:
        """Open one directory without following links and collect bounded metadata."""

        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise PathSafetyError(f"cannot securely open source directory {path}: {exc}") from exc
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISDIR(observed.st_mode):
                raise PathSafetyError(f"source entry is not a directory: {path}")
            if expected is not None and (observed.st_dev, observed.st_ino) != (
                expected.st_dev,
                expected.st_ino,
            ):
                raise WorkspaceConflictError(f"source directory changed while hashing: {path}")

            entries: list[tuple[str, os.stat_result]] = []
            try:
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        entry_path = path / entry.name
                        try:
                            metadata = entry.stat(follow_symlinks=False)
                        except OSError as exc:
                            raise WorkspaceError(
                                f"cannot stat source entry {entry_path}: {exc}"
                            ) from exc
                        mode = metadata.st_mode
                        counters[0] += 1
                        if counters[0] > self._maximum_files:
                            raise WorkspaceError(
                                f"source exceeds maximum entry count ({self._maximum_files})"
                            )
                        if stat.S_ISREG(mode):
                            counters[1] += metadata.st_size
                            if metadata.st_size > self._maximum_file_bytes:
                                raise WorkspaceError(
                                    "source file exceeds maximum size "
                                    f"({self._maximum_file_bytes} bytes): {entry_path}"
                                )
                            if counters[1] > self._maximum_total_bytes:
                                raise WorkspaceError(
                                    "source exceeds maximum total size "
                                    f"({self._maximum_total_bytes} bytes)"
                                )
                        elif not stat.S_ISDIR(mode):
                            if stat.S_ISLNK(mode):
                                raise PathSafetyError(
                                    f"symbolic links are not allowed: {entry_path}"
                                )
                            raise PathSafetyError(
                                f"only regular files and directories are allowed: {entry_path}"
                            )
                        entries.append((entry.name, metadata))
            except OSError as exc:
                raise WorkspaceError(f"cannot enumerate source directory {path}: {exc}") from exc
            entries.sort(key=lambda item: os.fsencode(item[0]))
            return entries
        finally:
            os.close(descriptor)

    @staticmethod
    def _hash_file(path: Path, expected: os.stat_result, digest: _Digest) -> None:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise PathSafetyError(f"cannot securely open source file {path}: {exc}") from exc
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode):
                raise PathSafetyError(f"source entry changed type while hashing: {path}")
            if (observed.st_dev, observed.st_ino, observed.st_size) != (
                expected.st_dev,
                expected.st_ino,
                expected.st_size,
            ):
                raise WorkspaceConflictError(f"source changed while hashing: {path}")
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
        finally:
            os.close(descriptor)

    @staticmethod
    def _make_tree_read_only(root: Path) -> None:
        for current, directory_names, file_names in os.walk(root, topdown=False):
            current_path = Path(current)
            for file_name in file_names:
                path = current_path / file_name
                mode = path.stat(follow_symlinks=False).st_mode
                executable = bool(mode & 0o111)
                path.chmod(0o500 if executable else 0o400, follow_symlinks=False)
            for directory_name in directory_names:
                (current_path / directory_name).chmod(0o500, follow_symlinks=False)
            current_path.chmod(0o500, follow_symlinks=False)

    @staticmethod
    def _make_tree_writable(root: Path) -> None:
        for current, directory_names, file_names in os.walk(root):
            current_path = Path(current)
            current_path.chmod(
                current_path.stat(follow_symlinks=False).st_mode | stat.S_IWUSR | stat.S_IXUSR,
                follow_symlinks=False,
            )
            for directory_name in directory_names:
                path = current_path / directory_name
                path.chmod(
                    path.stat(follow_symlinks=False).st_mode | stat.S_IWUSR | stat.S_IXUSR,
                    follow_symlinks=False,
                )
            for file_name in file_names:
                path = current_path / file_name
                path.chmod(
                    path.stat(follow_symlinks=False).st_mode | stat.S_IWUSR,
                    follow_symlinks=False,
                )

    def _normalize_root(self, value: str | Path, label: str) -> Path:
        raw = Path(value).expanduser()
        self._reject_parent_segments(raw, f"{label}_root")
        absolute = Path(os.path.abspath(raw))
        if absolute == Path(absolute.anchor):
            raise PathSafetyError(f"{label}_root must not be a filesystem root")
        self._reject_symlink_components(absolute, allow_missing=True)
        if absolute.exists() and not absolute.is_dir():
            raise PathSafetyError(f"{label}_root is not a directory: {absolute}")
        return absolute.resolve(strict=False)

    def _materialize_root(self, root: Path, label: str) -> Path:
        self._reject_symlink_components(root, allow_missing=True)
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise WorkspaceError(f"cannot create {label} root {root}: {exc}") from exc
        self._reject_symlink_components(root)
        if not root.is_dir():
            raise PathSafetyError(f"{label}_root is not a directory: {root}")
        root.chmod(0o700, follow_symlinks=False)
        canonical = root.resolve(strict=True)
        if canonical != root:
            raise PathSafetyError(f"{label}_root changed while being initialized: {root}")
        return canonical

    def _ensure_roots_initialized(self) -> None:
        with self._initialization_lock:
            if self._roots_initialized:
                return
            self._materialize_root(self._workspace_root, "workspace")
            self._materialize_root(self._artifact_root, "artifact")
            for category in (
                "sources",
                "build-copies",
                "codeql-databases",
                "temporary",
                "locks",
            ):
                self._ensure_directory(
                    self._workspace_root / category,
                    self._workspace_root,
                )
            self._ensure_directory(self._artifact_root / "runs", self._artifact_root)
            self._roots_initialized = True

    def _canonical_source(self, value: str | Path) -> Path:
        raw = Path(value).expanduser()
        self._reject_parent_segments(raw, "source_path")
        absolute = Path(os.path.abspath(raw))
        self._reject_symlink_components(absolute)
        try:
            canonical = absolute.resolve(strict=True)
        except OSError as exc:
            raise WorkspaceError(f"source path does not exist: {absolute}") from exc
        if not canonical.is_dir():
            raise WorkspaceError(f"source path is not a directory: {canonical}")
        return canonical

    @staticmethod
    def _reject_parent_segments(path: Path, label: str) -> None:
        if ".." in path.parts:
            raise PathSafetyError(f"{label} must not contain parent traversal")

    @staticmethod
    def _paths_overlap(first: Path, second: Path) -> bool:
        return first == second or first.is_relative_to(second) or second.is_relative_to(first)

    @staticmethod
    def _reject_symlink_components(path: Path, *, allow_missing: bool = False) -> None:
        absolute = path if path.is_absolute() else Path(os.path.abspath(path))
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                if allow_missing:
                    return
                raise PathSafetyError(f"path component does not exist: {current}") from None
            except OSError as exc:
                raise PathSafetyError(f"cannot inspect path component {current}: {exc}") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise PathSafetyError(f"symbolic-link path component is not allowed: {current}")

    def _managed_child(self, root: Path, category: str, identifier: str) -> Path:
        self._validate_identifier(identifier, "managed path identifier")
        category_path = root / category
        self._validate_existing_directory(category_path, root)
        candidate = category_path / identifier
        self._assert_within(candidate, root)
        if candidate.is_symlink():
            raise PathSafetyError(f"managed path must not be a symbolic link: {candidate}")
        return candidate

    def _ensure_directory(self, path: Path, root: Path) -> None:
        self._assert_within(path, root, allow_root=True)
        self._reject_symlink_components(root)
        if path.exists() or path.is_symlink():
            self._validate_existing_directory(path, root)
            path.chmod(0o700, follow_symlinks=False)
            return
        try:
            path.mkdir(parents=False)
        except FileExistsError:
            self._validate_existing_directory(path, root)
        except OSError as exc:
            raise WorkspaceError(f"cannot create managed directory {path}: {exc}") from exc
        self._validate_existing_directory(path, root)
        path.chmod(0o700, follow_symlinks=False)

    def _validate_existing_directory(self, path: Path, root: Path) -> None:
        self._assert_within(path, root, allow_root=True)
        self._reject_symlink_components(path)
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as exc:
            raise WorkspaceError(f"managed directory is unavailable {path}: {exc}") from exc
        if not stat.S_ISDIR(metadata.st_mode):
            raise PathSafetyError(f"managed path is not a directory: {path}")

    def _validate_managed_file(self, path: Path, root: Path) -> None:
        self._assert_within(path, root)
        self._reject_symlink_components(path)
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode):
            raise PathSafetyError(f"managed path is not a regular file: {path}")

    @staticmethod
    def _assert_within(path: Path, root: Path, *, allow_root: bool = False) -> None:
        candidate = path.resolve(strict=False)
        canonical_root = root.resolve(strict=True)
        if candidate == canonical_root:
            if allow_root:
                return
            raise PathSafetyError(f"managed child path resolves to its root: {path}")
        try:
            candidate.relative_to(canonical_root)
        except ValueError as exc:
            raise PathSafetyError(f"managed path escapes its configured root: {path}") from exc

    def _assert_exact_run_root(self, path: Path, root: Path, category: str, run_id: str) -> None:
        expected = root / category / run_id
        if path != expected:
            raise PathSafetyError(f"cleanup target is not an exact managed run root: {path}")
        self._assert_within(path, root)
        if path.exists() or path.is_symlink():
            self._reject_symlink_components(path)

    def _remove_managed_tree(self, path: Path) -> None:
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink():
            raise PathSafetyError(f"refusing to recursively remove symbolic link: {path}")
        try:
            self._make_tree_removable(path)
            shutil.rmtree(path)
        except OSError as exc:
            raise WorkspaceError(f"cannot remove managed run directory {path}: {exc}") from exc

    @staticmethod
    def _make_tree_removable(root: Path) -> None:
        """Add owner permissions without following links inside an owned tree."""

        for current, directory_names, _ in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            current_metadata = current_path.stat(follow_symlinks=False)
            current_path.chmod(
                current_metadata.st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
                follow_symlinks=False,
            )
            for directory_name in directory_names:
                directory = current_path / directory_name
                metadata = directory.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    continue
                directory.chmod(
                    metadata.st_mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
                    follow_symlinks=False,
                )

    def _write_equal_or_new(self, path: Path, data: bytes, root: Path) -> None:
        self._assert_within(path, root)
        if path.exists() or path.is_symlink():
            self._validate_managed_file(path, root)
            if path.read_bytes() != data:
                raise WorkspaceConflictError(f"managed file already has different content: {path}")
            return
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        self._assert_within(temporary, root)
        try:
            with temporary.open("xb") as output:
                temporary.chmod(0o600, follow_symlinks=False)
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            raise WorkspaceError(f"cannot write managed file {path}: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    def _atomic_write_json(self, path: Path, value: dict[str, object]) -> None:
        encoded = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
        temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
        self._assert_within(temporary, path.parent)
        try:
            with temporary.open("xb") as output:
                temporary.chmod(0o600, follow_symlinks=False)
                output.write(encoded)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            raise WorkspaceError(f"cannot write workspace descriptor {path}: {exc}") from exc
        finally:
            if temporary.exists():
                temporary.unlink()

    @contextmanager
    def _file_lock(self, key: str) -> Iterator[None]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,220}", key):
            raise PathSafetyError("invalid lock key")
        locks_root = self._workspace_root / "locks"
        self._validate_existing_directory(locks_root, self._workspace_root)
        path = locks_root / f"{key}.lock"
        self._assert_within(path, locks_root)
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except OSError as exc:
            raise PathSafetyError(f"cannot safely open workspace lock {path}: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PathSafetyError(f"workspace lock is not a regular file: {path}")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    @staticmethod
    def _validate_identifier(value: str, label: str) -> None:
        if not _SAFE_IDENTIFIER.fullmatch(value):
            raise PathSafetyError(f"{label} must match {_SAFE_IDENTIFIER.pattern!r}; got {value!r}")
