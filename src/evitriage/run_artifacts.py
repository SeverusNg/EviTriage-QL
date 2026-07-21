"""Confined artifact persistence and append-only Gate B run journaling."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from evitriage.domain.run import (
    ArtifactRecord,
    ArtifactRole,
    RunManifest,
    WorkflowEvent,
    WorkflowState,
)
from evitriage.domain.workspace import WorkspaceAllocation
from evitriage.errors import PathSafetyError, WorkflowError, WorkspaceConflictError

_MANIFEST_NAME = "run-manifest.json"
_EVENT_LOG_NAME = "workflow-events.jsonl"
_DEFAULT_MAXIMUM_INPUT_BYTES = 64 * 1024 * 1024

_ALLOWED_TRANSITIONS: dict[WorkflowState, frozenset[WorkflowState]] = {
    WorkflowState.CREATED: frozenset({WorkflowState.PROJECT_VALIDATED}),
    WorkflowState.PROJECT_VALIDATED: frozenset({WorkflowState.WORKSPACE_READY}),
    WorkflowState.WORKSPACE_READY: frozenset({WorkflowState.SOURCE_READY}),
    WorkflowState.SOURCE_READY: frozenset(
        {WorkflowState.BUILD_READY, WorkflowState.SARIF_INGESTED}
    ),
    WorkflowState.BUILD_READY: frozenset({WorkflowState.CODEQL_DB_READY}),
    WorkflowState.CODEQL_DB_READY: frozenset({WorkflowState.SCANNED}),
    WorkflowState.SCANNED: frozenset({WorkflowState.NORMALIZED}),
    WorkflowState.SARIF_INGESTED: frozenset({WorkflowState.NORMALIZED}),
    WorkflowState.NORMALIZED: frozenset({WorkflowState.CONTEXT_READY}),
    WorkflowState.CONTEXT_READY: frozenset(),
    WorkflowState.INVALID_SARIF: frozenset(),
    WorkflowState.CODEQL_FAILED: frozenset(),
    WorkflowState.CONTEXT_INCOMPLETE: frozenset(),
}


class RunJournal:
    """Persist immutable artifacts and a validated state history for one run."""

    def __init__(
        self,
        allocation: WorkspaceAllocation,
        *,
        input_mode: Literal["sarif", "scan"],
    ) -> None:
        if input_mode not in {"sarif", "scan"}:
            raise ValueError("input_mode must be 'sarif' or 'scan'")
        run_root = allocation.workspace.artifact_run_root
        self._root = self._canonical_run_root(run_root)
        self._allocation = allocation
        self._input_mode = input_mode
        self._events: list[WorkflowEvent] = []
        self._artifacts: list[ArtifactRecord] = []
        self._tool_versions: dict[str, str] = {}
        self._state = WorkflowState.CREATED
        self._status: Literal["running", "completed", "failed"] = "running"
        self._started_at = datetime.now(UTC)
        self._updated_at = self._started_at
        self._completed_at: datetime | None = None
        self._event_log = self._root / _EVENT_LOG_NAME
        for audit_path in (self._event_log, self._root / _MANIFEST_NAME):
            if audit_path.exists() or audit_path.is_symlink():
                raise WorkspaceConflictError(f"run audit file already exists: {audit_path}")
        self._append_event(
            event_type="run_created",
            from_state=None,
            to_state=WorkflowState.CREATED,
        )
        self._persist_manifest()
        for relative_path, media_type in (
            (".evitriage-workspace.json", "application/json"),
            ("project-spec.resolved.yaml", "application/json"),
        ):
            self.record_existing_artifact(
                relative_path,
                role="metadata",
                media_type=media_type,
            )

    @property
    def state(self) -> WorkflowState:
        """Current validated workflow state."""

        return self._state

    @property
    def manifest(self) -> RunManifest:
        """Return the current immutable run manifest."""

        return RunManifest(
            run_id=self._allocation.workspace.run_id,
            project_id=self._allocation.workspace.project_id,
            input_mode=self._input_mode,
            project_spec_sha256=self._allocation.project_spec_sha256,
            snapshot_identity=self._allocation.snapshot.snapshot_id,
            state=self._state,
            status=self._status,
            artifacts=tuple(self._artifacts),
            events=tuple(self._events),
            tool_versions=dict(self._tool_versions),
            started_at=self._started_at,
            updated_at=self._updated_at,
            completed_at=self._completed_at,
        )

    def transition(
        self,
        to_state: WorkflowState,
        *,
        event_type: str,
        input_sha256: str | None = None,
        output_sha256: str | None = None,
        tool_manifest_sha256: str | None = None,
    ) -> WorkflowEvent:
        """Validate, append, and durably persist one state transition."""

        if self._status != "running":
            raise WorkflowError("cannot transition a finalized run")
        allowed = _ALLOWED_TRANSITIONS[self._state]
        if to_state not in allowed:
            raise WorkflowError(
                f"invalid workflow transition {self._state.value} -> {to_state.value}",
                details={"from_state": self._state.value, "to_state": to_state.value},
            )
        previous = self._state
        self._state = to_state
        event = self._append_event(
            event_type=event_type,
            from_state=previous,
            to_state=to_state,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            tool_manifest_sha256=tool_manifest_sha256,
        )
        self._persist_manifest()
        return event

    def add_tool_versions(self, versions: dict[str, str]) -> None:
        """Add non-secret tool versions to the manifest without overwriting entries."""

        if self._status != "running":
            raise WorkflowError("cannot modify a finalized run")
        for name, version in versions.items():
            if not name or not version or any(ord(character) < 32 for character in name + version):
                raise WorkflowError("tool version entries must be non-empty printable text")
            existing = self._tool_versions.get(name)
            if existing is not None and existing != version:
                raise WorkspaceConflictError(f"tool version for {name!r} changed during the run")
            self._tool_versions[name] = version
        self._updated_at = datetime.now(UTC)
        self._persist_manifest()

    def write_artifact(
        self,
        relative_path: str,
        content: bytes,
        *,
        role: ArtifactRole,
        media_type: str,
    ) -> ArtifactRecord:
        """Atomically write one new run-confined artifact and record its digest."""

        if self._status != "running":
            raise WorkflowError("cannot add artifacts to a finalized run")
        target = self._artifact_target(relative_path)
        self._write_new_file(target, content)
        record = ArtifactRecord(
            relative_path=relative_path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            role=role,
            media_type=media_type,
        )
        self._record_artifact(record)
        return record

    def ingest_file(
        self,
        source: Path,
        relative_path: str,
        *,
        role: ArtifactRole = "input",
        media_type: str = "application/octet-stream",
        maximum_bytes: int = _DEFAULT_MAXIMUM_INPUT_BYTES,
    ) -> tuple[ArtifactRecord, bytes]:
        """Read a bounded regular file without following links, then persist it."""

        if maximum_bytes < 1:
            raise ValueError("maximum_bytes must be positive")
        content = self._read_regular_file(source, maximum_bytes=maximum_bytes)
        record = self.write_artifact(
            relative_path,
            content,
            role=role,
            media_type=media_type,
        )
        return record, content

    def record_existing_artifact(
        self,
        relative_path: str,
        *,
        role: ArtifactRole,
        media_type: str,
        maximum_bytes: int = _DEFAULT_MAXIMUM_INPUT_BYTES,
    ) -> tuple[ArtifactRecord, bytes]:
        """Hash and register a file already produced below this run's artifact root."""

        if self._status != "running":
            raise WorkflowError("cannot add artifacts to a finalized run")
        if maximum_bytes < 1:
            raise ValueError("maximum_bytes must be positive")
        target = self._artifact_target(relative_path)
        content = self._read_regular_file(target, maximum_bytes=maximum_bytes)
        record = ArtifactRecord(
            relative_path=relative_path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            role=role,
            media_type=media_type,
        )
        self._record_artifact(record)
        return record, content

    def complete(self) -> RunManifest:
        """Finalize a run only after Gate C context and evidence are ready."""

        if self._status != "running" or self._state is not WorkflowState.CONTEXT_READY:
            raise WorkflowError("only a CONTEXT_READY run can be completed")
        self._finalize_registered_artifacts()
        self._status = "completed"
        self._completed_at = datetime.now(UTC)
        self._updated_at = self._completed_at
        self._persist_manifest()
        self._finalize_audit_files()
        return self.manifest

    def fail(
        self,
        state: WorkflowState,
        *,
        error_code: str,
        error_artifact_sha256: str | None = None,
    ) -> RunManifest:
        """Record one terminal input/context failure without fabricating success."""

        if state not in {
            WorkflowState.INVALID_SARIF,
            WorkflowState.CODEQL_FAILED,
            WorkflowState.CONTEXT_INCOMPLETE,
        }:
            raise WorkflowError("unsupported input/context failure state")
        if self._status != "running":
            raise WorkflowError("cannot fail a finalized run")
        self._finalize_registered_artifacts()
        previous = self._state
        self._state = state
        self._status = "failed"
        self._completed_at = datetime.now(UTC)
        self._updated_at = self._completed_at
        self._append_event(
            event_type="run_failed",
            from_state=previous,
            to_state=state,
            output_sha256=error_artifact_sha256,
            error_code=error_code,
        )
        self._persist_manifest()
        self._finalize_audit_files()
        return self.manifest

    def _append_event(
        self,
        *,
        event_type: str,
        from_state: WorkflowState | None,
        to_state: WorkflowState,
        input_sha256: str | None = None,
        output_sha256: str | None = None,
        tool_manifest_sha256: str | None = None,
        error_code: str | None = None,
    ) -> WorkflowEvent:
        event = WorkflowEvent(
            sequence=len(self._events),
            event_type=event_type,
            from_state=from_state,
            to_state=to_state,
            project_spec_sha256=self._allocation.project_spec_sha256,
            snapshot_identity=self._allocation.snapshot.snapshot_id,
            input_sha256=input_sha256,
            output_sha256=output_sha256,
            tool_manifest_sha256=tool_manifest_sha256,
            error_code=error_code,
        )
        serialized = (
            json.dumps(
                event.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._event_log, flags, 0o600)
            try:
                self._write_all(descriptor, serialized)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise WorkflowError(f"cannot append run event log: {exc}") from exc
        self._events.append(event)
        self._updated_at = event.occurred_at
        return event

    def _record_artifact(self, record: ArtifactRecord) -> None:
        if any(existing.relative_path == record.relative_path for existing in self._artifacts):
            raise WorkspaceConflictError(f"artifact is already recorded: {record.relative_path}")
        self._artifacts.append(record)
        self._persist_manifest()

    def _persist_manifest(self) -> None:
        payload = (
            json.dumps(
                self.manifest.model_dump(mode="json"),
                allow_nan=False,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )
        self._replace_owned_file(self._root / _MANIFEST_NAME, payload)

    def _finalize_audit_files(self) -> None:
        for path in (self._event_log, self._root / _MANIFEST_NAME):
            try:
                path.chmod(0o400, follow_symlinks=False)
            except OSError as exc:
                raise WorkflowError(f"cannot finalize run audit file {path}: {exc}") from exc

    def _finalize_registered_artifacts(self) -> None:
        """Re-verify every registered digest and make the exact files owner-read-only."""

        opened: list[tuple[ArtifactRecord, Path, int]] = []
        try:
            for record in self._artifacts:
                path = self._artifact_target(record.relative_path)
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                try:
                    descriptor = os.open(path, flags)
                except OSError as exc:
                    raise WorkflowError(f"cannot reopen registered artifact {path}: {exc}") from exc
                opened.append((record, path, descriptor))
                metadata = os.fstat(descriptor)
                if not stat.S_ISREG(metadata.st_mode):
                    raise WorkflowError(f"registered artifact is not a regular file: {path}")
                if metadata.st_size != record.size_bytes:
                    raise WorkflowError(
                        f"registered artifact size changed before finalization: {path}"
                    )
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                if digest.hexdigest() != record.sha256:
                    raise WorkflowError(
                        f"registered artifact digest changed before finalization: {path}"
                    )
            for _record, path, descriptor in opened:
                try:
                    os.fchmod(descriptor, 0o400)
                except OSError as exc:
                    raise WorkflowError(
                        f"cannot finalize registered artifact {path}: {exc}"
                    ) from exc
        finally:
            for _record, _path, descriptor in opened:
                os.close(descriptor)

    def _artifact_target(self, relative_path: str) -> Path:
        try:
            normalized = ArtifactRecord(
                relative_path=relative_path,
                sha256="0" * 64,
                size_bytes=0,
                role="metadata",
                media_type="application/octet-stream",
            ).relative_path
        except ValueError as exc:
            raise PathSafetyError(f"unsafe artifact path: {relative_path!r}") from exc
        relative = PurePosixPath(normalized)
        parent = self._root
        for part in relative.parts[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise PathSafetyError(f"artifact directory must not be a symlink: {parent}")
            with suppress(FileExistsError):
                parent.mkdir(mode=0o700)
            if not parent.is_dir() or parent.is_symlink():
                raise PathSafetyError(f"artifact parent is not a safe directory: {parent}")
            parent.chmod(0o700, follow_symlinks=False)
        target = parent / relative.name
        if target == self._root or not target.is_relative_to(self._root):
            raise PathSafetyError("artifact target escapes the managed run root")
        return target

    @staticmethod
    def _canonical_run_root(run_root: Path) -> Path:
        if not run_root.is_absolute() or run_root.is_symlink():
            raise PathSafetyError("artifact run root must be an absolute non-symlink directory")
        try:
            canonical = run_root.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise PathSafetyError(f"cannot resolve artifact run root: {run_root}") from exc
        if not canonical.is_dir():
            raise PathSafetyError("artifact run root must be a directory")
        return canonical

    @staticmethod
    def _read_regular_file(path: Path, *, maximum_bytes: int) -> bytes:
        absolute = path if path.is_absolute() else Path.cwd() / path
        absolute = Path(os.path.abspath(absolute))
        current = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            current /= part
            if current.is_symlink():
                raise PathSafetyError(f"input file path contains a symbolic link: {current}")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(absolute, flags)
        except OSError as exc:
            raise WorkflowError(f"cannot securely open input file {absolute}: {exc}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise WorkflowError(f"input must be a regular file: {absolute}")
            if metadata.st_size > maximum_bytes:
                raise WorkflowError(
                    f"input exceeds maximum size ({maximum_bytes} bytes): {absolute}"
                )
            chunks: list[bytes] = []
            observed = 0
            while chunk := os.read(descriptor, min(1024 * 1024, maximum_bytes + 1)):
                observed += len(chunk)
                if observed > maximum_bytes:
                    raise WorkflowError(
                        f"input exceeds maximum size ({maximum_bytes} bytes): {absolute}"
                    )
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_new_file(target: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(target, flags, 0o600)
            try:
                RunJournal._write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError as exc:
            raise WorkspaceConflictError(f"refusing to overwrite run artifact: {target}") from exc
        except OSError as exc:
            raise WorkflowError(f"cannot write run artifact {target}: {exc}") from exc

    @staticmethod
    def _replace_owned_file(target: Path, content: bytes) -> None:
        if target.is_symlink():
            raise PathSafetyError(f"managed metadata must not be a symlink: {target}")
        temporary = target.parent / f".{target.name}.tmp-{uuid.uuid4().hex}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(temporary, flags, 0o600)
            try:
                RunJournal._write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, target)
            target.chmod(0o600, follow_symlinks=False)
        except OSError as exc:
            raise WorkflowError(f"cannot persist run manifest {target}: {exc}") from exc
        finally:
            if temporary.exists() and not temporary.is_symlink():
                temporary.unlink()

    @staticmethod
    def _write_all(descriptor: int, content: bytes) -> None:
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written < 1:
                raise OSError("short write while persisting run data")
            offset += written


__all__ = ["RunJournal"]
