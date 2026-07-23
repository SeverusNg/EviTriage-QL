from __future__ import annotations

import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from pydantic import ValidationError

from evitriage.domain.workspace import RepositorySnapshot, RunWorkspace, WorkspaceAllocation
from evitriage.errors import PathSafetyError, WorkspaceConflictError, WorkspaceError
from evitriage.workspace import WorkspaceManager


def _source(root: Path) -> Path:
    source = root / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "Main.java").write_text("class Main {}\n", encoding="utf-8")
    return source


def test_prepare_uses_read_only_shared_snapshot_and_writable_run_copy(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    original = (source / "src" / "Main.java").read_bytes()
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")

    first = manager.prepare(source, "project-one", "project: one\n", "run-one")
    second = manager.prepare(source, "project-one", "project: one\n", "run-two")

    assert first.snapshot.snapshot_id == second.snapshot.snapshot_id
    assert first.workspace.source_snapshot == second.workspace.source_snapshot
    assert first.workspace.build_copy != second.workspace.build_copy
    snapshot_mode = (first.workspace.source_snapshot / "src" / "Main.java").stat().st_mode
    assert not snapshot_mode & stat.S_IWUSR
    (first.workspace.build_copy / "src" / "Main.java").write_text(
        "class Changed {}\n", encoding="utf-8"
    )
    assert (source / "src" / "Main.java").read_bytes() == original
    assert (second.workspace.build_copy / "src" / "Main.java").read_bytes() == original
    assert first.project_spec_sha256 == hashlib.sha256(b"project: one\n").hexdigest()


def test_snapshot_and_build_copy_never_expand_source_permissions(tmp_path: Path) -> None:
    source = _source(tmp_path)
    source_file = source / "src" / "Main.java"
    source_file.chmod(0o600)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")

    allocation = manager.prepare(source, "project-one", "project: one\n", "private-run")

    assert stat.S_IMODE(source_file.stat().st_mode) == 0o600
    snapshot_file = allocation.workspace.source_snapshot / "src" / "Main.java"
    build_file = allocation.workspace.build_copy / "src" / "Main.java"
    assert stat.S_IMODE(snapshot_file.stat().st_mode) == 0o400
    assert stat.S_IMODE(build_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(manager.workspace_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(manager.artifact_root.stat().st_mode) == 0o700


def test_workspace_domain_models_reject_inconsistent_or_escaping_paths(
    tmp_path: Path,
) -> None:
    first_digest = "a" * 64
    second_digest = "b" * 64
    with pytest.raises(ValidationError, match="source_tree_sha256"):
        RepositorySnapshot(
            snapshot_id=first_digest,
            origin="fixture",
            checkout_path=tmp_path / "snapshot",
            source_tree_sha256=second_digest,
        )

    valid_workspace = RunWorkspace(
        run_id="run-one",
        project_id="project-one",
        snapshot_id=first_digest,
        workspace_root=tmp_path / "workspaces",
        artifact_root=tmp_path / "artifacts",
        source_snapshot=tmp_path / "workspaces/sources/snapshot",
        build_copy=tmp_path / "workspaces/build-copies/run-one",
        codeql_database=tmp_path / "workspaces/codeql-databases/run-one",
        temporary=tmp_path / "workspaces/temporary/run-one",
        artifact_run_root=tmp_path / "artifacts/runs/run-one",
    )
    escaping = valid_workspace.model_dump()
    escaping["build_copy"] = tmp_path / "workspaces/../outside/run-one"
    with pytest.raises(ValidationError, match="parent traversal"):
        RunWorkspace.model_validate(escaping)

    snapshot = RepositorySnapshot(
        snapshot_id=first_digest,
        origin="fixture",
        checkout_path=tmp_path / "snapshot",
        source_tree_sha256=first_digest,
    )
    mismatched_workspace = valid_workspace.model_copy(update={"snapshot_id": second_digest})
    with pytest.raises(ValidationError, match="must match"):
        WorkspaceAllocation(
            snapshot=snapshot,
            workspace=mismatched_workspace,
            project_spec_sha256=first_digest,
        )


def test_prepare_is_idempotent_but_rejects_changed_run_inputs(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    first = manager.prepare(source, "project-one", "project: one\n", "same-run")
    assert (
        manager.prepare(source, "project-one", "project: one\n", "same-run").workspace
        == first.workspace
    )
    with pytest.raises(WorkspaceConflictError):
        manager.prepare(source, "project-one", "project: changed\n", "same-run")


def test_tampered_snapshot_cannot_seed_a_new_build_copy(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    snapshot = manager.snapshot_local_source(source)
    snapshot_file = snapshot.checkout_path / "src" / "Main.java"
    snapshot_file.chmod(0o600)
    snapshot_file.write_text("class Tampered {}\n", encoding="utf-8")

    with pytest.raises(WorkspaceConflictError, match="recorded identity"):
        manager.create_run(
            project_id="project-one",
            snapshot=snapshot,
            resolved_yaml="project: one\n",
            run_id="tampered-run",
        )


@pytest.mark.security
def test_symlink_is_rejected_and_cleanup_is_exact(tmp_path: Path) -> None:
    source = _source(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("keep", encoding="utf-8")
    (source / "escape").symlink_to(outside)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    with pytest.raises(PathSafetyError):
        manager.prepare(source, "project-one", "project: one\n", "unsafe-run")

    (source / "escape").unlink()
    allocation = manager.prepare(source, "project-one", "project: one\n", "safe-run")
    sibling = manager.workspace_root / "build-copies" / "other-run"
    sibling.mkdir()
    manager.cleanup_run(allocation)
    assert sibling.is_dir()
    assert allocation.workspace.source_snapshot.is_dir()
    assert outside.read_text(encoding="utf-8") == "keep"
    with pytest.raises(PathSafetyError):
        manager.cleanup_run("../outside")


def test_roots_and_sources_must_not_overlap(tmp_path: Path) -> None:
    with pytest.raises(PathSafetyError, match="non-overlapping"):
        WorkspaceManager(tmp_path / "managed", tmp_path / "managed" / "artifacts")
    assert not (tmp_path / "managed").exists()

    source = _source(tmp_path)
    manager = WorkspaceManager(source / "workspaces", tmp_path / "artifacts")
    with pytest.raises(PathSafetyError, match="overlap"):
        manager.snapshot_local_source(source)
    assert not (source / "workspaces").exists()
    assert not (tmp_path / "artifacts").exists()


def test_source_entry_limit_counts_directories(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(
        tmp_path / "workspaces",
        tmp_path / "artifacts",
        maximum_files=1,
    )

    with pytest.raises(WorkspaceError, match="entry count"):
        manager.snapshot_local_source(source)


def test_source_depth_limit_returns_a_structured_workspace_error(tmp_path: Path) -> None:
    source = tmp_path / "source"
    deepest = source / "one" / "two" / "three"
    deepest.mkdir(parents=True)
    manager = WorkspaceManager(
        tmp_path / "workspaces",
        tmp_path / "artifacts",
        maximum_depth=2,
    )

    with pytest.raises(WorkspaceError, match="maximum directory depth"):
        manager.snapshot_local_source(source)


def test_constructor_and_source_resource_limits_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="maximum_files"):
        WorkspaceManager(tmp_path / "w1", tmp_path / "a1", maximum_files=0)
    with pytest.raises(ValueError, match="maximum_total_bytes"):
        WorkspaceManager(tmp_path / "w2", tmp_path / "a2", maximum_total_bytes=0)
    with pytest.raises(ValueError, match="maximum_file_bytes"):
        WorkspaceManager(tmp_path / "w3", tmp_path / "a3", maximum_file_bytes=0)
    with pytest.raises(ValueError, match="maximum_depth"):
        WorkspaceManager(tmp_path / "w4", tmp_path / "a4", maximum_depth=0)

    invalid_root = tmp_path / "root-file"
    invalid_root.write_text("not a directory", encoding="utf-8")
    with pytest.raises(PathSafetyError, match="not a directory"):
        WorkspaceManager(invalid_root, tmp_path / "artifacts")

    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    with pytest.raises(PathSafetyError, match="does not exist"):
        manager.snapshot_local_source(tmp_path / "missing")
    source_file = tmp_path / "source-file"
    source_file.write_text("not a directory", encoding="utf-8")
    with pytest.raises(WorkspaceError, match="not a directory"):
        manager.snapshot_local_source(source_file)


def test_file_size_total_size_and_special_file_limits(tmp_path: Path) -> None:
    large_source = tmp_path / "large-source"
    large_source.mkdir()
    (large_source / "large.bin").write_bytes(b"1234")
    large_manager = WorkspaceManager(
        tmp_path / "large-workspaces",
        tmp_path / "large-artifacts",
        maximum_file_bytes=3,
    )
    with pytest.raises(WorkspaceError, match="maximum size"):
        large_manager.snapshot_local_source(large_source)

    total_source = tmp_path / "total-source"
    total_source.mkdir()
    (total_source / "one.bin").write_bytes(b"12")
    (total_source / "two.bin").write_bytes(b"34")
    total_manager = WorkspaceManager(
        tmp_path / "total-workspaces",
        tmp_path / "total-artifacts",
        maximum_total_bytes=3,
    )
    with pytest.raises(WorkspaceError, match="maximum total size"):
        total_manager.snapshot_local_source(total_source)

    special_source = tmp_path / "special-source"
    special_source.mkdir()
    os.mkfifo(special_source / "named-pipe")
    special_manager = WorkspaceManager(
        tmp_path / "special-workspaces",
        tmp_path / "special-artifacts",
    )
    with pytest.raises(PathSafetyError, match="regular files"):
        special_manager.snapshot_local_source(special_source)


def test_create_run_rejects_forged_snapshot_identity_and_checkout(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    snapshot = manager.snapshot_local_source(source)
    forged_identity = snapshot.model_copy(update={"source_tree_sha256": "f" * 64})
    with pytest.raises(WorkspaceConflictError, match="source tree identity"):
        manager.create_run(
            project_id="project-one",
            snapshot=forged_identity,
            resolved_yaml="project: one\n",
        )

    forged_checkout = snapshot.model_copy(update={"checkout_path": tmp_path / "outside"})
    with pytest.raises(PathSafetyError, match="not managed"):
        manager.create_run(
            project_id="project-one",
            snapshot=forged_checkout,
            resolved_yaml="project: one\n",
        )

    generated = manager.create_run(
        project_id="project-one",
        snapshot=snapshot,
        resolved_yaml="project: one\n",
    )
    assert generated.workspace.run_id


def test_descriptor_tampering_is_rejected_before_reuse_or_cleanup(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")

    invalid_identity = manager.prepare(source, "project-one", "project: one\n", "invalid-identity")
    identity_descriptor = invalid_identity.workspace.artifact_run_root / ".evitriage-workspace.json"
    identity_value = json.loads(identity_descriptor.read_text(encoding="utf-8"))
    identity_value["run_id"] = "different-run"
    identity_descriptor.write_text(json.dumps(identity_value), encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="invalid identity"):
        manager.cleanup_run(invalid_identity)

    invalid_paths = manager.prepare(source, "project-one", "project: one\n", "invalid-paths")
    paths_descriptor = invalid_paths.workspace.artifact_run_root / ".evitriage-workspace.json"
    paths_value = json.loads(paths_descriptor.read_text(encoding="utf-8"))
    paths_value["paths"] = {}
    paths_descriptor.write_text(json.dumps(paths_value), encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="invalid paths"):
        manager.cleanup_run(invalid_paths)

    invalid_json = manager.prepare(source, "project-one", "project: one\n", "invalid-json")
    json_descriptor = invalid_json.workspace.artifact_run_root / ".evitriage-workspace.json"
    json_descriptor.write_text("not-json", encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="invalid run ownership descriptor"):
        manager.cleanup_run(invalid_json)

    invalid_status = manager.prepare(source, "project-one", "project: one\n", "invalid-status")
    status_descriptor = invalid_status.workspace.artifact_run_root / ".evitriage-workspace.json"
    status_value = json.loads(status_descriptor.read_text(encoding="utf-8"))
    status_value["status"] = "unknown"
    status_descriptor.write_text(json.dumps(status_value), encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="invalid status"):
        manager.prepare(source, "project-one", "project: one\n", "invalid-status")

    changed_spec = manager.prepare(source, "project-one", "project: one\n", "changed-spec")
    spec_path = changed_spec.workspace.artifact_run_root / "project-spec.resolved.yaml"
    spec_path.write_text("tampered: true\n", encoding="utf-8")
    with pytest.raises(WorkspaceConflictError, match="different resolved spec"):
        manager.prepare(source, "project-one", "project: one\n", "changed-spec")

    fresh = WorkspaceManager(tmp_path / "fresh-workspaces", tmp_path / "fresh-artifacts")
    fresh.cleanup_run("not-created")


def test_concurrent_same_run_preparation_is_serialized_and_idempotent(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                manager.prepare,
                source,
                "project-one",
                "project: one\n",
                "concurrent-run",
            )
            for _ in range(2)
        ]
    allocations = [future.result(timeout=5) for future in futures]

    assert allocations[0].workspace == allocations[1].workspace
    assert allocations[0].project_spec_sha256 == allocations[1].project_spec_sha256


def test_cleanup_rejects_forged_workspace_paths(tmp_path: Path) -> None:
    source = _source(tmp_path)
    manager = WorkspaceManager(tmp_path / "workspaces", tmp_path / "artifacts")
    allocation = manager.prepare(source, "project-one", "project: one\n", "owned-run")
    outside = tmp_path / "outside"
    outside.mkdir()
    forged = allocation.workspace.model_copy(update={"build_copy": outside})

    with pytest.raises(PathSafetyError, match="build_copy"):
        manager.cleanup_run(forged)

    assert outside.is_dir()

    unowned = manager.workspace_root / "build-copies" / "unowned-run"
    unowned.mkdir()
    with pytest.raises(WorkspaceConflictError, match="ownership descriptor"):
        manager.cleanup_run("unowned-run")
    assert unowned.is_dir()
