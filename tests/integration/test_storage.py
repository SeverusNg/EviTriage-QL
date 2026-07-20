from __future__ import annotations

import stat
from datetime import UTC
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select

from evitriage.errors import StorageError
from evitriage.storage import Database, Project, Run, WorkflowEvent


def test_initial_alembic_migration_and_sqlite_persistence(
    tmp_path: Path, repository_root: Path
) -> None:
    database_path = tmp_path / "nested" / "evitriage.sqlite"
    configuration = Config(str(repository_root / "alembic.ini"))
    configuration.set_main_option(
        "sqlalchemy.url", f"sqlite+pysqlite:///{database_path.as_posix()}"
    )
    command.upgrade(configuration, "head")

    database = Database.from_path(database_path)
    assert set(inspect(database.engine).get_table_names()) >= {
        "alembic_version",
        "projects",
        "runs",
        "workflow_events",
    }
    assert stat.S_IMODE(database_path.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(database_path.stat().st_mode) == 0o600
    digest = "a" * 64
    snapshot = "b" * 64
    with database.session() as session:
        session.add(
            Project(
                project_id="example",
                schema_version="1.0",
                spec_digest=digest,
                resolved_spec={"project": {"id": "example"}},
                source_identity="local-fixture",
            )
        )
        session.add(
            Run(
                run_id="run-one",
                project_id="example",
                snapshot_id=snapshot,
                project_spec_digest=digest,
                state="CREATED",
                workspace_path="/managed/workspaces/run-one",
                artifact_path="/managed/artifacts/run-one",
            )
        )
        session.add(
            WorkflowEvent(
                event_id="event-one",
                run_id="run-one",
                sequence=0,
                event_type="run_created",
                to_state="CREATED",
                idempotency_key="create-run-one",
                project_spec_digest=digest,
                snapshot_identity=snapshot,
                payload={"source": "fixture"},
            )
        )

    with database.session() as session:
        run = session.get(Run, "run-one")
        assert run is not None
        assert run.created_at.tzinfo is UTC
        events = session.scalars(
            select(WorkflowEvent).where(WorkflowEvent.run_id == "run-one")
        ).all()
        assert [event.event_id for event in events] == ["event-one"]
        assert events[0].payload == {"source": "fixture"}
        assert events[0].occurred_at.tzinfo is UTC
    database.dispose()


def test_direct_database_url_rejects_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.sqlite"
    target.touch()
    link = tmp_path / "linked.sqlite"
    link.symlink_to(target)

    with pytest.raises(StorageError, match="symbolic link"):
        Database(f"sqlite+pysqlite:///{link.as_posix()}")


def test_database_rejects_other_backends_and_rolls_back_failed_transactions() -> None:
    with pytest.raises(StorageError, match="SQLite"):
        Database("postgresql://localhost/evitriage")

    database = Database("sqlite+pysqlite:///:memory:")
    database.create_schema()
    project = Project(
        project_id="unique-project",
        schema_version="1.0",
        spec_digest="a" * 64,
        resolved_spec={"project": {"id": "unique-project"}},
        source_identity="local-fixture",
    )
    with database.session() as session:
        session.add(project)

    with (
        pytest.raises(StorageError, match="transaction failed"),
        database.session() as session,
    ):
        session.add(
            Project(
                project_id="unique-project",
                schema_version="1.0",
                spec_digest="b" * 64,
                resolved_spec={"project": {"id": "duplicate"}},
                source_identity="other-fixture",
            )
        )

    with database.session() as session:
        assert session.get(Project, "unique-project") is not None
    database.dispose()
