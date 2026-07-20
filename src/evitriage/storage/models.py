"""SQLAlchemy 2 persistence models for Gate A.

Large artifacts do not belong in these tables.  Hashes and managed filesystem
paths are stored instead so later gates can add normalized analysis records
without changing the run/event identity model.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    """Return an aware UTC timestamp for SQLAlchemy defaults."""

    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Persist aware UTC datetimes without losing awareness in SQLite."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("database timestamps must be timezone-aware")
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> datetime | None:
        del dialect
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base shared by migrations and runtime persistence."""


class Project(Base):
    """A validated, redacted project specification identity."""

    __tablename__ = "projects"
    __table_args__ = (
        CheckConstraint("length(spec_digest) = 64", name="ck_projects_spec_digest_sha256"),
    )

    project_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    spec_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    resolved_spec: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False)
    source_identity: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now, onupdate=utc_now
    )

    runs: Mapped[list[Run]] = relationship(back_populates="project")


class Run(Base):
    """Durable identity and current state for one workflow run."""

    __tablename__ = "runs"
    __table_args__ = (
        CheckConstraint(
            "length(project_spec_digest) = 64",
            name="ck_runs_project_spec_digest_sha256",
        ),
        CheckConstraint("length(snapshot_id) = 64", name="ck_runs_snapshot_id_sha256"),
        Index("ix_runs_project_created", "project_id", "created_at"),
    )

    run_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        ForeignKey("projects.project_id", ondelete="RESTRICT"), nullable=False
    )
    snapshot_id: Mapped[str] = mapped_column(String(64), nullable=False)
    project_spec_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False, default="CREATED")
    workspace_path: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_path: Mapped[str] = mapped_column(Text, nullable=False)
    manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), nullable=False, default=utc_now, onupdate=utc_now
    )

    project: Mapped[Project] = relationship(back_populates="runs")
    workflow_events: Mapped[list[WorkflowEvent]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="WorkflowEvent.sequence",
    )


class WorkflowEvent(Base):
    """Minimal state transition/audit row reserved for later workflow gates."""

    __tablename__ = "workflow_events"
    __table_args__ = (
        UniqueConstraint("run_id", "sequence", name="uq_workflow_events_run_sequence"),
        UniqueConstraint("run_id", "idempotency_key", name="uq_workflow_events_run_idempotency"),
        CheckConstraint("sequence >= 0", name="ck_workflow_events_sequence_nonnegative"),
        CheckConstraint("retry_count >= 0", name="ck_workflow_events_retry_nonnegative"),
        Index("ix_workflow_events_run_occurred", "run_id", "occurred_at"),
    )

    event_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    run_id: Mapped[str] = mapped_column(
        ForeignKey("runs.run_id", ondelete="CASCADE"), nullable=False
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(128), nullable=False)
    from_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_state: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    project_spec_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_identity: Mapped[str] = mapped_column(String(128), nullable=False)
    input_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_manifest_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload: Mapped[dict[str, object]] = mapped_column(JSON, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=False, default=utc_now)

    run: Mapped[Run] = relationship(back_populates="workflow_events")


# Explicit aliases ease migration from early Gate A code that used a ``Record``
# suffix while keeping concise names for new callers.
ProjectRecord = Project
RunRecord = Run
WorkflowEventRecord = WorkflowEvent

__all__ = [
    "Base",
    "Project",
    "ProjectRecord",
    "Run",
    "RunRecord",
    "UTCDateTime",
    "WorkflowEvent",
    "WorkflowEventRecord",
    "utc_now",
]
