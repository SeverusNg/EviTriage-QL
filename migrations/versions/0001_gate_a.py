"""Create Gate A project, run, and workflow event tables.

Revision ID: 0001_gate_a
Revises: None
Create Date: 2026-07-20
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_gate_a"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the first durable Gate A schema."""

    op.create_table(
        "projects",
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("spec_digest", sa.String(length=64), nullable=False),
        sa.Column("resolved_spec", sa.JSON(), nullable=False),
        sa.Column("source_identity", sa.String(length=512), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(spec_digest) = 64", name="ck_projects_spec_digest_sha256"),
        sa.PrimaryKeyConstraint("project_id"),
    )
    op.create_table(
        "runs",
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("project_id", sa.String(length=128), nullable=False),
        sa.Column("snapshot_id", sa.String(length=64), nullable=False),
        sa.Column("project_spec_digest", sa.String(length=64), nullable=False),
        sa.Column("state", sa.String(length=64), nullable=False),
        sa.Column("workspace_path", sa.Text(), nullable=False),
        sa.Column("artifact_path", sa.Text(), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(project_spec_digest) = 64",
            name="ck_runs_project_spec_digest_sha256",
        ),
        sa.CheckConstraint("length(snapshot_id) = 64", name="ck_runs_snapshot_id_sha256"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.project_id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("run_id"),
    )
    op.create_index("ix_runs_project_created", "runs", ["project_id", "created_at"])
    op.create_table(
        "workflow_events",
        sa.Column("event_id", sa.String(length=128), nullable=False),
        sa.Column("run_id", sa.String(length=128), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=128), nullable=False),
        sa.Column("from_state", sa.String(length=64), nullable=True),
        sa.Column("to_state", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=True),
        sa.Column("project_spec_digest", sa.String(length=64), nullable=False),
        sa.Column("snapshot_identity", sa.String(length=128), nullable=False),
        sa.Column("input_sha256", sa.String(length=64), nullable=True),
        sa.Column("output_sha256", sa.String(length=64), nullable=True),
        sa.Column("tool_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("error_code", sa.String(length=128), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("retry_count >= 0", name="ck_workflow_events_retry_nonnegative"),
        sa.CheckConstraint("sequence >= 0", name="ck_workflow_events_sequence_nonnegative"),
        sa.ForeignKeyConstraint(["run_id"], ["runs.run_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("event_id"),
        sa.UniqueConstraint("run_id", "idempotency_key", name="uq_workflow_events_run_idempotency"),
        sa.UniqueConstraint("run_id", "sequence", name="uq_workflow_events_run_sequence"),
    )
    op.create_index(
        "ix_workflow_events_run_occurred",
        "workflow_events",
        ["run_id", "occurred_at"],
    )


def downgrade() -> None:
    """Remove the Gate A schema in reverse dependency order."""

    op.drop_index("ix_workflow_events_run_occurred", table_name="workflow_events")
    op.drop_table("workflow_events")
    op.drop_index("ix_runs_project_created", table_name="runs")
    op.drop_table("runs")
    op.drop_table("projects")
