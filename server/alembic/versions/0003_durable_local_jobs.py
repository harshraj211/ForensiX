"""Create durable local background jobs.

Revision ID: 0003_jobs
Revises: 0002_capabilities
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_jobs"
down_revision: str | None = "0002_capabilities"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_type", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("current_step", sa.String(length=255), nullable=True),
        sa.Column("current_module", sa.String(length=128), nullable=True),
        sa.Column("cancellation_requested", sa.Boolean(), nullable=False),
        sa.Column("resume_supported", sa.Boolean(), nullable=False),
        sa.Column("result_reference", sa.String(length=512), nullable=True),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_jobs_progress_percent",
        ),
        sa.CheckConstraint(
            "job_type IN ('device_assessment', 'acquisition', 'parsing', 'indexing', "
            "'hashing', 'timeline', 'report', 'export', 'hash_verification')",
            name="ck_jobs_job_type",
        ),
        sa.CheckConstraint(
            "state IN ('created', 'validating', 'ready', 'running', 'paused', "
            "'cancelling', 'cancelled', 'interrupted', 'failed', 'completed', "
            "'verifying', 'verified')",
            name="ck_jobs_state",
        ),
        sa.CheckConstraint("version >= 1", name="ck_jobs_version"),
    )
    op.create_index("ix_jobs_created_at", "jobs", ["created_at"])
    op.create_index("ix_jobs_job_type", "jobs", ["job_type"])
    op.create_index("ix_jobs_state", "jobs", ["state"])
    op.create_index("ix_jobs_updated_at", "jobs", ["updated_at"])


def downgrade() -> None:
    op.drop_index("ix_jobs_updated_at", table_name="jobs")
    op.drop_index("ix_jobs_state", table_name="jobs")
    op.drop_index("ix_jobs_job_type", table_name="jobs")
    op.drop_index("ix_jobs_created_at", table_name="jobs")
    op.drop_table("jobs")
