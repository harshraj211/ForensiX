"""Link acquisition plans to durable jobs and append-only progress events.

Revision ID: 0008_job_events
Revises: 0007_acquisition_plans
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_job_events"
down_revision: str | None = "0007_acquisition_plans"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(sa.Column("owner_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("case_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("plan_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("checkpoint_json", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("last_event_sequence", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.create_check_constraint("ck_jobs_last_event_sequence", "last_event_sequence >= 0")
        batch_op.create_unique_constraint("uq_jobs_plan_id", ["plan_id"])
        batch_op.create_foreign_key(
            "fk_jobs_owner_id_users", "users", ["owner_id"], ["id"], ondelete="RESTRICT"
        )
        batch_op.create_foreign_key(
            "fk_jobs_case_id_cases", "cases", ["case_id"], ["id"], ondelete="RESTRICT"
        )
        batch_op.create_foreign_key(
            "fk_jobs_plan_id_acquisition_plans",
            "acquisition_plans",
            ["plan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_index("ix_jobs_owner_id", ["owner_id"])
        batch_op.create_index("ix_jobs_case_id", ["case_id"])

    op.create_table(
        "job_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("current_step", sa.String(length=255), nullable=True),
        sa.Column("current_module", sa.String(length=128), nullable=True),
        sa.Column("checkpoint_json", sa.Text(), nullable=True),
        sa.Column("safe_detail", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence >= 1", name="ck_job_events_sequence"),
        sa.CheckConstraint(
            "progress_percent >= 0 AND progress_percent <= 100",
            name="ck_job_events_progress_percent",
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", "sequence", name="uq_job_events_job_sequence"),
    )
    op.create_index("ix_job_events_created_at", "job_events", ["created_at"])
    op.create_index("ix_job_events_event_type", "job_events", ["event_type"])
    op.create_index("ix_job_events_job_id", "job_events", ["job_id"])
    op.create_index("ix_job_events_state", "job_events", ["state"])


def downgrade() -> None:
    op.drop_index("ix_job_events_state", table_name="job_events")
    op.drop_index("ix_job_events_job_id", table_name="job_events")
    op.drop_index("ix_job_events_event_type", table_name="job_events")
    op.drop_index("ix_job_events_created_at", table_name="job_events")
    op.drop_table("job_events")

    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_index("ix_jobs_case_id")
        batch_op.drop_index("ix_jobs_owner_id")
        batch_op.drop_constraint("fk_jobs_plan_id_acquisition_plans", type_="foreignkey")
        batch_op.drop_constraint("fk_jobs_case_id_cases", type_="foreignkey")
        batch_op.drop_constraint("fk_jobs_owner_id_users", type_="foreignkey")
        batch_op.drop_constraint("uq_jobs_plan_id", type_="unique")
        batch_op.drop_constraint("ck_jobs_last_event_sequence", type_="check")
        batch_op.drop_column("last_event_sequence")
        batch_op.drop_column("checkpoint_json")
        batch_op.drop_column("plan_id")
        batch_op.drop_column("case_id")
        batch_op.drop_column("owner_id")
