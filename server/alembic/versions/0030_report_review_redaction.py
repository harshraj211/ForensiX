"""Add report redaction profiles and append-only review decisions.

Revision ID: 0030_report_review_redaction
Revises: 0029_media_metadata
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030_report_review_redaction"
down_revision: str | None = "0029_media_metadata"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("reports") as batch:
        batch.add_column(
            sa.Column("redaction_profile", sa.String(32), nullable=False, server_default="full")
        )
        batch.create_check_constraint(
            "ck_reports_redaction_profile",
            "redaction_profile IN ('full', 'mask_sensitive', 'metadata_only')",
        )
    op.create_table(
        "report_review_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("report_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("reviewed_by", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("note", sa.String(1000), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence >= 1", name="ck_report_review_events_sequence"),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected')", name="ck_report_review_events_decision"
        ),
        sa.ForeignKeyConstraint(["report_id"], ["reports.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", "sequence", name="uq_report_review_sequence"),
        sa.UniqueConstraint("event_hash", name="uq_report_review_event_hash"),
    )
    for column in ("case_id", "created_at", "decision", "report_id", "reviewed_by"):
        op.create_index(f"ix_report_review_events_{column}", "report_review_events", [column])


def downgrade() -> None:
    for column in reversed(("case_id", "created_at", "decision", "report_id", "reviewed_by")):
        op.drop_index(f"ix_report_review_events_{column}", table_name="report_review_events")
    op.drop_table("report_review_events")
    with op.batch_alter_table("reports") as batch:
        batch.drop_constraint("ck_reports_redaction_profile", type_="check")
        batch.drop_column("redaction_profile")
