"""Create case lifecycle, membership, and event tables.

Revision ID: 0005_cases
Revises: 0004_auth_rbac
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_cases"
down_revision: str | None = "0004_auth_rbac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_number", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("legal_authority", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "status IN ('open', 'active', 'closed', 'archived')",
            name="ck_cases_status",
        ),
        sa.CheckConstraint("version >= 1", name="ck_cases_version"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cases_case_number", "cases", ["case_number"], unique=True)
    op.create_index("ix_cases_created_at", "cases", ["created_at"])
    op.create_index("ix_cases_created_by", "cases", ["created_by"])
    op.create_index("ix_cases_status", "cases", ["status"])
    op.create_index("ix_cases_updated_at", "cases", ["updated_at"])

    op.create_table(
        "case_members",
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("access_level", sa.String(length=16), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_by", sa.String(length=36), nullable=False),
        sa.CheckConstraint(
            "access_level IN ('owner', 'investigator', 'analyst', 'supervisor', 'reviewer')",
            name="ck_case_members_access_level",
        ),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("case_id", "user_id"),
    )
    op.create_index("ix_case_members_access_level", "case_members", ["access_level"])

    op.create_table(
        "case_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("from_status", sa.String(length=16), nullable=True),
        sa.Column("to_status", sa.String(length=16), nullable=True),
        sa.Column("safe_detail", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_events_actor_id", "case_events", ["actor_id"])
    op.create_index("ix_case_events_case_id", "case_events", ["case_id"])
    op.create_index("ix_case_events_created_at", "case_events", ["created_at"])
    op.create_index("ix_case_events_event_type", "case_events", ["event_type"])


def downgrade() -> None:
    op.drop_index("ix_case_events_event_type", table_name="case_events")
    op.drop_index("ix_case_events_created_at", table_name="case_events")
    op.drop_index("ix_case_events_case_id", table_name="case_events")
    op.drop_index("ix_case_events_actor_id", table_name="case_events")
    op.drop_table("case_events")
    op.drop_index("ix_case_members_access_level", table_name="case_members")
    op.drop_table("case_members")
    op.drop_index("ix_cases_updated_at", table_name="cases")
    op.drop_index("ix_cases_status", table_name="cases")
    op.drop_index("ix_cases_created_by", table_name="cases")
    op.drop_index("ix_cases_created_at", table_name="cases")
    op.drop_index("ix_cases_case_number", table_name="cases")
    op.drop_table("cases")
