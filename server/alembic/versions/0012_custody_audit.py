"""Create chained custody and audit histories.

Revision ID: 0012_custody_audit
Revises: 0011_verifications
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0012_custody_audit"
down_revision: str | None = "0011_verifications"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "custody_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("evidence_file_id", sa.String(36), nullable=True),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("from_custodian", sa.String(255), nullable=True),
        sa.Column("to_custodian", sa.String(255), nullable=True),
        sa.Column("location", sa.String(255), nullable=True),
        sa.Column("purpose", sa.String(1000), nullable=True),
        sa.Column("notes", sa.String(2000), nullable=True),
        sa.Column("related_event_id", sa.String(36), nullable=True),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence >= 1", name="ck_custody_events_sequence"),
        sa.CheckConstraint(
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'transferred', 'amendment')",
            name="ck_custody_events_type",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["related_event_id"], ["custody_events.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "sequence", name="uq_custody_events_case_sequence"),
        sa.UniqueConstraint("event_hash", name="uq_custody_events_hash"),
    )
    for column in (
        "actor_id",
        "case_id",
        "created_at",
        "event_hash",
        "event_type",
        "evidence_file_id",
    ):
        op.create_index(f"ix_custody_events_{column}", "custody_events", [column])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=True),
        sa.Column("actor_id", sa.String(36), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(32), nullable=False),
        sa.Column("object_id", sa.String(36), nullable=False),
        sa.Column("detail_json", sa.Text(), nullable=False),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence >= 1", name="ck_audit_logs_sequence"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sequence", name="uq_audit_logs_sequence"),
        sa.UniqueConstraint("entry_hash", name="uq_audit_logs_entry_hash"),
    )
    for column in ("actor_id", "case_id", "created_at", "entry_hash", "event_type", "object_id"):
        op.create_index(f"ix_audit_logs_{column}", "audit_logs", [column])


def downgrade() -> None:
    audit_columns = ("actor_id", "case_id", "created_at", "entry_hash", "event_type", "object_id")
    for column in reversed(audit_columns):
        op.drop_index(f"ix_audit_logs_{column}", table_name="audit_logs")
    op.drop_table("audit_logs")
    custody_columns = (
        "actor_id",
        "case_id",
        "created_at",
        "event_hash",
        "event_type",
        "evidence_file_id",
    )
    for column in reversed(custody_columns):
        op.drop_index(f"ix_custody_events_{column}", table_name="custody_events")
    op.drop_table("custody_events")
