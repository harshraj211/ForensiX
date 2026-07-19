"""Add sealed custody and audit checkpoint exports.

Revision ID: 0032_custody_checkpoints
Revises: 0031_recovery_assessments
Create Date: 2026-07-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032_custody_checkpoints"
down_revision: str | None = "0031_recovery_assessments"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "custody_checkpoints",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("custody_record_count", sa.Integer(), nullable=False),
        sa.Column("custody_head_hash", sa.String(64), nullable=True),
        sa.Column("audit_sequence", sa.Integer(), nullable=False),
        sa.Column("audit_head_hash", sa.String(64), nullable=True),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("storage_key", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("custody_record_count >= 0", name="ck_custody_checkpoints_count"),
        sa.CheckConstraint("audit_sequence >= 0", name="ck_custody_checkpoints_audit_sequence"),
        sa.CheckConstraint("size_bytes >= 1", name="ck_custody_checkpoints_size"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_custody_checkpoints_storage_key"),
    )
    for column in (
        "audit_head_hash",
        "case_id",
        "created_at",
        "created_by",
        "custody_head_hash",
        "sha256",
    ):
        op.create_index(
            f"ix_custody_checkpoints_{column}",
            "custody_checkpoints",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "audit_head_hash",
            "case_id",
            "created_at",
            "created_by",
            "custody_head_hash",
            "sha256",
        )
    ):
        op.drop_index(f"ix_custody_checkpoints_{column}", table_name="custody_checkpoints")
    op.drop_table("custody_checkpoints")
