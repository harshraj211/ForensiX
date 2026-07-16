"""Add durable acquisition partial recovery ledger.

Revision ID: 0013_partial_recovery
Revises: 0012_custody_audit
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0013_partial_recovery"
down_revision: str | None = "0012_custody_audit"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "acquisition_partials",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("evidence_file_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("disposition_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("disposition_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'retained', 'discarded', 'sealed', 'missing')",
            name="ck_acquisition_partials_status",
        ),
        sa.CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_acquisition_partials_size",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["disposition_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_acquisition_partials_storage_key"),
    )
    for column in (
        "case_id",
        "created_at",
        "created_by",
        "disposition_by",
        "evidence_file_id",
        "job_id",
        "reconciled_at",
        "sha256",
        "status",
    ):
        op.create_index(f"ix_acquisition_partials_{column}", "acquisition_partials", [column])


def downgrade() -> None:
    for column in reversed(
        (
            "case_id",
            "created_at",
            "created_by",
            "disposition_by",
            "evidence_file_id",
            "job_id",
            "reconciled_at",
            "sha256",
            "status",
        )
    ):
        op.drop_index(f"ix_acquisition_partials_{column}", table_name="acquisition_partials")
    op.drop_table("acquisition_partials")
