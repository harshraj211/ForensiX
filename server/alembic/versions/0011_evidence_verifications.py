"""Create append-only evidence verification records.

Revision ID: 0011_verifications
Revises: 0010_evidence_files
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011_verifications"
down_revision: str | None = "0010_evidence_files"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_verifications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("evidence_file_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("verified_by", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("expected_file_sha256", sa.String(length=64), nullable=False),
        sa.Column("observed_file_sha256", sa.String(length=64), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("file_matches", sa.Boolean(), nullable=False),
        sa.Column("expected_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("observed_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest_matches", sa.Boolean(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("verification_hash", sa.String(length=64), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('verified', 'mismatch', 'missing', 'error')",
            name="ck_evidence_verifications_status",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("verification_hash", name="uq_evidence_verifications_hash"),
    )
    for column in (
        "case_id",
        "evidence_file_id",
        "job_id",
        "status",
        "verification_hash",
        "verified_at",
        "verified_by",
    ):
        op.create_index(
            f"ix_evidence_verifications_{column}",
            "evidence_verifications",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "case_id",
            "evidence_file_id",
            "job_id",
            "status",
            "verification_hash",
            "verified_at",
            "verified_by",
        )
    ):
        op.drop_index(
            f"ix_evidence_verifications_{column}",
            table_name="evidence_verifications",
        )
    op.drop_table("evidence_verifications")
