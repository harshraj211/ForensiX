"""Add experimental SQLite recovery-readiness assessments.

Revision ID: 0031_recovery_assessments
Revises: 0030_report_review_redaction
Create Date: 2026-07-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031_recovery_assessments"
down_revision: str | None = "0030_report_review_redaction"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_recovery_assessments",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("inspection_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("assessed_by", sa.String(36), nullable=False),
        sa.Column("maturity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("candidate_region_count", sa.Integer(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("assessment_hash", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(32), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('candidate_regions_observed', 'no_candidate_regions', 'unsupported')",
            name="ck_evidence_recovery_assessments_status",
        ),
        sa.CheckConstraint(
            "candidate_region_count >= 0", name="ck_evidence_recovery_assessments_count"
        ),
        sa.CheckConstraint("maturity = 'experimental'", name="ck_evidence_recovery_maturity"),
        sa.ForeignKeyConstraint(["assessed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["inspection_id"], ["evidence_source_inspections.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["working_copy_id"], ["evidence_working_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assessment_hash", name="uq_evidence_recovery_hash"),
        sa.UniqueConstraint("working_copy_id", name="uq_evidence_recovery_working_copy"),
    )
    for column in (
        "assessed_at",
        "assessed_by",
        "assessment_hash",
        "case_id",
        "evidence_source_id",
        "inspection_id",
        "status",
        "working_copy_id",
    ):
        op.create_index(
            f"ix_evidence_recovery_assessments_{column}",
            "evidence_recovery_assessments",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "assessed_at",
            "assessed_by",
            "assessment_hash",
            "case_id",
            "evidence_source_id",
            "inspection_id",
            "status",
            "working_copy_id",
        )
    ):
        op.drop_index(
            f"ix_evidence_recovery_assessments_{column}",
            table_name="evidence_recovery_assessments",
        )
    op.drop_table("evidence_recovery_assessments")
