"""Add experimental, working-copy-scoped SQLite recovery fragment scans.

Revision ID: 0037_recovery_carving
Revises: 0036_key_evidence
Create Date: 2026-08-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0037_recovery_carving"
down_revision: str | None = "0036_key_evidence"
branch_labels: str | Sequence[str] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_recovery_carving_runs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("inspection_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("executed_by", sa.String(36), nullable=False),
        sa.Column("maturity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(40), nullable=False),
        sa.Column("fragment_count", sa.Integer(), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("run_hash", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(32), nullable=False),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('candidate_fragments_observed', 'no_candidate_fragments', 'unsupported')",
            name="ck_evidence_recovery_carving_status",
        ),
        sa.CheckConstraint("fragment_count >= 0", name="ck_evidence_recovery_carving_count"),
        sa.CheckConstraint(
            "maturity = 'experimental'", name="ck_evidence_recovery_carving_maturity"
        ),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="RESTRICT"),
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
        sa.UniqueConstraint("run_hash", name="uq_evidence_recovery_carving_hash"),
        sa.UniqueConstraint("working_copy_id", name="uq_evidence_recovery_carving_working_copy"),
    )
    for column in (
        "case_id",
        "evidence_source_id",
        "executed_at",
        "executed_by",
        "inspection_id",
        "run_hash",
        "status",
        "working_copy_id",
    ):
        op.create_index(
            f"ix_evidence_recovery_carving_runs_{column}",
            "evidence_recovery_carving_runs",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "case_id",
            "evidence_source_id",
            "executed_at",
            "executed_by",
            "inspection_id",
            "run_hash",
            "status",
            "working_copy_id",
        )
    ):
        op.drop_index(
            f"ix_evidence_recovery_carving_runs_{column}",
            table_name="evidence_recovery_carving_runs",
        )
    op.drop_table("evidence_recovery_carving_runs")
