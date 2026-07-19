"""Create signature-based Evidence Twin inspection records.

Revision ID: 0022_evidence_twin_inspection
Revises: 0021_evidence_twin_chunk_manifest
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_evidence_twin_inspection"
down_revision: str | None = "0021_evidence_twin_chunk_manifest"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_source_inspections",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("inspected_by", sa.String(36), nullable=False),
        sa.Column("detected_type", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("encryption_state", sa.String(16), nullable=False),
        sa.Column("signature_json", sa.Text(), nullable=False),
        sa.Column("warnings_json", sa.Text(), nullable=False),
        sa.Column("detector_version", sa.String(32), nullable=False),
        sa.Column("inspection_hash", sa.String(64), nullable=False),
        sa.Column("inspected_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "detected_type IN ('zip', 'tar', 'sqlite', 'android_sparse', 'ext4', "
            "'f2fs', 'opaque', 'unknown')",
            name="ck_evidence_source_inspections_type",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_evidence_source_inspections_confidence",
        ),
        sa.CheckConstraint(
            "encryption_state IN ('not_detected', 'suspected', 'unknown')",
            name="ck_evidence_source_inspections_encryption",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["inspected_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["working_copy_id"], ["evidence_working_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("working_copy_id", name="uq_evidence_source_inspections_working_copy"),
        sa.UniqueConstraint("inspection_hash", name="uq_evidence_source_inspections_hash"),
    )
    for column in (
        "case_id",
        "confidence",
        "detected_type",
        "encryption_state",
        "evidence_source_id",
        "inspected_at",
        "inspected_by",
        "inspection_hash",
        "working_copy_id",
    ):
        op.create_index(
            f"ix_evidence_source_inspections_{column}",
            "evidence_source_inspections",
            [column],
        )


def downgrade() -> None:
    op.drop_table("evidence_source_inspections")
