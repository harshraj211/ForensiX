"""Add unified key-evidence findings for both normalized artifact families.

Revision ID: 0036_key_evidence
Revises: 0035_media_analysis
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036_key_evidence"
down_revision: str | None = "0035_media_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "key_evidence",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("target_type", sa.String(24), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=True),
        sa.Column("source_artifact_id", sa.String(36), nullable=True),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("priority", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(2000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "target_type IN ('artifact', 'source_artifact')",
            name="ck_key_evidence_target_type",
        ),
        sa.CheckConstraint(
            "(target_type = 'artifact' AND artifact_id IS NOT NULL "
            "AND source_artifact_id IS NULL) OR "
            "(target_type = 'source_artifact' AND source_artifact_id IS NOT NULL "
            "AND artifact_id IS NULL)",
            name="ck_key_evidence_target_reference",
        ),
        sa.CheckConstraint(
            "priority IN ('critical', 'high', 'normal')",
            name="ck_key_evidence_priority",
        ),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["source_artifact_id"],
            ["evidence_source_artifacts.id"],
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", name="uq_key_evidence_artifact"),
        sa.UniqueConstraint(
            "source_artifact_id",
            name="uq_key_evidence_source_artifact",
        ),
    )
    for column in (
        "artifact_id",
        "case_id",
        "created_at",
        "created_by",
        "priority",
        "source_artifact_id",
        "target_type",
    ):
        op.create_index(f"ix_key_evidence_{column}", "key_evidence", [column])
    op.create_index(
        "ix_key_evidence_case_priority_created",
        "key_evidence",
        ["case_id", "priority", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_key_evidence_case_priority_created", table_name="key_evidence")
    for column in reversed(
        (
            "artifact_id",
            "case_id",
            "created_at",
            "created_by",
            "priority",
            "source_artifact_id",
            "target_type",
        )
    ):
        op.drop_index(f"ix_key_evidence_{column}", table_name="key_evidence")
    op.drop_table("key_evidence")
