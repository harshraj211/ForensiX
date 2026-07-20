"""Add external anchor receipt records for custody checkpoints.

Revision ID: 0033_custody_checkpoint_anchors
Revises: 0032_custody_checkpoints
Create Date: 2026-07-20
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033_custody_checkpoint_anchors"
down_revision: str | None = "0032_custody_checkpoints"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "custody_checkpoint_anchors",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("checkpoint_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("recorded_by", sa.String(36), nullable=False),
        sa.Column("anchor_type", sa.String(32), nullable=False),
        sa.Column("anchor_provider", sa.String(255), nullable=False),
        sa.Column("anchor_reference", sa.String(512), nullable=False),
        sa.Column("anchored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=True),
        sa.Column("notes", sa.String(2000), nullable=True),
        sa.Column("anchor_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "anchor_type IN ('external_timestamp', 'digital_signature', "
            "'evidence_vault', 'case_management', 'other')",
            name="ck_custody_checkpoint_anchors_type",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["checkpoint_id"], ["custody_checkpoints.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["recorded_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("anchor_hash", name="uq_custody_checkpoint_anchors_hash"),
    )
    for column in (
        "anchor_hash",
        "anchor_type",
        "case_id",
        "checkpoint_sha256",
        "created_at",
        "receipt_sha256",
        "recorded_by",
    ):
        op.create_index(
            f"ix_custody_checkpoint_anchors_{column}",
            "custody_checkpoint_anchors",
            [column],
        )
    op.create_index(
        "ix_custody_checkpoint_anchors_checkpoint_created",
        "custody_checkpoint_anchors",
        ["checkpoint_id", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_custody_checkpoint_anchors_checkpoint_created",
        table_name="custody_checkpoint_anchors",
    )
    for column in reversed(
        (
            "anchor_hash",
            "anchor_type",
            "case_id",
            "checkpoint_sha256",
            "created_at",
            "receipt_sha256",
            "recorded_by",
        )
    ):
        op.drop_index(
            f"ix_custody_checkpoint_anchors_{column}",
            table_name="custody_checkpoint_anchors",
        )
    op.drop_table("custody_checkpoint_anchors")
