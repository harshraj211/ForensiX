"""Persist selected evidence-file acquisition provenance.

Revision ID: 0010_evidence_files
Revises: 0009_inventory
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010_evidence_files"
down_revision: str | None = "0009_inventory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "acquired_evidence_files",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("inventory_id", sa.String(length=36), nullable=False),
        sa.Column("inventory_item_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("acquired_by", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("source_root_id", sa.String(length=32), nullable=False),
        sa.Column("source_path_hash", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.String(length=1024), nullable=False),
        sa.Column("manifest_storage_key", sa.String(length=1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest_hash", sa.String(length=64), nullable=True),
        sa.Column("transfer_limit_bytes", sa.Integer(), nullable=False),
        sa.Column("tool_version", sa.String(length=32), nullable=False),
        sa.Column("validation_state", sa.String(length=32), nullable=False),
        sa.Column("partial_preserved", sa.Boolean(), nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('acquiring', 'completed', 'failed', 'interrupted')",
            name="ck_acquired_evidence_files_status",
        ),
        sa.CheckConstraint(
            "validation_state IN ('not_physically_validated')",
            name="ck_acquired_evidence_files_validation_state",
        ),
        sa.CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0",
            name="ck_acquired_evidence_files_size",
        ),
        sa.CheckConstraint(
            "transfer_limit_bytes >= 1",
            name="ck_acquired_evidence_files_transfer_limit",
        ),
        sa.ForeignKeyConstraint(
            ["inventory_id"], ["acquisition_inventories.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["inventory_item_id"],
            ["acquisition_inventory_items.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["plan_id"], ["acquisition_plans.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["acquired_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("inventory_item_id", name="uq_acquired_evidence_files_item"),
        sa.UniqueConstraint("storage_key", name="uq_acquired_evidence_files_storage_key"),
        sa.UniqueConstraint(
            "manifest_storage_key", name="uq_acquired_evidence_files_manifest_storage_key"
        ),
        sa.UniqueConstraint("manifest_hash", name="uq_acquired_evidence_files_manifest_hash"),
    )
    for column in (
        "acquired_by",
        "case_id",
        "completed_at",
        "device_id",
        "inventory_id",
        "inventory_item_id",
        "job_id",
        "manifest_hash",
        "plan_id",
        "sha256",
        "source_path_hash",
        "status",
    ):
        op.create_index(
            f"ix_acquired_evidence_files_{column}",
            "acquired_evidence_files",
            [column],
        )


def downgrade() -> None:
    for column in reversed(
        (
            "acquired_by",
            "case_id",
            "completed_at",
            "device_id",
            "inventory_id",
            "inventory_item_id",
            "job_id",
            "manifest_hash",
            "plan_id",
            "sha256",
            "source_path_hash",
            "status",
        )
    ):
        op.drop_index(
            f"ix_acquired_evidence_files_{column}",
            table_name="acquired_evidence_files",
        )
    op.drop_table("acquired_evidence_files")
