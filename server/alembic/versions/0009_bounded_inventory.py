"""Persist bounded content-free shared-storage inventories.

Revision ID: 0009_inventory
Revises: 0008_job_events
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0009_inventory"
down_revision: str | None = "0008_job_events"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "acquisition_inventories",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("plan_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("root_id", sa.String(length=32), nullable=False),
        sa.Column("display_path", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("discovered_count", sa.Integer(), nullable=False),
        sa.Column("persisted_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("max_items", sa.Integer(), nullable=False),
        sa.Column("max_depth", sa.Integer(), nullable=False),
        sa.Column("manifest_hash", sa.String(length=64), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "discovered_count >= 0 AND persisted_count >= 0 AND skipped_count >= 0",
            name="ck_acquisition_inventories_counts",
        ),
        sa.CheckConstraint(
            "max_items >= 1 AND max_depth >= 1",
            name="ck_acquisition_inventories_limits",
        ),
        sa.CheckConstraint(
            "status IN ('completed', 'truncated')",
            name="ck_acquisition_inventories_status",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["plan_id"], ["acquisition_plans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id", name="uq_acquisition_inventories_job_id"),
        sa.UniqueConstraint("manifest_hash", name="uq_acquisition_inventories_manifest_hash"),
    )
    for column in (
        "case_id",
        "completed_at",
        "created_by",
        "device_id",
        "job_id",
        "manifest_hash",
        "plan_id",
        "status",
    ):
        op.create_index(
            f"ix_acquisition_inventories_{column}",
            "acquisition_inventories",
            [column],
        )

    op.create_table(
        "acquisition_inventory_items",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("inventory_id", sa.String(length=36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("path_hash", sa.String(length=64), nullable=False),
        sa.Column("extension", sa.String(length=32), nullable=True),
        sa.CheckConstraint("ordinal >= 1", name="ck_acquisition_inventory_items_ordinal"),
        sa.ForeignKeyConstraint(
            ["inventory_id"], ["acquisition_inventories.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "inventory_id", "ordinal", name="uq_acquisition_inventory_items_ordinal"
        ),
        sa.UniqueConstraint(
            "inventory_id", "path_hash", name="uq_acquisition_inventory_items_path_hash"
        ),
    )
    op.create_index(
        "ix_acquisition_inventory_items_extension",
        "acquisition_inventory_items",
        ["extension"],
    )
    op.create_index(
        "ix_acquisition_inventory_items_inventory_id",
        "acquisition_inventory_items",
        ["inventory_id"],
    )
    op.create_index(
        "ix_acquisition_inventory_items_path_hash",
        "acquisition_inventory_items",
        ["path_hash"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_acquisition_inventory_items_path_hash",
        table_name="acquisition_inventory_items",
    )
    op.drop_index(
        "ix_acquisition_inventory_items_inventory_id",
        table_name="acquisition_inventory_items",
    )
    op.drop_index(
        "ix_acquisition_inventory_items_extension",
        table_name="acquisition_inventory_items",
    )
    op.drop_table("acquisition_inventory_items")
    for column in reversed(
        (
            "case_id",
            "completed_at",
            "created_by",
            "device_id",
            "job_id",
            "manifest_hash",
            "plan_id",
            "status",
        )
    ):
        op.drop_index(
            f"ix_acquisition_inventories_{column}",
            table_name="acquisition_inventories",
        )
    op.drop_table("acquisition_inventories")
