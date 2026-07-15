"""Create immutable acquisition plan records.

Revision ID: 0007_acquisition_plans
Revises: 0006_case_devices
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_acquisition_plans"
down_revision: str | None = "0006_case_devices"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "acquisition_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("created_by", sa.String(length=36), nullable=False),
        sa.Column("scope", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("modules_json", sa.Text(), nullable=False),
        sa.Column("limitations_json", sa.Text(), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("plan_hash", sa.String(length=64), nullable=False),
        sa.Column("schema_version", sa.String(length=16), nullable=False),
        sa.Column("readiness_assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("readiness_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', 'custom')",
            name="ck_acquisition_plans_scope",
        ),
        sa.CheckConstraint("status IN ('ready')", name="ck_acquisition_plans_status"),
        sa.ForeignKeyConstraint(
            ["assessment_id"], ["case_device_assessments.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("plan_hash", name="uq_acquisition_plans_plan_hash"),
    )
    for column in (
        "assessment_id",
        "case_id",
        "created_at",
        "created_by",
        "device_id",
        "plan_hash",
        "readiness_assessed_at",
        "readiness_expires_at",
        "scope",
        "status",
    ):
        op.create_index(f"ix_acquisition_plans_{column}", "acquisition_plans", [column])


def downgrade() -> None:
    for column in reversed(
        (
            "assessment_id",
            "case_id",
            "created_at",
            "created_by",
            "device_id",
            "plan_hash",
            "readiness_assessed_at",
            "readiness_expires_at",
            "scope",
            "status",
        )
    ):
        op.drop_index(f"ix_acquisition_plans_{column}", table_name="acquisition_plans")
    op.drop_table("acquisition_plans")
