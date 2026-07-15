"""Create case-scoped device and readiness history tables.

Revision ID: 0006_case_devices
Revises: 0005_cases
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_case_devices"
down_revision: str | None = "0005_cases"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "case_devices",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("serial_hash", sa.String(length=64), nullable=False),
        sa.Column("serial_suffix", sa.String(length=8), nullable=False),
        sa.Column("manufacturer", sa.String(length=255), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("android_version", sa.String(length=64), nullable=True),
        sa.Column("sdk_level", sa.Integer(), nullable=True),
        sa.Column("build_fingerprint", sa.Text(), nullable=True),
        sa.Column("security_patch", sa.String(length=64), nullable=True),
        sa.Column("registered_by", sa.String(length=36), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["registered_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "serial_hash", name="uq_case_devices_case_serial_hash"),
    )
    op.create_index("ix_case_devices_case_id", "case_devices", ["case_id"])
    op.create_index("ix_case_devices_first_seen_at", "case_devices", ["first_seen_at"])
    op.create_index("ix_case_devices_last_seen_at", "case_devices", ["last_seen_at"])
    op.create_index("ix_case_devices_registered_by", "case_devices", ["registered_by"])
    op.create_index("ix_case_devices_serial_hash", "case_devices", ["serial_hash"])

    op.create_table(
        "case_device_detections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("operator_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("adb_version", sa.String(length=32), nullable=False),
        sa.Column("device_count", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.CheckConstraint("device_count >= 0", name="ck_case_device_detections_count"),
        sa.CheckConstraint(
            "result IN ('no_devices', 'single_device', 'multiple_devices')",
            name="ck_case_device_detections_result",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["operator_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_case_device_detections_case_id", "case_device_detections", ["case_id"])
    op.create_index(
        "ix_case_device_detections_observed_at",
        "case_device_detections",
        ["observed_at"],
    )
    op.create_index(
        "ix_case_device_detections_operator_id",
        "case_device_detections",
        ["operator_id"],
    )
    op.create_index("ix_case_device_detections_result", "case_device_detections", ["result"])

    op.create_table(
        "case_device_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("assessed_by", sa.String(length=36), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("package_count", sa.Integer(), nullable=False),
        sa.Column("assessor_version", sa.String(length=32), nullable=False),
        sa.Column("snapshot_json", sa.Text(), nullable=False),
        sa.CheckConstraint("package_count >= 0", name="ck_case_device_assessments_packages"),
        sa.ForeignKeyConstraint(["assessed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_case_device_assessments_assessed_at",
        "case_device_assessments",
        ["assessed_at"],
    )
    op.create_index(
        "ix_case_device_assessments_assessed_by",
        "case_device_assessments",
        ["assessed_by"],
    )
    op.create_index("ix_case_device_assessments_case_id", "case_device_assessments", ["case_id"])
    op.create_index(
        "ix_case_device_assessments_device_id",
        "case_device_assessments",
        ["device_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_case_device_assessments_device_id", table_name="case_device_assessments")
    op.drop_index("ix_case_device_assessments_case_id", table_name="case_device_assessments")
    op.drop_index("ix_case_device_assessments_assessed_by", table_name="case_device_assessments")
    op.drop_index("ix_case_device_assessments_assessed_at", table_name="case_device_assessments")
    op.drop_table("case_device_assessments")
    op.drop_index("ix_case_device_detections_result", table_name="case_device_detections")
    op.drop_index("ix_case_device_detections_operator_id", table_name="case_device_detections")
    op.drop_index("ix_case_device_detections_observed_at", table_name="case_device_detections")
    op.drop_index("ix_case_device_detections_case_id", table_name="case_device_detections")
    op.drop_table("case_device_detections")
    op.drop_index("ix_case_devices_serial_hash", table_name="case_devices")
    op.drop_index("ix_case_devices_registered_by", table_name="case_devices")
    op.drop_index("ix_case_devices_last_seen_at", table_name="case_devices")
    op.drop_index("ix_case_devices_first_seen_at", table_name="case_devices")
    op.drop_index("ix_case_devices_case_id", table_name="case_devices")
    op.drop_table("case_devices")
