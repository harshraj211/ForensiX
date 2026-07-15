"""Create immutable device capability snapshots.

Revision ID: 0002_capabilities
Revises: 0001_phase0
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002_capabilities"
down_revision: str | None = "0001_phase0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "device_capability_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("serial_hash", sa.String(length=64), nullable=False),
        sa.Column("manufacturer", sa.String(length=255), nullable=True),
        sa.Column("model", sa.String(length=255), nullable=True),
        sa.Column("android_version", sa.String(length=64), nullable=True),
        sa.Column("sdk_level", sa.Integer(), nullable=True),
        sa.Column("snapshot_json", sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_device_capability_runs_assessed_at",
        "device_capability_runs",
        ["assessed_at"],
    )
    op.create_index(
        "ix_device_capability_runs_serial_hash",
        "device_capability_runs",
        ["serial_hash"],
    )


def downgrade() -> None:
    op.drop_index("ix_device_capability_runs_serial_hash", table_name="device_capability_runs")
    op.drop_index("ix_device_capability_runs_assessed_at", table_name="device_capability_runs")
    op.drop_table("device_capability_runs")
