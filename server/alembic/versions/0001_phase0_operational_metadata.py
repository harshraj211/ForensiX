"""Create Phase 0 operational metadata tables.

Revision ID: 0001_phase0
Revises:
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_phase0"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "system_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("safe_detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_system_events_created_at", "system_events", ["created_at"])
    op.create_index("ix_system_events_event_type", "system_events", ["event_type"])
    op.create_index("ix_system_events_severity", "system_events", ["severity"])
    op.create_table(
        "device_detection_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("adb_version", sa.String(length=32), nullable=False),
        sa.Column("device_count", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(length=32), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_device_detection_runs_observed_at", "device_detection_runs", ["observed_at"]
    )
    op.create_index("ix_device_detection_runs_result", "device_detection_runs", ["result"])


def downgrade() -> None:
    op.drop_index("ix_device_detection_runs_result", table_name="device_detection_runs")
    op.drop_index("ix_device_detection_runs_observed_at", table_name="device_detection_runs")
    op.drop_table("device_detection_runs")
    op.drop_index("ix_system_events_severity", table_name="system_events")
    op.drop_index("ix_system_events_event_type", table_name="system_events")
    op.drop_index("ix_system_events_created_at", table_name="system_events")
    op.drop_table("system_events")
