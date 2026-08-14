"""Add auditable interactive screen recording sessions.

Revision ID: 0039_screen_recordings
Revises: 0038_external_recovery
Create Date: 2026-08-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0039_screen_recordings"
down_revision: str | None = "0038_external_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "screen_recording_sessions",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), nullable=False),
        sa.Column("started_by", sa.String(36), nullable=False),
        sa.Column("stopped_by", sa.String(36), nullable=True),
        sa.Column("evidence_source_id", sa.String(36), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("process_id", sa.Integer(), nullable=False),
        sa.Column("serial_hash", sa.String(64), nullable=False),
        sa.Column("scrcpy_version", sa.String(64), nullable=False),
        sa.Column("executable_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(1000), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stopped_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('active', 'sealed', 'failed')",
            name="ck_screen_recording_sessions_status",
        ),
        sa.CheckConstraint("process_id >= 1", name="ck_screen_recording_sessions_process_id"),
        sa.CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 1",
            name="ck_screen_recording_sessions_size",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["started_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["stopped_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_source_id", name="uq_screen_recording_sessions_source"),
    )
    for column in (
        "case_id",
        "device_id",
        "started_by",
        "stopped_by",
        "status",
        "started_at",
        "stopped_at",
    ):
        op.create_index(
            f"ix_screen_recording_sessions_{column}",
            "screen_recording_sessions",
            [column],
        )
    op.create_index(
        "ix_screen_recording_sessions_case_started",
        "screen_recording_sessions",
        ["case_id", "started_at"],
    )
    op.create_index(
        "uq_screen_recording_sessions_active_device",
        "screen_recording_sessions",
        ["device_id"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )


def downgrade() -> None:
    op.drop_index(
        "uq_screen_recording_sessions_active_device",
        table_name="screen_recording_sessions",
    )
    op.drop_index(
        "ix_screen_recording_sessions_case_started",
        table_name="screen_recording_sessions",
    )
    for column in reversed(
        (
            "case_id",
            "device_id",
            "started_by",
            "stopped_by",
            "status",
            "started_at",
            "stopped_at",
        )
    ):
        op.drop_index(
            f"ix_screen_recording_sessions_{column}",
            table_name="screen_recording_sessions",
        )
    op.drop_table("screen_recording_sessions")
