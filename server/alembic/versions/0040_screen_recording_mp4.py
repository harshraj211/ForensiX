"""Track playable MP4 companions for documented screen recordings.

Revision ID: 0040_screen_recording_mp4
Revises: 0039_screen_recordings
Create Date: 2026-08-14
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0040_screen_recording_mp4"
down_revision: str | None = "0039_screen_recordings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "screen_recording_sessions",
        sa.Column("mp4_storage_key", sa.String(1024), nullable=True),
    )
    op.create_index(
        "uq_screen_recording_sessions_mp4_key",
        "screen_recording_sessions",
        ["mp4_storage_key"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_screen_recording_sessions_mp4_key",
        table_name="screen_recording_sessions",
    )
    op.drop_column("screen_recording_sessions", "mp4_storage_key")
