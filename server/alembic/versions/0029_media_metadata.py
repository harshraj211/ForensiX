"""Add bounded source media metadata to safe preview records.

Revision ID: 0029_media_metadata
Revises: 0028_physical_block_probes
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029_media_metadata"
down_revision: str | None = "0028_physical_block_probes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("artifact_previews") as batch:
        batch.add_column(sa.Column("source_width", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("source_height", sa.Integer(), nullable=True))
        batch.add_column(
            sa.Column("media_metadata_json", sa.Text(), nullable=False, server_default="{}")
        )


def downgrade() -> None:
    with op.batch_alter_table("artifact_previews") as batch:
        batch.drop_column("media_metadata_json")
        batch.drop_column("source_height")
        batch.drop_column("source_width")
