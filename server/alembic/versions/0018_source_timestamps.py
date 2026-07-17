"""Preserve Android stat size and modification-time claims.

Revision ID: 0018_source_timestamps
Revises: 0017_reports_exports
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_source_timestamps"
down_revision: str | None = "0017_reports_exports"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("acquisition_inventory_items", recreate="always") as batch:
        batch.add_column(sa.Column("size_bytes", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("modified_time_raw", sa.String(32), nullable=True))
        batch.add_column(sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("timestamp_source", sa.String(64), nullable=True))
        batch.add_column(sa.Column("timestamp_confidence", sa.String(16), nullable=True))
        batch.create_check_constraint(
            "ck_acquisition_inventory_items_size", "size_bytes IS NULL OR size_bytes >= 0"
        )
        batch.create_check_constraint(
            "ck_acquisition_inventory_items_timestamp_confidence",
            "timestamp_confidence IS NULL OR timestamp_confidence IN ('medium')",
        )
        batch.create_index("ix_acquisition_inventory_items_modified_at", ["modified_at"])


def downgrade() -> None:
    with op.batch_alter_table("acquisition_inventory_items", recreate="always") as batch:
        batch.drop_index("ix_acquisition_inventory_items_modified_at")
        batch.drop_constraint("ck_acquisition_inventory_items_timestamp_confidence", type_="check")
        batch.drop_constraint("ck_acquisition_inventory_items_size", type_="check")
        batch.drop_column("timestamp_confidence")
        batch.drop_column("timestamp_source")
        batch.drop_column("modified_at")
        batch.drop_column("modified_time_raw")
        batch.drop_column("size_bytes")
