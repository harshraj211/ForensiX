"""Persist experimental physical block probes.

Revision ID: 0028_physical_block_probes
Revises: 0027_parser_input_provenance
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028_physical_block_probes"
down_revision: str | None = "0027_parser_input_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "physical_block_probes",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), nullable=False),
        sa.Column("root_probe_id", sa.String(36), nullable=False),
        sa.Column("probed_by", sa.String(36), nullable=False),
        sa.Column("profile", sa.String(32), nullable=False),
        sa.Column("device_path", sa.String(255), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("encryption_state", sa.String(16), nullable=False),
        sa.Column("probe_hash", sa.String(64), nullable=False),
        sa.Column("probed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "profile IN ('userdata_by_name')", name="ck_physical_block_probes_profile"
        ),
        sa.CheckConstraint("size_bytes > 0", name="ck_physical_block_probes_size"),
        sa.CheckConstraint(
            "encryption_state IN ('unknown', 'suspected', 'not_detected')",
            name="ck_physical_block_probes_encryption",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["root_probe_id"], ["root_access_probes.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["probed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("probe_hash", name="uq_physical_block_probes_hash"),
    )
    for column in (
        "case_id",
        "device_id",
        "probe_hash",
        "probed_at",
        "probed_by",
        "root_probe_id",
    ):
        op.create_index(f"ix_physical_block_probes_{column}", "physical_block_probes", [column])


def downgrade() -> None:
    op.drop_table("physical_block_probes")
