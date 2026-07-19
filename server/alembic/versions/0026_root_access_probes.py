"""Persist explicit rooted access probes.

Revision ID: 0026_root_access_probes
Revises: 0025_evidence_twin_provenance
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026_root_access_probes"
down_revision: str | None = "0025_evidence_twin_provenance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "root_access_probes",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), nullable=False),
        sa.Column("probed_by", sa.String(36), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("uid", sa.Integer(), nullable=True),
        sa.Column("identity", sa.String(240), nullable=True),
        sa.Column("reason_code", sa.String(64), nullable=False),
        sa.Column("potential_side_effect", sa.String(500), nullable=False),
        sa.Column("probe_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("probed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('available', 'unavailable', 'indeterminate')",
            name="ck_root_access_probes_status",
        ),
        sa.CheckConstraint("uid IS NULL OR uid >= 0", name="ck_root_access_probes_uid"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["probed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("probe_hash", name="uq_root_access_probes_hash"),
    )
    for column in (
        "case_id",
        "device_id",
        "expires_at",
        "probe_hash",
        "probed_at",
        "probed_by",
        "status",
    ):
        op.create_index(f"ix_root_access_probes_{column}", "root_access_probes", [column])
    op.create_index(
        "ix_root_access_probes_device_time",
        "root_access_probes",
        ["device_id", "probed_at", "id"],
    )


def downgrade() -> None:
    op.drop_table("root_access_probes")
