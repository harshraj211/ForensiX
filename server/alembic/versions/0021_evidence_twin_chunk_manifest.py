"""Persist sealed Evidence Twin chunk-manifest provenance.

Revision ID: 0021_evidence_twin_chunk_manifest
Revises: 0020_evidence_twin_foundation
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021_evidence_twin_chunk_manifest"
down_revision: str | None = "0020_evidence_twin_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("evidence_sources", recreate="always") as batch:
        batch.add_column(sa.Column("chunks_storage_key", sa.String(1024), nullable=True))
        batch.add_column(sa.Column("chunks_sha256", sa.String(64), nullable=True))
        batch.create_unique_constraint("uq_evidence_sources_chunks_key", ["chunks_storage_key"])
        batch.create_index("ix_evidence_sources_chunks_sha256", ["chunks_sha256"])


def downgrade() -> None:
    with op.batch_alter_table("evidence_sources", recreate="always") as batch:
        batch.drop_index("ix_evidence_sources_chunks_sha256")
        batch.drop_constraint("uq_evidence_sources_chunks_key", type_="unique")
        batch.drop_column("chunks_sha256")
        batch.drop_column("chunks_storage_key")
