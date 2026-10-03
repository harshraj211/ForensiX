"""Add gallery-level media visual embeddings.

Revision ID: 0045_media_visual_embeddings
Revises: 0044_media_face_clusters
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0045_media_visual_embeddings"
down_revision: str | None = "0044_media_face_clusters"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "media_visual_embeddings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column(
            "artifact_id",
            sa.String(36),
            sa.ForeignKey("artifacts.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "media_analysis_id",
            sa.String(36),
            sa.ForeignKey("media_analyses.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("embedding_model", sa.String(255), nullable=False),
        sa.Column("embedding_json", sa.Text(), nullable=False),
        sa.Column("dimension_count", sa.Integer(), nullable=False),
        sa.Column("embedding_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("dimension_count >= 1", name="ck_media_visual_embeddings_dimensions"),
        sa.UniqueConstraint("media_analysis_id", name="uq_media_visual_embeddings_analysis"),
        sa.UniqueConstraint("embedding_hash", name="uq_media_visual_embeddings_hash"),
    )
    op.create_index("ix_media_visual_embeddings_case_id", "media_visual_embeddings", ["case_id"])
    op.create_index(
        "ix_media_visual_embeddings_artifact_id", "media_visual_embeddings", ["artifact_id"]
    )
    op.create_index(
        "ix_media_visual_embeddings_media_analysis_id",
        "media_visual_embeddings",
        ["media_analysis_id"],
    )
    op.create_index(
        "ix_media_visual_embeddings_created_at", "media_visual_embeddings", ["created_at"]
    )
    op.create_index(
        "ix_media_visual_embeddings_case_model",
        "media_visual_embeddings",
        ["case_id", "embedding_model"],
    )


def downgrade() -> None:
    op.drop_index("ix_media_visual_embeddings_case_model", table_name="media_visual_embeddings")
    op.drop_index("ix_media_visual_embeddings_created_at", table_name="media_visual_embeddings")
    op.drop_index(
        "ix_media_visual_embeddings_media_analysis_id", table_name="media_visual_embeddings"
    )
    op.drop_index("ix_media_visual_embeddings_artifact_id", table_name="media_visual_embeddings")
    op.drop_index("ix_media_visual_embeddings_case_id", table_name="media_visual_embeddings")
    op.drop_table("media_visual_embeddings")
