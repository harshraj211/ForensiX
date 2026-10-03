"""Add media face embedding and cluster records.

Revision ID: 0044_media_face_clusters
Revises: 0043_html_report_output
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0044_media_face_clusters"
down_revision: str | None = "0043_html_report_output"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "media_face_embeddings",
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
        sa.Column("face_index", sa.Integer(), nullable=False),
        sa.Column("embedding_model", sa.String(64), nullable=False),
        sa.Column("embedding_json", sa.Text(), nullable=False),
        sa.Column("region_json", sa.Text(), nullable=False),
        sa.Column("cluster_key", sa.String(64), nullable=True),
        sa.Column("embedding_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("face_index >= 0", name="ck_media_face_embeddings_index"),
        sa.UniqueConstraint(
            "media_analysis_id", "face_index", name="uq_media_face_embedding_analysis_index"
        ),
        sa.UniqueConstraint("embedding_hash", name="uq_media_face_embeddings_hash"),
    )
    op.create_index("ix_media_face_embeddings_case_id", "media_face_embeddings", ["case_id"])
    op.create_index(
        "ix_media_face_embeddings_artifact_id", "media_face_embeddings", ["artifact_id"]
    )
    op.create_index(
        "ix_media_face_embeddings_media_analysis_id", "media_face_embeddings", ["media_analysis_id"]
    )
    op.create_index(
        "ix_media_face_embeddings_cluster_key", "media_face_embeddings", ["cluster_key"]
    )
    op.create_index("ix_media_face_embeddings_created_at", "media_face_embeddings", ["created_at"])
    op.create_index(
        "ix_media_face_embeddings_case_cluster", "media_face_embeddings", ["case_id", "cluster_key"]
    )

    op.create_table(
        "media_face_clusters",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="RESTRICT"), nullable=False
        ),
        sa.Column("cluster_key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(128), nullable=False),
        sa.Column("member_count", sa.Integer(), nullable=False),
        sa.Column("centroid_json", sa.Text(), nullable=False),
        sa.Column("member_ids_json", sa.Text(), nullable=False),
        sa.Column("algorithm", sa.String(64), nullable=False),
        sa.Column("cluster_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_by",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("member_count >= 1", name="ck_media_face_clusters_member_count"),
        sa.UniqueConstraint("case_id", "cluster_key", name="uq_media_face_clusters_case_key"),
        sa.UniqueConstraint("cluster_hash", name="uq_media_face_clusters_hash"),
    )
    op.create_index("ix_media_face_clusters_case_id", "media_face_clusters", ["case_id"])
    op.create_index("ix_media_face_clusters_cluster_key", "media_face_clusters", ["cluster_key"])
    op.create_index("ix_media_face_clusters_created_by", "media_face_clusters", ["created_by"])
    op.create_index("ix_media_face_clusters_created_at", "media_face_clusters", ["created_at"])
    op.create_index(
        "ix_media_face_clusters_case_count", "media_face_clusters", ["case_id", "member_count"]
    )


def downgrade() -> None:
    op.drop_index("ix_media_face_clusters_case_count", table_name="media_face_clusters")
    op.drop_index("ix_media_face_clusters_created_at", table_name="media_face_clusters")
    op.drop_index("ix_media_face_clusters_created_by", table_name="media_face_clusters")
    op.drop_index("ix_media_face_clusters_cluster_key", table_name="media_face_clusters")
    op.drop_index("ix_media_face_clusters_case_id", table_name="media_face_clusters")
    op.drop_table("media_face_clusters")

    op.drop_index("ix_media_face_embeddings_case_cluster", table_name="media_face_embeddings")
    op.drop_index("ix_media_face_embeddings_created_at", table_name="media_face_embeddings")
    op.drop_index("ix_media_face_embeddings_cluster_key", table_name="media_face_embeddings")
    op.drop_index("ix_media_face_embeddings_media_analysis_id", table_name="media_face_embeddings")
    op.drop_index("ix_media_face_embeddings_artifact_id", table_name="media_face_embeddings")
    op.drop_index("ix_media_face_embeddings_case_id", table_name="media_face_embeddings")
    op.drop_table("media_face_embeddings")
