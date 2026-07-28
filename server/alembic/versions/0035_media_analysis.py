"""Add derived media analysis for image/video/audio artifacts.

Revision ID: 0035_media_analysis
Revises: 0034_custody_checkpoint_signatures
Create Date: 2026-07-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0035_media_analysis"
down_revision: str | None = "0034_custody_checkpoint_signatures"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_INDEXED_COLUMNS = (
    "analyzed_at",
    "analyzed_by",
    "artifact_id",
    "case_id",
    "evidence_file_id",
    "gps_present",
    "media_kind",
    "perceptual_hash",
    "status",
)


def upgrade() -> None:
    op.create_table(
        "media_analyses",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("evidence_file_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("analyzed_by", sa.String(36), nullable=False),
        sa.Column("media_kind", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("detected_mime", sa.String(255), nullable=True),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("perceptual_hash", sa.String(32), nullable=True),
        sa.Column("captured_at_raw", sa.String(128), nullable=True),
        sa.Column("camera_make", sa.String(128), nullable=True),
        sa.Column("camera_model", sa.String(128), nullable=True),
        sa.Column("gps_present", sa.Boolean(), nullable=False),
        sa.Column("gps_latitude", sa.Float(), nullable=True),
        sa.Column("gps_longitude", sa.Float(), nullable=True),
        sa.Column("exif_json", sa.Text(), nullable=False),
        sa.Column("ocr_status", sa.String(16), nullable=False),
        sa.Column("ocr_engine", sa.String(64), nullable=True),
        sa.Column("ocr_text", sa.Text(), nullable=True),
        sa.Column("detection_json", sa.Text(), nullable=False),
        sa.Column("detector_maturity", sa.String(24), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(1000), nullable=True),
        sa.Column("analysis_hash", sa.String(64), nullable=False),
        sa.Column("worker_version", sa.String(32), nullable=False),
        sa.Column("analyzed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "media_kind IN ('image', 'video', 'audio')",
            name="ck_media_analyses_kind",
        ),
        sa.CheckConstraint(
            "status IN ('analyzed', 'unsupported', 'rejected', 'failed')",
            name="ck_media_analyses_status",
        ),
        sa.CheckConstraint(
            "ocr_status IN ('not_attempted', 'completed', 'unavailable', 'empty')",
            name="ck_media_analyses_ocr_status",
        ),
        sa.CheckConstraint("width IS NULL OR width >= 0", name="ck_media_analyses_width"),
        sa.CheckConstraint("height IS NULL OR height >= 0", name="ck_media_analyses_height"),
        sa.ForeignKeyConstraint(["analyzed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", name="uq_media_analyses_artifact"),
        sa.UniqueConstraint("analysis_hash", name="uq_media_analyses_hash"),
    )
    for column in _INDEXED_COLUMNS:
        op.create_index(f"ix_media_analyses_{column}", "media_analyses", [column])
    op.create_index(
        "ix_media_analyses_case_kind", "media_analyses", ["case_id", "media_kind"]
    )
    op.create_index(
        "ix_media_analyses_perceptual", "media_analyses", ["case_id", "perceptual_hash"]
    )


def downgrade() -> None:
    op.drop_index("ix_media_analyses_perceptual", table_name="media_analyses")
    op.drop_index("ix_media_analyses_case_kind", table_name="media_analyses")
    for column in reversed(_INDEXED_COLUMNS):
        op.drop_index(f"ix_media_analyses_{column}", table_name="media_analyses")
    op.drop_table("media_analyses")
