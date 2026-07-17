"""Add process-isolated safe artifact derivative records.

Revision ID: 0016_safe_previews
Revises: 0015_timeline_analysis
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_safe_previews"
down_revision: str | None = "0015_timeline_analysis"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "artifact_previews",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("evidence_file_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("generated_by", sa.String(36), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("extension_mismatch", sa.Boolean(), nullable=False),
        sa.Column("detected_mime", sa.String(255), nullable=False),
        sa.Column("output_mime", sa.String(255), nullable=True),
        sa.Column("output_storage_key", sa.String(1024), nullable=True),
        sa.Column("output_size_bytes", sa.Integer(), nullable=True),
        sa.Column("output_sha256", sa.String(64), nullable=True),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("worker_version", sa.String(32), nullable=False),
        sa.Column("limits_json", sa.Text(), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('available', 'rejected', 'failed')",
            name="ck_artifact_previews_status",
        ),
        sa.CheckConstraint(
            "output_size_bytes IS NULL OR output_size_bytes >= 1",
            name="ck_artifact_previews_output_size",
        ),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", name="uq_artifact_previews_artifact"),
        sa.UniqueConstraint("output_storage_key", name="uq_artifact_previews_storage_key"),
    )
    for column in (
        "artifact_id",
        "case_id",
        "created_at",
        "evidence_file_id",
        "generated_by",
        "output_sha256",
        "status",
    ):
        op.create_index(f"ix_artifact_previews_{column}", "artifact_previews", [column])


def downgrade() -> None:
    for column in reversed(
        (
            "artifact_id",
            "case_id",
            "created_at",
            "evidence_file_id",
            "generated_by",
            "output_sha256",
            "status",
        )
    ):
        op.drop_index(f"ix_artifact_previews_{column}", table_name="artifact_previews")
    op.drop_table("artifact_previews")
