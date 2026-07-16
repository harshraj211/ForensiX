"""Create normalized artifacts and SQLite FTS5 search index.

Revision ID: 0014_artifacts_search
Revises: 0013_partial_recovery
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014_artifacts_search"
down_revision: str | None = "0013_partial_recovery"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("evidence_file_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("device_id", sa.String(length=36), nullable=False),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("category", sa.String(length=24), nullable=False),
        sa.Column("subtype", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("summary", sa.String(length=1000), nullable=False),
        sa.Column("source_relative_path", sa.String(length=1024), nullable=False),
        sa.Column("source_path_hash", sa.String(length=64), nullable=False),
        sa.Column("extension", sa.String(length=16), nullable=True),
        sa.Column("detected_mime", sa.String(length=255), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("primary_sha256", sa.String(length=64), nullable=False),
        sa.Column("parser_id", sa.String(length=128), nullable=False),
        sa.Column("parser_version", sa.String(length=32), nullable=False),
        sa.Column("timestamp_confidence", sa.String(length=16), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("schema_version", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('image', 'video', 'audio', 'document', 'archive', 'other')",
            name="ck_artifacts_category",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'deleted', 'recovered', 'partial', 'corrupted', 'unverified')",
            name="ck_artifacts_status",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifacts_size"),
        sa.ForeignKeyConstraint(
            ["evidence_file_id"], ["acquired_evidence_files.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_file_id", name="uq_artifacts_evidence_file"),
    )
    for column in (
        "case_id",
        "category",
        "collected_at",
        "created_at",
        "detected_mime",
        "device_id",
        "evidence_file_id",
        "extension",
        "job_id",
        "parser_id",
        "primary_sha256",
        "source_path_hash",
        "status",
    ):
        op.create_index(f"ix_artifacts_{column}", "artifacts", [column])
    op.create_index(
        "ix_artifacts_case_category_collected",
        "artifacts",
        ["case_id", "category", "collected_at"],
    )
    op.create_index(
        "ix_artifacts_case_status_collected",
        "artifacts",
        ["case_id", "status", "collected_at"],
    )
    op.execute(
        "CREATE VIRTUAL TABLE artifact_search USING fts5("
        "artifact_id UNINDEXED, case_id UNINDEXED, title, summary, source_name, "
        "tokenize='unicode61 remove_diacritics 2')"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS artifact_search")
    op.drop_index("ix_artifacts_case_status_collected", table_name="artifacts")
    op.drop_index("ix_artifacts_case_category_collected", table_name="artifacts")
    for column in reversed(
        (
            "case_id",
            "category",
            "collected_at",
            "created_at",
            "detected_mime",
            "device_id",
            "evidence_file_id",
            "extension",
            "job_id",
            "parser_id",
            "primary_sha256",
            "source_path_hash",
            "status",
        )
    ):
        op.drop_index(f"ix_artifacts_{column}", table_name="artifacts")
    op.drop_table("artifacts")
