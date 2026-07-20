"""Create Evidence Twin source, chunks, copies, and verification records.

Revision ID: 0020_evidence_twin_foundation
Revises: 0019_acquisition_scopes
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0020_evidence_twin_foundation"
down_revision: str | None = "0019_acquisition_scopes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_sources",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("device_id", sa.String(36), nullable=True),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("source_type", sa.String(32), nullable=False),
        sa.Column("acquisition_level", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("source_name", sa.String(255), nullable=False),
        sa.Column("container_format", sa.String(32), nullable=False),
        sa.Column("sealed_storage_key", sa.String(1024), nullable=True),
        sa.Column("manifest_storage_key", sa.String(1024), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=True),
        sa.Column("manifest_sha256", sa.String(64), nullable=True),
        sa.Column("chunk_size_bytes", sa.Integer(), nullable=False),
        sa.Column("chunk_count", sa.Integer(), nullable=False),
        sa.Column("read_only_applied", sa.Boolean(), nullable=False),
        sa.Column("validation_state", sa.String(64), nullable=False),
        sa.Column("limitations_json", sa.Text(), nullable=False),
        sa.Column("tool_version", sa.String(32), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(1000), nullable=True),
        sa.Column("sealed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "source_type IN ('imported_file', 'logical_adb', 'rooted_filesystem', "
            "'physical_block')",
            name="ck_evidence_sources_type",
        ),
        sa.CheckConstraint(
            "acquisition_level IN ('logical', 'selective', 'filesystem', 'physical')",
            name="ck_evidence_sources_level",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'sealed', 'failed')",
            name="ck_evidence_sources_status",
        ),
        sa.CheckConstraint(
            "container_format IN ('raw', 'img', 'dd', 'tar', 'zip', 'directory_bundle', 'unknown')",
            name="ck_evidence_sources_format",
        ),
        sa.CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0", name="ck_evidence_sources_size"
        ),
        sa.CheckConstraint(
            "chunk_size_bytes >= 1048576 AND chunk_size_bytes <= 67108864",
            name="ck_evidence_sources_chunk_size",
        ),
        sa.CheckConstraint("chunk_count >= 0", name="ck_evidence_sources_chunk_count"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["device_id"], ["case_devices.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("sealed_storage_key", name="uq_evidence_sources_storage_key"),
        sa.UniqueConstraint("manifest_storage_key", name="uq_evidence_sources_manifest_key"),
    )
    for column in (
        "case_id",
        "container_format",
        "created_at",
        "created_by",
        "device_id",
        "acquisition_level",
        "manifest_sha256",
        "sealed_at",
        "sha256",
        "source_type",
        "status",
    ):
        op.create_index(f"ix_evidence_sources_{column}", "evidence_sources", [column])
    op.create_index(
        "ix_evidence_sources_case_created", "evidence_sources", ["case_id", "created_at"]
    )

    op.create_table(
        "evidence_source_chunks",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("ordinal", sa.Integer(), nullable=False),
        sa.Column("offset_bytes", sa.Integer(), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("ordinal >= 0", name="ck_evidence_source_chunks_ordinal"),
        sa.CheckConstraint("offset_bytes >= 0", name="ck_evidence_source_chunks_offset"),
        sa.CheckConstraint("size_bytes >= 1", name="ck_evidence_source_chunks_size"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "evidence_source_id", "ordinal", name="uq_evidence_source_chunks_ordinal"
        ),
        sa.UniqueConstraint(
            "evidence_source_id", "offset_bytes", name="uq_evidence_source_chunks_offset"
        ),
    )
    op.create_index(
        "ix_evidence_source_chunks_evidence_source_id",
        "evidence_source_chunks",
        ["evidence_source_id"],
    )
    op.create_index("ix_evidence_source_chunks_sha256", "evidence_source_chunks", ["sha256"])

    op.create_table(
        "evidence_working_copies",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("storage_key", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("expected_source_sha256", sa.String(64), nullable=False),
        sa.Column("observed_sha256", sa.String(64), nullable=True),
        sa.Column("copy_method", sa.String(32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('creating', 'ready', 'verification_failed')",
            name="ck_evidence_working_copies_status",
        ),
        sa.CheckConstraint(
            "size_bytes IS NULL OR size_bytes >= 0", name="ck_evidence_working_copies_size"
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("storage_key", name="uq_evidence_working_copies_storage_key"),
    )
    for column in (
        "case_id",
        "created_at",
        "created_by",
        "evidence_source_id",
        "observed_sha256",
        "status",
        "verified_at",
    ):
        op.create_index(f"ix_evidence_working_copies_{column}", "evidence_working_copies", [column])
    op.create_index(
        "ix_evidence_working_copies_source_created",
        "evidence_working_copies",
        ["evidence_source_id", "created_at"],
    )

    op.create_table(
        "evidence_source_verifications",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=True),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("verified_by", sa.String(36), nullable=False),
        sa.Column("target_type", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("expected_sha256", sa.String(64), nullable=False),
        sa.Column("observed_sha256", sa.String(64), nullable=True),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("verification_hash", sa.String(64), nullable=False),
        sa.Column("tool_version", sa.String(32), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "target_type IN ('master', 'working_copy')",
            name="ck_evidence_source_verifications_target",
        ),
        sa.CheckConstraint(
            "status IN ('verified', 'mismatch', 'missing', 'error')",
            name="ck_evidence_source_verifications_status",
        ),
        sa.CheckConstraint(
            "(target_type = 'master' AND working_copy_id IS NULL) OR "
            "(target_type = 'working_copy' AND working_copy_id IS NOT NULL)",
            name="ck_evidence_source_verifications_reference",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["working_copy_id"], ["evidence_working_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("verification_hash", name="uq_evidence_source_verifications_hash"),
    )
    for column in (
        "case_id",
        "evidence_source_id",
        "status",
        "target_type",
        "verification_hash",
        "verified_at",
        "verified_by",
        "working_copy_id",
    ):
        op.create_index(
            f"ix_evidence_source_verifications_{column}",
            "evidence_source_verifications",
            [column],
        )


def downgrade() -> None:
    op.drop_table("evidence_source_verifications")
    op.drop_table("evidence_working_copies")
    op.drop_table("evidence_source_chunks")
    op.drop_table("evidence_sources")
