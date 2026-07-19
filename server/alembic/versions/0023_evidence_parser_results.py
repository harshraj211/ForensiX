"""Persist Evidence Twin parser runs and normalized artifacts.

Revision ID: 0023_evidence_parser_results
Revises: 0022_evidence_twin_inspection
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_evidence_parser_results"
down_revision: str | None = "0022_evidence_twin_inspection"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_parser_runs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("inspection_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("executed_by", sa.String(36), nullable=False),
        sa.Column("parser_id", sa.String(128), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("artifact_count", sa.Integer(), nullable=False),
        sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("run_hash", sa.String(64), nullable=False),
        sa.Column("error_code", sa.String(64), nullable=True),
        sa.Column("error_message", sa.String(1000), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('completed', 'failed')", name="ck_evidence_parser_runs_status"
        ),
        sa.CheckConstraint("artifact_count >= 0", name="ck_evidence_parser_runs_artifact_count"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["executed_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["inspection_id"], ["evidence_source_inspections.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["working_copy_id"], ["evidence_working_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "working_copy_id",
            "parser_id",
            "parser_version",
            name="uq_evidence_parser_runs_identity",
        ),
        sa.UniqueConstraint("run_hash", name="uq_evidence_parser_runs_hash"),
    )
    for column in (
        "case_id",
        "completed_at",
        "evidence_source_id",
        "executed_by",
        "inspection_id",
        "parser_id",
        "run_hash",
        "source_sha256",
        "status",
        "working_copy_id",
    ):
        op.create_index(f"ix_evidence_parser_runs_{column}", "evidence_parser_runs", [column])

    op.create_table(
        "evidence_source_artifacts",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("parser_run_id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("subtype", sa.String(64), nullable=False),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("summary", sa.String(2000), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_locator", sa.String(1024), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("parser_id", sa.String(128), nullable=False),
        sa.Column("parser_version", sa.String(32), nullable=False),
        sa.Column("metadata_json", sa.Text(), nullable=False),
        sa.Column("provenance_json", sa.Text(), nullable=False),
        sa.Column("artifact_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('contact', 'communication', 'application', 'location', 'system', 'file')",
            name="ck_evidence_source_artifacts_category",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'deleted', 'recovered', 'partial', 'corrupted', 'unverified')",
            name="ck_evidence_source_artifacts_status",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_evidence_source_artifacts_confidence",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["evidence_source_id"], ["evidence_sources.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["parser_run_id"], ["evidence_parser_runs.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["working_copy_id"], ["evidence_working_copies.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_hash", name="uq_evidence_source_artifacts_hash"),
    )
    for column in (
        "artifact_hash",
        "case_id",
        "category",
        "confidence",
        "created_at",
        "event_time",
        "evidence_source_id",
        "parser_id",
        "parser_run_id",
        "status",
        "subtype",
        "working_copy_id",
    ):
        op.create_index(
            f"ix_evidence_source_artifacts_{column}", "evidence_source_artifacts", [column]
        )
    op.create_index(
        "ix_evidence_source_artifacts_case_event",
        "evidence_source_artifacts",
        ["case_id", "event_time"],
    )


def downgrade() -> None:
    op.drop_table("evidence_source_artifacts")
    op.drop_table("evidence_parser_runs")
