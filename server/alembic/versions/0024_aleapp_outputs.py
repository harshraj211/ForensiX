"""Persist sealed outputs from pinned external forensic tools.

Revision ID: 0024_aleapp_outputs
Revises: 0023_evidence_parser_results
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024_aleapp_outputs"
down_revision: str | None = "0023_evidence_parser_results"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_tool_outputs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("parser_run_id", sa.String(36), nullable=False),
        sa.Column("evidence_source_id", sa.String(36), nullable=False),
        sa.Column("working_copy_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("relative_path", sa.String(1024), nullable=False),
        sa.Column("storage_key", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("size_bytes >= 0", name="ck_evidence_tool_outputs_size"),
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
        sa.UniqueConstraint(
            "parser_run_id", "relative_path", name="uq_evidence_tool_outputs_run_path"
        ),
        sa.UniqueConstraint("storage_key", name="uq_evidence_tool_outputs_storage_key"),
    )
    for column in (
        "case_id",
        "created_at",
        "evidence_source_id",
        "parser_run_id",
        "sha256",
        "working_copy_id",
    ):
        op.create_index(f"ix_evidence_tool_outputs_{column}", "evidence_tool_outputs", [column])


def downgrade() -> None:
    op.drop_table("evidence_tool_outputs")
