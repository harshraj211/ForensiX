"""Add immutable preliminary reports, outputs, and custody linkage.

Revision ID: 0017_reports_exports
Revises: 0016_safe_previews
Create Date: 2026-07-17
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017_reports_exports"
down_revision: str | None = "0016_safe_previews"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("generated_by", sa.String(36), nullable=False),
        sa.Column("report_type", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("template_version", sa.String(32), nullable=False),
        sa.Column("snapshot_storage_key", sa.String(1024), nullable=False),
        sa.Column("snapshot_size_bytes", sa.Integer(), nullable=False),
        sa.Column("snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('available')", name="ck_reports_status"),
        sa.CheckConstraint("report_type IN ('preliminary')", name="ck_reports_type"),
        sa.CheckConstraint("snapshot_size_bytes >= 1", name="ck_reports_snapshot_size"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("snapshot_storage_key", name="uq_reports_snapshot_storage_key"),
        sa.UniqueConstraint("snapshot_sha256", name="uq_reports_snapshot_sha256"),
    )
    for column in (
        "case_id",
        "generated_at",
        "generated_by",
        "report_type",
        "snapshot_sha256",
        "status",
    ):
        op.create_index(f"ix_reports_{column}", "reports", [column])

    op.create_table(
        "report_outputs",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("report_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("format", sa.String(8), nullable=False),
        sa.Column("media_type", sa.String(255), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("storage_key", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("format IN ('pdf', 'json', 'csv')", name="ck_report_outputs_format"),
        sa.CheckConstraint("size_bytes >= 1", name="ck_report_outputs_size"),
        sa.ForeignKeyConstraint(["report_id"], ["reports.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_id", "format", name="uq_report_outputs_report_format"),
        sa.UniqueConstraint("storage_key", name="uq_report_outputs_storage_key"),
    )
    for column in ("case_id", "created_at", "format", "report_id", "sha256"):
        op.create_index(f"ix_report_outputs_{column}", "report_outputs", [column])

    with op.batch_alter_table("custody_events", recreate="always") as batch:
        batch.drop_constraint("ck_custody_events_type", type_="check")
        batch.add_column(sa.Column("report_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_custody_events_report_id_reports",
            "reports",
            ["report_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_custody_events_type",
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'transferred', 'amendment', 'report_generated')",
        )
        batch.create_index("ix_custody_events_report_id", ["report_id"])


def downgrade() -> None:
    with op.batch_alter_table("custody_events", recreate="always") as batch:
        batch.drop_index("ix_custody_events_report_id")
        batch.drop_constraint("ck_custody_events_type", type_="check")
        batch.drop_constraint("fk_custody_events_report_id_reports", type_="foreignkey")
        batch.drop_column("report_id")
        batch.create_check_constraint(
            "ck_custody_events_type",
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'transferred', 'amendment')",
        )
    for column in reversed(("case_id", "created_at", "format", "report_id", "sha256")):
        op.drop_index(f"ix_report_outputs_{column}", table_name="report_outputs")
    op.drop_table("report_outputs")
    for column in reversed(
        (
            "case_id",
            "generated_at",
            "generated_by",
            "report_type",
            "snapshot_sha256",
            "status",
        )
    ):
        op.drop_index(f"ix_reports_{column}", table_name="reports")
    op.drop_table("reports")
