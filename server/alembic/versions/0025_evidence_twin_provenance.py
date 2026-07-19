"""Link Evidence Twin activity to custody and timeline history.

Revision ID: 0025_evidence_twin_provenance
Revises: 0024_aleapp_outputs
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_evidence_twin_provenance"
down_revision: str | None = "0024_aleapp_outputs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "evidence_source_timeline_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("source_artifact_id", sa.String(36), nullable=False),
        sa.Column("parser_run_id", sa.String(36), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("timestamp_type", sa.String(64), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("original_time", sa.String(128), nullable=False),
        sa.Column("timezone_basis", sa.String(128), nullable=False),
        sa.Column("precision", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("builder_version", sa.String(32), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('device', 'file', 'media', 'communication', 'application', "
            "'location', 'system', 'acquisition', 'custody')",
            name="ck_source_timeline_events_category",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["source_artifact_id"], ["evidence_source_artifacts.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["parser_run_id"], ["evidence_parser_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_artifact_id",
            "timestamp_type",
            name="uq_source_timeline_events_artifact_type",
        ),
        sa.UniqueConstraint("event_hash", name="uq_source_timeline_events_hash"),
    )
    for column in (
        "case_id",
        "category",
        "confidence",
        "created_at",
        "event_hash",
        "event_time",
        "parser_run_id",
        "source_artifact_id",
    ):
        op.create_index(
            f"ix_evidence_source_timeline_events_{column}",
            "evidence_source_timeline_events",
            [column],
        )
    op.create_index(
        "ix_source_timeline_events_case_time",
        "evidence_source_timeline_events",
        ["case_id", "event_time", "id"],
    )

    with op.batch_alter_table("custody_events") as batch:
        batch.drop_constraint("ck_custody_events_type", type_="check")
        batch.add_column(sa.Column("evidence_source_id", sa.String(36), nullable=True))
        batch.add_column(sa.Column("parser_run_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_custody_events_evidence_source_id",
            "evidence_sources",
            ["evidence_source_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_foreign_key(
            "fk_custody_events_parser_run_id",
            "evidence_parser_runs",
            ["parser_run_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch.create_check_constraint(
            "ck_custody_events_type",
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'evidence_source_registered', "
            "'source_integrity_verified', 'working_copy_verified', "
            "'parser_completed', 'parser_failed', "
            "'transferred', 'amendment', 'report_generated')",
        )
    op.create_index(
        "ix_custody_events_evidence_source_id", "custody_events", ["evidence_source_id"]
    )
    op.create_index("ix_custody_events_parser_run_id", "custody_events", ["parser_run_id"])


def downgrade() -> None:
    op.drop_index("ix_custody_events_parser_run_id", table_name="custody_events")
    op.drop_index("ix_custody_events_evidence_source_id", table_name="custody_events")
    with op.batch_alter_table("custody_events") as batch:
        batch.drop_constraint("ck_custody_events_type", type_="check")
        batch.drop_constraint("fk_custody_events_parser_run_id", type_="foreignkey")
        batch.drop_constraint("fk_custody_events_evidence_source_id", type_="foreignkey")
        batch.drop_column("parser_run_id")
        batch.drop_column("evidence_source_id")
        batch.create_check_constraint(
            "ck_custody_events_type",
            "event_type IN ('evidence_registered', 'integrity_verified', "
            "'integrity_exception', 'transferred', 'amendment', 'report_generated')",
        )
    op.drop_table("evidence_source_timeline_events")
