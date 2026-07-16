"""Create deterministic timeline and analyst annotation records.

Revision ID: 0015_timeline_analysis
Revises: 0014_artifacts_search
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015_timeline_analysis"
down_revision: str | None = "0014_artifacts_search"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "timeline_events",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("job_id", sa.String(36), nullable=False),
        sa.Column("category", sa.String(24), nullable=False),
        sa.Column("timestamp_type", sa.String(64), nullable=False),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("original_time", sa.String(128), nullable=False),
        sa.Column("timezone_basis", sa.String(64), nullable=False),
        sa.Column("precision", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=False),
        sa.Column("builder_version", sa.String(32), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "category IN ('device', 'file', 'media', 'communication', 'application', "
            "'location', 'system', 'acquisition', 'custody')",
            name="ck_timeline_events_category",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "artifact_id", "timestamp_type", name="uq_timeline_events_artifact_type"
        ),
        sa.UniqueConstraint("event_hash", name="uq_timeline_events_hash"),
    )
    for column in (
        "artifact_id",
        "case_id",
        "category",
        "confidence",
        "created_at",
        "event_hash",
        "event_time",
        "job_id",
    ):
        op.create_index(f"ix_timeline_events_{column}", "timeline_events", [column])
    op.create_index(
        "ix_timeline_events_case_time", "timeline_events", ["case_id", "event_time", "id"]
    )

    op.create_table(
        "bookmarks",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("user_id", sa.String(36), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", "user_id", name="uq_bookmarks_artifact_user"),
    )
    for column in ("artifact_id", "case_id", "created_at", "user_id"):
        op.create_index(f"ix_bookmarks_{column}", "bookmarks", [column])

    op.create_table(
        "tags",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("normalized_name", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("case_id", "normalized_name", name="uq_tags_case_name"),
    )
    for column in ("case_id", "created_at", "created_by"):
        op.create_index(f"ix_tags_{column}", "tags", [column])

    op.create_table(
        "artifact_tags",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("tag_id", sa.String(36), nullable=False),
        sa.Column("added_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["added_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("artifact_id", "tag_id", name="uq_artifact_tags_pair"),
    )
    for column in ("added_by", "artifact_id", "created_at", "tag_id"):
        op.create_index(f"ix_artifact_tags_{column}", "artifact_tags", [column])

    op.create_table(
        "analyst_notes",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("artifact_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("author_id", sa.String(36), nullable=False),
        sa.Column("body", sa.String(4000), nullable=False),
        sa.Column("supersedes_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["artifact_id"], ["artifacts.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["supersedes_id"], ["analyst_notes.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("artifact_id", "author_id", "case_id", "created_at", "supersedes_id"):
        op.create_index(f"ix_analyst_notes_{column}", "analyst_notes", [column])


def downgrade() -> None:
    for table, columns in (
        ("analyst_notes", ("artifact_id", "author_id", "case_id", "created_at", "supersedes_id")),
        ("artifact_tags", ("added_by", "artifact_id", "created_at", "tag_id")),
        ("tags", ("case_id", "created_at", "created_by")),
        ("bookmarks", ("artifact_id", "case_id", "created_at", "user_id")),
    ):
        for column in reversed(columns):
            op.drop_index(f"ix_{table}_{column}", table_name=table)
        op.drop_table(table)
    op.drop_index("ix_timeline_events_case_time", table_name="timeline_events")
    for column in reversed(
        (
            "artifact_id",
            "case_id",
            "category",
            "confidence",
            "created_at",
            "event_hash",
            "event_time",
            "job_id",
        )
    ):
        op.drop_index(f"ix_timeline_events_{column}", table_name="timeline_events")
    op.drop_table("timeline_events")
