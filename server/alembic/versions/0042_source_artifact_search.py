"""Add FTS5 full-text search table for normalized evidence source artifacts.

Revision ID: 0042_source_artifact_search
Revises: 0041_separate_media_scopes
"""

from alembic import op

revision = "0042_source_artifact_search"
down_revision = "0041_separate_media_scopes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE VIRTUAL TABLE IF NOT EXISTS source_artifact_search USING fts5("
        "artifact_id UNINDEXED, "
        "case_id UNINDEXED, "
        "category UNINDEXED, "
        "subtype UNINDEXED, "
        "title, "
        "summary, "
        "content, "
        "metadata, "
        "tokenize='unicode61 remove_diacritics 2')"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS source_artifact_search")
