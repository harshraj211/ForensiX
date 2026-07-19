"""Add server-enforced file-category acquisition scopes.

Revision ID: 0019_acquisition_scopes
Revises: 0018_source_timestamps
Create Date: 2026-07-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0019_acquisition_scopes"
down_revision: str | None = "0018_source_timestamps"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("acquisition_plans", recreate="always") as batch:
        batch.drop_constraint("ck_acquisition_plans_scope", type_="check")
        batch.create_check_constraint(
            "ck_acquisition_plans_scope",
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', "
            "'media_files', 'document_files', 'downloads_files', 'custom')",
        )


def downgrade() -> None:
    with op.batch_alter_table("acquisition_plans", recreate="always") as batch:
        batch.drop_constraint("ck_acquisition_plans_scope", type_="check")
        batch.create_check_constraint(
            "ck_acquisition_plans_scope",
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', 'custom')",
        )
