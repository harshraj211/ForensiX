"""Add explicit image, video, and audio acquisition scopes.

Revision ID: 0041_separate_media_scopes
Revises: 0040_screen_recording_mp4
"""

from alembic import op

revision = "0041_separate_media_scopes"
down_revision = "0040_screen_recording_mp4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("acquisition_plans") as batch:
        batch.drop_constraint("ck_acquisition_plans_scope", type_="check")
        batch.create_check_constraint(
            "ck_acquisition_plans_scope",
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', "
            "'image_files', 'video_files', 'audio_files', 'media_files', "
            "'document_files', 'downloads_files', 'custom')",
        )


def downgrade() -> None:
    with op.batch_alter_table("acquisition_plans") as batch:
        batch.drop_constraint("ck_acquisition_plans_scope", type_="check")
        batch.create_check_constraint(
            "ck_acquisition_plans_scope",
            "scope IN ('metadata_only', 'quick_triage', 'shared_storage_inventory', "
            "'media_files', 'document_files', 'downloads_files', 'custom')",
        )
