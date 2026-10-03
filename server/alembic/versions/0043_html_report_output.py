"""Allow portable HTML report outputs.

Revision ID: 0043_html_report_output
Revises: 0042_source_artifact_search
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0043_html_report_output"
down_revision: str | None = "0042_source_artifact_search"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("report_outputs") as batch:
        batch.drop_constraint("ck_report_outputs_format", type_="check")
        batch.create_check_constraint(
            "ck_report_outputs_format",
            "format IN ('pdf', 'json', 'csv', 'html')",
        )


def downgrade() -> None:
    with op.batch_alter_table("report_outputs") as batch:
        batch.drop_constraint("ck_report_outputs_format", type_="check")
        batch.create_check_constraint(
            "ck_report_outputs_format",
            "format IN ('pdf', 'json', 'csv')",
        )
