"""Record parser input member provenance.

Revision ID: 0027_parser_input_provenance
Revises: 0026_root_access_probes
Create Date: 2026-07-19
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027_parser_input_provenance"
down_revision: str | None = "0026_root_access_probes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "evidence_parser_runs",
        sa.Column(
            "input_locator", sa.String(1024), nullable=False, server_default="working_copy"
        ),
    )
    op.add_column(
        "evidence_parser_runs",
        sa.Column("input_sha256", sa.String(64), nullable=True),
    )
    op.execute("UPDATE evidence_parser_runs SET input_sha256 = source_sha256")
    with op.batch_alter_table("evidence_parser_runs") as batch:
        batch.alter_column("input_sha256", existing_type=sa.String(64), nullable=False)
        batch.drop_constraint("uq_evidence_parser_runs_identity", type_="unique")
        batch.create_unique_constraint(
            "uq_evidence_parser_runs_identity",
            ["working_copy_id", "input_locator", "parser_id", "parser_version"],
        )
    op.create_index(
        "ix_evidence_parser_runs_input_sha256", "evidence_parser_runs", ["input_sha256"]
    )


def downgrade() -> None:
    op.drop_index("ix_evidence_parser_runs_input_sha256", table_name="evidence_parser_runs")
    with op.batch_alter_table("evidence_parser_runs") as batch:
        batch.drop_constraint("uq_evidence_parser_runs_identity", type_="unique")
        batch.create_unique_constraint(
            "uq_evidence_parser_runs_identity",
            ["working_copy_id", "parser_id", "parser_version"],
        )
        batch.drop_column("input_sha256")
        batch.drop_column("input_locator")
