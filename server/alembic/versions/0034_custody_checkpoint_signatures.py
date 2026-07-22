"""Add verified detached signatures for custody checkpoints.

Revision ID: 0034_custody_checkpoint_signatures
Revises: 0033_custody_checkpoint_anchors
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034_custody_checkpoint_signatures"
down_revision: str | None = "0033_custody_checkpoint_anchors"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "custody_checkpoint_signatures",
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("checkpoint_id", sa.String(36), nullable=False),
        sa.Column("case_id", sa.String(36), nullable=False),
        sa.Column("verified_by", sa.String(36), nullable=False),
        sa.Column("signature_algorithm", sa.String(32), nullable=False),
        sa.Column("signer_subject", sa.String(2000), nullable=False),
        sa.Column("signer_issuer", sa.String(2000), nullable=False),
        sa.Column("certificate_serial", sa.String(128), nullable=False),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_pem", sa.Text(), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("signature_base64", sa.Text(), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("certificate_not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("certificate_not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("checkpoint_sha256", sa.String(64), nullable=False),
        sa.Column("verification_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "signature_algorithm IN ('rsa_pkcs1v15_sha256', 'rsa_pss_sha256', "
            "'ecdsa_sha256')",
            name="ck_custody_checkpoint_signatures_algorithm",
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["checkpoint_id"], ["custody_checkpoints.id"], ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(["verified_by"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "verification_hash", name="uq_custody_checkpoint_signatures_verification_hash"
        ),
    )
    for column in (
        "case_id",
        "certificate_sha256",
        "checkpoint_sha256",
        "created_at",
        "signature_algorithm",
        "signature_sha256",
        "verification_hash",
        "verified_by",
    ):
        op.create_index(
            f"ix_custody_checkpoint_signatures_{column}",
            "custody_checkpoint_signatures",
            [column],
        )
    op.create_index(
        "ix_custody_checkpoint_signatures_checkpoint_created",
        "custody_checkpoint_signatures",
        ["checkpoint_id", "created_at", "id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_custody_checkpoint_signatures_checkpoint_created",
        table_name="custody_checkpoint_signatures",
    )
    for column in reversed(
        (
            "case_id",
            "certificate_sha256",
            "checkpoint_sha256",
            "created_at",
            "signature_algorithm",
            "signature_sha256",
            "verification_hash",
            "verified_by",
        )
    ):
        op.drop_index(
            f"ix_custody_checkpoint_signatures_{column}",
            table_name="custody_checkpoint_signatures",
        )
    op.drop_table("custody_checkpoint_signatures")
