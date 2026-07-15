"""Create local authentication and RBAC tables.

Revision ID: 0004_auth_rbac
Revises: 0003_jobs
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_auth_rbac"
down_revision: str | None = "0003_jobs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("failed_login_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_changed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("failed_login_count >= 0", name="ck_users_failed_login_count"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_created_at", "users", ["created_at"])
    op.create_index("ix_users_is_active", "users", ["is_active"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "roles",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_roles_name", "roles", ["name"], unique=True)

    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role_id", sa.String(length=36), nullable=False),
        sa.Column("assigned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assigned_by", sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(["assigned_by"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("user_id", "role_id"),
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_sessions_created_at", "auth_sessions", ["created_at"])
    op.create_index("ix_auth_sessions_expires_at", "auth_sessions", ["expires_at"])
    op.create_index("ix_auth_sessions_token_hash", "auth_sessions", ["token_hash"], unique=True)
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])

    op.create_table(
        "auth_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("username_hash", sa.String(length=64), nullable=False),
        sa.Column("event_type", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("safe_detail", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_auth_events_created_at", "auth_events", ["created_at"])
    op.create_index("ix_auth_events_event_type", "auth_events", ["event_type"])
    op.create_index("ix_auth_events_outcome", "auth_events", ["outcome"])
    op.create_index("ix_auth_events_user_id", "auth_events", ["user_id"])
    op.create_index("ix_auth_events_username_hash", "auth_events", ["username_hash"])


def downgrade() -> None:
    op.drop_index("ix_auth_events_username_hash", table_name="auth_events")
    op.drop_index("ix_auth_events_user_id", table_name="auth_events")
    op.drop_index("ix_auth_events_outcome", table_name="auth_events")
    op.drop_index("ix_auth_events_event_type", table_name="auth_events")
    op.drop_index("ix_auth_events_created_at", table_name="auth_events")
    op.drop_table("auth_events")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_token_hash", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_expires_at", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_created_at", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_table("user_roles")
    op.drop_index("ix_roles_name", table_name="roles")
    op.drop_table("roles")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_is_active", table_name="users")
    op.drop_index("ix_users_created_at", table_name="users")
    op.drop_table("users")
