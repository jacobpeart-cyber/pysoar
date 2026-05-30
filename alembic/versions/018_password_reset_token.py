"""Add password_reset_token to users.

Revision ID: 018_password_reset_token
Revises: 017
Create Date: 2026-05-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "018_password_reset_token"
down_revision: Union[str, None] = "017"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("password_reset_token", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("password_reset_token_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    # unique=True: two users CANNOT share a reset token. With 48-byte
    # url-safe tokens the collision probability is vanishingly small, but
    # the DB-layer guarantee removes "what if?" doubt from the URL handler.
    op.create_index(
        "ix_users_password_reset_token",
        "users",
        ["password_reset_token"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_users_password_reset_token", table_name="users")
    op.drop_column("users", "password_reset_token_expires_at")
    op.drop_column("users", "password_reset_token")
