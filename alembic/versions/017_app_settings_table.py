"""Create app_settings table for DB-persisted runtime configuration.

Revision ID: 017
Revises: 016
Create Date: 2026-04-18

Settings edited via PATCH /settings/{general,smtp,notifications,security} and
POST /settings/integrations/{id} were being written only to the runtime
``app_settings`` config object, so every container restart reverted them.
This migration adds an ``app_settings`` (note: distinct from the pydantic
config object) table: a per-org JSON blob keyed by ``(organization_id,
section)``. ``organization_id`` is nullable so a global default row can exist
for self-hosted single-tenant installs.
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    value_type = JSONB() if is_postgres else sa.JSON()

    op.create_table(
        "app_settings",
        sa.Column("id", sa.String(length=36), primary_key=True, nullable=False),
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=True,
        ),
        sa.Column("section", sa.String(length=100), nullable=False),
        sa.Column("value", value_type, nullable=False),
        sa.Column(
            "updated_by",
            sa.String(length=36),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "organization_id", "section", name="uq_app_settings_org_section"
        ),
    )
    op.create_index(
        "ix_app_settings_organization_id",
        "app_settings",
        ["organization_id"],
    )
    op.create_index(
        "ix_app_settings_section",
        "app_settings",
        ["section"],
    )


def downgrade() -> None:
    op.drop_index("ix_app_settings_section", table_name="app_settings")
    op.drop_index("ix_app_settings_organization_id", table_name="app_settings")
    op.drop_table("app_settings")
