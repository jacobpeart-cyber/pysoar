"""Make adversary_profiles.organization_id nullable for built-in profiles.

Revision ID: 010
Revises: 009
Create Date: 2026-04-11

The BAS engine ships with 5 built-in APT profiles (APT29, APT28, FIN7,
Lazarus, Generic Ransomware). These are global reference data that every
tenant can use, so they should have no ``organization_id``. Previously the
engine tried to seed them with a sentinel string ``"builtin"`` which
violated the foreign key into ``organizations`` and caused the entire
``GET /simulation/adversaries`` endpoint to 400 every time.

This migration drops NOT NULL from ``adversary_profiles.organization_id``
so built-ins can live as NULL while tenant-authored profiles still point
at their owning org. The corresponding query filter (``is_builtin=True OR
organization_id=org``) is applied in the API layer.
"""

from alembic import op
import sqlalchemy as sa


revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Clean up any stale "builtin" rows that a prior crash attempt may
    # have partially inserted — they're FK-invalid and of no value.
    op.execute("DELETE FROM adversary_profiles WHERE organization_id = 'builtin'")

    op.alter_column(
        "adversary_profiles",
        "organization_id",
        existing_type=sa.String(length=36),
        nullable=True,
    )


def downgrade() -> None:
    # Before re-applying NOT NULL, any NULL built-in rows must be removed
    # or they'd violate the constraint.
    op.execute("DELETE FROM adversary_profiles WHERE organization_id IS NULL")
    op.alter_column(
        "adversary_profiles",
        "organization_id",
        existing_type=sa.String(length=36),
        nullable=False,
    )
