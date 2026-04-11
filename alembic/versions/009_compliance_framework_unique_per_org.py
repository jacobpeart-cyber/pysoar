"""Drop global unique-on-name from compliance_frameworks.

Revision ID: 009
Revises: 008
Create Date: 2026-04-11

ComplianceFramework.name had `unique=True` at the column level, which
created a global unique constraint. But a framework like "FedRAMP
Moderate" must exist once per organization (so every tenant can track
their own compliance posture). The model already has a composite
UniqueConstraint("organization_id", "short_name") which is the correct
uniqueness rule.

This migration drops the global name constraint so multi-org deployments
can seed framework catalogs for every organization.
"""

from alembic import op


revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PostgreSQL auto-generates constraint name compliance_frameworks_name_key
    # for `unique=True` on the name column.
    op.execute(
        "ALTER TABLE compliance_frameworks "
        "DROP CONSTRAINT IF EXISTS compliance_frameworks_name_key"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE compliance_frameworks "
        "ADD CONSTRAINT compliance_frameworks_name_key UNIQUE (name)"
    )
