"""Add organization_id to alerts and incidents for multi-tenant scoping.

Revision ID: 015
Revises: 014
Create Date: 2026-04-11

P0 audit finding: the two core SOC tables — ``alerts`` and ``incidents`` —
had no ``organization_id`` column. Every authenticated user could read /
list / patch / delete every other tenant's alerts and incidents, and every
dashboard stat query across the app (analytics, incident dashboards, alert
aggregates, correlation feeds) aggregated counts globally instead of per
tenant.

This migration adds nullable ``organization_id`` FKs to both tables and
backfills existing rows to the first organization in the database
(single-tenant default for self-hosted installs). The columns are left
nullable for tolerance of legacy rows that can't be cleanly attributed —
the API layer's filter will still exclude un-tagged rows when a tenant is
present on the request.
"""

from alembic import op
import sqlalchemy as sa


revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    fallback_org = conn.execute(
        sa.text("SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1")
    ).scalar()

    # --- alerts ---
    op.add_column(
        "alerts",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
    )
    op.create_index("ix_alerts_organization_id", "alerts", ["organization_id"])
    if fallback_org:
        conn.execute(
            sa.text(
                "UPDATE alerts SET organization_id = :org WHERE organization_id IS NULL"
            ),
            {"org": fallback_org},
        )

    # --- incidents ---
    op.add_column(
        "incidents",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_incidents_organization_id", "incidents", ["organization_id"]
    )
    if fallback_org:
        conn.execute(
            sa.text(
                "UPDATE incidents SET organization_id = :org WHERE organization_id IS NULL"
            ),
            {"org": fallback_org},
        )


def downgrade() -> None:
    op.drop_index("ix_incidents_organization_id", table_name="incidents")
    op.drop_column("incidents", "organization_id")
    op.drop_index("ix_alerts_organization_id", table_name="alerts")
    op.drop_column("alerts", "organization_id")
