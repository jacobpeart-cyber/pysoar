"""Add organization_id to assets and playbook_executions for multi-tenant scoping.

Revision ID: 014
Revises: 013
Create Date: 2026-04-11

During the extreme audit we discovered that two tables had never been retrofitted
for multi-tenancy:

- ``assets``: the core asset inventory. Every authenticated user could see every
  other tenant's asset inventory via GET /assets. For a SaaS SOAR that sells
  to multiple customers this is a P0 cross-tenant data leak.
- ``playbook_executions``: per-tenant execution history including input_data
  payloads that often reference sensitive context (incident ids, alert ids,
  indicator values).

This migration adds a nullable ``organization_id`` foreign key to both tables.
Existing rows are backfilled to the first organization in the database (the
single-tenant default for self-hosted installs). New rows are tagged at create
time by the API layer. The column is left nullable to tolerate legacy rows
that can't be cleanly attributed.
"""

from alembic import op
import sqlalchemy as sa


revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Determine a fallback org id for backfill (first org by created_at)
    conn = op.get_bind()
    fallback_org = conn.execute(
        sa.text("SELECT id FROM organizations ORDER BY created_at ASC LIMIT 1")
    ).scalar()

    # --- assets ---
    op.add_column(
        "assets",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_assets_organization_id", "assets", ["organization_id"]
    )
    if fallback_org:
        conn.execute(
            sa.text(
                "UPDATE assets SET organization_id = :org WHERE organization_id IS NULL"
            ),
            {"org": fallback_org},
        )

    # --- playbook_executions ---
    op.add_column(
        "playbook_executions",
        sa.Column(
            "organization_id",
            sa.String(length=36),
            sa.ForeignKey("organizations.id"),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_playbook_executions_organization_id",
        "playbook_executions",
        ["organization_id"],
    )
    if fallback_org:
        # Backfill via triggered_by -> user.organization_id when possible
        conn.execute(
            sa.text(
                """
                UPDATE playbook_executions
                SET organization_id = (
                    SELECT users.organization_id FROM users
                    WHERE users.id = playbook_executions.triggered_by
                )
                WHERE playbook_executions.organization_id IS NULL
                  AND playbook_executions.triggered_by IS NOT NULL
                """
            )
        )
        # Remaining rows fall back to the default org
        conn.execute(
            sa.text(
                "UPDATE playbook_executions SET organization_id = :org WHERE organization_id IS NULL"
            ),
            {"org": fallback_org},
        )


def downgrade() -> None:
    op.drop_index("ix_playbook_executions_organization_id", table_name="playbook_executions")
    op.drop_column("playbook_executions", "organization_id")
    op.drop_index("ix_assets_organization_id", table_name="assets")
    op.drop_column("assets", "organization_id")
