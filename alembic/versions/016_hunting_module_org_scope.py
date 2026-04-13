"""Add organization_id to hunting module tables.

Revision ID: 016
Revises: 015
Create Date: 2026-04-12

The hunting module (hunt_hypotheses, hunt_sessions, hunt_findings) had no
organization_id column. Tenant scoping was only possible via the
users.created_by chain, which is fragile and prevents direct org-filtered
queries. This migration adds a nullable organization_id FK to all three
tables and backfills from the created_by -> users.organization_id chain
where possible.
"""

from alembic import op
import sqlalchemy as sa


revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    for table in ("hunt_hypotheses", "hunt_sessions", "hunt_findings"):
        op.add_column(
            table,
            sa.Column(
                "organization_id",
                sa.String(length=36),
                sa.ForeignKey("organizations.id"),
                nullable=True,
            ),
        )
        op.create_index(
            f"ix_{table}_organization_id", table, ["organization_id"]
        )

    # Backfill hunt_hypotheses via created_by -> users.organization_id
    conn.execute(
        sa.text(
            """
            UPDATE hunt_hypotheses
            SET organization_id = (
                SELECT users.organization_id FROM users
                WHERE users.id = hunt_hypotheses.created_by
            )
            WHERE hunt_hypotheses.organization_id IS NULL
              AND hunt_hypotheses.created_by IS NOT NULL
            """
        )
    )

    # Backfill hunt_sessions via created_by -> users.organization_id
    conn.execute(
        sa.text(
            """
            UPDATE hunt_sessions
            SET organization_id = (
                SELECT users.organization_id FROM users
                WHERE users.id = hunt_sessions.created_by
            )
            WHERE hunt_sessions.organization_id IS NULL
              AND hunt_sessions.created_by IS NOT NULL
            """
        )
    )

    # Backfill hunt_findings via session -> hunt_sessions.organization_id
    conn.execute(
        sa.text(
            """
            UPDATE hunt_findings
            SET organization_id = (
                SELECT hunt_sessions.organization_id FROM hunt_sessions
                WHERE hunt_sessions.id = hunt_findings.session_id
            )
            WHERE hunt_findings.organization_id IS NULL
              AND hunt_findings.session_id IS NOT NULL
            """
        )
    )


def downgrade() -> None:
    for table in ("hunt_findings", "hunt_sessions", "hunt_hypotheses"):
        op.drop_index(f"ix_{table}_organization_id", table_name=table)
        op.drop_column(table, "organization_id")
