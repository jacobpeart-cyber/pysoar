"""Make simulation timestamp columns timezone-aware.

Revision ID: 011
Revises: 010
Create Date: 2026-04-11

``attack_simulations.scheduled_at/started_at/completed_at`` and
``simulation_tests.started_at/completed_at`` were all declared as
``DateTime`` (no tz) while the rest of the codebase populates them with
``utc_now()``, which returns a tz-aware datetime. asyncpg rejects that
mix with "can't subtract offset-naive and offset-aware datetimes", so
every simulation start or finish 500'd.

This migration upgrades the five columns to ``TIMESTAMPTZ`` in place.
Existing naive values are assumed to be UTC (the only value
``utc_now`` ever produced in dev/staging before this fix).
"""

from alembic import op
import sqlalchemy as sa


revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


_COLUMNS = [
    ("attack_simulations", "scheduled_at"),
    ("attack_simulations", "started_at"),
    ("attack_simulations", "completed_at"),
    ("simulation_tests", "started_at"),
    ("simulation_tests", "completed_at"),
]


def upgrade() -> None:
    for table, column in _COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN {column} TYPE TIMESTAMPTZ '
            f"USING {column} AT TIME ZONE 'UTC'"
        )


def downgrade() -> None:
    for table, column in _COLUMNS:
        op.execute(
            f'ALTER TABLE {table} '
            f'ALTER COLUMN {column} TYPE TIMESTAMP '
            f"USING {column} AT TIME ZONE 'UTC'"
        )
