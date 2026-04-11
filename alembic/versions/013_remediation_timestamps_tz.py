"""Make remediation_executions timestamp columns timezone-aware.

Revision ID: 013
Revises: 012
Create Date: 2026-04-11

Same root cause as migration 011 (simulation timestamps): the
``remediation_executions.started_at`` / ``completed_at`` /
``approved_at`` / ``rolled_back_at`` columns were declared as naive
``DateTime``, but every code path that writes to them uses
``utc_now()`` which returns tz-aware. asyncpg refuses the mix with
"can't subtract offset-naive and offset-aware datetimes" the moment a
quick-action tries to mark a remediation as completed.

Upgrade to ``TIMESTAMPTZ`` in place; existing naive values are
assumed UTC (the only value ``utc_now`` ever produced in dev).
"""

from alembic import op
import sqlalchemy as sa


revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


_COLUMNS = [
    ("remediation_executions", "started_at"),
    ("remediation_executions", "completed_at"),
    ("remediation_executions", "approved_at"),
    ("remediation_executions", "rolled_back_at"),
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
