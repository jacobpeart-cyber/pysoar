"""Wave 2: record the triggering user's role on visual playbook executions.

Revision ID: 025
Revises: 024
Create Date: 2026-10-12

The visual playbook runner re-checks privileged nodes (containment, agent
commands, outbound HTTP, non-read-only integration actions) against the role
recorded at dispatch, so a playbook edited after dispatch cannot escalate an
analyst's run. Existing rows stay NULL and are treated as non-admin.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "025"
down_revision: Union[str, None] = "024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "visual_playbook_executions"
COLUMN = "triggered_by_role"


def _has_column() -> bool:
    inspector = sa.inspect(op.get_bind())
    if TABLE not in inspector.get_table_names():
        return True  # table absent: nothing to alter
    return COLUMN in {c["name"] for c in inspector.get_columns(TABLE)}


def upgrade() -> None:
    if not _has_column():
        op.add_column(TABLE, sa.Column(COLUMN, sa.String(length=50), nullable=True))


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    if TABLE in inspector.get_table_names() and COLUMN in {c["name"] for c in inspector.get_columns(TABLE)}:
        op.drop_column(TABLE, COLUMN)
