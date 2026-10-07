"""Agentic SOC: first-approver columns for require_second_approver (AC-5).

Revision ID: 021
Revises: 020
Create Date: 2026-10-06

When an organization enables ``require_second_approver`` (``app_settings``
section ``agentic_policy``; no schema change needed for the setting itself),
a destructive/privileged proposal needs two distinct approvers. The first
approval is recorded here and the proposal stays ``pending_approval``; the
second approver lands in the existing ``approved_by`` column.

Three nullable columns on ``agent_actions``; no data is rewritten, so the
downgrade simply drops them. Both directions are idempotent (columns are
added/dropped only when absent/present) so fresh installs that created the
table from the ORM are unaffected.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "021"
down_revision: Union[str, None] = "020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "agent_actions"

#: Consumed by tests to check the round trip.
NEW_COLUMNS: tuple[str, ...] = ("first_approved_by", "first_approved_at", "first_approver_role")


def _columns() -> list[sa.Column]:
    return [
        sa.Column("first_approved_by", sa.String(36), nullable=True),
        sa.Column("first_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_approver_role", sa.String(20), nullable=True),
    ]


def _existing(bind: sa.engine.Connection) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(TABLE):
        return None
    return {c["name"] for c in inspector.get_columns(TABLE)}


def upgrade() -> None:
    bind = op.get_bind()
    existing = _existing(bind)
    if existing is None:
        return
    missing = [c for c in _columns() if c.name not in existing]
    if not missing:
        return
    with op.batch_alter_table(TABLE) as batch:
        for column in missing:
            batch.add_column(column)


def downgrade() -> None:
    bind = op.get_bind()
    existing = _existing(bind)
    if existing is None:
        return
    present = [name for name in NEW_COLUMNS if name in existing]
    if not present:
        return
    with op.batch_alter_table(TABLE) as batch:
        for name in present:
            batch.drop_column(name)
