"""Wave 2: automation-rule evaluator state and firing history.

Revision ID: 024
Revises: 023
Create Date: 2026-10-12

TicketHub automation rules were stored but never evaluated. The beat
evaluator (``src/tickethub/tasks.py``) needs:

* on ``automation_rules``: ``evaluation_status`` (``active`` /
  ``unsupported``), ``unsupported_reason`` and ``last_evaluated_at`` (the
  per-rule event cursor);
* a new ``automation_rule_firings`` table: one row per (rule, event, action)
  with the honest outcome.

``automation_rules`` itself was only ever created by ``init_db``'s
``create_all`` (no earlier revision creates it), so every step is idempotent:
columns are added only when the table exists and lacks them, the firings
table only when missing. Existing rules start ``active`` with a NULL cursor;
the evaluator then looks back at most 24 h on its first run and marks any
rule it cannot evaluate ``unsupported`` with the reason.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "024"
down_revision: Union[str, None] = "023"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RULES = "automation_rules"
FIRINGS = "automation_rule_firings"

#: Consumed by tests to check the round trip.
NEW_RULE_COLUMNS: tuple[str, ...] = ("evaluation_status", "unsupported_reason", "last_evaluated_at")
FIRING_INDEXES: tuple[tuple[str, str], ...] = (
    ("ix_automation_rule_firings_rule_id", "rule_id"),
    ("ix_automation_rule_firings_organization_id", "organization_id"),
    ("ix_automation_rule_firings_target_id", "target_id"),
    ("ix_automation_rule_firings_event_id", "event_id"),
    ("ix_automation_rule_firings_fired_at", "fired_at"),
)


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind, RULES)
    if existing is not None:
        missing = [c for c in NEW_RULE_COLUMNS if c not in existing]
        if missing:
            with op.batch_alter_table(RULES) as batch:
                if "evaluation_status" in missing:
                    batch.add_column(
                        sa.Column("evaluation_status", sa.String(20), nullable=False, server_default="active"),
                    )
                if "unsupported_reason" in missing:
                    batch.add_column(sa.Column("unsupported_reason", sa.Text(), nullable=True))
                if "last_evaluated_at" in missing:
                    batch.add_column(sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=True))

    if _columns(bind, FIRINGS) is None and existing is not None:
        op.create_table(
            FIRINGS,
            sa.Column("id", sa.String(36), primary_key=True, nullable=False),
            sa.Column(
                "rule_id",
                sa.String(36),
                sa.ForeignKey(f"{RULES}.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("organization_id", sa.String(36), nullable=False),
            sa.Column("target_type", sa.String(50), nullable=False),
            sa.Column("target_id", sa.String(36), nullable=False),
            sa.Column("event_id", sa.String(36), nullable=False),
            sa.Column("action", sa.String(50), nullable=False),
            sa.Column("result", sa.String(30), nullable=False),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("detail", sa.JSON(), nullable=True),
            sa.Column("fired_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        for name, column in FIRING_INDEXES:
            op.create_index(name, FIRINGS, [column])


def downgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, FIRINGS) is not None:
        op.drop_table(FIRINGS)
    existing = _columns(bind, RULES)
    if existing is None:
        return
    present = [c for c in NEW_RULE_COLUMNS if c in existing]
    if present:
        with op.batch_alter_table(RULES) as batch:
            for column in present:
                batch.drop_column(column)
