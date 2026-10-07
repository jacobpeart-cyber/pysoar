"""Agentic SOC: run-level summary on agent_run_transcripts (AU-3 / AU-12).

Revision ID: 022
Revises: 021
Create Date: 2026-10-06

Every agent run now writes one ``agent_run_transcripts`` row
(``src.agentic.transcript.persist_run_transcript``). The per-step list already
has a column (``steps``); the run-level record -- prompt version, usage
totals, trust summary, proposal ids/hashes, policy events, the redacted and
capped final answer and the writer's truncation record -- goes in one new
nullable ``summary`` column (``EncryptedJSON`` at the ORM layer, Text here,
like ``steps``). No data is rewritten, so the downgrade simply drops it. Both
directions are idempotent so fresh installs that created the table from the
ORM are unaffected.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "022"
down_revision: Union[str, None] = "021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "agent_run_transcripts"

#: Consumed by tests to check the round trip.
NEW_COLUMNS: tuple[str, ...] = ("summary",)


def _columns() -> list[sa.Column]:
    return [sa.Column("summary", sa.Text(), nullable=True)]  # EncryptedJSON at the ORM layer


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
