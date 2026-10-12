"""Wave 1 tenancy: organization_id on audit_logs and hunt_notebooks.

Revision ID: 023
Revises: 022
Create Date: 2026-10-12

Both tables lacked a tenant column, so audit history and hunt notebooks could
only be scoped indirectly (or not at all). Adds a nullable, indexed
``organization_id`` (String(36), no FK: audit history must survive an
organisation's deletion, and notebooks follow the same shape).

Backfill rules:

* ``audit_logs``: historic rows stay NULL. New rows are stamped with the acting
  user's organisation by the ``before_insert`` listener in
  ``src/models/audit.py``.
* ``hunt_notebooks``: existing rows take the organisation of their parent
  ``hunt_sessions`` row (a notebook always belongs to one session). New rows
  are stamped by the create route.

Both directions are idempotent (add only when missing, drop only when present)
so installs that created the tables from the ORM are unaffected.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "023"
down_revision: Union[str, None] = "022"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

COLUMN = "organization_id"

#: Consumed by tests to check the round trip.
TABLES: tuple[str, ...] = ("audit_logs", "hunt_notebooks")


def _index_name(table: str) -> str:
    return f"ix_{table}_{COLUMN}"


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(bind: sa.engine.Connection, table: str) -> set[str]:
    return {i["name"] for i in sa.inspect(bind).get_indexes(table) if i.get("name")}


def upgrade() -> None:
    bind = op.get_bind()
    for table in TABLES:
        existing = _columns(bind, table)
        if existing is None:
            continue
        if COLUMN not in existing:
            with op.batch_alter_table(table) as batch:
                batch.add_column(sa.Column(COLUMN, sa.String(36), nullable=True))
        if _index_name(table) not in _indexes(bind, table):
            op.create_index(_index_name(table), table, [COLUMN])

    if _columns(bind, "hunt_notebooks") is not None and _columns(bind, "hunt_sessions") is not None:
        op.execute(
            sa.text(
                "UPDATE hunt_notebooks SET organization_id = ("
                " SELECT hunt_sessions.organization_id FROM hunt_sessions"
                " WHERE hunt_sessions.id = hunt_notebooks.session_id)"
                " WHERE organization_id IS NULL"
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    for table in TABLES:
        existing = _columns(bind, table)
        if existing is None or COLUMN not in existing:
            continue
        if _index_name(table) in _indexes(bind, table):
            op.drop_index(_index_name(table), table_name=table)
        with op.batch_alter_table(table) as batch:
            batch.drop_column(COLUMN)
