"""Integration execution history: ``playbook_run_id`` widened, ``error_code``
and ``http_status`` stored on the row.

Idempotent like 027-038: every step runs only when the table exists and
needs it (databases whose tables came from ``create_all`` may already match).

``integration_executions.playbook_run_id`` was VARCHAR(36) while the playbook
engine, containment and remediation pass ``playbook_execution:<uuid>`` (55
characters): on PostgreSQL the history write failed and the action left no
execution row. The column becomes VARCHAR(100). ``error_code`` (VARCHAR(50))
and ``http_status`` (INTEGER) hold what the execute response already reported
so the execution history carries them too.

Downgrade drops the two columns; the width is kept (older code only reads
the column and a wider one is compatible).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "039"
down_revision: Union[str, None] = "038"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "integration_executions"
RUN_REF = "playbook_run_id"
RUN_REF_WIDTH = 100
NEW_COLUMNS = (
    ("error_code", sa.String(50)),
    ("http_status", sa.Integer()),
)


def _columns(bind: sa.engine.Connection, table: str) -> dict[str, dict] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"]: c for c in inspector.get_columns(table)}


def _width(column: dict) -> int | None:
    return getattr(column.get("type"), "length", None)


def upgrade() -> None:
    existing = _columns(op.get_bind(), TABLE)
    if existing is None:
        return
    run_ref = existing.get(RUN_REF)
    width = _width(run_ref) if run_ref is not None else None
    narrow = width is not None and width < RUN_REF_WIDTH
    missing = [(name, type_) for name, type_ in NEW_COLUMNS if name not in existing]
    if not narrow and not missing:
        return
    with op.batch_alter_table(TABLE) as batch:
        if narrow:
            batch.alter_column(
                RUN_REF, existing_type=sa.String(width), type_=sa.String(RUN_REF_WIDTH), existing_nullable=True,
            )
        for name, type_ in missing:
            batch.add_column(sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    existing = _columns(op.get_bind(), TABLE)
    if existing is None:
        return
    present = [name for name, _ in NEW_COLUMNS if name in existing]
    if not present:
        return
    with op.batch_alter_table(TABLE) as batch:
        for name in present:
            batch.drop_column(name)
