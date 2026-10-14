"""Wave 3 (W3-E simulation / phishing): per-recipient phishing tracking token.

Adds ``phishing_targets.tracking_token`` — an unguessable
``secrets.token_urlsafe`` value that keys the public open / click / report
endpoints (``GET /phishing_sim/t/{token}.gif``, ``GET /phishing_sim/c/{token}``,
``POST /phishing_sim/r/{token}``). It is distinct from the existing
``tracking_id`` (a UUID kept for backward compatibility); events are accepted
for a token or not at all, so a recipient id space can never be enumerated.

Idempotent like 027/028: the column (and its unique index) is added only when
the table exists and lacks it (databases whose tables came from ``init_db``'s
``create_all`` may already have it). Downgrade drops what this revision adds.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "029"
down_revision: Union[str, None] = "028"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLE = "phishing_targets"
COLUMN = "tracking_token"
INDEX = "ix_phishing_targets_tracking_token"


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    return {ix["name"] for ix in inspector.get_indexes(table)}


def upgrade() -> None:
    bind = op.get_bind()
    columns = _columns(bind, TABLE)
    if columns is None:
        # Table not present on this database; create_all/other revisions own it.
        return
    if COLUMN not in columns:
        op.add_column(TABLE, sa.Column(COLUMN, sa.String(64), nullable=True))
    if INDEX not in _indexes(bind, TABLE):
        op.create_index(INDEX, TABLE, [COLUMN], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, TABLE) is None:
        return
    if INDEX in _indexes(bind, TABLE):
        op.drop_index(INDEX, table_name=TABLE)
    op.drop_column(TABLE, COLUMN)
