"""Wave 3 (UEBA / ITDR ingestion): log consumer cursors; identity provenance columns.

Revision ID: 027
Revises: 026
Create Date: 2026-10-13

* ``log_ingest_cursors`` (``src.ueba.models.LogIngestCursor``): per
  organisation and consumer, the read position over ``log_entries``
  (``ueba_siem`` for the UEBA SIEM bridge, ``itdr_auth`` for the ITDR
  auth-event analysis) and the last run's status / summary (also used by the
  ITDR identity scan and directory syncs). Unique on
  (organization_id, consumer).
* ``identity_profiles``: ``account_status``, ``source``,
  ``source_integration_id``, ``last_synced_at`` (directory provenance) and
  ``auth_baseline`` (sign-in baseline learned from auth events).

Idempotent like 024/026: the table is created only when missing and each
column added only when its table exists and lacks it (databases whose tables
came from ``init_db``'s ``create_all`` may already have them). Downgrade
drops what this revision adds.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "027"
down_revision: Union[str, None] = "026"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CURSORS = "log_ingest_cursors"
IDENTITIES = "identity_profiles"

#: Consumed by tests to check the round trip.
NEW_IDENTITY_COLUMNS: tuple[str, ...] = (
    "account_status",
    "source",
    "source_integration_id",
    "last_synced_at",
    "auth_baseline",
)


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _identity_column(name: str) -> sa.Column:
    if name == "auth_baseline":
        return sa.Column(name, sa.JSON(), nullable=True)
    length = 36 if name == "source_integration_id" else 50
    return sa.Column(name, sa.String(length), nullable=True)


def upgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, CURSORS) is None:
        op.create_table(
            CURSORS,
            sa.Column("id", sa.String(36), primary_key=True, nullable=False),
            sa.Column(
                "organization_id",
                sa.String(36),
                sa.ForeignKey("organizations.id"),
                nullable=False,
            ),
            sa.Column("consumer", sa.String(50), nullable=False),
            sa.Column("last_received_at", sa.String(50), nullable=True),
            sa.Column("last_log_id", sa.String(36), nullable=True),
            sa.Column("rows_processed_total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_run_rows", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_status", sa.String(20), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("last_run_summary", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("organization_id", "consumer", name="uix_log_ingest_cursor"),
        )

    existing = _columns(bind, IDENTITIES)
    if existing is not None:
        missing = [c for c in NEW_IDENTITY_COLUMNS if c not in existing]
        if missing:
            with op.batch_alter_table(IDENTITIES) as batch:
                for name in missing:
                    batch.add_column(_identity_column(name))


def downgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind, IDENTITIES)
    if existing is not None:
        present = [c for c in NEW_IDENTITY_COLUMNS if c in existing]
        if present:
            with op.batch_alter_table(IDENTITIES) as batch:
                for name in present:
                    batch.drop_column(name)
    if _columns(bind, CURSORS) is not None:
        op.drop_table(CURSORS)
