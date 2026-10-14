"""Wave 3 (SIEM): data-source event counters; correlation_events in the model's shape.

Revision ID: 026
Revises: 025
Create Date: 2026-10-12

* ``siem_data_sources.events_received`` (lifetime count of ingested logs
  whose ``source_name`` equals the data source's name; written by the
  ingest pipeline next to ``events_today`` and ``last_event_at``).
* ``correlation_events``: migration 001 created it as
  (id, event_data, correlated_at), a shape no code writes, so on a database
  built by alembic alone every correlation insert failed. When the table
  still has that legacy shape it is renamed to ``correlation_events_legacy_001``
  (kept, never dropped) and the table is created with the columns of
  ``src.siem.models.CorrelationEvent``. A table that already has the model's
  shape (databases whose tables came from ``create_all``) is left alone.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "026"
down_revision: Union[str, None] = "025"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

SOURCES = "siem_data_sources"
COUNTER = "events_received"
CORRELATIONS = "correlation_events"
LEGACY = "correlation_events_legacy_001"


def _columns(inspector, table: str) -> set[str]:
    return {c["name"] for c in inspector.get_columns(table)}


def _create_correlation_events() -> None:
    op.create_table(
        CORRELATIONS,
        sa.Column("id", sa.String(36), nullable=False),
        sa.Column("correlation_id", sa.String(100), nullable=False),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(50), nullable=False, server_default="medium"),
        sa.Column("rule_id", sa.String(36), sa.ForeignKey("detection_rules.id"), nullable=True),
        sa.Column("log_entry_ids", sa.Text(), nullable=True),
        sa.Column("source_addresses", sa.Text(), nullable=True),
        sa.Column("usernames", sa.Text(), nullable=True),
        sa.Column("hostnames", sa.Text(), nullable=True),
        sa.Column("timespan_start", sa.String(50), nullable=False),
        sa.Column("timespan_end", sa.String(50), nullable=False),
        sa.Column("event_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("mitre_tactics", sa.Text(), nullable=True),
        sa.Column("mitre_techniques", sa.Text(), nullable=True),
        sa.Column("alert_generated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("alert_id", sa.String(36), nullable=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="new"),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        # Explicit name: a renamed legacy table keeps "correlation_events_pkey".
        sa.PrimaryKeyConstraint("id", name="correlation_events_model_pkey"),
    )
    op.create_index("ix_correlation_events_correlation_id", CORRELATIONS, ["correlation_id"], unique=True)
    op.create_index("ix_correlation_events_severity", CORRELATIONS, ["severity"])
    op.create_index("ix_correlation_events_timespan_start", CORRELATIONS, ["timespan_start"])
    op.create_index("ix_correlation_events_status", CORRELATIONS, ["status"])
    op.create_index("ix_correlation_events_organization_id", CORRELATIONS, ["organization_id"])


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if SOURCES in tables and COUNTER not in _columns(inspector, SOURCES):
        op.add_column(
            SOURCES,
            sa.Column(COUNTER, sa.BigInteger(), nullable=False, server_default="0"),
        )

    if CORRELATIONS not in tables:
        _create_correlation_events()
    elif "correlation_id" not in _columns(inspector, CORRELATIONS):
        legacy_name, suffix = LEGACY, 2
        while legacy_name in tables:
            legacy_name, suffix = f"{LEGACY}_{suffix}", suffix + 1
        op.rename_table(CORRELATIONS, legacy_name)
        _create_correlation_events()


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())
    if SOURCES in tables and COUNTER in _columns(inspector, SOURCES):
        op.drop_column(SOURCES, COUNTER)
    # The correlation_events reshape is not reversed: the legacy table, if one
    # was renamed, is still there for an operator to inspect.
