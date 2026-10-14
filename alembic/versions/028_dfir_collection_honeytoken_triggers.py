"""Wave 3 (DFIR / deception): agent collection columns; honeytoken trigger rows.

Revision ID: 028
Revises: 027
Create Date: 2026-10-13

* ``forensic_evidence``: ``collection_status``, ``collection_command_id``,
  ``collection_agent_id``, ``collection_error``. Evidence collected through an
  endpoint agent (``collect_*`` commands) tracks the agent command here; the
  status follows the command result (``src.dfir.collection``).
* ``honey_token_triggers`` (``src.deception.models.HoneyTokenTrigger``): one
  row per call to ``POST /deception/canary/{token_id}`` with the caller's
  source metadata. ``honey_tokens.triggered_count`` is the count of these.

Idempotent like 024/026/027: the table is created only when missing and each
column added only when its table exists and lacks it (databases whose tables
came from ``init_db``'s ``create_all`` may already have them). Downgrade
drops what this revision adds.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "028"
down_revision: Union[str, None] = "027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EVIDENCE = "forensic_evidence"
TRIGGERS = "honey_token_triggers"

#: Consumed by tests to check the round trip.
NEW_EVIDENCE_COLUMNS: tuple[str, ...] = (
    "collection_status",
    "collection_command_id",
    "collection_agent_id",
    "collection_error",
)


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _evidence_column(name: str) -> sa.Column:
    if name == "collection_error":
        return sa.Column(name, sa.Text(), nullable=True)
    if name == "collection_status":
        return sa.Column(name, sa.String(30), nullable=True)
    return sa.Column(name, sa.String(36), nullable=True)


def upgrade() -> None:
    bind = op.get_bind()
    existing = _columns(bind, EVIDENCE)
    if existing is not None:
        missing = [c for c in NEW_EVIDENCE_COLUMNS if c not in existing]
        if missing:
            with op.batch_alter_table(EVIDENCE) as batch:
                for name in missing:
                    batch.add_column(_evidence_column(name))
            if "collection_status" in missing:
                op.create_index("ix_forensic_evidence_collection_status", EVIDENCE, ["collection_status"])
            if "collection_command_id" in missing:
                op.create_index("ix_forensic_evidence_collection_command_id", EVIDENCE, ["collection_command_id"])

    if _columns(bind, TRIGGERS) is None:
        op.create_table(
            TRIGGERS,
            sa.Column("id", sa.String(36), primary_key=True, nullable=False),
            sa.Column(
                "token_id",
                sa.String(36),
                sa.ForeignKey("honey_tokens.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "organization_id",
                sa.String(36),
                sa.ForeignKey("organizations.id"),
                nullable=False,
            ),
            sa.Column("source_ip", sa.String(45), nullable=True),
            sa.Column("forwarded_for", sa.String(500), nullable=True),
            sa.Column("user_agent", sa.String(500), nullable=True),
            sa.Column("http_method", sa.String(10), nullable=False, server_default="POST"),
            sa.Column("request_metadata", sa.JSON(), nullable=False, server_default="{}"),
            sa.Column("value_presented", sa.Boolean(), nullable=True),
            sa.Column("alert_id", sa.String(36), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_honey_token_triggers_token_id", TRIGGERS, ["token_id"])
        op.create_index("ix_honey_token_triggers_organization_id", TRIGGERS, ["organization_id"])

    # Honeytoken values are no longer stored: rows written before this
    # revision kept the plaintext in token_value. Keep a short preview only
    # (token_hash already holds the SHA-256 used for matching). Not reversed.
    if _columns(bind, "honey_tokens") is not None:
        op.execute(
            sa.text(
                "UPDATE honey_tokens SET token_value = substr(token_value, 1, 8) || '...' "
                "WHERE length(token_value) > 12 AND token_value NOT LIKE '%...%'",
            ),
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, TRIGGERS) is not None:
        op.drop_table(TRIGGERS)
    existing = _columns(bind, EVIDENCE)
    if existing is not None:
        present = [c for c in NEW_EVIDENCE_COLUMNS if c in existing]
        if present:
            indexes = {i["name"] for i in sa.inspect(bind).get_indexes(EVIDENCE)}
            for name in ("ix_forensic_evidence_collection_status", "ix_forensic_evidence_collection_command_id"):
                if name in indexes:
                    op.drop_index(name, table_name=EVIDENCE)
            with op.batch_alter_table(EVIDENCE) as batch:
                for name in present:
                    batch.drop_column(name)
