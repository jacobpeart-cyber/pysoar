"""Wave 4 (W4-E privacy, DLP, data lake).

Idempotent like 027-033: every step runs only when the table exists and
lacks what it adds (tables created by ``init_db``'s ``create_all`` may
already have the columns).

1. ``dlp_policies``: ``evaluation_status`` (active / inactive),
   ``evaluation_reason`` and ``last_evaluated_at`` written by the DLP
   content scanner (src/dlp/scanner.py).
2. ``dlp_violations``: ``source_type``, ``source_id``, ``location``,
   ``redacted_excerpt`` and ``detected_by`` for content-scan findings, plus
   the unique constraint ``uq_dlp_violation_policy_source`` (one finding per
   policy and stored record; manual violations leave the source NULL).
3. ``dlp_incidents``: ``resolution_notes`` (the UI sent it; it was dropped).
4. ``dlp_scan_cursors``: per organisation / data source position and run
   counters of the content scan.
5. ``data_subject_requests``: the DSR workflow record (identity
   verification attestation, search / export / erasure timestamps, export
   digest and count, erasure log, completion and deadline breach).

Downgrade drops what was added.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "034"
down_revision: Union[str, None] = "033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ADDITIONS: dict[str, tuple[tuple[str, sa.types.TypeEngine], ...]] = {
    "dlp_policies": (
        ("evaluation_status", sa.String(20)),
        ("evaluation_reason", sa.Text()),
        ("last_evaluated_at", sa.DateTime(timezone=True)),
    ),
    "dlp_violations": (
        ("source_type", sa.String(50)),
        ("source_id", sa.String(36)),
        ("location", sa.Text()),
        ("redacted_excerpt", sa.Text()),
        ("detected_by", sa.String(20)),
    ),
    "dlp_incidents": (
        ("resolution_notes", sa.Text()),
    ),
    "data_subject_requests": (
        ("identity_verified_at", sa.DateTime(timezone=True)),
        ("identity_verified_by", sa.String(36)),
        ("identity_verification_method", sa.String(50)),
        ("identity_verification_evidence", sa.Text()),
        ("searched_at", sa.DateTime(timezone=True)),
        ("exported_at", sa.DateTime(timezone=True)),
        ("export_sha256", sa.String(64)),
        ("export_record_count", sa.Integer()),
        ("erasure_executed_at", sa.DateTime(timezone=True)),
        ("erasure_log", sa.Text()),
        ("completed_at", sa.DateTime(timezone=True)),
        ("deadline_breached_at", sa.DateTime(timezone=True)),
    ),
}
VIOLATION_UNIQUE = "uq_dlp_violation_policy_source"
CURSOR_TABLE = "dlp_scan_cursors"
CURSOR_UNIQUE = "uq_dlp_scan_cursor_org_source"
CURSOR_ORG_INDEX = "ix_dlp_scan_cursors_organization_id"


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _unique_names(bind: sa.engine.Connection, table: str) -> set[str]:
    return {u["name"] for u in sa.inspect(bind).get_unique_constraints(table) if u.get("name")}


def upgrade() -> None:
    bind = op.get_bind()
    for table, wanted in ADDITIONS.items():
        existing = _columns(bind, table)
        if existing is None:
            continue
        missing = [(name, type_) for name, type_ in wanted if name not in existing]
        if missing:
            with op.batch_alter_table(table) as batch:
                for name, type_ in missing:
                    batch.add_column(sa.Column(name, type_, nullable=True))

    if _columns(bind, "dlp_violations") is not None and VIOLATION_UNIQUE not in _unique_names(bind, "dlp_violations"):
        with op.batch_alter_table("dlp_violations") as batch:
            batch.create_unique_constraint(VIOLATION_UNIQUE, ["policy_id", "source_type", "source_id"])

    if _columns(bind, CURSOR_TABLE) is None:
        op.create_table(
            CURSOR_TABLE,
            sa.Column("id", sa.String(36), primary_key=True),
            sa.Column("organization_id", sa.String(36), nullable=False),
            sa.Column("source_type", sa.String(50), nullable=False),
            sa.Column("last_created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_id", sa.String(36), nullable=True),
            sa.Column("rows_scanned_total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_run_rows", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_run_findings", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.UniqueConstraint("organization_id", "source_type", name=CURSOR_UNIQUE),
        )
        op.create_index(CURSOR_ORG_INDEX, CURSOR_TABLE, ["organization_id"])


def downgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, CURSOR_TABLE) is not None:
        op.drop_table(CURSOR_TABLE)
    if _columns(bind, "dlp_violations") is not None and VIOLATION_UNIQUE in _unique_names(bind, "dlp_violations"):
        with op.batch_alter_table("dlp_violations") as batch:
            batch.drop_constraint(VIOLATION_UNIQUE, type_="unique")
    for table, wanted in ADDITIONS.items():
        existing = _columns(bind, table)
        if existing is None:
            continue
        present = [name for name, _ in wanted if name in existing]
        if present:
            with op.batch_alter_table(table) as batch:
                for name in present:
                    batch.drop_column(name)
