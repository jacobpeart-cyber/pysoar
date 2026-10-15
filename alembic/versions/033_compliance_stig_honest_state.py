"""Wave 4 (W4-D compliance, FedRAMP, STIG, audit evidence).

Idempotent like 027-032: every step runs only when the table exists and
lacks what it adds (tables created by ``init_db``'s ``create_all`` may
already have the columns).

1. ``compliance_controls``: ``assessment_basis`` (JSON: what the last
   automated check read, its result and reason) and ``status_source``
   (seed / attester / manual; the attester never overwrites a manual status).
2. ``compliance_assessments``: ``results`` (JSON: computed score, per-check
   outcomes of a ConMon cycle).
3. ``stig_scan_results``: ``agent_id``, ``command_id`` (the endpoint agent's
   ``stig_scan`` command) and ``status_reason`` (why a scan did not run).
4. Data: statuses the previous auto-attester wrote without a check
   (``implemented`` / ``partially_implemented`` with its "Evidence:" narrative)
   are reset to ``not_assessed`` with the narrative removed, and the
   "Auto-attestation:" evidence rows it inserted on every run are marked
   invalid. Scans the in-process scanner stored as ``completed`` without
   evaluating a single rule (every rule not reviewed, no ARF) are marked
   ``not_run``. Re-running ``POST /compliance/frameworks/{id}/attest`` (or
   the daily sweep) records honest results.

Downgrade drops the added columns; the data reset is not reversed.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "033"
down_revision: Union[str, None] = "032"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ADDITIONS: dict[str, tuple[tuple[str, sa.types.TypeEngine], ...]] = {
    "compliance_controls": (
        ("assessment_basis", sa.JSON()),
        ("status_source", sa.String(20)),
    ),
    "compliance_assessments": (
        ("results", sa.JSON()),
    ),
    "stig_scan_results": (
        ("agent_id", sa.String(36)),
        ("command_id", sa.String(36)),
        ("status_reason", sa.Text()),
    ),
}
COMMAND_INDEX = "ix_stig_scan_results_command_id"


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


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

    stig_cols = _columns(bind, "stig_scan_results")
    if stig_cols is not None:
        indexes = {ix["name"] for ix in sa.inspect(bind).get_indexes("stig_scan_results")}
        if COMMAND_INDEX not in indexes:
            op.create_index(COMMAND_INDEX, "stig_scan_results", ["command_id"])
        # Completed scans that evaluated nothing (the pre-2026-10-08 in-process
        # scanner): every rule not reviewed and no result recorded.
        op.execute(sa.text(
            "UPDATE stig_scan_results SET status = 'not_run', compliance_percentage = 0, "
            "status_reason = 'no rule was evaluated: stored by the in-process scanner without contacting the host' "
            "WHERE status = 'completed' AND COALESCE(not_a_finding, 0) = 0 AND COALESCE(open_findings, 0) = 0 "
            "AND COALESCE(not_reviewed, 0) = COALESCE(total_checks, 0)",
        ))

    if _columns(bind, "compliance_controls") is not None:
        op.execute(sa.text(
            "UPDATE compliance_controls SET status = 'not_assessed', implementation_status = 0, "
            "last_assessment_result = 'not_assessed', implementation_details = NULL, status_source = 'attester' "
            "WHERE status IN ('implemented', 'partially_implemented') "
            "AND last_assessment_result IN ('satisfied', 'other_than_satisfied') "
            "AND implementation_details LIKE '%Evidence:%' "
            "AND (status_source IS NULL OR status_source <> 'manual')",
        ))
    if _columns(bind, "compliance_evidence") is not None:
        op.execute(sa.text(
            "UPDATE compliance_evidence SET is_valid = false "
            "WHERE source_system = 'PySOAR Control Auto-Attester' AND title LIKE 'Auto-attestation:%'",
        ))


def downgrade() -> None:
    bind = op.get_bind()
    stig_cols = _columns(bind, "stig_scan_results")
    if stig_cols is not None:
        indexes = {ix["name"] for ix in sa.inspect(bind).get_indexes("stig_scan_results")}
        if COMMAND_INDEX in indexes:
            op.drop_index(COMMAND_INDEX, table_name="stig_scan_results")
    for table, wanted in ADDITIONS.items():
        existing = _columns(bind, table)
        if existing is None:
            continue
        present = [name for name, _ in wanted if name in existing]
        if present:
            with op.batch_alter_table(table) as batch:
                for name in present:
                    batch.drop_column(name)
