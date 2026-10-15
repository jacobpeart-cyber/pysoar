"""Wave 4 (W4-A vulnerability and exposure management).

Three changes, all idempotent like 027-029 (each step runs only when the
table exists and lacks what it adds; databases whose tables came from
``init_db``'s ``create_all`` may already have them):

1. ``vulnerability_instances`` gains the scanner identity a finding is
   deduplicated on: ``port``, ``protocol``, ``plugin_id`` and ``dedupe_key``
   (asset + catalog vulnerability + port/protocol), with a unique index on
   ``(organization_id, dedupe_key)``. ``remediated_at`` records when an
   instance was patched or mitigated, so MTTR is measured from detection to
   remediation instead of first-seen to last-seen.
2. ``vulnerabilities``: the ORM declared ``cve_id`` unique across the whole
   table, so a second tenant importing a CVE the first tenant already had
   failed with an integrity error. The single-column unique index (or
   constraint) is replaced by a plain index plus a unique index on
   ``(organization_id, cve_id)``. ``kev_date_added`` / ``kev_due_date`` keep
   the CISA KEV dates the BOD 22-01 deadline is computed from.
3. ``exposure_daily_snapshots``: one row per organisation per day of the
   exposure posture, written by ``src.exposure.tasks.snapshot_exposure_daily``;
   the exposure dashboard charts read these rows instead of inventing a series.

Downgrade removes what this revision adds (the per-tenant CVE index is left in
place: restoring a global unique index could fail on multi-tenant data).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "030"
down_revision: Union[str, None] = "029"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

INSTANCES = "vulnerability_instances"
VULNS = "vulnerabilities"
SNAPSHOTS = "exposure_daily_snapshots"

INSTANCE_DEDUPE_INDEX = "uq_vulnerability_instances_org_dedupe"
VULN_ORG_CVE_INDEX = "uq_vulnerabilities_org_cve"
VULN_CVE_INDEX = "ix_vulnerabilities_cve_id"
SNAPSHOT_UNIQUE = "uq_exposure_daily_snapshots_org_day"

#: Columns added to vulnerability_instances, in order.
INSTANCE_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("port", sa.Integer()),
    ("protocol", sa.String(16)),
    ("plugin_id", sa.String(100)),
    ("dedupe_key", sa.String(255)),
    ("remediated_at", sa.String(50)),
)
VULN_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("kev_date_added", sa.String(50)),
    ("kev_due_date", sa.String(50)),
)


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _indexes(bind: sa.engine.Connection, table: str) -> list[dict]:
    return list(sa.inspect(bind).get_indexes(table))


def _add_missing(table: str, existing: set[str], wanted: tuple[tuple[str, sa.types.TypeEngine], ...]) -> None:
    missing = [(name, type_) for name, type_ in wanted if name not in existing]
    if not missing:
        return
    with op.batch_alter_table(table) as batch:
        for name, type_ in missing:
            batch.add_column(sa.Column(name, type_, nullable=True))


def _drop_present(table: str, existing: set[str], wanted: tuple[tuple[str, sa.types.TypeEngine], ...]) -> None:
    present = [name for name, _ in wanted if name in existing]
    if not present:
        return
    with op.batch_alter_table(table) as batch:
        for name in present:
            batch.drop_column(name)


def _upgrade_instances(bind: sa.engine.Connection) -> None:
    existing = _columns(bind, INSTANCES)
    if existing is None:
        return
    _add_missing(INSTANCES, existing, INSTANCE_COLUMNS)
    existing = _columns(bind, INSTANCES) or set()
    names = {ix["name"] for ix in _indexes(bind, INSTANCES)}
    if "organization_id" in existing and INSTANCE_DEDUPE_INDEX not in names:
        # Existing rows carry a NULL dedupe_key; NULLs never collide.
        op.create_index(INSTANCE_DEDUPE_INDEX, INSTANCES, ["organization_id", "dedupe_key"], unique=True)


def _upgrade_vulnerabilities(bind: sa.engine.Connection) -> None:
    existing = _columns(bind, VULNS)
    if existing is None:
        return
    _add_missing(VULNS, existing, VULN_COLUMNS)
    existing = _columns(bind, VULNS) or set()
    if "organization_id" not in existing or "cve_id" not in existing:
        return

    inspector = sa.inspect(bind)
    for uc in inspector.get_unique_constraints(VULNS):
        if uc.get("column_names") == ["cve_id"] and uc.get("name"):
            with op.batch_alter_table(VULNS) as batch:
                batch.drop_constraint(uc["name"], type_="unique")
    indexes = _indexes(bind, VULNS)
    names = {ix["name"] for ix in indexes}
    for ix in indexes:
        if ix.get("column_names") == ["cve_id"] and ix.get("unique"):
            op.drop_index(ix["name"], table_name=VULNS)
            names.discard(ix["name"])
    if VULN_CVE_INDEX not in names:
        op.create_index(VULN_CVE_INDEX, VULNS, ["cve_id"], unique=False)

    if VULN_ORG_CVE_INDEX not in names:
        duplicates = bind.execute(
            sa.text(
                "SELECT COUNT(*) FROM (SELECT organization_id, cve_id FROM vulnerabilities "
                "GROUP BY organization_id, cve_id HAVING COUNT(*) > 1) AS d",
            ),
        ).scalar()
        if duplicates:
            # Never fail the deploy on legacy data; the importer still
            # deduplicates in code. Logged so the operator can merge rows.
            print(
                f"030: {duplicates} duplicate (organization_id, cve_id) groups in vulnerabilities; "
                f"{VULN_ORG_CVE_INDEX} not created",
            )
        else:
            op.create_index(VULN_ORG_CVE_INDEX, VULNS, ["organization_id", "cve_id"], unique=True)


def _upgrade_snapshots(bind: sa.engine.Connection) -> None:
    if _columns(bind, SNAPSHOTS) is not None:
        return
    op.create_table(
        SNAPSHOTS,
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("snapshot_date", sa.String(10), nullable=False),
        sa.Column("total_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("internet_facing_assets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_with_open_exposures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("open_exposures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("informational_open", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("new_exposures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("remediated_exposures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overdue_tickets", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("overall_risk_score", sa.Float(), nullable=True),
        sa.Column("compliance_score", sa.Float(), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("organization_id", "snapshot_date", name=SNAPSHOT_UNIQUE),
    )
    op.create_index("ix_exposure_daily_snapshots_organization_id", SNAPSHOTS, ["organization_id"])


def upgrade() -> None:
    bind = op.get_bind()
    _upgrade_instances(bind)
    _upgrade_vulnerabilities(bind)
    _upgrade_snapshots(bind)


def downgrade() -> None:
    bind = op.get_bind()
    if _columns(bind, SNAPSHOTS) is not None:
        op.drop_table(SNAPSHOTS)

    existing = _columns(bind, INSTANCES)
    if existing is not None:
        if INSTANCE_DEDUPE_INDEX in {ix["name"] for ix in _indexes(bind, INSTANCES)}:
            op.drop_index(INSTANCE_DEDUPE_INDEX, table_name=INSTANCES)
        _drop_present(INSTANCES, existing, INSTANCE_COLUMNS)

    existing = _columns(bind, VULNS)
    if existing is not None:
        _drop_present(VULNS, existing, VULN_COLUMNS)
