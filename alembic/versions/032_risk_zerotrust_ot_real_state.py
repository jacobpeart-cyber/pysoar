"""Wave 4 (W4-C risk quantification, Zero Trust, OT security).

Idempotent like 027-031: every step runs only when the table exists and lacks
what it adds (databases whose tables came from ``init_db``'s ``create_all``
may already have them).

0. Legacy shapes. Revisions 003/005 created ``zero_trust_policies``,
   ``device_trust_profiles``, ``access_decisions``, ``micro_segments``,
   ``identity_verifications``, ``risk_scenarios``, ``fair_analyses``,
   ``risk_controls``, ``risk_registers``, ``business_impact_assessments``,
   ``ot_assets``, ``ot_zones``, ``ot_alerts``, ``ot_incidents`` and
   ``ot_policy_rules`` with placeholder columns that do not match the ORM (no
   ``organization_id``), so every route on them failed. A table in that shape
   is rebuilt from the ORM definition **only when it is empty**; a non-empty
   legacy table is left alone and reported.
1. ``device_trust_profiles.device_id`` becomes unique per organisation
   (``uq_device_trust_profiles_org_device`` on ``(organization_id,
   device_id)``) instead of globally; ``device_id`` keeps a plain index. Two
   tenants can now hold the same device id, which lets the compliance
   override / agent posture upsert work inside a tenant.
2. ``ot_incidents``: ``safe_shutdown_command_id`` / ``safe_shutdown_status`` /
   ``safe_shutdown_requested_at`` / ``safe_shutdown_detail`` (agent-commanded
   safe shutdown, status driven by the agent's result).
3. ``ot_zones``: ``segmentation_audit_command_id`` /
   ``segmentation_audit_status`` / ``segmentation_audited_at`` /
   ``segmentation_findings`` (agent-run segmentation probe).
4. New tables ``ot_ics_advisories`` (platform-wide CISA ICS advisory cache)
   and ``ot_advisory_feed_status``.

Downgrade drops the new tables and columns (the per-org unique index is left
in place: restoring the global one could fail on multi-tenant data).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "032"
down_revision: Union[str, None] = "031"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEVICES = "device_trust_profiles"
DEVICE_ORG_UNIQUE = "uq_device_trust_profiles_org_device"
DEVICE_ID_INDEX = "ix_device_trust_profiles_device_id"
INCIDENTS = "ot_incidents"
ZONES = "ot_zones"
NEW_TABLES = ("ot_ics_advisories", "ot_advisory_feed_status")

INCIDENT_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("safe_shutdown_command_id", sa.String(36)),
    ("safe_shutdown_status", sa.String(30)),
    ("safe_shutdown_requested_at", sa.DateTime(timezone=True)),
    ("safe_shutdown_detail", sa.Text()),
)
ZONE_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("segmentation_audit_command_id", sa.String(36)),
    ("segmentation_audit_status", sa.String(30)),
    ("segmentation_audited_at", sa.DateTime(timezone=True)),
    ("segmentation_findings", sa.JSON()),
)

#: Tables 003/005 created with placeholder shapes (children before parents)
#: and a column the ORM needs that the placeholder lacks.
LEGACY_SENTINELS: tuple[tuple[str, str], ...] = (
    ("access_decisions", "organization_id"),
    ("zero_trust_policies", "organization_id"),
    ("device_trust_profiles", "organization_id"),
    ("micro_segments", "organization_id"),
    ("identity_verifications", "organization_id"),
    ("fair_analyses", "organization_id"),
    ("risk_controls", "organization_id"),
    ("risk_scenarios", "organization_id"),
    ("risk_registers", "organization_id"),
    ("business_impact_assessments", "organization_id"),
    ("ot_alerts", "organization_id"),
    ("ot_incidents", "organization_id"),
    ("ot_assets", "organization_id"),
    ("ot_zones", "organization_id"),
    ("ot_policy_rules", "organization_id"),
)


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _index_names(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    names = {ix["name"] for ix in inspector.get_indexes(table)}
    names |= {uc["name"] for uc in inspector.get_unique_constraints(table) if uc.get("name")}
    return names


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


def _orm_tables() -> dict[str, sa.Table]:
    import src.ot_security.models
    import src.risk_quant.models
    import src.zerotrust.models  # noqa: F401
    from src.models.base import Base

    return dict(Base.metadata.tables)


def _rebuild_empty_legacy(bind: sa.engine.Connection, tables: dict[str, sa.Table]) -> None:
    legacy: list[str] = []
    for table, sentinel in LEGACY_SENTINELS:
        cols = _columns(bind, table)
        if cols is None or sentinel in cols:
            continue
        rows = bind.execute(sa.text(f"SELECT COUNT(*) FROM {table}")).scalar()
        if rows:
            print(f"032: {table} has the placeholder shape from revision 003/005 and {rows} rows; left as is")
            continue
        legacy.append(table)
    inspector = sa.inspect(bind)
    refs = {t: [fk.get("referred_table") for fk in inspector.get_foreign_keys(t)] for t in inspector.get_table_names()}
    changed = True
    while changed:  # a kept table must not reference a dropped one
        changed = False
        for other, referred in refs.items():
            if other in legacy:
                continue
            for target in referred:
                if target in legacy:
                    print(f"032: {target} is referenced by {other}; placeholder table left as is")
                    legacy.remove(target)
                    changed = True
    for table in legacy:  # children first
        op.drop_table(table)
    for table in reversed(legacy):  # parents first
        tables[table].create(bind, checkfirst=True)
        print(f"032: rebuilt empty placeholder table {table} from the ORM definition")


def _device_unique_per_org(bind: sa.engine.Connection) -> None:
    cols = _columns(bind, DEVICES)
    if cols is None or not {"organization_id", "device_id"} <= cols:
        return
    inspector = sa.inspect(bind)
    # Drop the global uniqueness on device_id (a unique constraint or the
    # unique index create_all made from ``index=True, unique=True``).
    for uc in inspector.get_unique_constraints(DEVICES):
        if uc.get("column_names") == ["device_id"] and uc.get("name"):
            with op.batch_alter_table(DEVICES) as batch:
                batch.drop_constraint(uc["name"], type_="unique")
    has_plain_index = False
    for ix in sa.inspect(bind).get_indexes(DEVICES):
        if ix.get("column_names") == ["device_id"]:
            if ix.get("unique"):
                op.drop_index(ix["name"], table_name=DEVICES)
            else:
                has_plain_index = True
    if not has_plain_index and DEVICE_ID_INDEX not in _index_names(bind, DEVICES):
        op.create_index(DEVICE_ID_INDEX, DEVICES, ["device_id"])
    if DEVICE_ORG_UNIQUE in _index_names(bind, DEVICES):
        return
    duplicates = bind.execute(sa.text(
        f"SELECT COUNT(*) FROM (SELECT organization_id, device_id FROM {DEVICES} "
        "GROUP BY organization_id, device_id HAVING COUNT(*) > 1) AS d",
    )).scalar()
    if duplicates:
        # Cannot happen while device_id was globally unique; never fail a deploy on it.
        print(f"032: {duplicates} duplicate (organization_id, device_id) groups; {DEVICE_ORG_UNIQUE} not created")
        return
    op.create_index(DEVICE_ORG_UNIQUE, DEVICES, ["organization_id", "device_id"], unique=True)


def upgrade() -> None:
    bind = op.get_bind()
    tables = _orm_tables()

    _rebuild_empty_legacy(bind, tables)
    _device_unique_per_org(bind)

    cols = _columns(bind, INCIDENTS)
    if cols is not None:
        _add_missing(INCIDENTS, cols, INCIDENT_COLUMNS)
    cols = _columns(bind, ZONES)
    if cols is not None:
        _add_missing(ZONES, cols, ZONE_COLUMNS)

    for name in NEW_TABLES:
        tables[name].create(bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    for name in reversed(NEW_TABLES):
        if inspector.has_table(name):
            op.drop_table(name)
    cols = _columns(bind, ZONES)
    if cols is not None:
        _drop_present(ZONES, cols, ZONE_COLUMNS)
    cols = _columns(bind, INCIDENTS)
    if cols is not None:
        _drop_present(INCIDENTS, cols, INCIDENT_COLUMNS)
