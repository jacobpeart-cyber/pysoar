"""Wave 5 (W5-C): names and serial numbers unique per organisation.

Idempotent like 027-034: each step runs only when the table exists and the
target state is not already there (tables created by ``init_db``'s
``create_all`` from the current models already have it).

1. ``ot_assets.serial_number``: the global uniqueness (a unique constraint,
   or an unnamed inline UNIQUE on SQLite) is dropped; ``uq_org_serial`` on
   ``(organization_id, serial_number)`` is ensured.
2. ``siem_data_sources.name`` and ``detection_rules.name``: the global
   unique index ``ix_<table>_name`` (or unique constraint) is replaced by a
   plain index, ``uq_<table>_org_name`` on ``(organization_id, name)``, and
   ``uq_<table>_platform_name`` on ``name`` for platform rows (a NULL
   ``organization_id``; NULLs never collide in a composite unique index, so
   platform rows keep their own uniqueness through a partial index).

Duplicate groups cannot exist while the old global uniqueness held; if one
is found anyway the new unique index is not created and the migration says
so instead of failing the deploy.

Downgrade drops the per-organisation indexes and restores the global
uniqueness when no value is shared across organisations (otherwise it keeps
a plain index and reports the conflict).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "035"
down_revision: Union[str, None] = "034"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

OT_ASSETS = "ot_assets"
OT_SERIAL = "serial_number"
OT_ORG_UNIQUE = "uq_org_serial"
OT_GLOBAL_UNIQUE = "ot_assets_serial_number_key"

#: table -> (per-org unique index, platform-row partial unique index, plain index)
NAMED_TABLES: dict[str, tuple[str, str, str]] = {
    "siem_data_sources": (
        "uq_siem_data_sources_org_name",
        "uq_siem_data_sources_platform_name",
        "ix_siem_data_sources_name",
    ),
    "detection_rules": (
        "uq_detection_rules_org_name",
        "uq_detection_rules_platform_name",
        "ix_detection_rules_name",
    ),
}
PLATFORM_ROWS = sa.text("organization_id IS NULL")


def _columns(bind: sa.engine.Connection, table: str) -> set[str] | None:
    inspector = sa.inspect(bind)
    if not inspector.has_table(table):
        return None
    return {c["name"] for c in inspector.get_columns(table)}


def _index_names(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    names = {ix["name"] for ix in inspector.get_indexes(table) if ix.get("name")}
    names |= {uc["name"] for uc in inspector.get_unique_constraints(table) if uc.get("name")}
    return names


def _drop_global_unique(bind: sa.engine.Connection, table: str, column: str, keep: str = "") -> None:
    """Drop every single-column uniqueness on ``column`` (constraint or index)
    except the index named ``keep`` (the platform-row partial index)."""
    inspector = sa.inspect(bind)
    for uc in inspector.get_unique_constraints(table):
        if uc.get("column_names") != [column]:
            continue
        if uc.get("name"):
            with op.batch_alter_table(table) as batch:
                batch.drop_constraint(uc["name"], type_="unique")
        else:
            # SQLite inline UNIQUE has no name: name it while the batch
            # reflects the table, then drop it (Alembic's documented recipe).
            generated = f"uq_{table}_{column}"
            with op.batch_alter_table(
                table, naming_convention={"uq": "uq_%(table_name)s_%(column_0_name)s"},
            ) as batch:
                batch.drop_constraint(generated, type_="unique")
    for ix in sa.inspect(bind).get_indexes(table):
        if ix.get("column_names") == [column] and ix.get("unique") and ix.get("name") != keep:
            op.drop_index(ix["name"], table_name=table)


def _has_duplicates(bind: sa.engine.Connection, sql: str) -> int:
    return int(bind.execute(sa.text(f"SELECT COUNT(*) FROM ({sql}) AS d")).scalar() or 0)


def _ot_upgrade(bind: sa.engine.Connection) -> None:
    cols = _columns(bind, OT_ASSETS)
    if cols is None or not {"organization_id", OT_SERIAL} <= cols:
        return
    _drop_global_unique(bind, OT_ASSETS, OT_SERIAL)
    if OT_ORG_UNIQUE in _index_names(bind, OT_ASSETS):
        return
    duplicates = _has_duplicates(
        bind,
        f"SELECT organization_id, {OT_SERIAL} FROM {OT_ASSETS} WHERE {OT_SERIAL} IS NOT NULL "
        f"GROUP BY organization_id, {OT_SERIAL} HAVING COUNT(*) > 1",
    )
    if duplicates:
        print(f"035: {duplicates} duplicate (organization_id, serial_number) groups; {OT_ORG_UNIQUE} not created")
        return
    with op.batch_alter_table(OT_ASSETS) as batch:
        batch.create_unique_constraint(OT_ORG_UNIQUE, ["organization_id", OT_SERIAL])


def _named_upgrade(bind: sa.engine.Connection, table: str, names: tuple[str, str, str]) -> None:
    org_unique, platform_unique, plain_index = names
    cols = _columns(bind, table)
    if cols is None or not {"organization_id", "name"} <= cols:
        return
    _drop_global_unique(bind, table, "name", keep=platform_unique)
    existing = _index_names(bind, table)
    has_plain = any(
        ix.get("column_names") == ["name"] and not ix.get("unique")
        for ix in sa.inspect(bind).get_indexes(table)
    )
    if not has_plain and plain_index not in existing:
        op.create_index(plain_index, table, ["name"])
    if org_unique not in existing:
        duplicates = _has_duplicates(
            bind,
            f"SELECT organization_id, name FROM {table} WHERE organization_id IS NOT NULL "
            "GROUP BY organization_id, name HAVING COUNT(*) > 1",
        )
        if duplicates:
            print(f"035: {duplicates} duplicate (organization_id, name) groups in {table}; {org_unique} not created")
        else:
            op.create_index(org_unique, table, ["organization_id", "name"], unique=True)
    if platform_unique not in existing:
        duplicates = _has_duplicates(
            bind,
            f"SELECT name FROM {table} WHERE organization_id IS NULL GROUP BY name HAVING COUNT(*) > 1",
        )
        if duplicates:
            print(f"035: {duplicates} duplicate platform names in {table}; {platform_unique} not created")
        else:
            op.create_index(
                platform_unique, table, ["name"], unique=True,
                postgresql_where=PLATFORM_ROWS, sqlite_where=PLATFORM_ROWS,
            )


def upgrade() -> None:
    bind = op.get_bind()
    _ot_upgrade(bind)
    for table, names in NAMED_TABLES.items():
        _named_upgrade(bind, table, names)


def _ot_downgrade(bind: sa.engine.Connection) -> None:
    cols = _columns(bind, OT_ASSETS)
    if cols is None or OT_SERIAL not in cols:
        return
    # uq_org_serial predates this revision in the model; it stays.
    if any(
        uc.get("column_names") == [OT_SERIAL] for uc in sa.inspect(bind).get_unique_constraints(OT_ASSETS)
    ):
        return
    duplicates = _has_duplicates(
        bind,
        f"SELECT {OT_SERIAL} FROM {OT_ASSETS} WHERE {OT_SERIAL} IS NOT NULL "
        f"GROUP BY {OT_SERIAL} HAVING COUNT(*) > 1",
    )
    if duplicates:
        print(f"035 downgrade: {duplicates} serial numbers shared across organisations; global unique not restored")
        return
    with op.batch_alter_table(OT_ASSETS) as batch:
        batch.create_unique_constraint(OT_GLOBAL_UNIQUE, [OT_SERIAL])


def _named_downgrade(bind: sa.engine.Connection, table: str, names: tuple[str, str, str]) -> None:
    org_unique, platform_unique, plain_index = names
    cols = _columns(bind, table)
    if cols is None or "name" not in cols:
        return
    existing = _index_names(bind, table)
    for name in (org_unique, platform_unique):
        if name in existing:
            op.drop_index(name, table_name=table)
    duplicates = _has_duplicates(bind, f"SELECT name FROM {table} GROUP BY name HAVING COUNT(*) > 1")
    if duplicates:
        print(f"035 downgrade: {duplicates} names shared across organisations in {table}; global unique not restored")
        return
    for ix in sa.inspect(bind).get_indexes(table):
        if ix.get("column_names") == ["name"] and not ix.get("unique"):
            op.drop_index(ix["name"], table_name=table)
    op.create_index(plain_index, table, ["name"], unique=True)


def downgrade() -> None:
    bind = op.get_bind()
    for table, names in NAMED_TABLES.items():
        _named_downgrade(bind, table, names)
    _ot_downgrade(bind)
