"""Wave 4 (W4-B container security and supply chain).

Idempotent like 027-030: every step runs only when the table exists and
lacks what it adds (databases whose tables came from ``init_db``'s
``create_all`` may already have them).

0. Legacy shapes. Revisions 004/005 created ``container_images``,
   ``kubernetes_clusters``, ``image_vulnerabilities``, ``k8s_security_findings``,
   ``runtime_alerts``, ``software_components``, ``supply_chain_risks``,
   ``vendor_assessments``, ``sboms`` and ``sbom_components`` with placeholder
   columns that do not match the ORM (e.g. ``image_name`` instead of
   ``registry`` / ``repository``), so every route on them failed. A table in
   that shape is rebuilt from the ORM definition **only when it is empty**;
   a non-empty legacy table is left alone and reported.
1. ``container_images``: ``scanned_at`` becomes nullable (it defaulted to the
   insert time, so never-scanned images showed a scan date; rows still
   ``not_scanned`` get NULL) and gains ``scan_status`` / ``scan_error`` /
   ``last_scan_id``.
2. ``kubernetes_clusters``: the encrypted API credential
   (``credential_encrypted`` / ``credential_type`` / ``credential_set_at``)
   and the CIS assessment state (``assessment_status`` / ``assessment_error``);
   ``name`` becomes unique per organisation instead of globally.
3. ``k8s_security_findings``: ``check_id`` / ``image_ref`` / ``dedupe_key`` /
   ``last_seen_at`` with a unique index on ``(organization_id, dedupe_key)``
   (findings deduplicated per cluster, image and check).
4. ``software_components``: ``purl`` / ``cpe`` unique per organisation instead
   of globally (``checksum_sha256`` becomes a plain index).
5. ``supply_chain_risks``: ``advisory_id`` / ``source`` (OSV / NVD advisory a
   known_vulnerability risk came from).
6. New tables: ``container_image_scans``, ``k8s_check_results``,
   ``supplychain_vuln_cache``, ``supplychain_provider_status``.

Downgrade drops the new tables and columns (the per-org unique indexes are
left in place: restoring the global ones could fail on multi-tenant data).
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "031"
down_revision: Union[str, None] = "030"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

IMAGES = "container_images"
CLUSTERS = "kubernetes_clusters"
FINDINGS = "k8s_security_findings"
COMPONENTS = "software_components"
RISKS = "supply_chain_risks"

CLUSTER_ORG_NAME = "uq_kubernetes_clusters_org_name"
FINDING_DEDUPE = "uq_k8s_findings_org_dedupe"
COMPONENT_ORG_PURL = "uq_software_components_org_purl"
COMPONENT_ORG_CPE = "uq_software_components_org_cpe"
COMPONENT_CHECKSUM = "ix_software_components_checksum_sha256"
RISK_ADVISORY = "idx_risk_component_advisory"

IMAGE_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("scan_status", sa.String(50)),
    ("scan_error", sa.Text()),
    ("last_scan_id", sa.String(36)),
)
CLUSTER_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("credential_encrypted", sa.Text()),
    ("credential_type", sa.String(30)),
    ("credential_set_at", sa.DateTime(timezone=True)),
    ("assessment_status", sa.String(30)),
    ("assessment_error", sa.Text()),
)
FINDING_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("check_id", sa.String(50)),
    ("image_ref", sa.String(512)),
    ("dedupe_key", sa.String(64)),
    ("last_seen_at", sa.DateTime(timezone=True)),
)
RISK_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("advisory_id", sa.String(100)),
    ("source", sa.String(30)),
)

NEW_TABLES = ("container_image_scans", "k8s_check_results", "supplychain_vuln_cache", "supplychain_provider_status")

#: Tables 004/005 created with placeholder shapes, children before parents,
#: with a column the ORM needs that the placeholder lacks.
LEGACY_SENTINELS: tuple[tuple[str, str], ...] = (
    ("runtime_alerts", "cluster_id"),
    ("k8s_security_findings", "organization_id"),
    ("image_vulnerabilities", "organization_id"),
    ("container_images", "registry"),
    ("kubernetes_clusters", "name"),
    ("sbom_components", "organization_id"),
    ("supply_chain_risks", "organization_id"),
    ("software_components", "organization_id"),
    ("sboms", "organization_id"),
    ("vendor_assessments", "organization_id"),
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


def _drop_single_column_unique(bind: sa.engine.Connection, table: str, column: str) -> None:
    """Drop a unique constraint / unique index covering exactly ``column``."""
    inspector = sa.inspect(bind)
    for uc in inspector.get_unique_constraints(table):
        if uc.get("column_names") == [column] and uc.get("name"):
            with op.batch_alter_table(table) as batch:
                batch.drop_constraint(uc["name"], type_="unique")
    for ix in sa.inspect(bind).get_indexes(table):
        if ix.get("column_names") == [column] and ix.get("unique"):
            op.drop_index(ix["name"], table_name=table)


def _unique_if_clean(bind: sa.engine.Connection, table: str, name: str, columns: list[str]) -> None:
    if name in _index_names(bind, table):
        return
    cols = ", ".join(columns)
    not_null = " AND ".join(f"{c} IS NOT NULL" for c in columns)
    duplicates = bind.execute(sa.text(
        f"SELECT COUNT(*) FROM (SELECT {cols} FROM {table} WHERE {not_null} "
        f"GROUP BY {cols} HAVING COUNT(*) > 1) AS d",
    )).scalar()
    if duplicates:
        # Never fail the deploy on legacy data; the routes deduplicate in code.
        print(f"031: {duplicates} duplicate ({cols}) groups in {table}; {name} not created")
        return
    op.create_index(name, table, columns, unique=True)


def _orm_tables() -> dict[str, sa.Table]:
    import src.container_security.models
    import src.supplychain.models  # noqa: F401
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
            print(f"031: {table} has the placeholder shape from revision 004/005 and {rows} rows; left as is")
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
                    print(f"031: {target} is referenced by {other}; placeholder table left as is")
                    legacy.remove(target)
                    changed = True
    for table in legacy:  # children first
        op.drop_table(table)
    for table in reversed(legacy):  # parents first
        tables[table].create(bind, checkfirst=True)
        print(f"031: rebuilt empty placeholder table {table} from the ORM definition")


def upgrade() -> None:
    bind = op.get_bind()
    tables = _orm_tables()
    _rebuild_empty_legacy(bind, tables)

    cols = _columns(bind, IMAGES)
    if cols is not None:
        _add_missing(IMAGES, cols, IMAGE_COLUMNS)
        if "scanned_at" in cols:
            with op.batch_alter_table(IMAGES) as batch:
                batch.alter_column("scanned_at", existing_type=sa.DateTime(timezone=True), nullable=True)
            if "compliance_status" in cols:
                bind.execute(sa.text(
                    "UPDATE container_images SET scanned_at = NULL, scan_status = 'not_scanned' "
                    "WHERE compliance_status = 'not_scanned'",
                ))

    cols = _columns(bind, CLUSTERS)
    if cols is not None:
        _add_missing(CLUSTERS, cols, CLUSTER_COLUMNS)
        if "name" in cols and "organization_id" in cols:
            _drop_single_column_unique(bind, CLUSTERS, "name")
            _unique_if_clean(bind, CLUSTERS, CLUSTER_ORG_NAME, ["organization_id", "name"])

    cols = _columns(bind, FINDINGS)
    if cols is not None:
        _add_missing(FINDINGS, cols, FINDING_COLUMNS)
        if "organization_id" in cols and FINDING_DEDUPE not in _index_names(bind, FINDINGS):
            # Existing rows carry a NULL dedupe_key; NULLs never collide.
            op.create_index(FINDING_DEDUPE, FINDINGS, ["organization_id", "dedupe_key"], unique=True)

    cols = _columns(bind, COMPONENTS)
    if cols is not None and "organization_id" in cols:
        for column in ("purl", "cpe", "checksum_sha256"):
            if column in cols:
                _drop_single_column_unique(bind, COMPONENTS, column)
        if "purl" in cols:
            _unique_if_clean(bind, COMPONENTS, COMPONENT_ORG_PURL, ["organization_id", "purl"])
        if "cpe" in cols:
            _unique_if_clean(bind, COMPONENTS, COMPONENT_ORG_CPE, ["organization_id", "cpe"])
        if "checksum_sha256" in cols and COMPONENT_CHECKSUM not in _index_names(bind, COMPONENTS):
            op.create_index(COMPONENT_CHECKSUM, COMPONENTS, ["checksum_sha256"])

    cols = _columns(bind, RISKS)
    if cols is not None:
        _add_missing(RISKS, cols, RISK_COLUMNS)
        if "component_id" in cols and RISK_ADVISORY not in _index_names(bind, RISKS):
            op.create_index(RISK_ADVISORY, RISKS, ["component_id", "advisory_id"])

    for name in NEW_TABLES:
        tables[name].create(bind, checkfirst=True)


def downgrade() -> None:
    bind = op.get_bind()
    for name in reversed(NEW_TABLES):
        if _columns(bind, name) is not None:
            op.drop_table(name)

    cols = _columns(bind, RISKS)
    if cols is not None:
        if RISK_ADVISORY in _index_names(bind, RISKS):
            op.drop_index(RISK_ADVISORY, table_name=RISKS)
        _drop_present(RISKS, cols, RISK_COLUMNS)

    cols = _columns(bind, FINDINGS)
    if cols is not None:
        if FINDING_DEDUPE in _index_names(bind, FINDINGS):
            op.drop_index(FINDING_DEDUPE, table_name=FINDINGS)
        _drop_present(FINDINGS, cols, FINDING_COLUMNS)

    cols = _columns(bind, CLUSTERS)
    if cols is not None:
        _drop_present(CLUSTERS, cols, CLUSTER_COLUMNS)

    cols = _columns(bind, IMAGES)
    if cols is not None:
        _drop_present(IMAGES, cols, IMAGE_COLUMNS)
