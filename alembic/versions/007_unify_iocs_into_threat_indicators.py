"""Unify iocs table into threat_indicators and drop iocs.

Revision ID: 007
Revises: 006
Create Date: 2026-04-11

Background
----------
PySOAR historically had two indicator tables that were not connected:

  * ``iocs`` — legacy manual IOC management, no feed connectivity.
  * ``threat_indicators`` — modern table populated by threat feeds.

The alert automation pipeline only queried ``iocs``, so indicators coming
from real threat feeds (AlienVault OTX, CISA KEV, etc.) never matched any
alerts. This migration:

  1. Copies every row from ``iocs`` into ``threat_indicators``, preserving
     provenance and stashing legacy-only fields (description, category,
     malware_family, threat_actor, campaign, source_url, source_reference,
     enrichment_data, is_internal) inside ``threat_indicators.context``
     as a JSON dict.
  2. Drops the ``iocs`` table once data is migrated.

Field mapping
-------------
    iocs.value           -> threat_indicators.value
    iocs.ioc_type        -> threat_indicators.indicator_type
    iocs.status          -> threat_indicators.is_active (True if 'active')
    iocs.threat_level    -> threat_indicators.severity
    iocs.confidence      -> threat_indicators.confidence
    iocs.source          -> threat_indicators.source
    iocs.tags            -> threat_indicators.tags (parsed from JSON text)
    iocs.mitre_tactics   -> threat_indicators.mitre_tactics (parsed)
    iocs.mitre_techniques-> threat_indicators.mitre_techniques (parsed)
    iocs.first_seen/last_seen/expires_at (str ISO)
                         -> threat_indicators.* (DateTime)
    iocs.sighting_count  -> threat_indicators.sighting_count
    iocs.last_sighting   -> threat_indicators.last_sighting_at
    iocs.is_whitelisted  -> threat_indicators.is_whitelisted
    iocs.<extras>        -> threat_indicators.context[<key>]

Deduplication: if a threat_indicators row already exists with the same
(indicator_type, value), the legacy iocs row is merged — sighting_count
summed, context extras overlaid — rather than duplicated.
"""

from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def _parse_dt(value):
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def _parse_json(value, default):
    import json as _json
    if value is None or value == "":
        return default
    if isinstance(value, (list, dict)):
        return value
    try:
        return _json.loads(value)
    except (ValueError, TypeError):
        return default


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # If the legacy iocs table does not exist (fresh install), nothing to do.
    if "iocs" not in inspector.get_table_names():
        return

    # Load all legacy iocs rows
    legacy_rows = list(
        bind.execute(
            sa.text(
                "SELECT id, value, ioc_type, status, threat_level, confidence, "
                "description, tags, category, source, source_url, source_reference, "
                "malware_family, threat_actor, campaign, mitre_tactics, mitre_techniques, "
                "enrichment_data, last_enriched, first_seen, last_seen, expires_at, "
                "sighting_count, last_sighting, is_whitelisted, is_internal, "
                "created_at, updated_at "
                "FROM iocs"
            )
        )
    )

    migrated = 0
    merged = 0
    for row in legacy_rows:
        legacy = dict(row._mapping)

        value = legacy.get("value")
        ioc_type = legacy.get("ioc_type") or "unknown"
        if not value:
            continue

        # Legacy IOCType.IP stored as "ip" but ThreatIndicator uses "ipv4"
        if ioc_type == "ip":
            ioc_type = "ipv4"

        # Build context JSON from IOC-only fields
        ctx: dict = {}
        for key in (
            "description", "category", "source_url", "source_reference",
            "malware_family", "threat_actor", "campaign", "is_internal",
        ):
            val = legacy.get(key)
            if val not in (None, "", False):
                ctx[key] = val

        enr = _parse_json(legacy.get("enrichment_data"), None)
        if enr:
            ctx["enrichment_data"] = enr
        if legacy.get("last_enriched"):
            ctx["last_enriched"] = legacy["last_enriched"]

        tags = _parse_json(legacy.get("tags"), []) or []
        mitre_tactics = _parse_json(legacy.get("mitre_tactics"), []) or []
        mitre_techniques = _parse_json(legacy.get("mitre_techniques"), []) or []

        is_active = (legacy.get("status") or "active") == "active"
        severity = legacy.get("threat_level") or "informational"
        if severity == "unknown":
            severity = "informational"
        confidence = legacy.get("confidence")

        first_seen = _parse_dt(legacy.get("first_seen"))
        last_seen = _parse_dt(legacy.get("last_seen"))
        expires_at = _parse_dt(legacy.get("expires_at"))
        last_sighting_at = _parse_dt(legacy.get("last_sighting"))

        # Deduplicate against existing threat_indicators row
        existing = bind.execute(
            sa.text(
                "SELECT id, sighting_count, context FROM threat_indicators "
                "WHERE indicator_type = :t AND value = :v LIMIT 1"
            ),
            {"t": ioc_type, "v": value},
        ).fetchone()

        if existing:
            existing_id = existing._mapping["id"]
            existing_ctx = existing._mapping.get("context") or {}
            if isinstance(existing_ctx, str):
                existing_ctx = _parse_json(existing_ctx, {}) or {}
            merged_ctx = {**existing_ctx, **ctx}
            merged_count = (existing._mapping.get("sighting_count") or 0) + (legacy.get("sighting_count") or 0)
            bind.execute(
                sa.text(
                    "UPDATE threat_indicators "
                    "SET context = :ctx, "
                    "    sighting_count = :cnt, "
                    "    last_sighting_at = COALESCE(:lsa, last_sighting_at), "
                    "    last_seen = COALESCE(:ls, last_seen) "
                    "WHERE id = :id"
                ),
                {
                    "ctx": merged_ctx,
                    "cnt": merged_count,
                    "lsa": last_sighting_at,
                    "ls": last_seen,
                    "id": existing_id,
                },
            )
            merged += 1
            continue

        # Insert fresh row in threat_indicators
        bind.execute(
            sa.text(
                "INSERT INTO threat_indicators ("
                "id, indicator_type, value, source, confidence, severity, "
                "is_active, is_whitelisted, first_seen, last_seen, expires_at, "
                "mitre_tactics, mitre_techniques, tags, context, related_indicators, "
                "sighting_count, last_sighting_at, false_positive_count, "
                "created_at, updated_at"
                ") VALUES ("
                ":id, :itype, :value, :source, :confidence, :severity, "
                ":is_active, :is_whitelisted, :first_seen, :last_seen, :expires_at, "
                ":mtact, :mtech, :tags, :ctx, :related, "
                ":sc, :lsa, 0, "
                ":created_at, :updated_at)"
            ),
            {
                "id": legacy.get("id"),
                "itype": ioc_type,
                "value": value,
                "source": legacy.get("source"),
                "confidence": confidence,
                "severity": severity,
                "is_active": is_active,
                "is_whitelisted": bool(legacy.get("is_whitelisted")),
                "first_seen": first_seen,
                "last_seen": last_seen,
                "expires_at": expires_at,
                "mtact": mitre_tactics,
                "mtech": mitre_techniques,
                "tags": tags,
                "ctx": ctx,
                "related": [],
                "sc": legacy.get("sighting_count") or 0,
                "lsa": last_sighting_at,
                "created_at": legacy.get("created_at") or datetime.now(timezone.utc),
                "updated_at": legacy.get("updated_at") or datetime.now(timezone.utc),
            },
        )
        migrated += 1

    print(f"[migration 007] iocs → threat_indicators: migrated={migrated} merged={merged}")

    # Drop the legacy table
    op.drop_table("iocs")


def downgrade() -> None:
    # Recreate the legacy iocs table (empty). Full reverse-migration is not
    # supported because it would lose any post-unification enrichment data.
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("value", sa.String(2048), nullable=False, index=True),
        sa.Column("ioc_type", sa.String(50), nullable=False, index=True),
        sa.Column("status", sa.String(50), nullable=False, server_default="active"),
        sa.Column("threat_level", sa.String(50), nullable=False, server_default="unknown"),
        sa.Column("confidence", sa.Integer, nullable=False, server_default="50"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("tags", sa.Text, nullable=True),
        sa.Column("category", sa.String(100), nullable=True),
        sa.Column("source", sa.String(255), nullable=True),
        sa.Column("source_url", sa.Text, nullable=True),
        sa.Column("source_reference", sa.String(255), nullable=True),
        sa.Column("malware_family", sa.String(255), nullable=True),
        sa.Column("threat_actor", sa.String(255), nullable=True),
        sa.Column("campaign", sa.String(255), nullable=True),
        sa.Column("mitre_tactics", sa.Text, nullable=True),
        sa.Column("mitre_techniques", sa.Text, nullable=True),
        sa.Column("enrichment_data", sa.Text, nullable=True),
        sa.Column("last_enriched", sa.String(50), nullable=True),
        sa.Column("first_seen", sa.String(50), nullable=True),
        sa.Column("last_seen", sa.String(50), nullable=True),
        sa.Column("expires_at", sa.String(50), nullable=True),
        sa.Column("sighting_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_sighting", sa.String(50), nullable=True),
        sa.Column("is_whitelisted", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("is_internal", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
