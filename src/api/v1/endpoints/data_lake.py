"""Data Lake / Data Mesh API endpoints

SECURITY NOTE (2026-10-08): the raw SQL path of ``POST /data-lake/query`` is
restricted to platform superusers. ``_build_tenant_scoped_sql`` is NOT a safe
per-tenant guard: it is regex based, scopes only the first FROM table, ignores
comma joins, JOIN targets and subqueries, and never enforces the column
whitelist, so ``SELECT users.email, users.hashed_password FROM alerts, users``
passed it. The guard is kept as defence in depth for superusers. Opening the
route to tenant users again requires rewriting the guard on a real SQL parser
(see docs/agentic-soc.md section 11).
"""

import json
import math
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import Depends, APIRouter, Body, Path, HTTPException, Query, status
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import CurrentUser, DatabaseSession, OrganizationId, require_role
from src.models.user import User, UserRole
from src.core.logging import get_logger
from src.core.secrets import SecretUnreadable, encrypt_secret_json
from src.data_lake.models import (
    DataPartition,
    DataPipeline,
    DataSource,
    QueryJob,
    UnifiedDataModel,
)
from src.schemas.data_lake import (
    CostEstimate,
    DataPartitionCreate,
    DataPartitionListResponse,
    DataPartitionResponse,
    DataPartitionUpdate,
    DataPipelineCreate,
    DataPipelineListResponse,
    DataPipelineResponse,
    DataPipelineUpdate,
    DataQualityReport,
    DashboardMetrics,
    DataSourceCreate,
    DataSourceListResponse,
    DataSourceResponse,
    DataSourceUpdate,
    IngestionMetrics,
    QueryExecutionResult,
    QueryJobCreate,
    QueryJobListResponse,
    QueryJobResponse,
    QueryPerformance,
    StorageCost,
    StorageUsage,
    UnifiedDataModelCreate,
    UnifiedDataModelListResponse,
    UnifiedDataModelResponse,
    UnifiedDataModelUpdate,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/data-lake", tags=["Data Lake"])

# Wave 1 role gates: viewers read only; analysts for operational writes;
# admins for configuration and actions against live systems.
AnalystUser = Annotated[User, Depends(require_role([UserRole.ADMIN, UserRole.ANALYST]))]
AdminRoleUser = Annotated[User, Depends(require_role([UserRole.ADMIN]))]


def _not_implemented(detail: str) -> HTTPException:
    """Honest 501 for data-lake operations PySOAR does not actually perform."""
    return HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"error": "not_implemented", "detail": detail},
    )


SOURCE_REGISTERED = "registered"
PIPELINE_REGISTERED = "registered"
PIPELINE_NO_EXECUTOR = (
    "no executor runs user-defined data-lake pipelines: the row records the "
    "pipeline's definition only; built-in pipelines are the scheduled platform tasks"
)
SOURCE_NO_CONNECTOR = (
    "no connector ingests registered data sources; built-in sources are the "
    "platform's own tables"
)

# Platform tasks (in the beat schedule) that read a built-in table: the
# lineage of a built-in source. Each entry is a code path in this
# repository, not a guess.
BUILTIN_TABLE_CONSUMERS: dict[str, list[dict]] = {
    "log_entries": [
        {"task": "src.ueba.tasks.bridge_siem_logs", "name": "UEBA SIEM bridge",
         "reads": "authentication / access events into behavior events"},
        {"task": "src.itdr.tasks.analyze_identity_auth_events", "name": "ITDR auth-event analysis",
         "reads": "authentication events per identity"},
        {"task": "src.exposure.tasks.run_asset_discovery", "name": "Exposure asset discovery",
         "reads": "hosts and addresses seen in logs"},
        {"task": "src.dlp.tasks.dlp_content_scan_sweep", "name": "DLP content scan",
         "reads": "message / raw log text against active DLP policies"},
    ],
    "alerts": [
        {"task": "automation.periodic_ioc_sweep", "name": "IOC sweep",
         "reads": "recent alerts against threat indicators"},
        {"task": "automation.hourly_correlation_sweep", "name": "Correlation sweep",
         "reads": "recent alerts for correlation"},
        {"task": "automation.auto_escalate_stale_alerts", "name": "Stale alert escalation",
         "reads": "open alerts past their SLA"},
        {"task": "automation.auto_close_resolved_alerts", "name": "Resolved alert closure",
         "reads": "resolved alerts"},
        {"task": "src.agentic.tasks.auto_triage_new_alerts", "name": "Agentic auto-triage",
         "reads": "new alerts"},
    ],
    "incidents": [
        {"task": "src.agentic.tasks.followup_open_incidents", "name": "Agentic incident follow-up",
         "reads": "open incidents"},
        {"task": "src.dlp.tasks.dlp_content_scan_sweep", "name": "DLP content scan",
         "reads": "incident text against active DLP policies"},
    ],
    "threat_indicators": [
        {"task": "automation.periodic_ioc_sweep", "name": "IOC sweep",
         "reads": "active indicators matched against alerts"},
    ],
}


def _beat_schedule() -> dict:
    from src.workers.celery_app import celery_app

    return celery_app.conf.beat_schedule or {}


def _builtin_table(source: DataSource) -> Optional[str]:
    """The platform table behind a built-in source, else None."""
    cfg = source.connection_config_encrypted or {}
    if isinstance(cfg, dict) and cfg.get("builtin") and cfg.get("table") in DATA_LAKE_READABLE_TABLES:
        return cfg["table"]
    return None


async def _builtin_table_quality(
    db: AsyncSession, org_id: str, source: DataSource, table: str,
) -> dict:
    """Quality of a built-in source measured on its table (org rows only):
    freshness of the newest row, volume over 24 h / 7 d / 30 d and the
    number of the last 7 days with no rows at all."""
    from sqlalchemy import text as sa_text

    now = datetime.now(timezone.utc)
    params = {
        "org_id": org_id,
        "d1": now - timedelta(days=1),
        "d7": now - timedelta(days=7),
        "d30": now - timedelta(days=30),
    }
    try:
        async with db.begin_nested():
            row = (await db.execute(
                sa_text(
                    f"SELECT COUNT(*), MAX(created_at), "
                    f"SUM(CASE WHEN created_at >= :d1 THEN 1 ELSE 0 END), "
                    f"SUM(CASE WHEN created_at >= :d7 THEN 1 ELSE 0 END), "
                    f"SUM(CASE WHEN created_at >= :d30 THEN 1 ELSE 0 END) "
                    f"FROM {table} WHERE organization_id = :org_id",
                ),
                params,
            )).first()
            day_rows = (await db.execute(
                sa_text(
                    f"SELECT created_at FROM {table} "
                    f"WHERE organization_id = :org_id AND created_at >= :d7 "
                    f"ORDER BY created_at DESC LIMIT 50000",
                ),
                params,
            )).scalars().all()
    except Exception as exc:  # table absent in this deployment
        raise _not_implemented(
            f"quality of {table!r} cannot be measured here: {type(exc).__name__}",
        ) from exc

    total, newest, n1, n7, n30 = row if row else (0, None, 0, 0, 0)
    if isinstance(newest, str):
        try:
            newest = datetime.fromisoformat(newest.replace("Z", "+00:00"))
        except ValueError:
            newest = None
    if newest is not None and newest.tzinfo is None:
        newest = newest.replace(tzinfo=timezone.utc)
    freshness_hours = round((now - newest).total_seconds() / 3600.0, 2) if newest else None

    seen_days: set = set()
    for value in day_rows:
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                continue
        if value is not None:
            seen_days.add(value.date())
    expected_days = {(now - timedelta(days=i)).date() for i in range(7)}
    empty_days = len(expected_days - seen_days)

    total = int(total or 0)
    if total == 0:
        status_ = "no_data"
    elif freshness_hours is None:
        status_ = "unknown"
    elif freshness_hours < 24:
        status_ = "healthy"
    elif freshness_hours < 168:
        status_ = "degraded"
    else:
        status_ = "stale"

    return {
        "dataset_id": source.id,
        "dataset_name": source.name,
        "source_type": source.source_type,
        "status": status_,
        "freshness_hours": freshness_hours,
        "partition_count": 0,
        "total_records": total,
        "total_bytes": None,
        "indexed_ratio": None,
        "storage_bytes_by_tier": {},
        "time_range": {"earliest": None, "latest": newest.isoformat() if newest else None},
        "basis": f"table {table} (this organisation's rows)",
        "records_24h": int(n1 or 0),
        "records_7d": int(n7 or 0),
        "records_30d": int(n30 or 0),
        "empty_days_last_7": empty_days,
    }


# ==================== BUILT-IN DATA SOURCES ====================
# Every org gets a read-only DataSource row per canonical platform table
# so the Sources tab shows real, queryable entities from day one instead
# of an empty page. These are auto-seeded on first /sources fetch and
# row counts + last-event timestamps refresh on every GET.

BUILTIN_DATA_SOURCES: list[dict] = [
    {
        "name": "SIEM Logs",
        "description": "Canonical ingest surface — every correlated log event the platform sees lands here (AWS CloudTrail, syslog, Windows events, custom connectors).",
        "source_type": "siem_events",
        "format": "json",
        "ingestion_type": "streaming",
        "table": "log_entries",
        "timestamp_col": "created_at",
    },
    {
        "name": "Alerts",
        "description": "Detection-engine output — rule-driven + ML-scored alerts with severity, status, and MITRE mapping.",
        "source_type": "siem_events",
        "format": "json",
        "ingestion_type": "push",
        "table": "alerts",
        "timestamp_col": "created_at",
    },
    {
        "name": "Incidents",
        "description": "Verdict-confirmed security incidents opened by the autonomous investigator.",
        "source_type": "siem_events",
        "format": "json",
        "ingestion_type": "push",
        "table": "incidents",
        "timestamp_col": "created_at",
    },
    {
        "name": "UEBA Risk Alerts",
        "description": "Behavioral anomalies — dormant-account logins, off-hours privileged actions, baseline deviations.",
        "source_type": "identity_logs",
        "format": "json",
        "ingestion_type": "batch",
        "table": "ueba_risk_alerts",
        "timestamp_col": "created_at",
    },
    {
        "name": "Identity Threats",
        "description": "ITDR detections — dormant admin, MFA-missing privileged, stale credentials.",
        "source_type": "identity_logs",
        "format": "json",
        "ingestion_type": "batch",
        "table": "identity_threats",
        "timestamp_col": "created_at",
    },
    {
        "name": "Vulnerabilities",
        "description": "CVE inventory per asset — consumed by RA-5 attester + Supply Chain cross-reference sweep.",
        "source_type": "vulnerability_scans",
        "format": "json",
        "ingestion_type": "batch",
        "table": "vulnerabilities",
        "timestamp_col": "created_at",
    },
    {
        "name": "Supply Chain Risks",
        "description": "Typosquat hits + CVE cross-refs + vendor cert expiry from the daily supply-chain sweep.",
        "source_type": "threat_intel",
        "format": "json",
        "ingestion_type": "batch",
        "table": "supply_chain_risks",
        "timestamp_col": "created_at",
    },
    {
        "name": "Software Components",
        "description": "SBOM-sourced dependency inventory (SPDX + CycloneDX imports) with license + purl + risk score.",
        "source_type": "application_logs",
        "format": "json",
        "ingestion_type": "batch",
        "table": "software_components",
        "timestamp_col": "created_at",
    },
    {
        "name": "STIG Scan Results",
        "description": "DISA STIG / SCAP compliance findings (ARF ingested per endpoint per benchmark).",
        "source_type": "vulnerability_scans",
        "format": "json",
        "ingestion_type": "batch",
        "table": "stig_scan_results",
        "timestamp_col": "created_at",
    },
    {
        "name": "Assets",
        "description": "Platform asset inventory — hosts, cloud instances, endpoints with criticality + owner.",
        "source_type": "application_logs",
        "format": "json",
        "ingestion_type": "batch",
        "table": "assets",
        "timestamp_col": "created_at",
    },
    {
        "name": "Threat Indicators",
        "description": "IOC feed — IPs, domains, hashes pulled from threat-intel feeds every 30 min.",
        "source_type": "threat_intel",
        "format": "json",
        "ingestion_type": "pull",
        "table": "threat_indicators",
        "timestamp_col": "created_at",
    },
    {
        "name": "Decoy Interactions",
        "description": "Honeypot / decoy captures — any connection = guaranteed-malicious signal.",
        "source_type": "network_flow",
        "format": "json",
        "ingestion_type": "push",
        "table": "decoy_interactions",
        "timestamp_col": "created_at",
    },
    {
        "name": "Audit Trails",
        "description": "AU-2 audit trail — every privileged action + data-access event across the platform.",
        "source_type": "application_logs",
        "format": "json",
        "ingestion_type": "push",
        "table": "audit_trails",
        "timestamp_col": "created_at",
    },
]

BUILTIN_SOURCE_NAMES = {s["name"] for s in BUILTIN_DATA_SOURCES}


async def _ensure_builtin_sources(db: AsyncSession, org_id: str) -> None:
    """Upsert a DataSource row per BUILTIN_DATA_SOURCES entry for this org
    and refresh live row count + last-event timestamp from the underlying
    table. Safe to call on every /sources list — runs in O(builtins) and
    skips updates when the table doesn't exist or the org has no rows.
    """
    from sqlalchemy import text as sa_text

    existing = (await db.execute(
        select(DataSource).where(
            DataSource.organization_id == org_id,
            DataSource.name.in_(list(BUILTIN_SOURCE_NAMES)),
        )
    )).scalars().all()
    by_name = {s.name: s for s in existing}

    changed = False
    for spec in BUILTIN_DATA_SOURCES:
        table = spec["table"]
        ts_col = spec["timestamp_col"]
        # Live row count + last-event timestamp. Use :org_id param to
        # prevent any tenant leakage even though these are fixed literals.
        try:
            # Savepoint: a missing table / column must not abort the
            # transaction for the remaining tables (Postgres).
            async with db.begin_nested():
                count_q = sa_text(
                    f"SELECT COUNT(*), MAX({ts_col}) FROM {table} "
                    f"WHERE organization_id = :org_id",
                )
                count_row = (await db.execute(count_q, {"org_id": org_id})).first()
            live_count = int(count_row[0] or 0) if count_row else 0
            last_event = count_row[1] if count_row else None
        except Exception:  # noqa: BLE001 - table absent in this deployment
            live_count = 0
            last_event = None

        last_event_iso = last_event.isoformat() if hasattr(last_event, "isoformat") else (
            last_event if isinstance(last_event, str) else None
        )

        row = by_name.get(spec["name"])
        if row is None:
            db.add(DataSource(
                organization_id=org_id,
                name=spec["name"],
                description=spec["description"],
                source_type=spec["source_type"],
                format=spec["format"],
                ingestion_type=spec["ingestion_type"],
                connection_config_encrypted={"builtin": True, "table": table},
                schema_definition={"columns": DATA_LAKE_READABLE_TABLES.get(table, [])},
                normalization_mapping={},
                status="active" if live_count > 0 else "initializing",
                total_events_ingested=live_count,
                last_event_received=last_event_iso,
                is_enabled=True,
            ))
            changed = True
        else:
            if (row.total_events_ingested or 0) != live_count or row.last_event_received != last_event_iso:
                row.total_events_ingested = live_count
                row.last_event_received = last_event_iso
                row.status = "active" if live_count > 0 else row.status
                changed = True

    if changed:
        try:
            await db.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"ensure_builtin_sources commit failed: {exc}")
            await db.rollback()


# --- Real Celery beat entries surfaced as built-in pipelines ---
# Lets the Pipelines tab show the actual scheduled work PySOAR runs
# (SIEM cloud poll, ITDR sweep, supply-chain sweep, STIG fleet sweep,
# threat-intel poll, agentic auto-triage) instead of a blank table.

def _builtin_celery_pipelines(org_id: str) -> list[dict]:
    """Reflect the live celery_app.beat_schedule into pipeline cards."""
    try:
        from src.workers.celery_app import celery_app
        schedule = celery_app.conf.beat_schedule or {}
    except Exception:  # noqa: BLE001
        return []

    out = []
    for name, cfg in schedule.items():
        task = cfg.get("task", "")
        schedule_val = cfg.get("schedule")
        if hasattr(schedule_val, "hour"):
            cadence = f"crontab {schedule_val}"
        else:
            try:
                secs = float(schedule_val)
                if secs >= 3600:
                    cadence = f"every {int(secs/3600)}h"
                elif secs >= 60:
                    cadence = f"every {int(secs/60)}min"
                else:
                    cadence = f"every {int(secs)}s"
            except Exception:  # noqa: BLE001
                cadence = str(schedule_val)
        ptype = "ingestion"
        if "sweep" in task or "poll" in task:
            ptype = "ingestion"
        elif "cleanup" in task or "retention" in task:
            ptype = "retention_management"
        elif "enrichment" in task or "correlation" in task:
            ptype = "enrichment"
        elif "automation." in task:
            ptype = "transformation"
        out.append({
            "id": f"builtin:{name}",
            "organization_id": org_id,
            "name": name.replace("-", " ").title(),
            "description": f"Celery beat task `{task}` — {cadence}",
            "pipeline_type": ptype,
            "destination": task,
            "transform_rules": [],
            "schedule_cron": cadence,
            # A beat entry is scheduled work; Celery keeps no per-run
            # history PySOAR can read, so it is never reported "active"
            # with a success rate.
            "status": "scheduled",
            "run_history": "not_recorded",
            "task": task,
            "last_run": None,
            "next_run": None,
            "avg_processing_time_ms": None,
            "records_processed_total": None,
            "error_count": None,
            "last_error": None,
            "created_at": None,
            "updated_at": None,
            "builtin": True,
        })
    return out


# ==================== DATA SOURCE ENDPOINTS ====================


@router.post("/sources", response_model=DataSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_data_source(
    source_in: DataSourceCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Register a data source.

    The connection settings (``connection_config``, or the legacy
    ``connection_config_encrypted``) are stored as an ``enc:v1:`` envelope
    and never returned; the response lists only which keys are set. No
    connector ingests registered sources yet, so the source is
    ``registered`` (not "initializing" forever) and its
    ``ingestion_note`` says so.
    """
    raw_config = source_in.connection_config or source_in.connection_config_encrypted or {}
    stored_config: dict = {}
    if raw_config:
        try:
            stored_config = {
                "envelope": encrypt_secret_json(raw_config),
                "keys": sorted(str(k) for k in raw_config),
            }
        except SecretUnreadable as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "encryption_unavailable", "detail": exc.reason},
            ) from exc
    try:
        source = DataSource(
            organization_id=org_id,
            name=source_in.name,
            description=source_in.description,
            source_type=source_in.source_type,
            ingestion_type=source_in.ingestion_type,
            format=source_in.format,
            schema_definition=source_in.schema_definition,
            normalization_mapping=source_in.normalization_mapping,
            connection_config_encrypted=stored_config,
            retention_days=source_in.retention_days,
            status=SOURCE_REGISTERED,
        )
        db.add(source)
        await db.commit()
        await db.refresh(source)
        return source
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/sources", response_model=DataSourceListResponse)
async def list_data_sources(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    source_type: Optional[str] = None,
    status: Optional[str] = None,
):
    """List data sources with filtering and pagination.

    Auto-seeds one DataSource row per canonical platform table (SIEM Logs,
    Alerts, Incidents, UEBA, ITDR, Supply Chain, STIG, Assets, …) for this
    org if they're missing, and refreshes live row counts + last-event
    timestamps on every call. Without this, the Sources tab is an empty
    shell for a brand-new org even though the platform is actively
    ingesting logs.
    """
    await _ensure_builtin_sources(db, org_id)

    query = select(DataSource).where(
        DataSource.organization_id == org_id
    )

    if search:
        search_filter = f"%{search}%"
        query = query.where(DataSource.name.ilike(search_filter))

    if source_type:
        query = query.where(DataSource.source_type == source_type)

    if status:
        query = query.where(DataSource.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataSource.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return DataSourceListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/sources/{source_id}", response_model=DataSourceResponse)
async def get_data_source(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Get data source by ID"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == org_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")
    return source


@router.patch("/sources/{source_id}", response_model=DataSourceResponse)
async def update_data_source(
    source_in: DataSourceUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Update data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == org_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    try:
        update_data = source_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(source, field, value)
        await db.commit()
        await db.refresh(source)
        return source
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.post("/sources/{source_id}/start")
async def start_data_source_ingestion(
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Start ingestion for a data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == org_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    # Not implemented: no ingestion worker exists for registered sources (the
    # in-memory DataIngestionEngine registry was always empty, so this
    # always 400'd and would have stamped a fabricated last_event_received).
    raise _not_implemented(
        "Starting ingestion is not implemented: no connector ingests registered "
        "data sources. Built-in sources are fed by the platform itself."
    )


@router.post("/sources/{source_id}/stop")
async def stop_data_source_ingestion(
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    source_id: str = Path(...),
):
    """Stop ingestion for a data source"""
    result = await db.execute(
        select(DataSource).where(
            (DataSource.id == source_id)
            & (DataSource.organization_id == org_id)
        )
    )
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Data source not found")

    raise _not_implemented(
        "Stopping ingestion is not implemented: no connector ingests registered "
        "data sources, so there is nothing to stop."
    )


# ==================== DATA PARTITION ENDPOINTS ====================


@router.post("/partitions", response_model=DataPartitionResponse, status_code=status.HTTP_201_CREATED)
async def create_partition(
    partition_in: DataPartitionCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create new data partition"""
    if partition_in.source_id:
        owned = await db.execute(
            select(DataSource.id).where(
                DataSource.id == partition_in.source_id,
                DataSource.organization_id == org_id,
            )
        )
        if owned.scalar_one_or_none() is None:
            raise HTTPException(
                status_code=422,
                detail={"field": "source_id", "detail": "Unknown data source"},
            )
    try:
        partition = DataPartition(
            organization_id=org_id,
            source_id=partition_in.source_id,
            partition_key=partition_in.partition_key,
            time_range_start=partition_in.time_range_start,
            time_range_end=partition_in.time_range_end,
            format=partition_in.format,
            compression=partition_in.compression,
            storage_tier=partition_in.storage_tier,
            location=partition_in.location,
        )
        db.add(partition)
        await db.commit()
        await db.refresh(partition)
        return partition
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/partitions", response_model=DataPartitionListResponse)
async def list_partitions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    source_id: Optional[str] = None,
    storage_tier: Optional[str] = None,
):
    """List data partitions with filtering"""
    query = select(DataPartition).where(
        DataPartition.organization_id == org_id
    )

    if source_id:
        query = query.where(DataPartition.source_id == source_id)

    if storage_tier:
        query = query.where(DataPartition.storage_tier == storage_tier)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataPartition.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return DataPartitionListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/partitions/daily/{table}")
async def get_daily_partitions(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    table: str = Path(..., description="Whitelisted table name (e.g. log_entries)"),
    days: int = Query(30, ge=1, le=365),
):
    """Synthetic time-based partitions over a real canonical table.

    PySOAR doesn't run native Postgres declarative partitioning yet —
    instead we surface one partition row per day by bucketing
    `created_at`, returning count + estimated bytes + age-based tier so
    the UI can show a real partitioned-data view without schema changes.
    Tenant-scoped when the table has an organization_id column.
    """
    from sqlalchemy import text as sa_text
    if table not in DATA_LAKE_READABLE_TABLES:
        raise HTTPException(status_code=400, detail=f"Unknown table '{table}'")

    # Introspect whether the table has organization_id.
    has_org = (await db.execute(
        sa_text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=:t "
            "AND column_name='organization_id'"
        ),
        {"t": table},
    )).scalar() is not None

    where_org = "WHERE organization_id = :org_id AND created_at >= NOW() - :days * INTERVAL '1 day'"
    if not has_org:
        # Counting a table with no organization_id column would report every
        # tenant's rows to the caller.
        raise HTTPException(
            status_code=400,
            detail=f"Table '{table}' is not tenant-scoped; per-tenant partitions are unavailable",
        )
    params = {"days": days, "org_id": org_id}
    where = where_org

    try:
        rows = (await db.execute(
            sa_text(
                f"""
                SELECT
                  date_trunc('day', created_at) AS day,
                  COUNT(*) AS row_count,
                  MIN(created_at) AS first_at,
                  MAX(created_at) AS last_at
                FROM {table}
                {where}
                GROUP BY 1
                ORDER BY 1 DESC
                """
            ),
            params,
        )).all()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"Partition query failed: {exc}")

    # Pull table total bytes to estimate per-partition size.
    try:
        tbl_bytes = (await db.execute(
            sa_text("SELECT pg_total_relation_size(quote_ident(:t))"),
            {"t": table},
        )).scalar() or 0
        # All-tenant row count: the table's bytes are shared by every org, so
        # bytes-per-row must divide by every row, not just the caller's.
        total_rows_row = (await db.execute(
            sa_text(f"SELECT COUNT(*) FROM {table}")
        )).scalar() or 0
        total_rows = int(total_rows_row)
    except Exception:  # noqa: BLE001
        tbl_bytes = 0
        total_rows = 0

    bytes_per_row = (int(tbl_bytes) / total_rows) if total_rows else 0

    partitions = []
    for day, row_count, first_at, last_at in rows:
        row_count = int(row_count or 0)
        age_days = (datetime.now(timezone.utc) - (day if day.tzinfo else day.replace(tzinfo=timezone.utc))).days
        if age_days < 7:
            tier = "hot"
        elif age_days < 30:
            tier = "warm"
        elif age_days < 365:
            tier = "cold"
        else:
            tier = "archived"
        partitions.append({
            "partition_key": f"{table}_{day.strftime('%Y_%m_%d')}",
            "day": day.isoformat(),
            "record_count": row_count,
            "size_bytes": int(row_count * bytes_per_row),
            "storage_tier": tier,
            "first_at": first_at.isoformat() if first_at else None,
            "last_at": last_at.isoformat() if last_at else None,
        })

    return {
        "table": table,
        "days_window": days,
        "partition_count": len(partitions),
        "total_rows_scanned": sum(p["record_count"] for p in partitions),
        "partitions": partitions,
    }


@router.patch("/partitions/{partition_id}", response_model=DataPartitionResponse)
async def update_partition(
    partition_in: DataPartitionUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    partition_id: str = Path(...),
):
    """Update partition (e.g., storage tier, indexes)"""
    result = await db.execute(
        select(DataPartition).where(
            (DataPartition.id == partition_id)
            & (DataPartition.organization_id == org_id)
        )
    )
    partition = result.scalar_one_or_none()
    if not partition:
        raise HTTPException(status_code=404, detail="Partition not found")

    try:
        update_data = partition_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(partition, field, value)
        await db.commit()
        await db.refresh(partition)
        return partition
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== DATA PIPELINE ENDPOINTS ====================


@router.post("/pipelines", response_model=DataPipelineResponse, status_code=status.HTTP_201_CREATED)
async def create_pipeline(
    pipeline_in: DataPipelineCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create new data pipeline"""
    try:
        pipeline = DataPipeline(
            organization_id=org_id,
            name=pipeline_in.name,
            description=pipeline_in.description,
            pipeline_type=pipeline_in.pipeline_type,
            source_id=pipeline_in.source_id,
            destination=pipeline_in.destination,
            transform_rules=[r.dict() for r in pipeline_in.transform_rules],
            schedule_cron=pipeline_in.schedule_cron,
            # No executor runs user-defined pipelines: the row is a
            # registration and says so (it never turns "active").
            status=PIPELINE_REGISTERED,
        )
        db.add(pipeline)
        await db.commit()
        await db.refresh(pipeline)
        return pipeline
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/pipelines")
async def list_pipelines(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    pipeline_type: Optional[str] = None,
    status: Optional[str] = None,
    include_builtins: bool = Query(True, description="Include live Celery beat pipelines"),
):
    """List data pipelines — user-created rows merged with live Celery
    beat pipelines (SIEM poll, ITDR sweep, supply-chain sweep, threat-
    intel poll, agentic auto-triage, STIG fleet sweep, etc.). Set
    include_builtins=false to see only the org's own DataPipeline rows.
    """
    query = select(DataPipeline).where(
        DataPipeline.organization_id == org_id
    )

    if pipeline_type:
        query = query.where(DataPipeline.pipeline_type == pipeline_type)

    if status:
        query = query.where(DataPipeline.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(DataPipeline.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    # Serialize custom rows to plain dicts so we can union with builtins.
    custom_items = [
        {
            "id": p.id,
            "organization_id": p.organization_id,
            "name": p.name,
            "description": p.description,
            "pipeline_type": p.pipeline_type,
            "source_id": p.source_id,
            "destination": p.destination,
            "transform_rules": p.transform_rules,
            "schedule_cron": p.schedule_cron,
            "status": p.status,
            "last_run": p.last_run,
            "next_run": p.next_run,
            "avg_processing_time_ms": p.avg_processing_time_ms,
            "records_processed_total": p.records_processed_total,
            "error_count": p.error_count,
            "last_error": p.last_error,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "updated_at": p.updated_at.isoformat() if p.updated_at else None,
            "builtin": False,
            "executor": None,
            "execution_note": PIPELINE_NO_EXECUTOR,
        }
        for p in items
    ]

    merged = custom_items
    if include_builtins:
        builtins = _builtin_celery_pipelines(org_id)
        # Apply the same filters the caller passed.
        if pipeline_type:
            builtins = [b for b in builtins if b["pipeline_type"] == pipeline_type]
        if status:
            builtins = [b for b in builtins if b["status"] == status]
        merged = custom_items + builtins

    return {
        "items": merged,
        "total": total + (len(merged) - len(custom_items)),
        "page": page,
        "size": size,
        "pages": pages,
    }


@router.patch("/pipelines/{pipeline_id}", response_model=DataPipelineResponse)
async def update_pipeline(
    pipeline_in: DataPipelineUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    pipeline_id: str = Path(...),
):
    """Update data pipeline"""
    result = await db.execute(
        select(DataPipeline).where(
            (DataPipeline.id == pipeline_id)
            & (DataPipeline.organization_id == org_id)
        )
    )
    pipeline = result.scalar_one_or_none()
    if not pipeline:
        raise HTTPException(status_code=404, detail="Pipeline not found")

    update_data = pipeline_in.dict(exclude_unset=True)
    if str(update_data.get("status") or "").lower() in ("active", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "no_executor", "detail": PIPELINE_NO_EXECUTOR},
        )
    try:
        for field, value in update_data.items():
            if field == "transform_rules" and value:
                value = [r.dict() if hasattr(r, "dict") else r for r in value]
            setattr(pipeline, field, value)
        await db.commit()
        await db.refresh(pipeline)
        return pipeline
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== UNIFIED DATA MODEL ENDPOINTS ====================


@router.post("/models", response_model=UnifiedDataModelResponse, status_code=status.HTTP_201_CREATED)
async def create_unified_model(
    model_in: UnifiedDataModelCreate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
):
    """Create unified data model"""
    try:
        model = UnifiedDataModel(
            organization_id=org_id,
            name=model_in.name,
            description=model_in.description,
            entity_type=model_in.entity_type,
            field_definitions=[f.dict() for f in model_in.field_definitions],
            normalization_rules=model_in.normalization_rules,
            enrichment_rules=model_in.enrichment_rules,
            sample_data=model_in.sample_data,
        )
        db.add(model)
        await db.commit()
        await db.refresh(model)
        return model
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


@router.get("/models", response_model=UnifiedDataModelListResponse)
async def list_unified_models(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    entity_type: Optional[str] = None,
    search: Optional[str] = None,
):
    """List unified data models"""
    query = select(UnifiedDataModel).where(
        UnifiedDataModel.organization_id == org_id
    )

    if entity_type:
        query = query.where(UnifiedDataModel.entity_type == entity_type)

    if search:
        search_filter = f"%{search}%"
        query = query.where(UnifiedDataModel.name.ilike(search_filter))

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(UnifiedDataModel.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return UnifiedDataModelListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.patch("/models/{model_id}", response_model=UnifiedDataModelResponse)
async def update_unified_model(
    model_in: UnifiedDataModelUpdate,
    org_id: OrganizationId,
    _user: AdminRoleUser = None,
    db: DatabaseSession = None,
    model_id: str = Path(...),
):
    """Update unified data model"""
    result = await db.execute(
        select(UnifiedDataModel).where(
            (UnifiedDataModel.id == model_id)
            & (UnifiedDataModel.organization_id == org_id)
        )
    )
    model = result.scalar_one_or_none()
    if not model:
        raise HTTPException(status_code=404, detail="Model not found")

    try:
        update_data = model_in.dict(exclude_unset=True)
        for field, value in update_data.items():
            if field == "field_definitions" and value:
                value = [f.dict() if hasattr(f, "dict") else f for f in value]
            setattr(model, field, value)
        await db.commit()
        await db.refresh(model)
        return model
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=400, detail="Operation failed. Please try again or contact support.")


# ==================== QUERY ENGINE ENDPOINTS ====================


@router.post("/queries", response_model=QueryJobResponse, status_code=status.HTTP_201_CREATED)
async def submit_query(
    query_in: QueryJobCreate,
    org_id: OrganizationId,
    current_user: AnalystUser = None,
    db: DatabaseSession = None,
):
    """Submit a query job.

    Not implemented: the QueryEngine never ran the query text. It summed
    partition metadata across every tenant (no org filter), marked the job
    ``completed`` and fired a data-lake "anomaly" automation for each query.
    Saved-query history is written by ``POST /data-lake/query``.
    """
    logger.info(
        "data_lake_query_job_not_implemented",
        organization_id=org_id,
        user_id=str(current_user.id),
        query_language=query_in.query_language,
    )
    raise _not_implemented(
        "Queued query jobs are not implemented: nothing executes them. Use "
        "POST /data-lake/query (catalog filter) instead."
    )


@router.get("/queries", response_model=QueryJobListResponse)
async def list_queries(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
):
    """List query jobs"""
    query = select(QueryJob).where(
        QueryJob.organization_id == org_id
    )

    if status:
        query = query.where(QueryJob.status == status)

    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar() or 0

    offset = (page - 1) * size
    results = await db.execute(
        query.order_by(QueryJob.created_at.desc()).limit(size).offset(offset)
    )
    items = results.scalars().all()

    pages = math.ceil(total / size) if total > 0 else 0

    return QueryJobListResponse(
        items=items,
        total=total,
        page=page,
        size=size,
        pages=pages,
    )


@router.get("/queries/{query_id}", response_model=QueryJobResponse)
async def get_query(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    query_id: str = Path(...),
):
    """Get query job details"""
    result = await db.execute(
        select(QueryJob).where(
            (QueryJob.id == query_id)
            & (QueryJob.organization_id == org_id)
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Query not found")
    return job


@router.post("/queries/{query_id}/estimate-cost")
async def estimate_query_cost(
    org_id: OrganizationId,
    _user: AnalystUser = None,
    db: DatabaseSession = None,
    query_id: str = Path(...),
    data_scanned_gb: int = Query(..., ge=1),
):
    """Estimate query execution cost.

    Not implemented: the estimate was hardcoded BigQuery $/TB pricing for a
    Postgres store. The job is looked up (tenant-scoped, 404 otherwise) and
    the route then refuses honestly.
    """
    job = (await db.execute(
        select(QueryJob.id).where(
            QueryJob.id == query_id, QueryJob.organization_id == org_id
        )
    )).scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=404, detail="Query job not found")
    raise _not_implemented(
        f"Cost estimation for {data_scanned_gb} GB is not implemented: the data "
        "lake is Postgres and has no per-scan pricing."
    )


# ==================== DATA CATALOG ENDPOINTS ====================


@router.get("/catalog")
async def list_catalog(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Real data catalog — introspects Postgres for every whitelisted
    table and returns its column list, live row count (tenant-scoped),
    and total table size. Augmented with any UnifiedDataModel rows the
    org has registered. This is what an analyst needs to know *before*
    writing a query against the lake.
    """
    from sqlalchemy import text as sa_text

    entries: list[dict] = []

    for table, whitelisted_cols in DATA_LAKE_READABLE_TABLES.items():
        # Real schema from information_schema.
        try:
            cols_result = await db.execute(
                sa_text(
                    "SELECT column_name, data_type, is_nullable "
                    "FROM information_schema.columns "
                    "WHERE table_schema='public' AND table_name=:t "
                    "ORDER BY ordinal_position"
                ),
                {"t": table},
            )
            columns = [
                {
                    "name": c[0],
                    "type": c[1],
                    "nullable": c[2] == "YES",
                    "queryable": c[0] in whitelisted_cols,
                }
                for c in cols_result.all()
            ]
        except Exception:  # noqa: BLE001
            columns = []

        if not columns:
            continue  # table doesn't exist in this DB

        # Tenant-scoped row count.
        org_scoped = any(c["name"] == "organization_id" for c in columns)
        # Tables without organization_id get no count: a global COUNT would
        # report every tenant's rows to the caller.
        row_count: Optional[int] = None
        if org_scoped:
            try:
                rc = (await db.execute(
                    sa_text(f"SELECT COUNT(*) FROM {table} WHERE organization_id = :org_id"),
                    {"org_id": org_id},
                )).scalar()
                row_count = int(rc or 0)
            except Exception:  # noqa: BLE001
                row_count = 0

        # Table bytes via pg_total_relation_size.
        try:
            tbytes = (await db.execute(
                sa_text("SELECT pg_total_relation_size(quote_ident(:t))"),
                {"t": table},
            )).scalar() or 0
        except Exception:  # noqa: BLE001
            tbytes = 0

        # Last event timestamp.
        last_event = None
        for ts_col in ("created_at", "detected_at", "timestamp"):
            if not org_scoped:
                break
            if any(c["name"] == ts_col for c in columns):
                try:
                    last = (await db.execute(
                        sa_text(
                            f"SELECT MAX({ts_col}) FROM {table} "
                            "WHERE organization_id = :org_id"
                        ),
                        {"org_id": org_id},
                    )).scalar()
                    if last is not None:
                        last_event = last.isoformat() if hasattr(last, "isoformat") else str(last)
                    break
                except Exception:  # noqa: BLE001
                    continue

        entries.append({
            "id": f"table:{table}",
            "name": table,
            "description": f"Built-in canonical table `{table}` ({len(columns)} columns).",
            "type": "table",
            "entity_type": table,
            "queryable": True,
            "tenant_scoped": org_scoped,
            "row_count": row_count,
            "size_bytes": int(tbytes),
            "last_event_at": last_event,
            "schema": columns,
        })

    # Layer org-registered DataSource + UnifiedDataModel entries on top.
    sources = (await db.execute(
        select(DataSource).where(DataSource.organization_id == org_id)
    )).scalars().all()
    for s in sources:
        if s.name in BUILTIN_SOURCE_NAMES:
            continue  # the table row above already represents this
        entries.append({
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "type": "source",
            "source_type": s.source_type,
            "status": s.status,
            "format": getattr(s, "format", None),
            "row_count": int(s.total_events_ingested or 0),
            "last_event_at": s.last_event_received,
        })

    models = (await db.execute(
        select(UnifiedDataModel).where(UnifiedDataModel.organization_id == org_id)
    )).scalars().all()
    for m in models:
        entries.append({
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "type": "unified_model",
            "entity_type": m.entity_type,
        })
    return entries


# Tables the data lake SQL executor is allowed to read from.
# All reads are tenant-scoped by automatically injecting an
# organization_id filter when the row model has that column.
DATA_LAKE_READABLE_TABLES: dict[str, list[str]] = {
    "alerts": [
        "id", "title", "description", "severity", "status", "source",
        "alert_type", "confidence_score", "organization_id",
        "created_at", "updated_at", "acknowledged_at", "resolved_at",
    ],
    "incidents": [
        "id", "title", "description", "severity", "priority", "status",
        "incident_type", "category", "organization_id",
        "detected_at", "reported_at", "resolved_at", "created_at", "updated_at",
    ],
    "threat_indicators": [
        "id", "indicator_value", "indicator_type", "threat_level",
        "confidence_score", "is_active", "source", "organization_id",
        "first_seen", "last_seen", "created_at", "updated_at",
    ],
    "audit_trails": [
        "id", "event_type", "action", "actor_type", "actor_id",
        "resource_type", "resource_id", "result", "risk_level",
        "organization_id", "created_at",
    ],
    "audit_logs": [
        "id", "event_type", "action", "actor_id", "resource_type",
        "resource_id", "result", "organization_id", "created_at",
    ],
    # SIEM canonical log surface — the biggest data source in the platform.
    "log_entries": [
        "id", "organization_id", "source", "log_type", "severity",
        "source_ip", "destination_ip", "user_id", "host", "message",
        "raw_event", "indexed_fields", "created_at", "timestamp",
    ],
    # UEBA — behavioral anomalies.
    "ueba_risk_alerts": [
        "id", "organization_id", "user_id", "risk_type", "risk_score",
        "severity", "baseline_deviation", "status", "evidence",
        "detected_at", "created_at",
    ],
    # ITDR — identity threat detections (dormant_admin / MFA-less / stale).
    "identity_threats": [
        "id", "organization_id", "identity_id", "threat_type", "severity",
        "status", "evidence", "remediation_advice", "detected_at",
        "created_at", "resolved_at",
    ],
    # CVE table.
    "vulnerabilities": [
        "id", "organization_id", "cve_id", "title", "description",
        "severity", "cvss_score", "status", "asset_id",
        "first_seen", "patched_at", "created_at",
    ],
    # Supply chain risks (typosquat/vuln/vendor).
    "supply_chain_risks": [
        "id", "organization_id", "component_id", "risk_type", "severity",
        "description", "status", "detected_date", "remediation_date",
        "created_at", "updated_at",
    ],
    # Dependency inventory from SBOM imports.
    "software_components": [
        "id", "organization_id", "name", "version", "vendor",
        "package_type", "license_spdx_id", "license_type",
        "known_vulnerabilities_count", "risk_score", "purl", "cpe",
        "created_at",
    ],
    # STIG/SCAP compliance scan results.
    "stig_scan_results": [
        "id", "organization_id", "benchmark_id", "asset_id", "rule_id",
        "result", "severity", "compliance_score", "scanned_at", "created_at",
    ],
    # Asset inventory.
    "assets": [
        "id", "organization_id", "name", "asset_type", "ip_address",
        "hostname", "os", "criticality", "owner", "status",
        "created_at", "updated_at", "last_seen",
    ],
    # Deception / honeypot interactions.
    "decoy_interactions": [
        "id", "organization_id", "decoy_id", "interaction_type",
        "source_ip", "severity", "captured_at", "created_at",
    ],
}


def _build_tenant_scoped_sql(raw_sql: str, org_id: str) -> str:
    """Validate a SQL SELECT against the whitelist and inject org scoping.

    The executor only allows a narrow subset of SQL:
      * A single ``SELECT`` statement (trailing semicolons are stripped).
      * ``FROM <table>`` where *table* is listed in
        ``DATA_LAKE_READABLE_TABLES``.
      * No semicolons inside the statement (prevents stacked queries).
      * No DDL/DML verbs (``INSERT``, ``UPDATE``, ``DELETE``, ``DROP``,
        ``ALTER``, ``CREATE``, ``TRUNCATE``, ``COPY``, ``GRANT``,
        ``REVOKE`` anywhere in the text).
      * When the referenced table has an ``organization_id`` column we
        append ``organization_id = :org_id`` to the WHERE clause so
        callers can never read another tenant's rows, regardless of
        what filter they put in their own SQL.

    Returns the rewritten SQL. Raises ``HTTPException(400)`` if the
    query is rejected.
    """
    import re

    sql = (raw_sql or "").strip().rstrip(";").strip()
    if not sql:
        raise HTTPException(status_code=400, detail="Empty query")

    upper = sql.upper()
    if ";" in sql:
        raise HTTPException(status_code=400, detail="Multiple statements are not permitted")
    if not upper.startswith("SELECT") and not upper.startswith("WITH"):
        raise HTTPException(status_code=400, detail="Only SELECT / WITH queries are permitted")

    banned = {
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "TRUNCATE", "COPY", "GRANT", "REVOKE", "VACUUM", "ATTACH",
        "DETACH", "EXEC", "CALL", "MERGE", "PG_SLEEP", "PG_READ_FILE",
    }
    tokens = set(re.findall(r"\b[A-Za-z_]+\b", upper))
    offending = banned & tokens
    if offending:
        raise HTTPException(
            status_code=400,
            detail=f"Query contains disallowed verb(s): {', '.join(sorted(offending))}",
        )

    from_matches = re.findall(
        r"\bFROM\s+\"?([a-zA-Z_][a-zA-Z0-9_]*)\"?", sql, flags=re.IGNORECASE
    ) + re.findall(
        r"\bJOIN\s+\"?([a-zA-Z_][a-zA-Z0-9_]*)\"?", sql, flags=re.IGNORECASE
    )
    if not from_matches:
        raise HTTPException(status_code=400, detail="Query must reference a table via FROM")
    for tbl in from_matches:
        if tbl.lower() not in DATA_LAKE_READABLE_TABLES:
            allowed = ", ".join(sorted(DATA_LAKE_READABLE_TABLES.keys()))
            raise HTTPException(
                status_code=400,
                detail=f"Table '{tbl}' is not in the data-lake whitelist. Allowed: {allowed}",
            )

    # Inject tenant scoping for the first referenced table. This is a
    # belt-and-suspenders guard: callers with their own WHERE clause
    # already get filtered, and callers without one still get filtered.
    primary_table = from_matches[0].lower()
    if primary_table in DATA_LAKE_READABLE_TABLES:
        where_idx = upper.find(" WHERE ")
        tenant_clause = f"{primary_table}.organization_id = :__pysoar_org_id"
        if where_idx >= 0:
            # Wrap the existing WHERE contents in parentheses and AND our filter
            before = sql[:where_idx + len(" WHERE ")]
            after = sql[where_idx + len(" WHERE "):]
            sql = f"{before}({after}) AND {tenant_clause}"
        else:
            # Insert before GROUP BY / ORDER BY / LIMIT if present,
            # otherwise append at the end.
            insertion_keywords = [" GROUP BY ", " ORDER BY ", " LIMIT ", " HAVING "]
            positions = [
                upper.find(k) for k in insertion_keywords if upper.find(k) >= 0
            ]
            insert_at = min(positions) if positions else len(sql)
            sql = sql[:insert_at] + f" WHERE {tenant_clause} " + sql[insert_at:]

    return sql


@router.post("/query")
async def run_catalog_filter_query(
    org_id: OrganizationId,
    current_user: CurrentUser,
    payload: dict = Body(...),
    db: DatabaseSession = None,
):
    """Execute a read-only SQL query against the data-lake whitelist.

    This endpoint now actually runs SQL — previously it returned a metadata
    summary and ignored the query body. Two request shapes are supported:

    **Real SQL execution (new):** pass ``{"query": "SELECT ..."}`` or
    ``{"query_text": "SELECT ...", "query_language": "sql"}``. The executor
    validates the query against :data:`DATA_LAKE_READABLE_TABLES`, injects
    a tenant-scoping ``organization_id`` filter, runs it through the
    existing async SQLAlchemy session, and returns ``columns`` and ``rows``.
    Only ``SELECT``/``WITH`` queries are accepted; anything else is
    rejected with 400.

    **Catalog filter (legacy):** pass a JSON filter like ``{"source_type":
    "siem", "storage_tier": "hot"}`` (no ``query`` key) and you get the old
    catalog metadata response. This keeps older frontends that filter the
    partition catalog working.
    """

    # --- Real SQL execution path ---
    raw_sql: Optional[str] = None
    if isinstance(payload, dict):
        raw_sql = payload.get("query") or payload.get("query_text") or payload.get("sql")
    query_language = (payload.get("query_language") or "sql").lower() if isinstance(payload, dict) else "sql"

    if raw_sql and isinstance(raw_sql, str) and raw_sql.strip():
        # Raw SQL is platform-superuser only: the tenant guard below is not
        # sound (see the module docstring). The tenant "admin" role is not
        # enough, since a tenant admin must not read other tenants' rows.
        if not getattr(current_user, "is_superuser", False):
            logger.warning(
                "data_lake.raw_sql_refused",
                user_id=str(getattr(current_user, "id", "")),
                organization_id=org_id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "raw_sql_requires_superuser",
                    "detail": (
                        "raw SQL queries are limited to platform superusers until the "
                        "per-tenant SQL guard is rewritten on a real parser; use the "
                        "catalog filter or the saved queries instead"
                    ),
                },
            )
        if query_language not in ("sql", "dialect_sql"):
            raise HTTPException(
                status_code=400,
                detail=f"Query language '{query_language}' is not yet executable. Only 'sql' is supported.",
            )
        from sqlalchemy import text as sa_text
        started = datetime.now(timezone.utc)
        safe_sql = _build_tenant_scoped_sql(raw_sql, org_id)
        # Bound the result size. If the user didn't ask for a LIMIT, wrap
        # the statement to cap at 1000 rows regardless.
        upper_sql = safe_sql.upper()
        max_rows = 1000
        if " LIMIT " not in upper_sql:
            safe_sql = f"SELECT * FROM ({safe_sql}) AS __pysoar_q LIMIT {max_rows}"

        try:
            result = await db.execute(
                sa_text(safe_sql),
                {"__pysoar_org_id": org_id},
            )
            col_names = list(result.keys())
            rows_raw = result.mappings().all()
            rows_out = [dict(r) for r in rows_raw]
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"data-lake query execution failed: {exc}")
            raise HTTPException(
                status_code=400,
                detail=f"Query failed: {exc}",
            )

        elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)

        # Persist a real QueryJob audit row so the history page shows it.
        # `query_text` is a TEXT column — persist the full SQL (minus the
        # tenant scope suffix we auto-added) so the history is auditable.
        try:
            import json as _json
            job = QueryJob(
                organization_id=org_id,
                query_text=raw_sql,
                query_language=query_language,
                status="completed",
                records_scanned=len(rows_out),
                records_returned=len(rows_out),
                execution_time_ms=elapsed_ms,
                submitted_by=str(getattr(current_user, "id", "")),
                data_sources_queried=[],
            )
            db.add(job)
            await db.commit()
            await db.refresh(job)
            job_id = job.id
        except Exception as exc:
            logger.warning(f"QueryJob persist failed (SQL exec): {exc}")
            await db.rollback()
            job_id = None

        # Convert non-JSON-safe values (datetimes, UUIDs, etc.) to strings
        def _json_safe(v):
            if v is None or isinstance(v, (bool, int, float, str)):
                return v
            try:
                import uuid as _uuid
                if isinstance(v, _uuid.UUID):
                    return str(v)
            except Exception:
                pass
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_json_safe(x) for x in v]
            if isinstance(v, dict):
                return {k: _json_safe(val) for k, val in v.items()}
            return str(v)

        rows_out_safe = [{k: _json_safe(val) for k, val in r.items()} for r in rows_out]

        return {
            "mode": "sql",
            "query": raw_sql,
            "query_language": query_language,
            "columns": col_names,
            "rows": rows_out_safe,
            "row_count": len(rows_out_safe),
            "execution_time_ms": elapsed_ms,
            "job_id": job_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tenant_scoped": True,
        }

    # --- Legacy catalog filter path (no SQL provided) ---
    # Parse filter spec
    source_type = payload.get("source_type")
    name_contains = payload.get("source_name_contains") or payload.get("search")
    storage_tier = payload.get("storage_tier")
    time_range_start = payload.get("time_range_start")
    limit = min(int(payload.get("limit", 100)), 1000)

    # Build source filter
    source_stmt = select(DataSource).where(DataSource.organization_id == org_id)
    if source_type:
        source_stmt = source_stmt.where(DataSource.source_type == source_type)
    if name_contains:
        source_stmt = source_stmt.where(DataSource.name.ilike(f"%{name_contains}%"))
    source_stmt = source_stmt.limit(limit)

    sources_rows = (await db.execute(source_stmt)).scalars().all()
    matched_source_ids = [s.id for s in sources_rows]

    # Build partition filter (scoped to matched sources if source filter was given,
    # otherwise all org partitions)
    part_stmt = select(DataPartition).where(DataPartition.organization_id == org_id)
    if matched_source_ids and (source_type or name_contains):
        part_stmt = part_stmt.where(DataPartition.source_id.in_(matched_source_ids))
    if storage_tier:
        part_stmt = part_stmt.where(DataPartition.storage_tier == storage_tier)
    if time_range_start:
        part_stmt = part_stmt.where(DataPartition.time_range_start >= time_range_start)
    part_stmt = part_stmt.limit(limit)

    parts_rows = (await db.execute(part_stmt)).scalars().all()

    # Real aggregates
    total_records = sum(p.record_count or 0 for p in parts_rows)
    total_bytes = sum(p.size_bytes or 0 for p in parts_rows)

    sources_out = [
        {
            "id": s.id,
            "name": s.name,
            "source_type": s.source_type,
            "status": s.status,
            "format": s.format,
            "last_event_received": s.last_event_received,
        }
        for s in sources_rows
    ]
    parts_out = [
        {
            "id": p.id,
            "source_id": p.source_id,
            "partition_key": p.partition_key,
            "time_range_start": p.time_range_start,
            "time_range_end": p.time_range_end,
            "record_count": p.record_count,
            "size_bytes": p.size_bytes,
            "storage_tier": p.storage_tier,
            "format": p.format,
        }
        for p in parts_rows
    ]

    # Persist a QueryJob audit record for history
    now = datetime.now(timezone.utc)
    started = now
    try:
        import json as _json
        job = QueryJob(
            organization_id=org_id,
            query_text=_json.dumps(payload)[:4000],
            query_language="catalog_filter",
            status="completed",
            data_sources_queried=matched_source_ids,
            records_scanned=total_records,
            records_returned=len(parts_rows),
            execution_time_ms=int((datetime.now(timezone.utc) - started).total_seconds() * 1000),
            submitted_by=str(getattr(current_user, "id", "")),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
    except Exception as exc:
        logger.warning(f"QueryJob persist failed: {exc}")
        await db.rollback()
        job = None

    return {
        "filter": payload,
        "sources": sources_out,
        "partitions": parts_out,
        "aggregate": {
            "source_count": len(sources_out),
            "partition_count": len(parts_out),
            "total_records": total_records,
            "total_bytes": total_bytes,
        },
        "job_id": getattr(job, "id", None),
        "timestamp": now.isoformat(),
    }


@router.get("/catalog/datasets")
async def search_datasets(
    _org_id: OrganizationId,
    search: str = Query(..., min_length=1),
):
    """Search datasets in data catalog.

    Not implemented: this searched a fresh in-memory ``DataCatalog`` on every
    call, so it always returned no results. ``GET /data-lake/catalog`` is the
    real (tenant-scoped) catalog.
    """
    raise _not_implemented(
        f"Dataset search for {search!r} is not implemented; use GET /data-lake/catalog."
    )


@router.get("/catalog/lineage/{dataset_id}")
async def get_data_lineage(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    dataset_id: str = Path(...),
):
    """Real dataset lineage: upstream source + downstream pipelines + partitions.

    ``dataset_id`` is either a DataSource id or a UnifiedDataModel id.
    Builds a real lineage graph from the database:
        upstream: the DataSource row (for source-rooted lookups)
        downstream: every DataPipeline row whose ``sources`` list contains
                    this id AND every DataPartition rooted at this source
    Tenant-scoped via organization_id on every query.
    """

    # Try resolving as a DataSource first
    src = (
        await db.execute(
            select(DataSource).where(
                and_(DataSource.id == dataset_id, DataSource.organization_id == org_id)
            )
        )
    ).scalar_one_or_none()

    model = None
    if not src:
        model = (
            await db.execute(
                select(UnifiedDataModel).where(
                    and_(
                        UnifiedDataModel.id == dataset_id,
                        UnifiedDataModel.organization_id == org_id,
                    )
                )
            )
        ).scalar_one_or_none()

    if not src and not model:
        raise HTTPException(status_code=404, detail="Dataset not found")

    upstream: list[dict] = []
    downstream: list[dict] = []
    partitions: list[dict] = []
    builtin_table = _builtin_table(src) if src else None

    if builtin_table:
        # A built-in source *is* a platform table: its producers and
        # consumers are the platform code paths that write / read it,
        # listed only when the consuming task is in the beat schedule.
        scheduled = {cfg.get("task") for cfg in _beat_schedule().values()}
        for consumer in BUILTIN_TABLE_CONSUMERS.get(builtin_table, []):
            if consumer["task"] in scheduled:
                downstream.append({"type": "scheduled_task", "basis": "platform code", **consumer})

    if src:
        upstream.append({
            "type": "source",
            "id": src.id,
            "name": src.name,
            "source_type": src.source_type,
            "ingestion_type": src.ingestion_type,
        })

        # Partitions rooted at this source
        part_rows = (
            await db.execute(
                select(DataPartition).where(
                    and_(
                        DataPartition.source_id == src.id,
                        DataPartition.organization_id == org_id,
                    )
                )
            )
        ).scalars().all()
        partitions = [
            {
                "id": p.id,
                "partition_key": p.partition_key,
                "time_range_start": p.time_range_start,
                "time_range_end": p.time_range_end,
                "record_count": p.record_count,
                "size_bytes": p.size_bytes,
                "storage_tier": p.storage_tier,
            }
            for p in part_rows
        ]

    # Pipelines that reference this dataset via source_id FK
    pipelines = (
        await db.execute(
            select(DataPipeline).where(
                and_(
                    DataPipeline.organization_id == org_id,
                    DataPipeline.source_id == dataset_id,
                )
            )
        )
    ).scalars().all()
    for p in pipelines:
        downstream.append({
            "type": "pipeline",
            "id": p.id,
            "name": p.name,
            "pipeline_type": p.pipeline_type,
            "status": p.status,
            "destination": p.destination,
        })

    return {
        "dataset_id": dataset_id,
        "upstream_sources": upstream,
        "downstream_consumers": downstream,
        "partitions": partitions,
        "resolved_as": "source" if src else "unified_model",
        "builtin_table": builtin_table,
    }


@router.get("/catalog/quality/{dataset_id}")
async def get_data_quality(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    dataset_id: str = Path(...),
):
    """Real data quality report for a dataset.

    Quality is computed from observable DataPartition metadata on this org:
        - ingestion freshness: how recent is the latest partition?
        - record volume: total_record_count
        - storage distribution: bytes per storage_tier
        - partition count + indexed ratio
        - time coverage: earliest and latest time_range
    Raises 404 if the dataset is not a DataSource belonging to the caller's org.
    """

    src = (
        await db.execute(
            select(DataSource).where(
                and_(DataSource.id == dataset_id, DataSource.organization_id == org_id)
            )
        )
    ).scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Dataset not found")

    builtin_table = _builtin_table(src)
    if builtin_table:
        return await _builtin_table_quality(db, org_id, src, builtin_table)

    part_rows = (
        await db.execute(
            select(DataPartition).where(
                and_(
                    DataPartition.source_id == src.id,
                    DataPartition.organization_id == org_id,
                )
            )
        )
    ).scalars().all()

    total_records = sum(p.record_count or 0 for p in part_rows)
    total_bytes = sum(p.size_bytes or 0 for p in part_rows)
    indexed_count = sum(1 for p in part_rows if p.is_indexed)
    indexed_ratio = (indexed_count / len(part_rows)) if part_rows else 0.0

    by_tier: dict = {}
    for p in part_rows:
        tier = p.storage_tier or "unknown"
        by_tier[tier] = by_tier.get(tier, 0) + (p.size_bytes or 0)

    earliest = None
    latest = None
    for p in part_rows:
        if p.time_range_start and (earliest is None or p.time_range_start < earliest):
            earliest = p.time_range_start
        if p.time_range_end and (latest is None or p.time_range_end > latest):
            latest = p.time_range_end

    # Freshness: how old is the most recent partition relative to now
    freshness_hours = None
    if latest:
        try:
            latest_dt = datetime.fromisoformat(str(latest).replace("Z", "+00:00"))
            if latest_dt.tzinfo is None:
                latest_dt = latest_dt.replace(tzinfo=timezone.utc)
            freshness_hours = round(
                (datetime.now(timezone.utc) - latest_dt).total_seconds() / 3600.0, 2
            )
        except Exception:
            freshness_hours = None

    # Status derivation: healthy if freshness < 24h AND at least one partition,
    # degraded if freshness < 168h, stale otherwise.
    if not part_rows:
        status = "no_data"
    elif freshness_hours is None:
        status = "unknown"
    elif freshness_hours < 24:
        status = "healthy"
    elif freshness_hours < 168:
        status = "degraded"
    else:
        status = "stale"

    return {
        "dataset_id": dataset_id,
        "dataset_name": src.name,
        "source_type": src.source_type,
        "status": status,
        "freshness_hours": freshness_hours,
        "partition_count": len(part_rows),
        "total_records": total_records,
        "total_bytes": total_bytes,
        "indexed_ratio": round(indexed_ratio, 3),
        "storage_bytes_by_tier": by_tier,
        "time_range": {"earliest": earliest, "latest": latest},
    }


# ==================== DASHBOARD ENDPOINTS ====================


@router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Get unified dashboard metrics (real counts from DB, not hardcoded lies)."""
    now = datetime.now(timezone.utc)
    window_24h = now - timedelta(hours=24)

    # Sources
    sources_total = (await db.execute(
        select(func.count()).select_from(DataSource).where(DataSource.organization_id == org_id)
    )).scalar() or 0
    sources_active = (await db.execute(
        select(func.count()).select_from(DataSource).where(
            and_(DataSource.organization_id == org_id, DataSource.status == "active")
        )
    )).scalar() or 0

    # Pipelines
    pipelines_total = (await db.execute(
        select(func.count()).select_from(DataPipeline).where(DataPipeline.organization_id == org_id)
    )).scalar() or 0
    pipelines_active = (await db.execute(
        select(func.count()).select_from(DataPipeline).where(
            and_(DataPipeline.organization_id == org_id, DataPipeline.status == "active")
        )
    )).scalar() or 0
    pipelines_failed = (await db.execute(
        select(func.count()).select_from(DataPipeline).where(
            and_(DataPipeline.organization_id == org_id, DataPipeline.status == "failed")
        )
    )).scalar() or 0

    # Storage (sum real partition sizes if the column exists)
    total_bytes = 0
    try:
        total_bytes = (await db.execute(
            select(func.coalesce(func.sum(DataPartition.size_bytes), 0)).where(
                DataPartition.organization_id == org_id
            )
        )).scalar() or 0
    except Exception:
        total_bytes = 0

    # Queries in last 24h
    queries_24h = 0
    avg_exec_ms = 0
    try:
        queries_24h = (await db.execute(
            select(func.count()).select_from(QueryJob).where(
                and_(QueryJob.organization_id == org_id, QueryJob.created_at >= window_24h)
            )
        )).scalar() or 0
        avg_exec_ms = (await db.execute(
            select(func.coalesce(func.avg(QueryJob.execution_time_ms), 0)).where(
                and_(QueryJob.organization_id == org_id, QueryJob.created_at >= window_24h)
            )
        )).scalar() or 0
    except Exception:
        pass

    # Success rate = (records processed - errors) / records processed over
    # the org's pipeline rows; None when no pipeline has processed anything
    # (it used to be active / total pipelines, which is not a success rate).
    records_total, errors_total = (await db.execute(
        select(
            func.coalesce(func.sum(DataPipeline.records_processed_total), 0),
            func.coalesce(func.sum(DataPipeline.error_count), 0),
        ).where(DataPipeline.organization_id == org_id),
    )).one()
    records_total = int(records_total or 0)
    success_rate = (
        round(max(0.0, (records_total - int(errors_total or 0)) / records_total) * 100.0, 2)
        if records_total > 0 else None
    )

    return {
        "ingestion_metrics": {
            "active_sources": sources_active,
            "total_sources": sources_total,
            "success_rate": success_rate,
        },
        "storage_usage": {
            "total_bytes": int(total_bytes),
        },
        "query_performance": {
            "avg_execution_time_ms": int(avg_exec_ms or 0),
            "total_queries_24h": int(queries_24h),
        },
        "pipeline_health": {
            "active_pipelines": pipelines_active,
            "total_pipelines": pipelines_total,
            "failed_pipelines": pipelines_failed,
            "avg_success_rate": success_rate,
        },
        "timestamp": now.isoformat(),
    }


@router.get("/dashboard/storage-breakdown")
async def get_storage_breakdown(
    org_id: OrganizationId,
    db: DatabaseSession = None,
):
    """Real storage usage broken down by hot/warm/cold tier and by source.

    "Hot/warm/cold/archived" here is a real time-based heuristic over the
    underlying Postgres tables instead of the old fabricated percentages:
      * **hot**   — rows created in the last 7 days
      * **warm**  — 7 to 30 days old
      * **cold**  — 30 to 365 days old
      * **archived** — older than 365 days (retention candidate)

    Bytes are estimated from `pg_total_relation_size / total_rows * tier_rows`
    for each whitelisted table, tenant-scoped by organization_id. Also
    includes anything the org registered manually via DataPartition rows.
    """
    from sqlalchemy import text as sa_text

    # Real per-table byte count + tier breakdown via age bucketing.
    tiers = {"hot": 0, "warm": 0, "cold": 0, "archived": 0}
    by_source: dict[str, int] = {}
    by_table_detail: list[dict] = []

    dialect = db.bind.dialect.name if db.bind is not None else "postgresql"
    if dialect != "postgresql":
        return {
            "total_bytes": None,
            "by_tier": dict.fromkeys(tiers),
            "by_source": {},
            "by_table": [],
            "probe": {
                "method": "pg_total_relation_size",
                "available": False,
                "reason": f"storage sizes are measured on PostgreSQL only (database is {dialect})",
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    for table, _cols in DATA_LAKE_READABLE_TABLES.items():
        try:
            async with db.begin_nested():
                row = (await db.execute(
                    sa_text(f"SELECT pg_total_relation_size(quote_ident(:t))"),
                    {"t": table},
                )).scalar()
            table_bytes = int(row or 0)
        except Exception:  # noqa: BLE001
            continue

        if table_bytes == 0:
            continue

        # Tenant-scoped age bucket counts.
        where_org = "WHERE organization_id = :org_id"
        params = {"org_id": org_id}
        try:
            async with db.begin_nested():
                bucket_row = (await db.execute(
                    sa_text(
                        f"""
                        SELECT
                          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '7 days') AS hot,
                          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '30 days' AND created_at < NOW() - INTERVAL '7 days') AS warm,
                          COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '365 days' AND created_at < NOW() - INTERVAL '30 days') AS cold,
                          COUNT(*) FILTER (WHERE created_at < NOW() - INTERVAL '365 days') AS archived,
                          COUNT(*) AS total
                        FROM {table} {where_org}
                        """
                    ),
                    params,
                )).first()
                # All-tenant row count: the table's bytes are shared by every
                # org, so the caller is attributed only its share of them.
                table_rows = (await db.execute(
                    sa_text(f"SELECT COUNT(*) FROM {table}")
                )).scalar()
        except Exception:  # noqa: BLE001
            continue

        if bucket_row is None:
            continue
        hot, warm, cold, archived, total_rows = bucket_row
        total_rows = int(total_rows or 0)
        table_rows = int(table_rows or 0)
        if total_rows == 0 or table_rows == 0:
            continue
        # Estimate per-bucket bytes proportional to row counts.
        def _b(n, _table_bytes=table_bytes, _total_rows=table_rows):
            # Defaults bind the loop's values; a bare closure would see the
            # last iteration's table_bytes/total_rows if called late.
            return int(_table_bytes * (int(n or 0) / _total_rows))
        tiers["hot"] += _b(hot)
        tiers["warm"] += _b(warm)
        tiers["cold"] += _b(cold)
        tiers["archived"] += _b(archived)
        table_live_bytes = _b(hot) + _b(warm) + _b(cold) + _b(archived)
        by_source[table] = table_live_bytes
        by_table_detail.append({
            "table": table,
            "bytes": table_live_bytes,
            "total_rows": total_rows,
            "hot_rows": int(hot or 0),
            "warm_rows": int(warm or 0),
            "cold_rows": int(cold or 0),
            "archived_rows": int(archived or 0),
        })

    # Fold in any user-registered DataPartition rows so explicit archival
    # work still counts.
    try:
        async with db.begin_nested():
            part_tier = (await db.execute(
                select(DataPartition.storage_tier, func.coalesce(func.sum(DataPartition.size_bytes), 0))
                .where(DataPartition.organization_id == org_id)
                .group_by(DataPartition.storage_tier)
            )).all()
        for tier, bytes_ in part_tier:
            key = (tier or "hot").lower()
            if key in tiers:
                tiers[key] += int(bytes_ or 0)
    except Exception:  # noqa: BLE001
        pass

    total = sum(tiers.values())
    return {
        "total_bytes": total,
        "by_tier": tiers,
        "by_source": by_source,
        "by_table": by_table_detail,
        "probe": {
            "method": "pg_total_relation_size",
            "available": True,
            "reason": None,
            "attribution": "each table's bytes shared by its rows; this organisation's rows bucketed by created_at age",
            "tables_measured": len(by_table_detail),
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/pipeline-status")
async def get_pipeline_status(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    include_builtins: bool = Query(
        True, description="Count live Celery beat pipelines as active"
    ),
):
    """Real pipeline execution status and health.

    Previously returned hardcoded constants (42 active / 99.76% success /
    one fabricated execution). Now every number is computed from the
    caller's own DataPipeline rows (same org-scoping as the sibling
    /dashboard/metrics endpoint), optionally plus the live Celery beat
    schedule that /pipelines also surfaces:

      * ``active/paused/error_pipelines`` — one GROUP BY over the org's
        pipeline statuses ("error" + "failed" fold into error).
      * ``avg_success_rate`` — (records_processed - errors) / records
        across the org's pipelines when anything has been processed;
        falls back to the active/total ratio; 0.0 when the org has no
        pipelines at all.
      * ``recent_executions`` — the org's pipelines that actually ran
        (``last_run`` set), newest first. There is no per-run execution
        history model, so this honestly reflects the last run per
        pipeline and is an empty list when nothing has ever run.
    """

    # Status counts in one org-scoped GROUP BY.
    status_rows = (await db.execute(
        select(DataPipeline.status, func.count())
        .where(DataPipeline.organization_id == org_id)
        .group_by(DataPipeline.status)
    )).all()
    by_status = {str(s or "").lower(): int(c or 0) for s, c in status_rows}
    total_db = sum(by_status.values())
    active = by_status.get("active", 0)
    paused = by_status.get("paused", 0)
    error = by_status.get("error", 0) + by_status.get("failed", 0)

    # Real success rate from the pipelines' processed/error counters.
    records_total, errors_total = (await db.execute(
        select(
            func.coalesce(func.sum(DataPipeline.records_processed_total), 0),
            func.coalesce(func.sum(DataPipeline.error_count), 0),
        ).where(DataPipeline.organization_id == org_id)
    )).one()
    records_total = int(records_total or 0)
    errors_total = int(errors_total or 0)
    avg_success_rate: Optional[float] = None
    if records_total > 0:
        avg_success_rate = round(
            max(0.0, (records_total - errors_total) / records_total) * 100.0, 2
        )

    # Most recent real runs (org-scoped; empty when nothing has run).
    ran = (await db.execute(
        select(DataPipeline)
        .where(
            and_(
                DataPipeline.organization_id == org_id,
                DataPipeline.last_run.is_not(None),
            )
        )
        .order_by(DataPipeline.last_run.desc())
        .limit(10)
    )).scalars().all()
    recent_executions = [
        {
            "pipeline_id": p.id,
            "pipeline_name": p.name,
            "status": p.status,
            "execution_time_ms": int(p.avg_processing_time_ms or 0),
            "records_processed": int(p.records_processed_total or 0),
            "timestamp": p.last_run,
        }
        for p in ran
    ]

    # Beat entries are scheduled work with no readable run history: they
    # are counted separately, never as "active".
    builtin_scheduled = len(_builtin_celery_pipelines(org_id)) if include_builtins else 0

    return {
        "active_pipelines": active,
        "scheduled_builtin_pipelines": builtin_scheduled,
        "registered_pipelines": by_status.get(PIPELINE_REGISTERED, 0),
        "paused_pipelines": paused,
        "error_pipelines": error,
        "total_pipelines": total_db + builtin_scheduled,
        "recent_executions": recent_executions,
        "avg_success_rate": avg_success_rate,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/dashboard/ingestion-trend")
async def get_ingestion_trend(
    org_id: OrganizationId,
    db: DatabaseSession = None,
    hours: int = Query(24, ge=1, le=168, description="Trailing window size in hours"),
):
    """Hourly ingested-record counts over the trailing window.

    Sums real row counts (bucketed by ``created_at`` hour) across the
    built-in ingest surfaces from BUILTIN_DATA_SOURCES (log_entries,
    alerts, incidents, ...). Tenant-scoped: every table is filtered by
    the caller's organization_id, and any table that can't be filtered
    (missing table/column) is skipped rather than leaking cross-tenant
    rows. Returns an empty ``points`` list when nothing was ingested in
    the window — the UI renders its empty state instead of a fabricated
    line.
    """
    from sqlalchemy import text as sa_text

    now = datetime.now(timezone.utc)
    window_start = (now - timedelta(hours=hours - 1)).replace(
        minute=0, second=0, microsecond=0
    )

    dialect = db.bind.dialect.name if db.bind is not None else "postgresql"
    if dialect == "sqlite":
        # SQLite stores DateTime as naive-UTC text; strftime buckets it.
        bucket_expr = "strftime('%Y-%m-%dT%H:00:00', created_at)"
        cutoff = window_start.replace(tzinfo=None).strftime("%Y-%m-%d %H:%M:%S")
    else:
        # AT TIME ZONE 'UTC' pins buckets to UTC regardless of the server's
        # session timezone so they line up with the UTC zero-fill keys below.
        bucket_expr = (
            "to_char(date_trunc('hour', created_at AT TIME ZONE 'UTC'), "
            "'YYYY-MM-DD\"T\"HH24:00:00')"
        )
        cutoff = window_start

    buckets: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for spec in BUILTIN_DATA_SOURCES:
        table = spec["table"]
        if table not in DATA_LAKE_READABLE_TABLES:
            continue
        try:
            rows = (await db.execute(
                sa_text(
                    f"SELECT {bucket_expr} AS bucket, COUNT(*) "
                    f"FROM {table} "
                    f"WHERE organization_id = :org_id AND created_at >= :cutoff "
                    f"GROUP BY 1"
                ),
                {"org_id": org_id, "cutoff": cutoff},
            )).all()
        except Exception:  # noqa: BLE001 — missing table/column: skip, never leak
            await db.rollback()
            continue
        source_total = 0
        for bucket, cnt in rows:
            if bucket is None:
                continue
            buckets[str(bucket)] = buckets.get(str(bucket), 0) + int(cnt or 0)
            source_total += int(cnt or 0)
        if source_total:
            by_source[spec["name"]] = source_total

    total_events = sum(buckets.values())
    points: list[dict] = []
    if total_events > 0:
        # Dense hourly series (zero-filled) so the chart line is continuous.
        for i in range(hours):
            key = (window_start + timedelta(hours=i)).strftime("%Y-%m-%dT%H:00:00")
            points.append({"time": key, "count": buckets.get(key, 0)})

    return {
        "window_hours": hours,
        "bucket": "hour",
        "points": points,
        "total_events": total_events,
        "by_source": by_source,
        "generated_at": now.isoformat(),
    }
