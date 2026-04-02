"""
Prometheus metrics and monitoring endpoints.

Exports application metrics in Prometheus text exposition format
for scraping by Prometheus server.
"""

import time
import psutil
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Response
from sqlalchemy import select, func

from src.core.database import async_session_factory
from src.core.config import settings
from src.core.logging import get_logger
from src.siem.metrics import PrometheusExporter, siem_metrics

logger = get_logger(__name__)

router = APIRouter(tags=["monitoring"])

# Track request metrics in module-level counters
_request_count = 0
_request_errors = 0
_start_time = time.time()


@router.get("/metrics")
async def prometheus_metrics():
    """
    Export metrics in Prometheus text exposition format.

    Scraped by Prometheus at configurable interval.
    No authentication required (Prometheus needs direct access).
    """
    lines = []

    # --- System Metrics ---
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")

    lines.append(f'# HELP pysoar_cpu_usage_percent CPU usage percentage')
    lines.append(f'# TYPE pysoar_cpu_usage_percent gauge')
    lines.append(f'pysoar_cpu_usage_percent {cpu}')

    lines.append(f'# HELP pysoar_memory_usage_bytes Memory usage in bytes')
    lines.append(f'# TYPE pysoar_memory_usage_bytes gauge')
    lines.append(f'pysoar_memory_usage_bytes {mem.used}')

    lines.append(f'# HELP pysoar_memory_total_bytes Total memory in bytes')
    lines.append(f'# TYPE pysoar_memory_total_bytes gauge')
    lines.append(f'pysoar_memory_total_bytes {mem.total}')

    lines.append(f'# HELP pysoar_memory_usage_percent Memory usage percentage')
    lines.append(f'# TYPE pysoar_memory_usage_percent gauge')
    lines.append(f'pysoar_memory_usage_percent {mem.percent}')

    lines.append(f'# HELP pysoar_disk_usage_percent Disk usage percentage')
    lines.append(f'# TYPE pysoar_disk_usage_percent gauge')
    lines.append(f'pysoar_disk_usage_percent {disk.percent}')

    lines.append(f'# HELP pysoar_disk_free_bytes Free disk space in bytes')
    lines.append(f'# TYPE pysoar_disk_free_bytes gauge')
    lines.append(f'pysoar_disk_free_bytes {disk.free}')

    # --- Uptime ---
    uptime = time.time() - _start_time
    lines.append(f'# HELP pysoar_uptime_seconds Application uptime in seconds')
    lines.append(f'# TYPE pysoar_uptime_seconds gauge')
    lines.append(f'pysoar_uptime_seconds {uptime:.0f}')

    # --- Database Metrics ---
    try:
        from src.core.database import engine
        pool = engine.pool
        if hasattr(pool, 'size'):
            lines.append(f'# HELP pysoar_db_pool_size Database connection pool size')
            lines.append(f'# TYPE pysoar_db_pool_size gauge')
            lines.append(f'pysoar_db_pool_size {pool.size()}')
        if hasattr(pool, 'checkedin'):
            lines.append(f'# HELP pysoar_db_pool_checkedin Idle database connections')
            lines.append(f'# TYPE pysoar_db_pool_checkedin gauge')
            lines.append(f'pysoar_db_pool_checkedin {pool.checkedin()}')
        if hasattr(pool, 'checkedout'):
            lines.append(f'# HELP pysoar_db_pool_checkedout Active database connections')
            lines.append(f'# TYPE pysoar_db_pool_checkedout gauge')
            lines.append(f'pysoar_db_pool_checkedout {pool.checkedout()}')
    except Exception:
        pass

    # --- Application Metrics (from DB) ---
    try:
        async with async_session_factory() as db:
            from src.models.alert import Alert
            from src.models.incident import Incident

            # Alert counts by severity
            alert_result = await db.execute(
                select(Alert.severity, func.count(Alert.id)).group_by(Alert.severity)
            )
            lines.append(f'# HELP pysoar_alerts_total Total alerts by severity')
            lines.append(f'# TYPE pysoar_alerts_total gauge')
            for sev, count in alert_result.all():
                lines.append(f'pysoar_alerts_total{{severity="{sev or "unknown"}"}} {count}')

            # Alert counts by status
            status_result = await db.execute(
                select(Alert.status, func.count(Alert.id)).group_by(Alert.status)
            )
            lines.append(f'# HELP pysoar_alerts_by_status Alerts by status')
            lines.append(f'# TYPE pysoar_alerts_by_status gauge')
            for status, count in status_result.all():
                lines.append(f'pysoar_alerts_by_status{{status="{status or "unknown"}"}} {count}')

            # Incident counts
            incident_result = await db.execute(
                select(Incident.status, func.count(Incident.id)).group_by(Incident.status)
            )
            lines.append(f'# HELP pysoar_incidents_total Incidents by status')
            lines.append(f'# TYPE pysoar_incidents_total gauge')
            for status, count in incident_result.all():
                lines.append(f'pysoar_incidents_total{{status="{status or "unknown"}"}} {count}')

            # SIEM log count
            from src.siem.models import LogEntry, DetectionRule
            log_count = (await db.execute(select(func.count(LogEntry.id)))).scalar() or 0
            lines.append(f'# HELP pysoar_siem_logs_total Total SIEM log entries')
            lines.append(f'# TYPE pysoar_siem_logs_total gauge')
            lines.append(f'pysoar_siem_logs_total {log_count}')

            # Detection rule matches
            rule_matches = (await db.execute(select(func.sum(DetectionRule.match_count)))).scalar() or 0
            lines.append(f'# HELP pysoar_siem_rule_matches_total Total detection rule matches')
            lines.append(f'# TYPE pysoar_siem_rule_matches_total gauge')
            lines.append(f'pysoar_siem_rule_matches_total {rule_matches}')

            # Active rules
            active_rules = (await db.execute(
                select(func.count(DetectionRule.id)).where(DetectionRule.enabled == True)
            )).scalar() or 0
            lines.append(f'# HELP pysoar_siem_active_rules Active detection rules')
            lines.append(f'# TYPE pysoar_siem_active_rules gauge')
            lines.append(f'pysoar_siem_active_rules {active_rules}')

    except Exception as e:
        lines.append(f'# Error fetching app metrics: {e}')

    # --- SIEM Pipeline Metrics ---
    try:
        exporter = PrometheusExporter()
        siem_text = exporter.export_metrics()
        if siem_text:
            lines.append("")
            lines.append("# SIEM Pipeline Metrics")
            lines.append(siem_text)
    except Exception:
        pass

    # --- Redis Metrics ---
    try:
        from redis import asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        info = await r.info("memory")
        lines.append(f'# HELP pysoar_redis_memory_bytes Redis memory usage')
        lines.append(f'# TYPE pysoar_redis_memory_bytes gauge')
        lines.append(f'pysoar_redis_memory_bytes {info.get("used_memory", 0)}')

        clients = await r.info("clients")
        lines.append(f'# HELP pysoar_redis_connected_clients Redis connected clients')
        lines.append(f'# TYPE pysoar_redis_connected_clients gauge')
        lines.append(f'pysoar_redis_connected_clients {clients.get("connected_clients", 0)}')
        await r.aclose()
    except Exception:
        pass

    content = "\n".join(lines) + "\n"
    return Response(content=content, media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/health/live")
async def liveness_probe():
    """Kubernetes liveness probe — is the process alive?"""
    return {"status": "alive"}


@router.get("/health/ready")
async def readiness_probe():
    """Kubernetes readiness probe — can it accept traffic?"""
    from src.core.database import health_check as db_health
    db_ok = await db_health()

    try:
        from redis import asyncio as aioredis
        r = aioredis.from_url(settings.redis_url)
        await r.ping()
        redis_ok = True
        await r.aclose()
    except Exception:
        redis_ok = False

    ready = db_ok and redis_ok
    return {
        "status": "ready" if ready else "not_ready",
        "database": "ok" if db_ok else "unavailable",
        "redis": "ok" if redis_ok else "unavailable",
    }
