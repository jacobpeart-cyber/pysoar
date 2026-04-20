"""Real cloud log pollers for SIEM ingestion.

Replaces the stub ``CloudCollector._poll_aws/_poll_azure/_poll_gcp``
methods (which just called ``logger.debug("Polling …")`` and returned
nothing) with actual SDK calls into:

* AWS CloudTrail (``boto3.client("cloudtrail").lookup_events``)
* Azure Activity Log (``azure-mgmt-monitor`` ``activity_logs.list``)
* GCP Cloud Logging (``google.cloud.logging.Client.list_entries``)

Each poller dispatches every event through the existing SIEM pipeline
``process_log`` so detection rules, correlations, and alert generation
fire on cloud events the same way they do on syslog/agent/audit
ingestion.

Credentials live in the platform's existing integrations table —
operators install an ``aws_cloudtrail`` / ``azure_activity_log`` /
``gcp_cloud_logging`` integration through the Integrations page,
which encrypts the keys at rest. The poller reads them back, decrypts,
and uses them to authenticate.

Each poller is idempotent and stateful: it remembers the last
successful poll timestamp on the integration row's
``connection_config["last_poll_at"]`` so subsequent polls only fetch
incremental events. First poll fetches the last 1 hour to bootstrap
without flooding the SIEM.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.models import InstalledIntegration

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Credential helpers
# --------------------------------------------------------------------------- #


def _decrypt_creds(integration: InstalledIntegration) -> dict[str, Any]:
    """Pull credentials out of an InstalledIntegration row.

    Tolerates both the new AES-GCM-encrypted value (set by the
    /integrations/install endpoint after the security fix) and legacy
    plaintext rows for backwards compatibility.
    """
    from src.api.v1.endpoints.integrations import _decrypt_secret_json
    return _decrypt_secret_json(integration.auth_credentials_encrypted) or {}


def _decrypt_config(integration: InstalledIntegration) -> dict[str, Any]:
    """Read non-secret config (region, log group, project_id, etc.)."""
    if not integration.config_encrypted:
        return {}
    try:
        return json.loads(integration.config_encrypted) or {}
    except (json.JSONDecodeError, TypeError):
        return {}


def _last_poll_cutoff(config: dict[str, Any], default_minutes: int = 60) -> datetime:
    """Return the start time for this poll window.

    Uses ``config["last_poll_at"]`` (ISO-8601) if present, else
    ``datetime.now(UTC) - default_minutes`` as the bootstrap window.
    """
    raw = config.get("last_poll_at")
    if raw:
        try:
            ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            # Don't fetch more than 7 days at once — protects against
            # a stale last_poll_at causing a flood.
            min_cutoff = datetime.now(timezone.utc) - timedelta(days=7)
            return max(ts, min_cutoff)
        except ValueError:
            pass
    return datetime.now(timezone.utc) - timedelta(minutes=default_minutes)


async def _persist_poll_marker(
    db: AsyncSession, integration: InstalledIntegration, when: datetime
) -> None:
    """Update last_poll_at + last_successful_action on the integration row."""
    config = _decrypt_config(integration)
    config["last_poll_at"] = when.isoformat()
    integration.config_encrypted = json.dumps(config)
    integration.last_successful_action = when
    integration.health_status = "healthy"
    integration.error_message = None
    await db.flush()


# --------------------------------------------------------------------------- #
# Per-cloud pollers
# --------------------------------------------------------------------------- #


async def poll_aws_cloudtrail(
    db: AsyncSession,
    integration: InstalledIntegration,
) -> dict[str, Any]:
    """Pull CloudTrail events with boto3 and ship into the SIEM.

    Required credential keys (saved through Integrations page):
      * ``aws_access_key_id``
      * ``aws_secret_access_key``

    Optional config keys:
      * ``region`` (default ``us-east-1``)
      * ``last_poll_at`` (auto-managed)
    """
    try:
        import boto3  # noqa: WPS433
    except ImportError:
        return {"status": "error", "reason": "boto3 not installed"}

    creds = _decrypt_creds(integration)
    config = _decrypt_config(integration)

    access_key = creds.get("aws_access_key_id") or creds.get("access_key")
    secret_key = creds.get("aws_secret_access_key") or creds.get("secret_key")
    region = config.get("region") or creds.get("region") or "us-east-1"

    if not access_key or not secret_key:
        return {"status": "error", "reason": "Missing aws_access_key_id / aws_secret_access_key"}

    cutoff = _last_poll_cutoff(config)
    now = datetime.now(timezone.utc)

    try:
        client = boto3.client(
            "cloudtrail",
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        events: list[dict] = []
        paginator = client.get_paginator("lookup_events")
        for page in paginator.paginate(
            StartTime=cutoff,
            EndTime=now,
            PaginationConfig={"MaxItems": 1000, "PageSize": 50},
        ):
            events.extend(page.get("Events", []))
    except Exception as exc:  # noqa: BLE001
        integration.health_status = "unhealthy"
        integration.error_message = str(exc)[:500]
        await db.flush()
        return {"status": "error", "reason": str(exc)}

    org_id = integration.organization_id
    ingested = await _ingest_cloud_events(
        db, events, source_type="cloud_trail",
        source_name=f"aws-cloudtrail/{region}",
        organization_id=org_id,
        event_serializer=lambda e: e,
        ip_field="SourceIPAddress",
    )

    await _persist_poll_marker(db, integration, now)
    return {
        "status": "ok",
        "events_fetched": len(events),
        "events_ingested": ingested,
        "since": cutoff.isoformat(),
        "until": now.isoformat(),
    }


async def poll_azure_activity_log(
    db: AsyncSession,
    integration: InstalledIntegration,
) -> dict[str, Any]:
    """Pull Azure Activity Logs via azure-mgmt-monitor and ship into SIEM.

    Required credentials:
      * ``tenant_id``
      * ``client_id``
      * ``client_secret``
      * ``subscription_id``
    """
    try:
        from azure.identity import ClientSecretCredential
        from azure.mgmt.monitor import MonitorManagementClient
    except ImportError:
        return {"status": "error", "reason": "azure-mgmt-monitor / azure-identity not installed"}

    creds = _decrypt_creds(integration)
    config = _decrypt_config(integration)

    tenant_id = creds.get("tenant_id")
    client_id = creds.get("client_id")
    client_secret = creds.get("client_secret")
    subscription_id = creds.get("subscription_id") or config.get("subscription_id")

    if not all([tenant_id, client_id, client_secret, subscription_id]):
        return {"status": "error", "reason": "Missing tenant_id/client_id/client_secret/subscription_id"}

    cutoff = _last_poll_cutoff(config)
    now = datetime.now(timezone.utc)

    try:
        credential = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        client = MonitorManagementClient(credential, subscription_id)

        # Activity log filter syntax — see Azure REST docs.
        filter_str = (
            f"eventTimestamp ge '{cutoff.isoformat()}' "
            f"and eventTimestamp le '{now.isoformat()}'"
        )
        events_iter = client.activity_logs.list(filter=filter_str)
        events = []
        for ev in events_iter:
            events.append({
                "event_timestamp": ev.event_timestamp.isoformat() if ev.event_timestamp else None,
                "event_name": getattr(ev.event_name, "value", None) if ev.event_name else None,
                "category": getattr(ev.category, "value", None) if ev.category else None,
                "resource_id": ev.resource_id,
                "operation_name": getattr(ev.operation_name, "value", None) if ev.operation_name else None,
                "status": getattr(ev.status, "value", None) if ev.status else None,
                "caller": ev.caller,
                "level": str(ev.level) if ev.level else None,
            })
            if len(events) >= 1000:
                break
    except Exception as exc:  # noqa: BLE001
        integration.health_status = "unhealthy"
        integration.error_message = str(exc)[:500]
        await db.flush()
        return {"status": "error", "reason": str(exc)}

    ingested = await _ingest_cloud_events(
        db, events, source_type="azure_activity",
        source_name=f"azure-activity/{subscription_id[:8]}",
        organization_id=integration.organization_id,
        event_serializer=lambda e: e,
        ip_field="caller",  # not really an IP but the actor identifier
    )

    await _persist_poll_marker(db, integration, now)
    return {
        "status": "ok",
        "events_fetched": len(events),
        "events_ingested": ingested,
        "since": cutoff.isoformat(),
        "until": now.isoformat(),
    }


async def poll_gcp_cloud_logging(
    db: AsyncSession,
    integration: InstalledIntegration,
) -> dict[str, Any]:
    """Pull GCP Cloud Logging entries and ship into SIEM.

    Required credentials:
      * ``service_account_json`` — full JSON blob from GCP IAM
    Optional config:
      * ``project_id`` (auto-detected from SA JSON if missing)
      * ``log_filter`` (Cloud Logging filter expression — defaults to
        admin/audit logs only)
    """
    try:
        from google.cloud import logging as gcp_logging
        from google.oauth2 import service_account
    except ImportError:
        return {"status": "error", "reason": "google-cloud-logging not installed"}

    creds = _decrypt_creds(integration)
    config = _decrypt_config(integration)

    sa_json = creds.get("service_account_json") or creds.get("credentials_json")
    if not sa_json:
        return {"status": "error", "reason": "Missing service_account_json"}
    if isinstance(sa_json, str):
        try:
            sa_dict = json.loads(sa_json)
        except json.JSONDecodeError:
            return {"status": "error", "reason": "service_account_json is not valid JSON"}
    elif isinstance(sa_json, dict):
        sa_dict = sa_json
    else:
        return {"status": "error", "reason": "service_account_json must be JSON string or dict"}

    project_id = config.get("project_id") or sa_dict.get("project_id")
    if not project_id:
        return {"status": "error", "reason": "Missing project_id"}

    cutoff = _last_poll_cutoff(config)
    now = datetime.now(timezone.utc)
    log_filter_extra = config.get("log_filter") or 'log_id("cloudaudit.googleapis.com/activity")'

    try:
        credentials = service_account.Credentials.from_service_account_info(sa_dict)
        client = gcp_logging.Client(project=project_id, credentials=credentials)
        full_filter = (
            f'timestamp >= "{cutoff.isoformat()}" AND '
            f'timestamp <= "{now.isoformat()}" AND '
            f'{log_filter_extra}'
        )
        events = []
        for entry in client.list_entries(filter_=full_filter, max_results=1000):
            try:
                payload = entry.payload
                if hasattr(payload, "to_dict"):
                    payload = payload.to_dict()
                events.append({
                    "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                    "log_name": entry.log_name,
                    "severity": entry.severity,
                    "resource": (entry.resource.to_api_repr() if entry.resource else None),
                    "payload": payload,
                })
            except Exception:  # noqa: BLE001
                continue
    except Exception as exc:  # noqa: BLE001
        integration.health_status = "unhealthy"
        integration.error_message = str(exc)[:500]
        await db.flush()
        return {"status": "error", "reason": str(exc)}

    ingested = await _ingest_cloud_events(
        db, events, source_type="gcp_audit",
        source_name=f"gcp/{project_id}",
        organization_id=integration.organization_id,
        event_serializer=lambda e: e,
        ip_field=None,
    )

    await _persist_poll_marker(db, integration, now)
    return {
        "status": "ok",
        "events_fetched": len(events),
        "events_ingested": ingested,
        "since": cutoff.isoformat(),
        "until": now.isoformat(),
    }


# --------------------------------------------------------------------------- #
# Shared ingest helper
# --------------------------------------------------------------------------- #


async def _ingest_cloud_events(
    db: AsyncSession,
    events: list[Any],
    *,
    source_type: str,
    source_name: str,
    organization_id: Optional[str],
    event_serializer,
    ip_field: Optional[str],
) -> int:
    """Dispatch each fetched event through the SIEM pipeline."""
    if not events:
        return 0
    from src.siem.pipeline import process_log

    ingested = 0
    for ev in events:
        try:
            payload = event_serializer(ev)
            if isinstance(payload, dict):
                src_ip = payload.get(ip_field) if ip_field else None
                raw = json.dumps(payload, default=str)
            else:
                src_ip = None
                raw = str(payload)
            await process_log(
                raw_log=raw,
                source_type=source_type,
                source_name=source_name,
                source_ip=src_ip or "0.0.0.0",
                db=db,
                organization_id=organization_id,
            )
            ingested += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning("cloud event ingest failed: %s", exc)
    if ingested:
        await db.commit()
    return ingested


# --------------------------------------------------------------------------- #
# Top-level "poll all enabled cloud integrations" entrypoint
# --------------------------------------------------------------------------- #


_CLOUD_CONNECTOR_DISPATCH = {
    "aws_cloudtrail": poll_aws_cloudtrail,
    "azure_activity_log": poll_azure_activity_log,
    "azure_activity": poll_azure_activity_log,
    "gcp_cloud_logging": poll_gcp_cloud_logging,
    "gcp_logging": poll_gcp_cloud_logging,
}


async def poll_all_cloud_integrations(db: AsyncSession) -> list[dict[str, Any]]:
    """Iterate every enabled cloud integration and run its poller.

    Returns a list of per-integration result dicts so the caller (a
    Celery beat task or the manual /siem/cloud/poll-all endpoint) can
    log the outcomes.
    """
    res = await db.execute(
        select(InstalledIntegration).where(
            InstalledIntegration.connector_id.in_(list(_CLOUD_CONNECTOR_DISPATCH.keys())),
            InstalledIntegration.status == "active",
        )
    )
    results: list[dict[str, Any]] = []
    for integration in res.scalars().all():
        poller = _CLOUD_CONNECTOR_DISPATCH.get(integration.connector_id)
        if poller is None:
            continue
        try:
            outcome = await poller(db, integration)
            outcome["integration_id"] = integration.id
            outcome["connector_id"] = integration.connector_id
            results.append(outcome)
            logger.info(
                "Cloud poll complete: %s — %s",
                integration.connector_id,
                outcome.get("status"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("Cloud poll failed for %s: %s", integration.id, exc, exc_info=True)
            results.append({
                "integration_id": integration.id,
                "connector_id": integration.connector_id,
                "status": "error",
                "reason": str(exc),
            })
    return results
