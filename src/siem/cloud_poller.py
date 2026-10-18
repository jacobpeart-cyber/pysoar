"""Real cloud log pollers for SIEM ingestion.

Replaces the stub ``CloudCollector._poll_aws/_poll_azure/_poll_gcp``
methods (which just called ``logger.debug("Polling …")`` and returned
nothing) with actual SDK calls into:

* AWS CloudTrail (``boto3.client("cloudtrail").lookup_events``)
* Azure Activity Log (``azure-mgmt-monitor`` ``activity_logs.list``)
* GCP Cloud Logging (``google.cloud.logging.Client.list_entries``)
* Splunk (one-shot search through ``SplunkConnector``), Elasticsearch
  (``_search`` through ``ElasticConnector``) and QRadar (``/api/siem/offenses``)

The Splunk, Elastic and QRadar requests go through ``PinnedTransport``
(src/integrations/netguard.py) like every connector: the host is resolved
once, internal addresses are refused (a private one only opens when the
operator lists its network in ``OUTBOUND_PRIVATE_ALLOWLIST``), TLS
verification is always on and redirects are not followed. A stored
``verify_tls`` / ``ca_bundle`` from an earlier release is ignored and the
poll says so in ``error_message``.

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

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.integrations.connectors.base import (
    ConnectorHTTPError,
    REFUSED_INTERNAL,
    sanitize_message,
)
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


TLS_OPT_OUT_IGNORED = "verify_tls/ca_bundle are no longer honoured"


def _tls_note(config: dict[str, Any]) -> Optional[str]:
    """The note recorded when a stored config still carries the removed TLS opt-out."""
    if "verify_tls" in config or "ca_bundle" in config:
        return TLS_OPT_OUT_IGNORED
    return None


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
    db: AsyncSession, integration: InstalledIntegration, when: datetime, note: Optional[str] = None,
) -> None:
    """Update last_poll_at + last_successful_action on the integration row."""
    config = _decrypt_config(integration)
    config["last_poll_at"] = when.isoformat()
    integration.config_encrypted = json.dumps(config)
    integration.last_successful_action = when
    integration.health_status = "healthy"
    integration.error_message = note
    await db.flush()


async def _record_poll_failure(
    db: AsyncSession, integration: InstalledIntegration, reason: str, note: Optional[str] = None,
) -> dict[str, Any]:
    """Mark the integration unhealthy with a sanitised reason; nothing is ingested."""
    text = f"{reason}; {note}" if note else reason
    integration.health_status = "unhealthy"
    integration.error_message = text[:500]
    await db.flush()
    return {"status": "error", "reason": text}


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


def _connector_failure(connector: Any, exc: Exception) -> str:
    """A sanitised poll failure reason from a connector call (never a credential)."""
    if isinstance(exc, ConnectorHTTPError):
        if exc.status_code in (401, 403):
            return f"authentication rejected (HTTP {exc.status_code})"
        return connector.sanitize(exc.message)
    message = getattr(exc, "message", None) or str(exc)
    return connector.sanitize(message)


def _site_fields(creds: dict[str, Any], config: dict[str, Any], keys: tuple[str, ...]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Config and credentials for a connector class from a stored row.

    Rows installed before the connector classes kept ``base_url`` among the
    credentials; it is read from either place.
    """
    conn_config = {k: config[k] for k in keys if config.get(k) not in (None, "")}
    if not conn_config.get("base_url") and creds.get("base_url"):
        conn_config["base_url"] = creds["base_url"]
    return conn_config, dict(creds)


async def _poll_with_connector(
    db: AsyncSession,
    integration: InstalledIntegration,
    connector_cls: Any,
    config_keys: tuple[str, ...],
    *,
    default_minutes: int,
    source_type: str,
    source_name: Any,
    ip_field: Optional[str],
) -> dict[str, Any]:
    """Shared Splunk / Elastic poll: the connector class makes the (pinned) calls."""
    creds = _decrypt_creds(integration)
    config = _decrypt_config(integration)
    note = _tls_note(config)
    conn_config, conn_creds = _site_fields(creds, config, config_keys)
    missing = connector_cls.missing_fields(conn_config, conn_creds)
    invalid = connector_cls.invalid_fields(conn_config, conn_creds)
    if missing or invalid:
        problems = ([f"missing {', '.join(missing)}"] if missing else []) + ([f"invalid {', '.join(invalid)}"] if invalid else [])
        return await _record_poll_failure(db, integration, "; ".join(problems), note)
    connector = connector_cls(config=conn_config, credentials=conn_creds)
    cutoff = _last_poll_cutoff(config, default_minutes=default_minutes)
    now = datetime.now(timezone.utc)
    try:
        events = await connector.fetch_events(cutoff, now)
    except Exception as exc:  # noqa: BLE001 (a poll records the failure, never raises)
        return await _record_poll_failure(db, integration, _connector_failure(connector, exc), note)
    ingested = await _ingest_cloud_events(
        db, events, source_type=source_type,
        source_name=source_name(connector) if callable(source_name) else source_name,
        organization_id=integration.organization_id, event_serializer=lambda e: e, ip_field=ip_field,
    )
    await _persist_poll_marker(db, integration, now, note)
    out: dict[str, Any] = {
        "status": "ok", "events_fetched": len(events), "events_ingested": ingested,
        "since": cutoff.isoformat(), "until": now.isoformat(),
    }
    if note:
        out["note"] = note
    return out


async def poll_splunk(db: AsyncSession, integration: InstalledIntegration) -> dict[str, Any]:
    """Pull Splunk events with a one-shot search (``SplunkConnector.fetch_events``).

    Config: ``base_url`` (management port, https), optional ``search`` (SPL,
    default ``search index=*``; the window is passed as earliest_time /
    latest_time). Credentials: ``token`` (Bearer) or ``username`` +
    ``password``. Every request is pinned; a private Splunk address must be
    in ``OUTBOUND_PRIVATE_ALLOWLIST``.
    """
    from src.integrations.connectors.splunk import SplunkConnector

    return await _poll_with_connector(
        db, integration, SplunkConnector, ("base_url", "search"),
        default_minutes=10, source_type="splunk", source_name="splunk", ip_field="src_ip",
    )


async def poll_elastic(db: AsyncSession, integration: InstalledIntegration) -> dict[str, Any]:
    """Pull Elasticsearch documents in the poll window (``ElasticConnector.fetch_events``).

    Config: ``base_url`` (https), optional ``index`` (default ``logs-*``) and
    ``timestamp_field`` (default ``@timestamp``). Credentials: ``api_key``
    (ApiKey) or ``username`` + ``password``. Every request is pinned; a
    private cluster address must be in ``OUTBOUND_PRIVATE_ALLOWLIST``.
    """
    from src.integrations.connectors.elastic import ElasticConnector

    return await _poll_with_connector(
        db, integration, ElasticConnector, ("base_url", "index", "timestamp_field"),
        default_minutes=10, source_type="elastic",
        source_name=lambda c: f"elastic/{c.poll_index()}", ip_field="source.ip",
    )


QRADAR_API_VERSION = "12.0"
QRADAR_MAX_OFFENSES = 500


def _refusal_text(exc: httpx.ConnectError) -> Optional[str]:
    """The tenant-safe refusal reason when PinnedTransport refused the target, else None."""
    text = str(exc)
    if "outbound target refused" not in text:
        return None
    detail = text.split("outbound target refused:", 1)[-1].strip()
    if "internal address" in detail or "blocked" in detail:
        return REFUSED_INTERNAL
    return "refused: " + sanitize_message(detail)


async def poll_qradar(db: AsyncSession, integration: InstalledIntegration) -> dict[str, Any]:
    """Pull QRadar offenses that started since the last poll (GET /api/siem/offenses).

    Config: ``base_url`` (https, the console). Credentials: ``sec_token``
    (an authorized service token, sent in the ``SEC`` header). QRadar REST
    API reference, ``/siem/offenses`` (filter on ``start_time`` in epoch
    milliseconds, ``Range: items=0-499``). The request is pinned, TLS is
    verified and redirects are not followed; a private console address must
    be in ``OUTBOUND_PRIVATE_ALLOWLIST``.
    """
    from src.integrations.connectors.splunk import https_origin
    from src.integrations.netguard import PinnedTransport

    creds = _decrypt_creds(integration)
    config = _decrypt_config(integration)
    note = _tls_note(config)
    raw_base = config.get("base_url") or creds.get("base_url")
    sec_token = creds.get("sec_token") or creds.get("api_key") or creds.get("token")
    if not raw_base or not sec_token:
        return await _record_poll_failure(db, integration, "missing base_url / sec_token", note)
    try:
        base_url = https_origin(raw_base, "base_url")
    except ValueError as exc:
        return await _record_poll_failure(db, integration, str(exc), note)
    cutoff = _last_poll_cutoff(config, default_minutes=10)
    now = datetime.now(timezone.utc)
    headers = {
        "SEC": str(sec_token),
        "Version": QRADAR_API_VERSION,
        "Accept": "application/json",
        "Range": f"items=0-{QRADAR_MAX_OFFENSES - 1}",
    }
    params = {"filter": f"start_time>={int(cutoff.timestamp() * 1000)}"}
    secrets = [str(sec_token)]
    try:
        async with httpx.AsyncClient(
            timeout=30.0, transport=PinnedTransport(private_hint=True), follow_redirects=False,
        ) as client:
            r = await client.get(f"{base_url}/api/siem/offenses", params=params, headers=headers)
        if r.status_code in (401, 403):
            return await _record_poll_failure(db, integration, f"authentication rejected (HTTP {r.status_code})", note)
        if not 200 <= r.status_code < 300:
            # Includes 3xx: redirects are not followed.
            return await _record_poll_failure(db, integration, f"HTTP {r.status_code}", note)
        body = r.json()
        events = body if isinstance(body, list) else []
    except httpx.ConnectError as exc:
        reason = _refusal_text(exc) or "connection failed"
        return await _record_poll_failure(db, integration, reason, note)
    except httpx.TimeoutException:
        return await _record_poll_failure(db, integration, "timed out after 30s", note)
    except (httpx.RequestError, ValueError) as exc:
        return await _record_poll_failure(db, integration, sanitize_message(f"request failed: {type(exc).__name__}", secrets), note)
    ingested = await _ingest_cloud_events(
        db, events, source_type="qradar", source_name="qradar",
        organization_id=integration.organization_id, event_serializer=lambda e: e, ip_field="source_address_ids",
    )
    await _persist_poll_marker(db, integration, now, note)
    out: dict[str, Any] = {
        "status": "ok", "events_fetched": len(events), "events_ingested": ingested,
        "since": cutoff.isoformat(), "until": now.isoformat(),
    }
    if note:
        out["note"] = note
    return out


_CLOUD_CONNECTOR_DISPATCH = {
    "aws_cloudtrail": poll_aws_cloudtrail,
    "azure_activity_log": poll_azure_activity_log,
    "azure_activity": poll_azure_activity_log,
    "gcp_cloud_logging": poll_gcp_cloud_logging,
    "gcp_logging": poll_gcp_cloud_logging,
    # SIEM log sources — these are connectors the operator already has
    # installed (Splunk Cloud, Elastic Security, QRadar, etc.) that
    # PySOAR pulls events from so they all land in the same SIEM
    # search surface and detection rule evaluation.
    "splunk": poll_splunk,
    "elastic": poll_elastic,
    "qradar": poll_qradar,
}


async def poll_all_cloud_integrations(
    db: AsyncSession, organization_id: Optional[str] = None
) -> list[dict[str, Any]]:
    """Run the poller of every enabled cloud integration.

    ``organization_id`` limits the sweep to one organisation's
    integrations; the manual ``/siem/cloud/poll-all`` endpoint always
    passes the caller's organisation. ``None`` (every tenant) is reserved
    for the Celery beat task. Each integration's events are ingested with
    that integration's own organisation either way.

    Returns a list of per-integration result dicts so the caller can log
    the outcomes.
    """
    stmt = select(InstalledIntegration).where(
        InstalledIntegration.connector_id.in_(list(_CLOUD_CONNECTOR_DISPATCH.keys())),
        InstalledIntegration.status == "active",
    )
    if organization_id is not None:
        stmt = stmt.where(InstalledIntegration.organization_id == organization_id)
    res = await db.execute(stmt)
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
