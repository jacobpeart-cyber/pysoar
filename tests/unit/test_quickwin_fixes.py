"""Quick-win fixes from the 2026-06-11 claim-vs-implementation audit.

Covers:
- on_stig_finding entering the automation pipeline (it created the alert
  but skipped on_alert_created, so STIG findings never auto-escalated)
- /metrics being internal-only (Prometheus scrapes it directly inside the
  docker network; the public proxy path must not expose platform counts)
- refresh_ioc_enrichments actually re-enriching stale indicators instead
  of returning {"refreshed": 0} forever
- removal of the dead stub tasks that reported success while doing nothing
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from src.intel.models import ThreatIndicator


# ---------------------------------------------------------------------------
# STIG findings enter the automation pipeline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_on_stig_finding_enters_automation_pipeline(db_session):
    from src.services.automation import AutomationService

    service = AutomationService(db_session)
    with patch.object(service, "on_alert_created", new=AsyncMock()) as pipeline:
        alert = await service.on_stig_finding(
            benchmark="RHEL-9-STIG",
            finding_title="SSH root login permitted",
            severity="high",
        )

    assert alert is not None
    pipeline.assert_awaited_once()
    assert pipeline.await_args.args[0] is alert


# ---------------------------------------------------------------------------
# /metrics is internal-only
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_metrics_blocked_through_public_proxy(client):
    # Both nginx proxies always set X-Forwarded-For; its presence means
    # the request came from the public side.
    resp = await client.get(
        "/api/v1/metrics", headers={"X-Forwarded-For": "203.0.113.50"}
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_metrics_allowed_for_direct_internal_scrape(client):
    resp = await client.get("/api/v1/metrics")
    assert resp.status_code == 200
    assert "pysoar_uptime_seconds" in resp.text


# ---------------------------------------------------------------------------
# refresh_ioc_enrichments targets stale active indicators
# ---------------------------------------------------------------------------

def _indicator(value, *, is_active=True, last_seen=None, whitelisted=False):
    return ThreatIndicator(
        value=value,
        indicator_type="ipv4",
        severity="medium",
        is_active=is_active,
        is_whitelisted=whitelisted,
        source="test",
        confidence=50,
        last_seen=last_seen,
    )


@pytest.mark.asyncio
async def test_refresh_targets_only_stale_active_indicators(db_session):
    from src.workers.tasks import _refresh_stale_enrichments

    now = datetime.now(timezone.utc)
    stale = _indicator("198.51.100.1", last_seen=now - timedelta(days=30))
    never_enriched = _indicator("198.51.100.2", last_seen=None)
    fresh = _indicator("198.51.100.3", last_seen=now - timedelta(hours=1))
    inactive = _indicator("198.51.100.4", is_active=False, last_seen=None)
    whitelisted = _indicator("198.51.100.5", whitelisted=True, last_seen=None)
    db_session.add_all([stale, never_enriched, fresh, inactive, whitelisted])
    await db_session.commit()

    enriched_ids = []

    async def fake_enrich(self, indicator_id):
        enriched_ids.append(indicator_id)
        return {"indicator_id": indicator_id, "sources": []}

    with patch(
        "src.intel.enrichment.IndicatorEnricher.enrich_indicator", new=fake_enrich
    ):
        result = await _refresh_stale_enrichments(staleness_days=7, batch_limit=50)

    assert result["refreshed"] == 2
    assert set(enriched_ids) == {stale.id, never_enriched.id}


@pytest.mark.asyncio
async def test_refresh_respects_batch_limit(db_session):
    from src.workers.tasks import _refresh_stale_enrichments

    db_session.add_all([_indicator(f"203.0.113.{i}") for i in range(1, 6)])
    await db_session.commit()

    calls = []

    async def fake_enrich(self, indicator_id):
        calls.append(indicator_id)
        return {"indicator_id": indicator_id, "sources": []}

    with patch(
        "src.intel.enrichment.IndicatorEnricher.enrich_indicator", new=fake_enrich
    ):
        result = await _refresh_stale_enrichments(staleness_days=7, batch_limit=3)

    assert result["refreshed"] == 3
    assert len(calls) == 3


# ---------------------------------------------------------------------------
# Dead stub tasks are gone, not lying
# ---------------------------------------------------------------------------

def test_stub_tasks_are_removed():
    import src.workers.tasks as wt

    for stub in ("process_alert_task", "ingest_alerts_from_source", "generate_report"):
        assert not hasattr(wt, stub), (
            f"{stub} still exists — it reported success while doing nothing; "
            "implement it for real or keep it deleted"
        )
