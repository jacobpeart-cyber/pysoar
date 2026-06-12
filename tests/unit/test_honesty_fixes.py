"""Round-2 honesty fixes from the 2026-06-11 audit.

- NetworkActionExecutor previously logged an activity row and returned
  success while configuring nothing. It now registers the target as an
  active IOC (real detective control) and labels the result
  ``mode: detection_only`` instead of implying enforcement happened.
- The data-lake engine's fabricating dead code (hardcoded 125M-event
  metrics, fake Mountain View geo enrichment) is deleted; these guards
  keep it from coming back.
"""

from unittest.mock import patch

import pytest
from sqlalchemy import select

from src.intel.models import ThreatIndicator


@pytest.mark.asyncio
async def test_network_action_is_honest_and_creates_ioc(db_session):
    from src.remediation.engine import NetworkActionExecutor

    executor = NetworkActionExecutor(db_session)
    result = await executor.execute(
        "203.0.113.66",
        {"action": "sinkhole"},
        {"execution_id": "exec-1"},
    )

    assert result["success"] is True
    assert result["mode"] == "detection_only"
    assert "no network enforcement" in result["detail"].lower()

    ioc = (
        await db_session.execute(
            select(ThreatIndicator).where(ThreatIndicator.value == "203.0.113.66")
        )
    ).scalar_one()
    assert ioc.is_active is True
    assert ioc.indicator_type == "ipv4"
    assert "detection_only" in (ioc.tags or [])


@pytest.mark.asyncio
async def test_network_action_types_urls_and_domains(db_session):
    from src.remediation.engine import NetworkActionExecutor

    executor = NetworkActionExecutor(db_session)
    await executor.execute("https://evil.example/c2", {"action": "block_url"}, {})
    await executor.execute("evil.example", {"action": "dns_sinkhole"}, {})

    rows = (
        await db_session.execute(
            select(ThreatIndicator.value, ThreatIndicator.indicator_type).where(
                ThreatIndicator.source == "remediation_engine"
            )
        )
    ).all()
    types = {value: itype for value, itype in rows}
    assert types["https://evil.example/c2"] == "url"
    assert types["evil.example"] == "domain"


def test_darkweb_fabricators_are_gone():
    import src.darkweb.engine as dwe

    fabricators = [
        f"{klass.__name__}.{name}"
        for klass in vars(dwe).values()
        if isinstance(klass, type)
        for name in ("enrich_findings", "_map_campaign", "_get_historical_context")
        if name in vars(klass)
    ]
    assert not fabricators, (
        f"fabricating dark-web enrichment is back: {fabricators} — it "
        "returned canned campaign/history data with zero callers; "
        "reimplement against ThreatActor/ThreatCampaign rows instead"
    )


def test_data_lake_fabricators_are_gone():
    import src.data_lake.engine as dle

    fabricators = [
        f"{klass.__name__}.{name}"
        for klass in vars(dle).values()
        if isinstance(klass, type)
        for name in (
            "enrich_event",
            "calculate_ingestion_metrics",
            "generate_pipeline_metrics",
        )
        if name in vars(klass)
    ]
    assert not fabricators, (
        f"fabricating data-lake methods are back: {fabricators} — they "
        "returned hardcoded metrics/geo and must stay deleted or be "
        "reimplemented against real DataPartition data"
    )
