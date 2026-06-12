"""Enrichment transparency — no more silent empty results.

Audit gap #15: with no API keys configured, enrichment returned
``sources: []`` and the UI showed nothing, indistinguishable from "the
indicator is clean". Now every applicable provider that was NOT queried
appears in ``skipped`` with the reason (no key / not implemented), so an
analyst can tell "no data because nothing checked" from "checked and
clean".
"""

from unittest.mock import patch

import pytest

from src.intel.models import ThreatIndicator


@pytest.fixture
async def ip_indicator(db_session):
    ioc = ThreatIndicator(
        value="198.51.100.77",
        indicator_type="ipv4",
        severity="medium",
        is_active=True,
        is_whitelisted=False,
        source="test",
        confidence=50,
    )
    db_session.add(ioc)
    await db_session.commit()
    await db_session.refresh(ioc)
    return ioc


@pytest.mark.asyncio
async def test_missing_keys_reported_as_skipped(db_session, ip_indicator):
    from src.intel.enrichment import IndicatorEnricher

    enricher = IndicatorEnricher()
    # Test env has no provider keys configured.
    enricher.vt_available = False
    enricher.abuseipdb_available = False
    enricher.shodan_available = False
    enricher.greynoise_available = False

    result = await enricher.enrich_indicator(ip_indicator.id)

    assert result["sources"] == []
    skipped = {s["provider"]: s["reason"] for s in result["skipped"]}
    assert "virustotal" in skipped and "no API key" in skipped["virustotal"]
    assert "abuseipdb" in skipped and "no API key" in skipped["abuseipdb"]


@pytest.mark.asyncio
async def test_unimplemented_provider_with_key_says_so(db_session, ip_indicator):
    from src.intel.enrichment import IndicatorEnricher

    enricher = IndicatorEnricher()
    enricher.vt_available = False
    enricher.abuseipdb_available = False
    # Key present but PySOAR has no query code for these providers —
    # the analyst must not be left wondering why nothing happens.
    enricher.shodan_available = True
    enricher.greynoise_available = True

    result = await enricher.enrich_indicator(ip_indicator.id)

    skipped = {s["provider"]: s["reason"] for s in result["skipped"]}
    assert "not implemented" in skipped.get("shodan", "")
    assert "not implemented" in skipped.get("greynoise", "")


@pytest.mark.asyncio
async def test_provider_query_failure_reported(db_session, ip_indicator):
    from src.intel.enrichment import IndicatorEnricher

    enricher = IndicatorEnricher()
    enricher.vt_available = True
    enricher.abuseipdb_available = False
    enricher.shodan_available = False
    enricher.greynoise_available = False

    import httpx

    class BoomClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, *a, **k):
            raise httpx.ConnectTimeout("boom")

    with patch("httpx.AsyncClient", BoomClient):
        result = await enricher.enrich_indicator(ip_indicator.id)

    skipped = {s["provider"]: s["reason"] for s in result["skipped"]}
    assert "virustotal" in skipped and "failed" in skipped["virustotal"]
