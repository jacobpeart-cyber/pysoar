"""The exposure (CTEM) background tasks must do real work.

Before this fix, run_asset_discovery, generate_exposure_report, and
detect_attack_surface_changes were stubs that returned empty/zero
results with "In production, would ..." comments. These tests exercise
the real logic via the module-level ``_*_async`` helpers the Celery
entrypoints wrap.
"""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from src.exposure.models import (
    ExposureAsset,
    ExposureVulnerability,
    AssetVulnerability,
    RemediationTicket,
    AttackSurface,
)
from src.siem.models import LogEntry
from src.exposure.tasks import (
    _run_asset_discovery_async,
    _generate_exposure_report_async,
    _detect_attack_surface_changes_async,
)

ORG = "exposure-org-1"
OTHER = "exposure-org-2"


def _log(ip, org=ORG, hostname=None, age_hours=1):
    ts = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).isoformat()
    return LogEntry(
        timestamp=ts,
        received_at=ts,
        source_type="syslog",
        source_name="fw-01",
        source_ip=ip,
        source_address=ip,
        hostname=hostname,
        log_type="network",
        raw_log=f"traffic from {ip}",
        organization_id=org,
    )


# --------------------------------------------------------------------------
# Asset discovery
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_siem_discovery_creates_only_unknown_assets(db_session):
    # One asset already known; two fresh IPs in logs.
    db_session.add(ExposureAsset(
        ip_address="10.0.0.1", asset_type="host", organization_id=ORG,
    ))
    db_session.add_all([
        _log("10.0.0.1", hostname="known"),   # already known → skip
        _log("10.0.0.2", hostname="web-1"),   # new
        _log("10.0.0.3", hostname="db-1"),    # new
        _log("10.0.0.2", hostname="web-1"),   # duplicate of new → once
    ])
    await db_session.commit()

    result = await _run_asset_discovery_async(ORG, "siem")
    assert result["assets_discovered"] == 2

    ips = set((await db_session.execute(
        select(ExposureAsset.ip_address).where(
            ExposureAsset.organization_id == ORG
        )
    )).scalars().all())
    assert ips == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}


@pytest.mark.asyncio
async def test_siem_discovery_ignores_logs_older_than_24h(db_session):
    db_session.add(_log("10.9.9.9", age_hours=48))  # stale
    await db_session.commit()
    result = await _run_asset_discovery_async(ORG, "siem")
    assert result["assets_discovered"] == 0


@pytest.mark.asyncio
async def test_network_discovery_reports_requires_scanner(db_session):
    result = await _run_asset_discovery_async(ORG, "network")
    assert result["status"] == "requires_scanner"
    assert result["assets_discovered"] == 0
    assert "scanner" in result["detail"].lower()


@pytest.mark.asyncio
async def test_siem_discovery_is_org_scoped(db_session):
    db_session.add(_log("172.16.0.5", org=OTHER))  # belongs to another org
    await db_session.commit()
    result = await _run_asset_discovery_async(ORG, "siem")
    assert result["assets_discovered"] == 0


# --------------------------------------------------------------------------
# Exposure report
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_report_compiles_real_aggregates(db_session):
    db_session.add_all([
        ExposureAsset(ip_address="1.1.1.1", asset_type="host",
                      is_internet_facing=True, risk_score=90.0,
                      vulnerability_count=3, organization_id=ORG),
        ExposureAsset(ip_address="1.1.1.2", asset_type="host",
                      risk_score=10.0, organization_id=ORG),
        ExposureVulnerability(title="CVE-A", severity="critical", organization_id=ORG),
        ExposureVulnerability(title="CVE-B", severity="high", organization_id=ORG),
        ExposureVulnerability(title="CVE-C", severity="high", organization_id=ORG),
        RemediationTicket(title="fix", remediation_type="patch",
                          status="open", sla_breach=True, organization_id=ORG),
    ])
    await db_session.commit()

    result = await _generate_exposure_report_async(ORG, "json")
    assert result["status"] == "generated"
    data = result["report_data"]
    assert data["assets"]["total"] == 2
    assert data["assets"]["internet_facing"] == 1
    assert data["vulnerabilities"]["by_severity"] == {"critical": 1, "high": 2}
    assert data["vulnerabilities"]["total"] == 3
    assert data["remediation"]["open_tickets"] == 1
    assert data["remediation"]["sla_breached"] == 1
    # Highest risk asset first.
    assert data["top_risky_assets"][0]["ip_address"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_report_non_json_is_data_only(db_session):
    result = await _generate_exposure_report_async(ORG, "pdf")
    assert result["status"] == "data_only"
    assert result["file_path"] is None
    assert "no pdf file" in result["detail"].lower()
    # Data is still real even though nothing was rendered.
    assert "report_data" in result


# --------------------------------------------------------------------------
# Attack surface change detection
# --------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_attack_surface_baseline_then_diff(db_session):
    db_session.add(ExposureAsset(
        ip_address="192.0.2.10", asset_type="host", is_active=True,
        organization_id=ORG,
    ))
    await db_session.commit()

    # First run establishes the baseline snapshot.
    first = await _detect_attack_surface_changes_async(ORG)
    assert first["is_baseline"] is True
    assert first["details"]["new_assets"] == ["192.0.2.10"]

    # Add a second asset, then re-run: only the delta is "new".
    db_session.add(ExposureAsset(
        ip_address="192.0.2.11", asset_type="host", is_active=True,
        organization_id=ORG,
    ))
    await db_session.commit()

    second = await _detect_attack_surface_changes_async(ORG)
    assert second["is_baseline"] is False
    assert second["details"]["new_assets"] == ["192.0.2.11"]
    assert second["details"]["removed_assets"] == []

    # Two snapshots were persisted.
    snaps = (await db_session.execute(
        select(AttackSurface).where(
            AttackSurface.organization_id == ORG,
            AttackSurface.surface_type == "snapshot",
        )
    )).scalars().all()
    assert len(snaps) == 2


@pytest.mark.asyncio
async def test_all_org_sweep_covers_multiple_orgs(db_session):
    # Two orgs each with a fresh log; the beat sweep (org=None) must
    # discover assets for both.
    db_session.add_all([
        _log("10.5.0.1", org=ORG),
        _log("10.6.0.1", org=OTHER),
    ])
    await db_session.commit()

    from src.exposure.tasks import _sweep_asset_discovery_async
    result = await _sweep_asset_discovery_async("siem")
    assert result["organizations"] >= 2
    assert result["assets_discovered"] >= 2


@pytest.mark.asyncio
async def test_exposure_beat_tasks_registered():
    # Importing the tasks registers them; the beat schedule references them.
    from src.workers.celery_app import celery_app
    registered = set(celery_app.tasks.keys())
    beat = celery_app.conf.beat_schedule
    for name in (
        "src.exposure.tasks.run_asset_discovery",
        "src.exposure.tasks.detect_attack_surface_changes",
    ):
        assert name in registered, f"{name} not registered with Celery"
        assert any(e["task"] == name for e in beat.values()), f"{name} not scheduled"


@pytest.mark.asyncio
async def test_attack_surface_detects_removed_asset(db_session):
    asset = ExposureAsset(
        ip_address="192.0.2.20", asset_type="host", is_active=True,
        organization_id=ORG,
    )
    db_session.add(asset)
    await db_session.commit()
    await _detect_attack_surface_changes_async(ORG)  # baseline

    # Deactivate the asset — it drops out of the active surface.
    asset.is_active = False
    await db_session.commit()

    result = await _detect_attack_surface_changes_async(ORG)
    assert result["details"]["removed_assets"] == ["192.0.2.20"]
    assert result["details"]["new_assets"] == []
