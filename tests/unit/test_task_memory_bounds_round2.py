"""Memory bounds, round 2: the remaining Celery tasks that loaded whole tables.

Follow-up to ``test_task_memory_bounds.py`` (prod OOM post-mortem
2026-09-01). The tasks covered here each used to materialise an unbounded
``SELECT`` with ``.scalars().all()`` (usually as full ORM rows) and often
committed once at the very end:

* darkweb: ``darkweb_cross_org_sweep`` (all orgs + all monitors per org),
  ``credential_leak_check`` (every monitor of the org),
  ``threat_correlation`` (every 90-day IOC + every 90-day incident).
* stig: ``run_stig_scan`` / ``auto_remediate_findings`` (every rule of a
  benchmark) and ``scheduled_fleet_stig_sweep`` (every agent x benchmark).
* integrations: ``rate_limit_reset``, ``connector_update_check``,
  ``health_check_all_integrations``.
* supplychain: ``vulnerability_cross_reference``,
  ``vendor_certification_expiry_check``, ``typosquatting_scan`` and the
  daily ``supplychain_cross_org_sweep``.
* deception: ``reconcile_honeypot_dispatches``.
* playbooks: the every-minute ``check_scheduled_playbooks`` sweep.
* exposure: ``run_vuln_scan``, ``import_scanner_results``,
  ``calculate_risk_scores``, ``check_sla_breaches``, ``sync_kev_database``.

Each test seeds tens of thousands of synthetic rows (synthetic rows live
only here, never in the repo) with Core executemany, runs the real task
code, and asserts from the recorded statements that no read of the big
table is unbounded, that work is committed per window, and that the
result contract - including the new ``truncated`` flag - is right.
"""

import asyncio
import json
import math
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

import src.darkweb.tasks as darkweb_tasks
import src.deception.tasks as deception_tasks
import src.exposure.tasks as exposure_tasks
import src.integrations.tasks as integrations_tasks
import src.playbooks.tasks as playbook_tasks
import src.stig.tasks as stig_tasks
import src.supplychain.tasks as supplychain_tasks
from src.agents.models import AgentCommand, AgentResult, EndpointAgent
from src.core.database import async_session_factory
from src.darkweb.models import DarkWebFinding, DarkWebMonitor
from src.deception.models import Decoy
from src.exposure.models import ExposureScan
from src.integrations.models import InstalledIntegration, IntegrationConnector
from src.intel.models import ThreatIndicator
from src.models.incident import Incident
from src.models.organization import Organization
from src.models.playbook import Playbook, PlaybookExecution, PlaybookTrigger
from src.stig.models import STIGBenchmark, STIGRule
from src.supplychain.engine import SupplyChainRiskAnalyzer
from src.supplychain.models import SoftwareComponent, SupplyChainRisk, VendorAssessment
from src.tickethub.models import TicketActivity
from src.vulnmgmt.models import ScanProfile, Vulnerability, VulnerabilityInstance
from src.workers.celery_app import celery_app

# Shared recorder / seeding helpers from the first round. ``recorder`` is a
# fixture: importing it registers it for this module too.
from tests.unit.test_task_memory_bounds import (  # noqa: F401
    PEAK_LIMIT_BYTES,
    StatementRecorder,
    _bulk_insert,
    _measure,
    _RecordedStatement,
    recorder,
)

# The shared fixture is imported so pytest can inject it; referencing it here
# keeps ruff from reading every `recorder` parameter as a redefinition (F811).
_SHARED_RECORDER_FIXTURE = recorder

ORG = "org-bounds-round2"
OTHER_ORG = "org-bounds-round2-other"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _uid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _reset(rec: StatementRecorder) -> None:
    """Forget the seeding statements/commits so only the task is measured."""
    rec.statements.clear()
    rec.commits = 0


async def _seed_orgs(db: AsyncSession, *org_ids: str) -> None:
    now = _now()
    await _bulk_insert(
        db,
        Organization,
        [
            {
                "id": oid,
                "name": f"Synthetic {oid}",
                "slug": f"synthetic-{oid}",
                "created_at": now,
                "updated_at": now,
            }
            for oid in org_ids
        ],
    )


def _assert_bounded(rec: StatementRecorder, table: str, bound: int) -> None:
    reads = rec.for_table(table)
    assert reads, f"expected the task to read {table}"
    assert not rec.unbounded_for(table), rec.unbounded_for(table)
    assert rec.max_bound_for(table) <= bound, (table, rec.max_bound_for(table))


async def _count(db: AsyncSession, stmt: Any) -> int:
    return (await db.execute(stmt)).scalar_one()


# ---------------------------------------------------------------------------
# exposure: calculate_risk_scores
# ---------------------------------------------------------------------------
SEEDED_VULNS = 12_000


@pytest.mark.asyncio
async def test_calculate_risk_scores_windows_vulns_and_never_loads_instances(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_orgs(db_session, ORG)
    now = _now()
    severities = ["critical", "high", "medium", "low"]
    maturities = ["none", "poc"]
    vulns = [
        {
            "id": f"v-{i:06d}",
            "cve_id": f"CVE-2026-{i:05d}",
            "title": f"synthetic vuln {i}",
            "organization_id": ORG,
            "severity": severities[i % 4],
            "exploit_maturity": maturities[i % 2],
            "kev_listed": i % 5 == 0,
            "created_at": now,
            "updated_at": now,
        }
        for i in range(SEEDED_VULNS)
    ]
    await _bulk_insert(db_session, Vulnerability, vulns)
    await _bulk_insert(
        db_session,
        VulnerabilityInstance,
        [
            {
                "id": _uid(),
                "vulnerability_id": v["id"],
                "organization_id": ORG,
                "status": "open",
                "created_at": now,
                "updated_at": now,
            }
            for v in vulns
            for _ in range(2)
        ],
    )
    _reset(recorder)

    result, peak = await _measure(exposure_tasks._calculate_risk_scores_async(ORG))

    assert result == {"scored": 2 * SEEDED_VULNS, "truncated": False}
    assert peak < PEAK_LIMIT_BYTES
    _assert_bounded(recorder, "vulnerabilities", exposure_tasks.VULN_BATCH_SIZE)
    # Instances are only ever UPDATEd in bulk, never SELECTed.
    assert recorder.for_table("vulnerability_instances") == []
    assert recorder.commits >= math.ceil(SEEDED_VULNS / exposure_tasks.VULN_BATCH_SIZE)

    # v-000000: critical (100) + none (0) + KEV (15)
    db_session.expire_all()
    scores = (
        await db_session.execute(
            select(VulnerabilityInstance.risk_score).where(
                VulnerabilityInstance.vulnerability_id == "v-000000",
            ),
        )
    ).scalars().all()
    assert [float(s) for s in scores] == [115.0, 115.0]
    # v-000001: high (75) + poc (5)
    s1 = (
        await db_session.execute(
            select(VulnerabilityInstance.risk_score)
            .where(VulnerabilityInstance.vulnerability_id == "v-000001")
            .limit(1),
        )
    ).scalar_one()
    assert float(s1) == 80.0

    # Per-run cap: compared against the window actually requested.
    monkeypatch.setattr(exposure_tasks, "MAX_RISK_SCORE_VULNS_PER_RUN", 2_500)
    capped = await exposure_tasks._calculate_risk_scores_async(ORG)
    assert capped == {"scored": 5_000, "truncated": True}


# ---------------------------------------------------------------------------
# exposure: check_sla_breaches
# ---------------------------------------------------------------------------
SEEDED_INSTANCES = 20_000


@pytest.mark.asyncio
async def test_check_sla_breaches_is_windowed_and_bulk_updates(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_orgs(db_session, ORG)
    now = _now()
    vid = _uid()
    await _bulk_insert(
        db_session,
        Vulnerability,
        [{"id": vid, "cve_id": "CVE-2026-0001", "title": "t", "organization_id": ORG,
          "created_at": now, "updated_at": now}],
    )
    past = (now - timedelta(days=3)).isoformat()
    future = (now + timedelta(days=3)).isoformat()
    rows: list[dict[str, Any]] = []
    for i in range(SEEDED_INSTANCES):
        kind = i % 4
        rows.append(
            {
                "id": _uid(),
                "vulnerability_id": vid,
                "organization_id": ORG,
                "status": "closed" if kind == 0 else "open",
                "remediation_deadline": future if kind == 2 else past,
                "sla_status": "breached" if kind == 3 else "within_sla",
                "created_at": now,
                "updated_at": now,
            },
        )
    await _bulk_insert(db_session, VulnerabilityInstance, rows)
    expected = SEEDED_INSTANCES // 4  # kind == 1
    _reset(recorder)

    result = await exposure_tasks._check_sla_breaches_async(ORG)

    assert result["breached_count"] == expected
    assert len(result["breached_instances"]) == 100
    assert result["truncated"] is False
    _assert_bounded(recorder, "vulnerability_instances", exposure_tasks.VULN_BATCH_SIZE)
    candidates = SEEDED_INSTANCES // 2  # kinds 1 and 2 pass the SQL filter
    assert recorder.commits >= math.ceil(candidates / exposure_tasks.VULN_BATCH_SIZE)

    db_session.expire_all()
    assert await _count(
        db_session,
        select(func.count(TicketActivity.id)).where(TicketActivity.activity_type == "sla_breach"),
    ) == expected
    assert await _count(
        db_session,
        select(func.count(VulnerabilityInstance.id)).where(
            VulnerabilityInstance.sla_status == "breached",
        ),
    ) == 2 * expected

    # Idempotent; and the cap reports truncation even when nothing breached.
    monkeypatch.setattr(exposure_tasks, "MAX_SLA_INSTANCES_PER_RUN", 1_500)
    again = await exposure_tasks._check_sla_breaches_async(ORG)
    assert again == {"breached_count": 0, "breached_instances": [], "truncated": True}


# ---------------------------------------------------------------------------
# exposure: run_vuln_scan + import_scanner_results
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_run_vuln_scan_and_import_scanner_results_are_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_orgs(db_session, ORG)
    now = _now()
    past = (now - timedelta(hours=1)).isoformat()
    future = (now + timedelta(days=2)).isoformat()
    profiles = [
        {
            "id": _uid(),
            "name": f"profile {i}",
            "scanner_type": "nessus",
            "organization_id": ORG,
            "enabled": i < 20_000,
            "next_scan_date": None if i % 4 == 0 else (past if i % 2 == 0 else future),
            "created_at": now,
            "updated_at": now,
        }
        for i in range(21_000)
    ]
    await _bulk_insert(db_session, ScanProfile, profiles)
    scans = [
        {
            "id": _uid(),
            "scan_type": "vulnerability",
            "scan_name": f"scan {i}",
            "organization_id": ORG,
            "status": "pending" if i < 15_000 else "completed",
            "created_at": now,
            "updated_at": now,
        }
        for i in range(17_000)
    ]
    await _bulk_insert(db_session, ExposureScan, scans)
    _reset(recorder)

    vs = await exposure_tasks._run_vuln_scan_async(ORG)
    assert vs == {"processed": 10_000, "truncated": False}
    _assert_bounded(recorder, "scan_profiles", exposure_tasks.VULN_BATCH_SIZE)
    assert recorder.commits >= 20

    # Second run: everything was pushed a day out.
    assert await exposure_tasks._run_vuln_scan_async(ORG) == {"processed": 0, "truncated": False}
    monkeypatch.setattr(exposure_tasks, "MAX_SCAN_PROFILES_PER_RUN", 3_000)
    assert (await exposure_tasks._run_vuln_scan_async(ORG))["truncated"] is True

    _reset(recorder)
    imp = await exposure_tasks._import_scanner_results_async(ORG)
    assert imp == {"processed": 15_000, "errors": 0, "truncated": False}
    _assert_bounded(recorder, "exposure_scans", exposure_tasks.VULN_BATCH_SIZE)
    assert recorder.commits >= 15
    db_session.expire_all()
    assert await _count(
        db_session,
        select(func.count(ExposureScan.id)).where(ExposureScan.status == "pending"),
    ) == 0


# ---------------------------------------------------------------------------
# exposure: sync_kev_database
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_sync_kev_database_uses_windowed_in_lookups(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = _now()
    unrelated = [
        {
            "id": _uid(),
            "indicator_type": "ipv4",
            "value": f"198.51.{i // 256}.{i % 256}",
            "is_active": True,
            "is_whitelisted": False,
            "context": {},
            "created_at": now,
            "updated_at": now,
        }
        for i in range(20_000)
    ]
    existing = [
        {
            "id": _uid(),
            "indicator_type": "cve",
            "value": f"CVE-2026-{i:05d}",
            "is_active": False,
            "is_whitelisted": False,
            "context": {"note": "seeded"},
            "created_at": now,
            "updated_at": now,
        }
        for i in range(500)
    ]
    await _bulk_insert(db_session, ThreatIndicator, unrelated + existing)

    entries: list[dict[str, Any]] = [
        {"cveID": f"CVE-2026-{i:05d}", "vendorProject": "Synthetic", "shortDescription": f"d{i}"}
        for i in range(2_500)
    ]
    entries.append({"cveID": "CVE-2026-00000", "vendorProject": "Synthetic"})  # duplicate
    entries.append({"vendorProject": "no id"})

    async def fake_fetch() -> dict[str, Any]:
        return {"vulnerabilities": entries}

    monkeypatch.setattr(exposure_tasks, "_fetch_kev_catalog", fake_fetch)
    _reset(recorder)

    result = await exposure_tasks._sync_kev_database_async()

    assert result == {"updated": 501, "created": 2_000, "fetched": 2_502, "truncated": False}
    _assert_bounded(recorder, "threat_indicators", exposure_tasks.VULN_BATCH_SIZE)
    windows = math.ceil(2_501 / exposure_tasks.VULN_BATCH_SIZE)
    assert len(recorder.for_table("threat_indicators")) == windows
    assert recorder.commits >= windows

    db_session.expire_all()
    assert await _count(
        db_session,
        select(func.count(ThreatIndicator.id)).where(
            ThreatIndicator.indicator_type == "cve", ThreatIndicator.source == "CISA KEV",
        ),
    ) == 2_500


# ---------------------------------------------------------------------------
# integrations
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_integration_housekeeping_tasks_are_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = _now()
    connectors = [
        {
            "id": f"synthetic-{i}",
            "name": f"synthetic-{i}",
            "display_name": f"Synthetic {i}",
            "category": "siem",
            "version": "1.0.0",
            "supported_actions": "[]",
            "supported_triggers": "[]",
            "auth_type": "api_key",
            "config_schema": "{}",
            "is_builtin": False,
            "created_at": now,
            "updated_at": now,
        }
        for i in range(15_000)
    ]
    connectors.append(
        dict(connectors[0], id="splunk", name="splunk", display_name="Splunk", version="0.0.1"),
    )
    await _bulk_insert(db_session, IntegrationConnector, connectors)

    past = (now - timedelta(minutes=5)).isoformat()
    future = (now + timedelta(hours=1)).isoformat()
    integrations: list[dict[str, Any]] = []
    for i in range(20_000):
        kind = i % 3
        integrations.append(
            {
                "id": _uid(),
                "organization_id": ORG,
                "connector_id": "splunk",
                "display_name": f"instance {i}",
                "config_encrypted": "{}",
                "auth_credentials_encrypted": "{}",
                "status": "rate_limited" if kind == 0 else "active",
                "health_status": "unknown",
                "rate_limit_remaining": 5 if kind == 1 else None,
                "rate_limit_reset": past if kind == 0 else (future if kind == 1 else None),
                "created_at": now,
                "updated_at": now,
            },
        )
    await _bulk_insert(db_session, InstalledIntegration, integrations)
    expected_resets = len([i for i in range(20_000) if i % 3 == 0])
    _reset(recorder)

    rl = await integrations_tasks._rate_limit_reset_async()
    assert rl["reset_count"] == expected_resets
    assert rl["truncated"] is False
    _assert_bounded(recorder, "installed_integrations", integrations_tasks.INTEGRATIONS_BATCH_SIZE)
    assert recorder.commits >= math.ceil(
        (20_000 - 20_000 // 3) / integrations_tasks.INTEGRATIONS_BATCH_SIZE,
    )
    db_session.expire_all()
    assert await _count(
        db_session,
        select(func.count(InstalledIntegration.id)).where(
            InstalledIntegration.status == "rate_limited",
        ),
    ) == 0
    # Future-dated windows were left alone.
    assert await _count(
        db_session,
        select(func.count(InstalledIntegration.id)).where(
            InstalledIntegration.rate_limit_reset == future,
        ),
    ) == len([i for i in range(20_000) if i % 3 == 1])

    _reset(recorder)
    cu = await integrations_tasks._connector_update_check_async()
    assert [u["connector"] for u in cu["available_updates"]] == ["splunk"]
    assert cu["truncated"] is False
    _assert_bounded(recorder, "integration_connectors", integrations_tasks.INTEGRATIONS_BATCH_SIZE)

    from src.integrations.engine import IntegrationManager

    probed: list[str] = []

    async def fake_test_connection(self: Any, integration_id: str) -> dict[str, Any]:
        probed.append(integration_id)
        return {"status": "healthy"}

    monkeypatch.setattr(IntegrationManager, "test_connection", fake_test_connection)
    monkeypatch.setattr(integrations_tasks, "MAX_HEALTH_CHECKS_PER_RUN", 2_500)
    _reset(recorder)
    hc = await integrations_tasks._health_check_all_integrations_async(ORG)
    assert hc["total_checked"] == 2_500
    assert hc["healthy"] == 2_500
    assert hc["truncated"] is True
    assert len(set(probed)) == 2_500
    _assert_bounded(recorder, "installed_integrations", integrations_tasks.INTEGRATIONS_BATCH_SIZE)


# ---------------------------------------------------------------------------
# supplychain
# ---------------------------------------------------------------------------
SEEDED_COMPONENTS = 12_000
TYPO_NAMES = ["reqeusts", "djang0"]


@pytest.mark.asyncio
async def test_supplychain_tasks_are_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(supplychain_tasks, "_AsyncSessionLocal", async_session_factory)
    await _seed_orgs(db_session, ORG, OTHER_ORG)
    now = _now()
    naive_now = datetime.utcnow()

    components: list[dict[str, Any]] = []
    for i in range(SEEDED_COMPONENTS):
        components.append(
            {
                "id": f"c-{i:06d}",
                "organization_id": ORG,
                "name": f"pkg-{i}",
                "version": "1.0.0",
                "package_type": "pypi",
                "known_vulnerabilities_count": 1 if i % 10 == 0 else 0,
                "risk_score": 8.0 if i % 20 == 0 else 5.0,
                "created_at": now,
                "updated_at": now,
            },
        )
    # "reqeusts" in two versions: the old sweep's scalar_one_or_none() raised
    # MultipleResultsFound on this and aborted the whole run.
    for n, name in enumerate(TYPO_NAMES + ["reqeusts"]):
        components.append(
            {
                "id": f"t-{n}",
                "organization_id": ORG,
                "name": name,
                "version": f"0.{n}.0",
                "package_type": "pypi",
                "known_vulnerabilities_count": 0,
                "risk_score": 0.0,
                "created_at": now,
                "updated_at": now,
            },
        )
    await _bulk_insert(db_session, SoftwareComponent, components)

    # One vulnerable component already has an open risk.
    await _bulk_insert(
        db_session,
        SupplyChainRisk,
        [
            {
                "id": _uid(),
                "organization_id": ORG,
                "component_id": "c-000000",
                "risk_type": "vulnerability",
                "severity": "high",
                "description": "pre-existing",
                "status": "open",
                "detected_date": naive_now,
                "created_at": now,
                "updated_at": now,
            },
        ],
    )
    soon = (naive_now + timedelta(days=30)).isoformat()
    later = (naive_now + timedelta(days=400)).isoformat()
    vendors = [
        {
            "id": _uid(),
            "organization_id": ORG,
            "vendor_name": f"vendor {i}",
            "assessment_date": naive_now,
            "certifications": json.dumps(
                [{"name": "SOC2", "expiry_date": soon if i % 3 == 0 else later}],
            ),
            "created_at": now,
            "updated_at": now,
        }
        for i in range(3_000)
    ]
    await _bulk_insert(db_session, VendorAssessment, vendors)
    _reset(recorder)

    totals, peak = await _measure(
        supplychain_tasks._supplychain_cross_org_sweep_async(async_session_factory),
    )

    analyzer = SupplyChainRiskAnalyzer()
    hit_names = {
        h["component"]
        for h in analyzer.detect_typosquatting(
            [c["name"] for c in components],
            supplychain_tasks._TYPOSQUAT_SWEEP_POPULAR["pypi"],
            0.70,
        )
    }
    assert set(TYPO_NAMES) <= hit_names
    expected_typo = sum(1 for c in components if c["name"] in hit_names)
    vuln_comps = SEEDED_COMPONENTS // 10
    assert totals == {
        "orgs_scanned": 2,
        "typosquat_risks_created": expected_typo,
        "vuln_risks_created": vuln_comps - 1,
        "cert_warnings": 1_000,
        "truncated": False,
    }
    assert peak < PEAK_LIMIT_BYTES
    bound = supplychain_tasks.SUPPLYCHAIN_BATCH_SIZE
    _assert_bounded(recorder, "software_components", bound)
    _assert_bounded(recorder, "vendor_assessments", bound)
    _assert_bounded(recorder, "supply_chain_risks", bound)
    _assert_bounded(recorder, "organizations", bound)
    assert recorder.commits >= math.ceil(SEEDED_COMPONENTS / bound)

    # Idempotent: nothing new on a second run.
    again = await supplychain_tasks._supplychain_cross_org_sweep_async(async_session_factory)
    assert again["typosquat_risks_created"] == 0
    assert again["vuln_risks_created"] == 0
    # Run-wide row budget.
    monkeypatch.setattr(supplychain_tasks, "MAX_SUPPLYCHAIN_SWEEP_ROWS", 3_000)
    assert (
        await supplychain_tasks._supplychain_cross_org_sweep_async(async_session_factory)
    )["truncated"] is True

    # --- on-demand tasks ---
    await _bulk_insert(
        db_session,
        SupplyChainRisk,
        [
            {
                "id": _uid(),
                "organization_id": ORG,
                "component_id": "c-000001",
                "risk_type": "vulnerability",
                "severity": "medium",
                "description": f"synthetic risk {i}",
                "status": "open",
                "detected_date": naive_now,
                "created_at": now,
                "updated_at": now,
            }
            for i in range(12_000)
        ],
    )
    _reset(recorder)
    xref = await supplychain_tasks._vulnerability_cross_reference_async("c-000001")
    assert len(xref["cves"]) == supplychain_tasks.MAX_CROSSREF_RISKS_PER_RUN
    assert xref["truncated"] is True
    assert xref["max_severity"] == "none"  # risk_type is not a severity; unchanged
    _assert_bounded(recorder, "supply_chain_risks", bound)

    _reset(recorder)
    certs = await supplychain_tasks._vendor_certification_expiry_check_async(ORG)
    assert certs["vendor_count"] == 3_000
    assert len(certs["expiring_soon"]) == 1_000
    assert certs["expired"] == []
    assert certs["truncated"] is False
    _assert_bounded(recorder, "vendor_assessments", bound)

    _reset(recorder)
    typo = await supplychain_tasks._typosquatting_scan_async(ORG, "pypi", 0.70)
    assert typo["packages_scanned"] == len(components)
    assert {h["component"] for h in typo["suspected"]} >= set(TYPO_NAMES)
    assert typo["truncated"] is False
    _assert_bounded(recorder, "software_components", bound)


# ---------------------------------------------------------------------------
# deception: reconcile_honeypot_dispatches
# ---------------------------------------------------------------------------
SEEDED_DECOYS = 12_000


@pytest.mark.asyncio
async def test_reconcile_honeypot_dispatches_is_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deception_tasks, "_AsyncSessionLocal", async_session_factory)
    await _seed_orgs(db_session, ORG)
    now = _now()
    agent_id = _uid()
    await _bulk_insert(
        db_session,
        EndpointAgent,
        [{"id": agent_id, "hostname": "decoy-host", "organization_id": ORG,
          "status": "active", "capabilities": ["deception"], "created_at": now, "updated_at": now}],
    )
    commands: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    decoys: list[dict[str, Any]] = []
    for i in range(SEEDED_DECOYS):
        cid = f"cmd-{i:06d}"
        kind = i % 3
        commands.append(
            {
                "id": cid,
                "agent_id": agent_id,
                "action": "deploy_honeypot",
                "command_hash": "h" * 64,
                "chain_hash": "c" * 64,
                "payload": {},
                "status": "expired" if kind == 1 else "queued",
                "organization_id": ORG,
                "created_at": now,
                "updated_at": now,
            },
        )
        if kind == 0:
            results.append(
                {
                    "id": _uid(),
                    "command_id": cid,
                    "agent_id": agent_id,
                    "status": "success" if i % 2 == 0 else "error",
                    "stderr": None if i % 2 == 0 else "bind failed",
                    "created_at": now,
                    "updated_at": now,
                },
            )
        decoys.append(
            {
                "id": f"d-{i:06d}",
                "name": f"honeypot {i}",
                "decoy_type": "honeypot",
                "category": "network",
                "organization_id": ORG,
                "status": "deploying",
                "configuration": {"listener": {"command_id": cid, "state": "dispatched"}},
                "created_at": now,
                "updated_at": now,
            },
        )
    await _bulk_insert(db_session, AgentCommand, commands)
    await _bulk_insert(db_session, AgentResult, results)
    await _bulk_insert(db_session, Decoy, decoys)
    _reset(recorder)

    out = await deception_tasks._reconcile_honeypot_dispatches()

    kind0 = [i for i in range(SEEDED_DECOYS) if i % 3 == 0]
    activated = len([i for i in kind0 if i % 2 == 0])
    failed = len(kind0) - activated + len([i for i in range(SEEDED_DECOYS) if i % 3 == 1])
    pending = len([i for i in range(SEEDED_DECOYS) if i % 3 == 2])
    assert out == {"activated": activated, "failed": failed, "pending": pending, "truncated": False}
    bound = deception_tasks.RECONCILE_BATCH_SIZE
    _assert_bounded(recorder, "decoys", bound)
    _assert_bounded(recorder, "agent_results", bound)
    _assert_bounded(recorder, "agent_commands", bound)
    assert recorder.commits >= math.ceil(SEEDED_DECOYS / bound)

    db_session.expire_all()
    cfg = (
        await db_session.execute(select(Decoy.configuration).where(Decoy.id == "d-000003"))
    ).scalar_one()
    assert cfg["listener"]["state"] == "failed"
    assert cfg["listener"]["error"] == "bind failed"

    monkeypatch.setattr(deception_tasks, "MAX_RECONCILE_DECOYS_PER_RUN", 1_500)
    capped = await deception_tasks._reconcile_honeypot_dispatches()
    assert capped == {"activated": 0, "failed": 0, "pending": 1_500, "truncated": True}


# ---------------------------------------------------------------------------
# playbooks: check_scheduled_playbooks sweep
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_scheduled_playbook_sweep_is_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = _now()
    steps = json.dumps([{"name": "wait", "action": "wait", "parameters": {"seconds": 0}}])
    rows = [
        {
            "id": f"pb-{i:06d}",
            "name": f"scheduled {i}",
            "steps": steps,
            "trigger_type": PlaybookTrigger.SCHEDULED.value,
            # Unrecognised conditions: never due, but still checked.
            "trigger_conditions": json.dumps({"label": f"x{i}"}),
            "is_enabled": True,
            "created_at": now,
            "updated_at": now,
        }
        for i in range(12_000)
    ]
    due_ids = ["pb-000010", "pb-005000", "pb-011999"]
    for r in rows:
        if r["id"] in due_ids:
            r["trigger_conditions"] = json.dumps({"interval_minutes": 30})
    # One of the due ones ran recently, so it is not due after all.
    await _bulk_insert(db_session, Playbook, rows)
    await _bulk_insert(
        db_session,
        PlaybookExecution,
        [{"id": _uid(), "playbook_id": "pb-005000", "status": "completed",
          "trigger_source": "schedule", "created_at": datetime.utcnow(),
          "updated_at": datetime.utcnow()}],
    )

    dispatched: list[str] = []
    monkeypatch.setattr(
        playbook_tasks,
        "run_playbook_execution",
        SimpleNamespace(delay=lambda execution_id: dispatched.append(execution_id)),
    )
    _reset(recorder)

    result = await playbook_tasks.sweep_scheduled_playbooks(db_session)

    assert result == {
        "executed": 2,
        "checked": 12_000,
        "truncated": False,
        "task": "check_scheduled_playbooks",
    }
    assert len(dispatched) == 2
    bound = playbook_tasks.SCHEDULE_SWEEP_BATCH_SIZE
    _assert_bounded(recorder, "playbooks", bound)
    _assert_bounded(recorder, "playbook_executions", bound)
    # One latest-run lookup per window, not one per playbook.
    assert len(recorder.for_table("playbook_executions")) == math.ceil(12_000 / bound)

    monkeypatch.setattr(playbook_tasks, "MAX_SCHEDULED_PLAYBOOKS_PER_SWEEP", 2_500)
    capped = await playbook_tasks.sweep_scheduled_playbooks(db_session)
    assert capped["checked"] == 2_500
    assert capped["truncated"] is True


# ---------------------------------------------------------------------------
# stig: fleet sweep, scan, remediation
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_fleet_stig_sweep_is_windowed(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    orgs = [f"{ORG}-{n}" for n in range(3)]
    await _seed_orgs(db_session, *orgs)
    now = _now()
    agents = [
        {
            "id": f"a-{i:06d}",
            "hostname": f"host-{i}",
            "organization_id": orgs[i % 3],
            "status": "active" if i < 3_000 else "offline",
            "capabilities": [],
            "created_at": now,
            "updated_at": now,
        }
        for i in range(3_500)
    ]
    await _bulk_insert(db_session, EndpointAgent, agents)
    benches = []
    for n, oid in enumerate(orgs):
        for k in range(3):
            benches.append(
                {
                    "id": f"b-{n}-{k}",
                    "benchmark_id": f"SYN_{n}_{k}",
                    "organization_id": oid,
                    "status": "available" if k < 2 else "deprecated",
                    "created_at": now,
                    "updated_at": now,
                },
            )
    await _bulk_insert(db_session, STIGBenchmark, benches)

    queued: list[dict[str, str]] = []
    monkeypatch.setattr(
        stig_tasks.run_stig_scan, "delay", lambda **kw: queued.append(kw), raising=False,
    )
    _reset(recorder)

    result = await stig_tasks._scheduled_fleet_stig_sweep_async()

    assert result["status"] == "dispatched"
    assert result["count"] == 6_000 == len(queued) == len(result["items"])
    assert result["truncated"] is False
    assert all(q["org_id"] == orgs[int(q["host"].split("-")[1]) % 3] for q in queued)
    _assert_bounded(recorder, "endpoint_agents", stig_tasks.STIG_BATCH_SIZE)
    _assert_bounded(recorder, "stig_benchmarks", stig_tasks.STIG_BATCH_SIZE)

    monkeypatch.setattr(stig_tasks, "MAX_STIG_FLEET_DISPATCH_PER_RUN", 1_000)
    capped = await stig_tasks._scheduled_fleet_stig_sweep_async()
    assert capped["count"] == 1_000
    assert capped["truncated"] is True


SEEDED_RULES = 6_000


@pytest.mark.asyncio
async def test_run_stig_scan_and_remediation_window_the_rules(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _seed_orgs(db_session, ORG)
    now = _now()
    agent_id = _uid()
    await _bulk_insert(
        db_session,
        EndpointAgent,
        [{"id": agent_id, "hostname": "stig-host", "organization_id": ORG, "status": "active",
          "os_type": "linux", "capabilities": ["compliance"], "created_at": now, "updated_at": now}],
    )
    bench_id = _uid()
    await _bulk_insert(
        db_session,
        STIGBenchmark,
        [{"id": bench_id, "benchmark_id": "RHEL_8_SYN", "platform": "RHEL 8",
          "organization_id": ORG, "created_at": now, "updated_at": now}],
    )
    await _bulk_insert(
        db_session,
        STIGRule,
        [
            {
                "id": f"r-{i:06d}",
                "benchmark_id_ref": bench_id,
                "rule_id": f"SV-{i}",
                "severity": "medium",
                "title": f"rule {i}",
                "fix_text": f"fix {i}" if i % 3 else None,
                "automated_check": {"script": f"check {i}"} if i % 2 == 0 else {},
                "organization_id": ORG,
                "created_at": now,
                "updated_at": now,
            }
            for i in range(SEEDED_RULES)
        ],
    )

    # The agent "answers" during the first poll tick: every queued command
    # completes, alternating pass/fail. Statuses are written through another
    # session, so this also proves the poll sees fresh rows.
    async def agent_answers(_seconds: float) -> None:
        # This stands in for the agent, not the task: drop its statements
        # from the recording once it is done.
        mark = len(recorder.statements)
        await _agent_answers()
        del recorder.statements[mark:]

    async def _agent_answers() -> None:
        async with async_session_factory() as s:
            cmds = (
                await s.execute(select(AgentCommand.id, AgentCommand.payload))
            ).all()
            await s.execute(update(AgentCommand).values(status="completed"))
            s.add_all(
                [
                    AgentResult(
                        command_id=c.id,
                        agent_id=agent_id,
                        status="success",
                        artifacts={
                            "check_result": "pass"
                            if int(c.payload["rule_id"].split("-")[1]) % 4 == 0
                            else "fail",
                        },
                    )
                    for c in cmds
                ],
            )
            await s.commit()

    monkeypatch.setattr(stig_tasks, "asyncio", SimpleNamespace(sleep=agent_answers))
    monkeypatch.setattr(stig_tasks, "STIG_POLL_DEADLINE_SECONDS", 120.0)
    _reset(recorder)

    result = await stig_tasks._run_stig_scan_async("task-1", "stig-host", bench_id, ORG)

    considered = stig_tasks.MAX_STIG_RULES_PER_SCAN  # 5,000 of 6,000
    dispatched = considered // 2
    assert result["status"] == "completed"
    assert result["applicable_rules"] == SEEDED_RULES
    assert result["satisfied"] == dispatched // 2
    assert result["failed"] == dispatched // 2
    assert result["not_reviewed"] == SEEDED_RULES - dispatched
    assert result["truncated"] is True
    _assert_bounded(recorder, "stig_rules", stig_tasks.STIG_BATCH_SIZE)
    _assert_bounded(recorder, "agent_commands", stig_tasks.STIG_BATCH_SIZE)
    assert recorder.commits >= math.ceil(considered / stig_tasks.STIG_BATCH_SIZE)

    # No agent for this host: only a COUNT touches stig_rules.
    _reset(recorder)
    no_agent = await stig_tasks._run_stig_scan_async("task-2", "unknown-host", bench_id, ORG)
    assert no_agent["status"] == "no_agent"
    assert no_agent["applicable_rules"] == SEEDED_RULES
    assert no_agent["truncated"] is False
    assert recorder.max_bound_for("stig_rules") == 1

    # Remediation: rules with fix text, in windows.
    from src.stig.models import STIGScanResult

    _reset(recorder)
    rem = await stig_tasks._auto_remediate_findings_async("task-3", result["scan_id"], ORG)
    with_fix = len([i for i in range(SEEDED_RULES) if i % 3])
    assert rem["status"] == "completed"
    assert rem["remediated"] + rem["failed"] == with_fix
    assert rem["truncated"] is False
    _assert_bounded(recorder, "stig_rules", stig_tasks.STIG_BATCH_SIZE)
    assert recorder.commits >= math.ceil(with_fix / stig_tasks.STIG_BATCH_SIZE)
    assert (
        await db_session.execute(
            select(func.count(STIGScanResult.id)).where(STIGScanResult.benchmark_id_ref == bench_id),
        )
    ).scalar_one() == 2


# ---------------------------------------------------------------------------
# darkweb
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_darkweb_cross_org_sweep_pages_monitors_outside_the_loop(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    orgs = [f"{ORG}-dw-{n}" for n in range(3)]
    await _seed_orgs(db_session, *orgs)
    now = _now()
    monitors = [
        {
            "id": f"m-{i:06d}",
            "organization_id": orgs[i % 3] if i < 2_800 else "org-that-does-not-exist",
            "name": f"monitor {i}",
            "enabled": not (2_500 <= i < 2_800),
            "created_at": now,
            "updated_at": now,
        }
        for i in range(3_000)
    ]
    await _bulk_insert(db_session, DarkWebMonitor, monitors)

    scanned: list[str] = []
    nested_loop: list[bool] = []

    def fake_scan(monitor_id: str) -> dict[str, Any]:
        # The old sweep invoked the scan from inside its own running loop,
        # where the scan's run_until_complete() raises.
        try:
            asyncio.get_running_loop()
            nested_loop.append(True)
        except RuntimeError:
            nested_loop.append(False)
        scanned.append(monitor_id)
        return {"created": 1}

    monkeypatch.setattr(darkweb_tasks, "_scan_monitor", fake_scan)
    _reset(recorder)

    # The task drives its own event loop, so run it off this test's loop.
    result = await asyncio.to_thread(lambda: darkweb_tasks.darkweb_cross_org_sweep.apply().get())

    assert result == {
        "orgs_scanned": 3,
        "monitors_scanned": 2_500,
        "findings_created": 2_500,
        "truncated": False,
    }
    assert scanned == [f"m-{i:06d}" for i in range(2_500)]
    assert not any(nested_loop)
    _assert_bounded(recorder, "darkweb_monitors", darkweb_tasks.DARKWEB_BATCH_SIZE)
    assert len(recorder.for_table("darkweb_monitors")) == math.ceil(
        2_500 / darkweb_tasks.DARKWEB_BATCH_SIZE,
    )

    monkeypatch.setattr(darkweb_tasks, "MAX_DARKWEB_MONITORS_PER_SWEEP", 1_200)
    capped = await asyncio.to_thread(lambda: darkweb_tasks.darkweb_cross_org_sweep.apply().get())
    assert capped["monitors_scanned"] == 1_200
    assert capped["truncated"] is True


@pytest.mark.asyncio
async def test_credential_context_reads_two_columns_per_window(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = _now()
    monitors = [
        {
            "id": f"m-{i:06d}",
            "organization_id": ORG,
            "name": f"monitor {i}",
            "domains_watched": [f"d{i}.example", "shared.example"],
            "emails_watched": [f"u{i}@d{i}.example"] if i % 2 == 0 else None,
            "created_at": now,
            "updated_at": now,
        }
        for i in range(12_000)
    ]
    await _bulk_insert(db_session, DarkWebMonitor, monitors)
    finding_id = _uid()
    await _bulk_insert(
        db_session,
        DarkWebFinding,
        [{"id": finding_id, "organization_id": ORG, "monitor_id": "m-000000",
          "description": "user@d0.example:hash", "created_at": now, "updated_at": now}],
    )
    _reset(recorder)

    ctx = await darkweb_tasks._credential_context_async(finding_id)
    assert ctx["finding_found"] is True
    assert ctx["truncated"] is True  # default cap 10,000 < 12,000 monitors
    assert len(ctx["monitored_domains"]) == darkweb_tasks.MAX_MONITORS_PER_CREDENTIAL_CHECK + 1
    _assert_bounded(recorder, "darkweb_monitors", darkweb_tasks.DARKWEB_BATCH_SIZE)

    monkeypatch.setattr(darkweb_tasks, "MAX_MONITORS_PER_CREDENTIAL_CHECK", 20_000)
    full = await darkweb_tasks._credential_context_async(finding_id)
    assert full["truncated"] is False
    assert len(full["monitored_domains"]) == 12_001
    assert len(full["monitored_emails"]) == 6_000
    assert full["monitored_domains"] == sorted(full["monitored_domains"])


@pytest.mark.asyncio
async def test_threat_correlation_never_loads_the_ioc_or_incident_tables(
    db_session: AsyncSession, recorder: StatementRecorder,
) -> None:
    await _seed_orgs(db_session, ORG, OTHER_ORG)
    now = _now()
    domain = "breached.example"
    email = "ceo@breached.example"
    iocs = [
        {
            "id": _uid(),
            "indicator_type": "domain",
            "value": f"noise{i}.example",
            "organization_id": ORG,
            "is_active": True,
            "is_whitelisted": False,
            "context": {},
            "created_at": now - timedelta(days=i % 60),
            "updated_at": now,
        }
        for i in range(20_000)
    ]
    for value, itype in ((domain, "domain"), (email, "email")):
        iocs.append(dict(iocs[0], id=_uid(), value=value, indicator_type=itype))
    # Same value but outside the window / another tenant: never matched.
    iocs.append(dict(iocs[0], id=_uid(), value=domain, created_at=now - timedelta(days=200)))
    iocs.append(dict(iocs[0], id=_uid(), value=domain, organization_id=OTHER_ORG))
    await _bulk_insert(db_session, ThreatIndicator, iocs)

    incidents = [
        {
            "id": f"i-{i:06d}",
            "title": f"incident {i}",
            "organization_id": ORG,
            "indicators": json.dumps([domain] if i % 1_000 == 0 else [f"x{i}.example"]),
            "created_at": now - timedelta(days=1),
            "updated_at": now,
        }
        for i in range(15_000)
    ]
    # Another tenant's incidents naming the same domain must not correlate.
    incidents += [
        {
            "id": f"o-{i:06d}",
            "title": f"other {i}",
            "organization_id": OTHER_ORG,
            "indicators": json.dumps([domain]),
            "created_at": now - timedelta(days=1),
            "updated_at": now,
        }
        for i in range(50)
    ]
    await _bulk_insert(db_session, Incident, incidents)
    await _bulk_insert(
        db_session,
        DarkWebMonitor,
        [{"id": "m-x", "organization_id": ORG, "name": "m", "created_at": now, "updated_at": now}],
    )
    finding_id = _uid()
    await _bulk_insert(
        db_session,
        DarkWebFinding,
        [{"id": finding_id, "organization_id": ORG, "monitor_id": "m-x",
          "affected_assets": {"domain": domain, "email": email},
          "created_at": now, "updated_at": now}],
    )
    _reset(recorder)

    result, peak = await _measure(
        darkweb_tasks._threat_correlation_async(
            finding_id, ORG, darkweb_tasks.ThreatIntelCorrelator(),
        ),
    )

    assert result["finding_found"] is True
    assert result["ioc_count"] == 20_002
    assert sorted(c["match_type"] for c in result["ioc_correlations"]) == ["domain", "email"]
    assert result["incident_count"] == 15_000
    assert len(result["incident_correlations"]) == 15
    assert all(c["incident"]["id"].startswith("i-") for c in result["incident_correlations"])
    assert result["truncated"] is False
    assert peak < PEAK_LIMIT_BYTES
    _assert_bounded(recorder, "threat_indicators", darkweb_tasks.MAX_CORRELATION_IOC_MATCHES + 1)
    _assert_bounded(recorder, "incidents", darkweb_tasks.DARKWEB_BATCH_SIZE)


# ---------------------------------------------------------------------------
# Guard the guard: the pre-change read shapes must score as unbounded
# ---------------------------------------------------------------------------
def test_detector_flags_the_round2_pre_change_read_patterns() -> None:
    cutoff = _now() - timedelta(days=90)
    pre_change = {
        "organizations": select(Organization),
        "darkweb_monitors": select(DarkWebMonitor).where(
            DarkWebMonitor.organization_id == ORG,
            DarkWebMonitor.enabled == True,  # noqa: E712
        ),
        "threat_indicators": select(ThreatIndicator).where(
            (ThreatIndicator.organization_id == ORG) & (ThreatIndicator.created_at >= cutoff),
        ),
        "incidents": select(Incident).where(Incident.created_at >= cutoff),
        "stig_rules": select(STIGRule).where(STIGRule.benchmark_id_ref == "b"),
        "endpoint_agents": select(EndpointAgent).where(EndpointAgent.status == "active"),
        "installed_integrations": select(InstalledIntegration).where(
            or_(
                InstalledIntegration.rate_limit_remaining.isnot(None),
                InstalledIntegration.status == "rate_limited",
            ),
        ),
        "integration_connectors": select(IntegrationConnector),
        "supply_chain_risks": select(SupplyChainRisk).where(SupplyChainRisk.component_id == "c"),
        "vendor_assessments": select(VendorAssessment).where(VendorAssessment.organization_id == ORG),
        "software_components": select(SoftwareComponent.name).where(
            SoftwareComponent.organization_id == ORG,
        ),
        "decoys": select(Decoy).where(Decoy.decoy_type == "honeypot", Decoy.status == "deploying"),
        "playbooks": select(Playbook).where(Playbook.is_enabled == True),  # noqa: E712
        "scan_profiles": select(ScanProfile).where(ScanProfile.enabled == True),  # noqa: E712
        "exposure_scans": select(ExposureScan).where(ExposureScan.status == "pending"),
        "vulnerabilities": select(Vulnerability),
        "vulnerability_instances": select(VulnerabilityInstance).where(
            VulnerabilityInstance.status != "closed",
        ),
    }
    for table, stmt in pre_change.items():
        rec = _RecordedStatement(stmt, via_stream=False)
        assert rec.touches(table), table
        assert rec.row_bound() == math.inf, table

    # ...and the replacement shapes are bounded by their LIMIT, even when the
    # filter carries a sub-select IN rather than an expanded list.
    bounded = _RecordedStatement(
        select(DarkWebMonitor.id)
        .where(DarkWebMonitor.organization_id.in_(select(Organization.id)))
        .order_by(DarkWebMonitor.id)
        .limit(darkweb_tasks.DARKWEB_BATCH_SIZE),
        via_stream=False,
    )
    assert bounded.row_bound() == darkweb_tasks.DARKWEB_BATCH_SIZE
    # A sub-select IN on its own does not count as a bound.
    sub_in = _RecordedStatement(
        select(DarkWebMonitor.id).where(DarkWebMonitor.organization_id.in_(select(Organization.id))),
        via_stream=False,
    )
    assert sub_in.row_bound() == math.inf


# ---------------------------------------------------------------------------
# Wall-clock backstops
# ---------------------------------------------------------------------------
ROUND2_HEAVY_TASKS = (
    "src.stig.tasks.scheduled_fleet_stig_sweep",
    "src.stig.tasks.run_stig_scan",
    "src.stig.tasks.auto_remediate_findings",
    "src.integrations.tasks.rate_limit_reset",
    "src.integrations.tasks.connector_update_check",
    "src.supplychain.tasks.vulnerability_cross_reference",
    "src.supplychain.tasks.vendor_certification_expiry_check",
    "src.supplychain.tasks.typosquatting_scan",
    "src.supplychain.tasks.supplychain_cross_org_sweep",
    "src.darkweb.tasks.credential_leak_check",
    "src.darkweb.tasks.threat_correlation",
    "deception.reconcile_honeypot_dispatches",
    "playbooks.check_scheduled_playbooks",
    "src.exposure.tasks.run_vuln_scan",
    "src.exposure.tasks.import_scanner_results",
    "src.exposure.tasks.calculate_risk_scores",
    "src.exposure.tasks.check_sla_breaches",
    "src.exposure.tasks.sync_kev_database",
)
ROUND2_NETWORK_TASKS = (
    "src.darkweb.tasks.darkweb_cross_org_sweep",
    "src.integrations.tasks.health_check_all_integrations",
)


def test_round2_tasks_have_wall_clock_limits() -> None:
    annotations = celery_app.conf.task_annotations
    registered = set(celery_app.tasks.keys())
    for name in ROUND2_HEAVY_TASKS + ROUND2_NETWORK_TASKS:
        # A typo in the annotation key would silently apply no limit.
        assert name in registered, f"{name} is not a registered task"
        assert name in annotations, f"{name} has no task annotation"
        limits = annotations[name]
        ceiling = 900 if name in ROUND2_HEAVY_TASKS else 1800
        assert limits["soft_time_limit"] <= ceiling
        assert limits["time_limit"] > limits["soft_time_limit"]
        assert limits["time_limit"] < celery_app.conf.task_time_limit
