"""Wave 4 (W4-D): FedRAMP pages, ConMon, readiness and evidence collection.

FedRAMP reads the real control table (seeded on demand from the Moderate
catalogue); recommendations come from the tenant's gaps; the SSP and the
IRP / CMP / ConMon plan are built from stored facts with placeholders and no
invented architecture; ConMon checks are computed (no data = not_assessed),
a run is stored with an audit row and its time is ``lastRun``; readiness
coverage / freshness / assessor package are computed and read-only; evidence
rules collect real rows or say awaiting_integration; packages hold evidence.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_evidence.models import AuditTrail, AutomatedEvidenceRule, EvidencePackage
from src.audit_evidence.tasks import audit_evidence_daily_sweep_async, rule_is_due
from src.compliance.models import (
    POAM,
    ComplianceAssessment,
    ComplianceControl,
    ComplianceEvidence,
    ComplianceFramework,
)
from src.core.database import async_session_factory
from src.fedramp.controls import FEDRAMP_MODERATE_CONTROLS
from src.models.audit import AuditLog
from src.models.playbook import Playbook
from src.stig.models import STIGBenchmark
from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance

FED = "/api/v1/fedramp"
AE = "/api/v1/audit-evidence"
INVENTED = ("GovCloud", "ElastiCache", "CloudFront", "PySOAR Inc.", "CAB approval", "24/7", "CIS-hardened", "Multi-AZ", "Terraform state")


async def _framework(db: AsyncSession, org_id: str, codes: dict[str, str], short_name: str = "fedramp_moderate"):
    fw = ComplianceFramework(
        id=str(uuid.uuid4()), name=f"{short_name} {uuid.uuid4().hex[:6]}", short_name=short_name,
        version="Rev 5", authority="tests", organization_id=org_id,
    )
    db.add(fw)
    await db.flush()
    ids = {}
    for code, status in codes.items():
        c = ComplianceControl(
            id=str(uuid.uuid4()), framework_id=fw.id, control_id=code, control_family="Access Control",
            title=code, status=status, organization_id=org_id,
        )
        db.add(c)
        ids[code] = c.id
    fw_id = fw.id
    await db.commit()
    return fw_id, ids


# ---------------------------------------------------------------------------
# FedRAMP
# ---------------------------------------------------------------------------


async def test_controls_seed_the_real_catalogue_when_missing(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers,
) -> None:
    org_id = org_a.id
    resp = await client.get(f"{FED}/controls", params={"limit": 500}, headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == len(FEDRAMP_MODERATE_CONTROLS)
    # Seeded rows are not an assessment.
    assert {c["implementation_status"] for c in body["controls"]} == {"not_assessed"}
    assert all(c["control_record_id"] for c in body["controls"])
    assert {c["framework"] for c in body["controls"]} == {"fedramp_moderate"}
    stored = (await db_session.execute(
        select(func.count(ComplianceControl.id)).join(
            ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id,
        ).where(ComplianceFramework.organization_id == org_id, ComplianceFramework.short_name == "fedramp_moderate"),
    )).scalar()
    assert stored == len(FEDRAMP_MODERATE_CONTROLS)
    fw = (await db_session.execute(select(ComplianceFramework).where(
        ComplianceFramework.organization_id == org_id))).scalar_one()
    assert fw.total_controls == len(FEDRAMP_MODERATE_CONTROLS)  # not doubled


async def test_update_status_marks_manual_and_readiness_recommends_from_gaps(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers,
) -> None:
    _, ids = await _framework(db_session, org_a.id, {"AC-2": "not_implemented", "IA-2": "planned"})
    resp = await client.post(
        f"{FED}/controls/AC-2/update", params={"implementation_status": "not_implemented"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 200, resp.text
    db_session.expire_all()
    row = await db_session.get(ComplianceControl, ids["AC-2"])
    assert row.status_source == "manual"

    report = (await client.get(f"{FED}/readiness", headers=org_a_headers)).json()
    assert report["recommendations_basis"] == "computed_from_gaps"
    actions = " ".join(r["action"] for r in report["recommendations"])
    assert "AC-2" in actions and "IA-2" in actions
    assert report["status_breakdown"]["not_implemented"] == 1  # set by a person, so not "not_assessed"


async def test_ssp_and_plans_come_from_stored_facts(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers,
) -> None:
    org_id, org_name = org_a.id, org_a.name
    await _framework(db_session, org_id, {"IR-4": "implemented", "CM-6": "planned"})
    db_session.add(Playbook(name="Ransomware containment", status="active", trigger_type="manual",
                            steps="[]", organization_id=org_id))
    db_session.add(STIGBenchmark(benchmark_id=f"RHEL_9_STIG_{uuid.uuid4().hex[:6]}", title="RHEL 9 STIG",
                                 version="2", platform="Red Hat Enterprise Linux 9", organization_id=org_id))
    await db_session.commit()

    export = await client.get(f"{FED}/ssp/export", headers=org_a_headers)
    assert export.status_code == 200, export.text
    body = export.json()
    assert body["download_url"] is None
    ssp = body["document"]
    assert ssp["document_metadata"]["prepared_by"] == org_name
    assert ssp["system_information"]["organization"]["name"] == org_name
    assert ssp["system_environment"]["hosting"]["provider"].startswith("[TO BE COMPLETED")
    assert "hosting provider and region(s)" in ssp["missing_facts"]
    text = json.dumps(ssp)
    for word in INVENTED:
        assert word not in text, word
    ir4 = next(c for c in ssp["security_controls"]["IR"]["controls"] if c["control_id"] == "IR-4")
    assert ir4["implementation_status"] == "implemented"
    assert ir4["implementation_narrative"].startswith("[TO BE COMPLETED")  # nobody wrote one

    irp = (await client.get(f"{FED}/irp/generate", headers=org_a_headers)).json()
    assert [p["name"] for p in irp["incident_lifecycle"]["response_playbooks"]] == ["Ransomware containment"]
    cmp_doc = (await client.get(f"{FED}/cmp/generate", headers=org_a_headers)).json()
    assert [b["title"] for b in cmp_doc["configuration_baselines"]] == ["RHEL 9 STIG"]
    plan = (await client.get(f"{FED}/conmon-plan/generate", headers=org_a_headers)).json()
    tasks = {t["name"] for t in plan["monitoring_strategy"]["scheduled_tasks"]}
    assert {"stig-scan-reconcile", "compliance-attestation-sweep", "audit-evidence-daily-sweep"} <= tasks
    assert plan["metrics_and_indicators"]["vulnerability_scanning"]["status"] == "not_assessed"
    for doc in (irp, cmp_doc, plan):
        text = json.dumps(doc)
        for word in INVENTED:
            assert word not in text, word


async def test_poam_report_has_a_timeline(client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers) -> None:
    _, ids = await _framework(db_session, org_a.id, {"SC-7": "planned"})
    due = datetime.now(timezone.utc) - timedelta(days=2)
    db_session.add(POAM(control_id_ref=ids["SC-7"], weakness_name="w", weakness_source="tests", risk_level="high",
                        scheduled_completion_date=due, organization_id=org_a.id))
    await db_session.commit()
    body = (await client.get(f"{FED}/poam/report", headers=org_a_headers)).json()
    assert body["timeline"] == [{"month": due.strftime("%Y-%m"), "due": 1, "completed": 0, "open": 1}]
    assert body["summary"]["overdue_items"] == 1


# ---------------------------------------------------------------------------
# ConMon
# ---------------------------------------------------------------------------


async def test_conmon_with_no_data_is_not_assessed_and_has_no_last_run(
    client: AsyncClient, org_a, org_a_headers,
) -> None:
    rows = (await client.get(f"{AE}/conmon/status", headers=org_a_headers)).json()
    assert {r["status"] for r in rows} == {"not_assessed"}
    assert all(r["lastRun"] is None and r["compliance_percentage"] is None and r["reason"] for r in rows)
    assert not any(r["active"] for r in rows)
    report = (await client.get(f"{AE}/conmon/report", headers=org_a_headers)).json()
    assert report["overall_status"] == "not_assessed" and report["persisted"] is False


async def test_conmon_run_is_stored_audited_and_computed(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, viewer_headers,
) -> None:
    org_id = org_a.id
    vuln = Vulnerability(cve_id="CVE-2024-1111", title="t", severity="critical", organization_id=org_id)
    db_session.add(vuln)
    await db_session.flush()
    db_session.add(VulnerabilityInstance(vulnerability_id=vuln.id, asset_name="h", status="open",
                                         sla_status="breached", organization_id=org_id))
    await db_session.commit()

    assert (await client.post(f"{AE}/conmon/run", headers=viewer_headers)).status_code == 403
    resp = await client.post(f"{AE}/conmon/run", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    report = resp.json()["report"]
    assert report["checks"]["vulnerability_scanning"]["status"] == "non_compliant"
    assert report["overall_status"] == "non_compliant"
    assert report["persisted"] is True

    stored = (await db_session.execute(select(ComplianceAssessment).where(
        ComplianceAssessment.organization_id == org_id, ComplianceAssessment.assessment_type == "conmon"))).scalar_one()
    assert stored.overall_result == "non_compliant"
    trail = (await db_session.execute(select(func.count(AuditTrail.id)).where(
        AuditTrail.organization_id == org_id, AuditTrail.action == "conmon.run"))).scalar()
    assert trail == 1
    rows = (await client.get(f"{AE}/conmon/status", headers=org_a_headers)).json()
    assert all(r["lastRun"] for r in rows)
    stats = (await client.get(f"{AE}/dashboard/stats", headers=org_a_headers)).json()
    assert stats["conmon_status"] == "non_compliant" and stats["last_conmon_run"]


# ---------------------------------------------------------------------------
# readiness
# ---------------------------------------------------------------------------


async def test_readiness_coverage_freshness_and_package_are_computed(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers,
) -> None:
    org_id = org_a.id
    fw_id, ids = await _framework(db_session, org_id, {"AC-2": "implemented", "AU-2": "not_assessed"})
    db_session.add(ComplianceEvidence(control_id_ref=ids["AC-2"], organization_id=org_id, evidence_type="policy",
                                      title="old", collected_by="u",
                                      collected_at=datetime.now(timezone.utc) - timedelta(days=400)))
    await db_session.commit()

    cov = (await client.get(f"{AE}/readiness/coverage", params={"framework_id": fw_id}, headers=org_a_headers)).json()
    assert cov["total_controls"] == 2 and cov["controls_with_evidence"] == 1 and cov["coverage_percentage"] == 50.0
    assert [m["id"] for m in cov["controls_missing_evidence"]] == ["AU-2"]
    assert (await db_session.execute(select(func.count(POAM.id)).where(POAM.organization_id == org_id))).scalar() == 0

    fresh = (await client.get(f"{AE}/readiness/freshness", params={"framework_id": "fedramp_moderate"},
                              headers=org_a_headers)).json()
    assert fresh["stale_evidence_count"] == 1 and fresh["freshness_percentage"] == 0.0
    assert fresh["stale_controls"][0]["control"] == "AC-2"

    pkg = (await client.get(f"{AE}/readiness/assessor-package", params={"framework_id": fw_id},
                            headers=org_a_headers)).json()
    assert pkg["ready_for_assessment"] is False

    check = (await client.get(f"{AE}/readiness/check", params={"framework": "fedramp_moderate"},
                              headers=org_a_headers)).json()
    assert check["not_assessed"] == 1 and check["implemented"] == 1 and check["readiness_percentage"] == 50.0
    missing = await client.get(f"{AE}/readiness/coverage", params={"framework_id": "nope"}, headers=org_a_headers)
    assert missing.status_code == 404


# ---------------------------------------------------------------------------
# evidence collection and packages
# ---------------------------------------------------------------------------


async def test_evidence_rules_collect_real_rows_or_say_awaiting_integration(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, viewer_headers,
) -> None:
    org_id = org_a.id
    _, ids = await _framework(db_session, org_id, {"AU-2": "not_assessed"})
    db_session.add(AuditLog(organization_id=org_id, action="login", resource_type="user", success=True))
    log_rule = AutomatedEvidenceRule(name="audit volume", control_ids={"controls": ["AU-2"]}, evidence_type="log",
                                     collection_method="log_query", collection_config={"source": "audit_logs"},
                                     schedule="daily", organization_id=org_id)
    api_rule = AutomatedEvidenceRule(name="cloud api", control_ids={"controls": ["AU-2"]}, evidence_type="log",
                                     collection_method="api_query", collection_config={}, schedule="daily",
                                     organization_id=org_id)
    db_session.add_all([log_rule, api_rule])
    await db_session.commit()
    log_rule_id, api_rule_id = log_rule.id, api_rule.id

    assert (await client.post(f"{AE}/evidence/collect", json={"rule_id": log_rule_id},
                              headers=viewer_headers)).status_code == 403
    got = (await client.post(f"{AE}/evidence/collect", json={"rule_id": log_rule_id}, headers=org_a_headers)).json()
    assert got["status"] == "collected"
    assert got["evidence"]["data"]["total"] == 1
    row = (await db_session.execute(select(ComplianceEvidence).where(
        ComplianceEvidence.id == got["evidence"]["evidence_ids"][0]))).scalar_one()
    assert row.control_id_ref == ids["AU-2"] and row.is_automated and len(row.file_hash) == 128

    api = (await client.post(f"{AE}/evidence/collect", json={"rule_id": api_rule_id}, headers=org_a_headers)).json()
    assert api["status"] == "awaiting_integration" and api["evidence"]["evidence_written"] == 0

    every = (await client.post(f"{AE}/evidence/collect-all", json={"family": "SC"}, headers=org_a_headers)).json()
    assert every["status"] == "no_rules" and every["rules_run"] == 0
    every = (await client.post(f"{AE}/evidence/collect-all", json={"family": "AU"}, headers=org_a_headers)).json()
    assert every["rules_run"] == 2 and every["collected"] == 1 and every["awaiting_integration"] == 1


async def test_packages_hold_evidence_and_refuse_empty_sealing(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers, org_b_headers,
) -> None:
    org_id = org_a.id
    _, ids = await _framework(db_session, org_id, {"AC-2": "implemented"})
    ev = ComplianceEvidence(control_id_ref=ids["AC-2"], organization_id=org_id, evidence_type="policy",
                            title="policy", collected_by="u", file_hash="ab" * 64)
    pkg = EvidencePackage(name="Q4", package_type="fedramp", organization_id=org_id)
    db_session.add_all([ev, pkg])
    await db_session.commit()
    ev_id, pkg_id = ev.id, pkg.id

    assert (await client.post(f"{AE}/packages/{pkg_id}/package", headers=org_a_headers)).status_code == 409
    assert (await client.post(f"{AE}/packages/{pkg_id}/submit", headers=org_a_headers)).status_code == 409
    assert (await client.post(f"{AE}/packages/{pkg_id}/evidence", json={"evidence_ids": [ev_id]},
                              headers=org_b_headers)).status_code == 404
    added = (await client.post(f"{AE}/packages/{pkg_id}/evidence", json={"evidence_ids": [ev_id, "missing"]},
                               headers=org_a_headers)).json()
    assert added["added"] == 1 and added["not_found"] == ["missing"]
    sealed = (await client.post(f"{AE}/packages/{pkg_id}/package", headers=org_a_headers)).json()
    assert sealed["evidence_count"] == 1 and len(sealed["package_hash"]) == 128
    report = (await client.get(f"{AE}/packages/{pkg_id}/report", headers=org_a_headers)).json()
    assert report["evidence_items"][ev_id]["control"] == "AC-2"


async def test_dashboard_stats_and_daily_sweep(client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers) -> None:
    org_id = org_a.id
    _, ids = await _framework(db_session, org_id, {"AU-2": "not_assessed"})
    db_session.add(AuditTrail(event_type="access", action="read", actor_type="user", actor_id="u1",
                              resource_type="x", resource_id="1", description="d", result="success",
                              organization_id=org_id))
    db_session.add(AutomatedEvidenceRule(name="mfa", control_ids=["AU-2"], evidence_type="metric",
                                         collection_method="metric_snapshot",
                                         collection_config={"metric": "active_users"}, schedule="weekly",
                                         organization_id=org_id))
    await db_session.commit()

    stats = (await client.get(f"{AE}/dashboard/stats", headers=org_a_headers)).json()
    assert stats["audit_events_last_24h"] == 1 and stats["recent_audit_events"][0]["action"] == "read"
    assert stats["total_evidence_items"] == 0 and stats["conmon_status"] == "not_run"

    totals = await audit_evidence_daily_sweep_async(async_session_factory)
    assert totals["rules_run"] >= 1 and totals["conmon_cycles"] >= 1
    again = await audit_evidence_daily_sweep_async(async_session_factory)
    assert again["rules_run"] == 0 and again["conmon_cycles"] == 0  # weekly rule / weekly cycle not due
    count = (await db_session.execute(select(func.count(ComplianceEvidence.id)).where(
        ComplianceEvidence.control_id_ref == ids["AU-2"]))).scalar()
    assert count == 1
    now = datetime.now(timezone.utc)
    assert rule_is_due("weekly", now - timedelta(days=8), now) and not rule_is_due("monthly", now, now)
