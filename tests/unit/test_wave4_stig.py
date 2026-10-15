"""Wave 4 (W4-D): STIG scans run through endpoint agents or are ``not_run``.

``POST /stig/scans/launch`` queues one ``stig_scan`` command on the host's
agent (tenant-scoped, capability-gated) or stores the scan as ``not_run``
with the reason; the agent's ARF output is parsed by the same ingest as an
uploaded ARF (on read and by the reconcile task); no scan is scored without
results; the SCAP "scan" and the built-in benchmark loader no longer invent
numbers.
"""

from __future__ import annotations

import uuid

from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.capabilities import capability_allows, requires_approval
from src.agents.models import AgentCommand, EndpointAgent
from src.agents.service import AgentService
from src.core.database import async_session_factory
from src.models.audit import AuditLog
from src.stig.models import SCAPProfile, STIGBenchmark, STIGRule, STIGScanResult
from src.stig.tasks import reconcile_stig_scans_async, update_stig_benchmarks

BASE = "/api/v1/stig"


def _arf(results: dict[str, str]) -> str:
    rows = "".join(
        f'<rule-result idref="{rid}" severity="high"><result>{res}</result></rule-result>'
        for rid, res in results.items()
    )
    return (
        '<arf:asset-report-collection xmlns:arf="urn:oasis:names:tc:dfi:arf:1.0">'
        f'<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">{rows}</TestResult>'
        "</arf:asset-report-collection>"
    )


async def _benchmark(db: AsyncSession, org_id: str, rules: int = 4) -> tuple[str, list[str]]:
    bench = STIGBenchmark(benchmark_id=f"RHEL_9_{uuid.uuid4().hex[:8]}", title="RHEL 9", platform="RHEL 9",
                          organization_id=org_id)
    db.add(bench)
    await db.flush()
    rule_ids = []
    for i in range(rules):
        rid = f"SV-{uuid.uuid4().hex[:6]}r{i}_rule"
        db.add(STIGRule(benchmark_id_ref=bench.id, rule_id=rid, stig_id=rid, severity="high" if i == 0 else "medium",
                        title=f"rule {i}", organization_id=org_id))
        rule_ids.append(rid)
    bench_id = bench.id
    await db.commit()
    return bench_id, rule_ids


async def _agent(db: AsyncSession, org_id: str, host: str, caps: list[str]) -> str:
    agent = EndpointAgent(hostname=host, status="active", capabilities=caps, os_type="linux", organization_id=org_id)
    db.add(agent)
    await db.commit()
    return agent.id


async def _report(db: AsyncSession, agent_id: str, command_id: str, **kwargs) -> None:
    agent = (await db.execute(select(EndpointAgent).where(EndpointAgent.id == agent_id))).scalar_one()
    cmd = (await db.execute(select(AgentCommand).where(AgentCommand.id == command_id))).scalar_one()
    cmd.status = "dispatched"
    await AgentService(db).ingest_result(agent=agent, command_id=command_id, **kwargs)
    await db.commit()


def test_stig_scan_action_is_capability_gated() -> None:
    assert capability_allows(["stig_scan"], "stig_scan")
    assert capability_allows(["compliance"], "stig_scan")
    assert not capability_allows(["bas", "ir"], "stig_scan")
    assert not requires_approval("stig_scan")


async def test_launch_without_an_agent_is_not_run_and_never_scored(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers, viewer_headers,
) -> None:
    org_id = org_a.id
    bench_id, _ = await _benchmark(db_session, org_id)
    for headers in (org_a_headers, viewer_headers):
        resp = await client.post(f"{BASE}/scans/launch", json={"host": "web-1", "benchmark_id": bench_id},
                                 headers=headers)
        assert resp.status_code == 403
    resp = await client.post(f"{BASE}/scans/launch", json={"host": "web-1", "benchmark_id": bench_id},
                             headers=org_a_admin_headers)
    assert resp.status_code == 202, resp.text
    body = resp.json()
    assert body["status"] == "not_run" and "no endpoint agent" in body["status_reason"]
    assert body["compliance_percentage"] is None

    scans = (await client.get(f"{BASE}/scans", headers=org_a_headers)).json()  # validates new statuses
    assert [s["status"] for s in scans] == ["not_run"]
    assert scans[0]["compliance_percentage"] == 0.0 and scans[0]["status_reason"]
    stats = (await client.get(f"{BASE}/dashboard/stats", headers=org_a_headers)).json()
    assert stats["average_compliance"] == 0.0 and stats["scans_not_run"] == 1
    assert stats["recent_scans"][0]["compliance"] is None
    audit = (await db_session.execute(select(func.count(AuditLog.id)).where(
        AuditLog.action == "stig_scan_launch", AuditLog.organization_id == org_id))).scalar()
    assert audit == 1


async def test_agent_without_the_capability_is_not_used(
    client: AsyncClient, db_session: AsyncSession, org_a, org_b, org_a_admin_headers,
) -> None:
    org_id, org_b_id = org_a.id, org_b.id
    bench_id, _ = await _benchmark(db_session, org_id)
    await _agent(db_session, org_id, "bas-host", ["bas"])
    await _agent(db_session, org_b_id, "other-tenant-host", ["stig_scan"])
    body = (await client.post(f"{BASE}/scans/launch", json={"host": "bas-host", "benchmark_id": bench_id},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "not_run" and "stig_scan" in body["status_reason"]
    body = (await client.post(f"{BASE}/scans/launch", json={"host": "other-tenant-host", "benchmark_id": bench_id},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "not_run"  # another tenant's agent is invisible
    other_bench, _ = await _benchmark(db_session, org_b_id)
    resp = await client.post(f"{BASE}/scans/launch", json={"host": "bas-host", "benchmark_id": other_bench},
                             headers=org_a_admin_headers)
    assert resp.status_code == 404


async def test_agent_arf_is_parsed_into_the_scan(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers,
) -> None:
    org_id = org_a.id
    bench_id, rules = await _benchmark(db_session, org_id)
    agent_id = await _agent(db_session, org_id, "rhel-1", ["stig_scan"])
    body = (await client.post(f"{BASE}/scans/launch", json={"host": "rhel-1", "benchmark_id": bench_id},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "dispatched", body
    cmd = (await db_session.execute(select(AgentCommand).where(AgentCommand.id == body["command_id"]))).scalar_one()
    assert cmd.action == "stig_scan" and cmd.payload["scan_id"] == body["scan_id"]
    command_id = cmd.id

    pending = (await client.get(f"{BASE}/scans/{body['scan_id']}", headers=org_a_headers)).json()
    assert pending["status"] == "dispatched" and pending["compliance_percentage"] == 0.0

    arf = _arf({rules[0]: "fail", rules[1]: "pass", rules[2]: "pass", rules[3]: "notapplicable"})
    await _report(db_session, agent_id, command_id, status="success", exit_code=2, stdout=arf)
    done = (await client.get(f"{BASE}/scans/{body['scan_id']}", headers=org_a_headers)).json()
    assert done["status"] == "completed"
    assert (done["open_findings"], done["not_a_finding"], done["not_applicable"]) == (1, 2, 1)
    assert done["cat1_open"] == 1
    assert round(done["compliance_percentage"], 2) == 66.67  # 2 pass of 3 applicable


async def test_agent_failure_and_garbage_fail_the_scan_via_the_reconcile_task(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers,
) -> None:
    org_id = org_a.id
    bench_id, _ = await _benchmark(db_session, org_id)
    agent_id = await _agent(db_session, org_id, "rhel-2", ["compliance"])
    first = (await client.post(f"{BASE}/scans/launch", json={"host": "rhel-2", "benchmark_id": bench_id},
                               headers=org_a_admin_headers)).json()
    second = (await client.post(f"{BASE}/scans/launch", json={"host": "rhel-2", "benchmark_id": bench_id},
                                headers=org_a_admin_headers)).json()
    await _report(db_session, agent_id, first["command_id"], status="failed", exit_code=1, stderr="oscap: not found")
    await _report(db_session, agent_id, second["command_id"], status="success", exit_code=0, stdout="not xml")

    totals = await reconcile_stig_scans_async(async_session_factory)
    assert totals["changed"] == 2
    db_session.expire_all()
    a = await db_session.get(STIGScanResult, first["scan_id"])
    b = await db_session.get(STIGScanResult, second["scan_id"])
    assert a.status == "failed" and "oscap: not found" in a.status_reason
    assert b.status == "failed" and "ARF" in b.status_reason
    assert a.compliance_percentage == 0.0 and b.compliance_percentage == 0.0


async def test_manual_scan_waits_for_an_arf_and_empty_arf_is_refused(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers, org_a_headers,
) -> None:
    bench_id, _ = await _benchmark(db_session, org_a.id)
    body = (await client.post(f"{BASE}/scans/launch",
                              json={"host": "h", "benchmark_id": bench_id, "scan_type": "manual"},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "pending_results"
    resp = await client.post(f"{BASE}/scans/{body['scan_id']}/arf", headers=org_a_headers,
                             files={"file": ("arf.xml", _arf({}).encode(), "application/xml")})
    assert resp.status_code == 400


async def test_scap_scan_and_builtin_loader_invent_nothing(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_admin_headers,
) -> None:
    org_id = org_a.id
    await _benchmark(db_session, org_id)
    profile = SCAPProfile(name="p", profile_type="xccdf", organization_id=org_id)
    db_session.add(profile)
    await db_session.commit()
    body = (await client.post(f"{BASE}/scap/scan", json={"profile_id": profile.id, "target": "h"},
                              headers=org_a_admin_headers)).json()
    assert body["status"] == "not_run"
    assert body["checks_passed"] == 0 and body["checks_failed"] == 0 and body["rules_in_profile"] == 4

    result = update_stig_benchmarks.apply(args=(org_id,)).get()
    assert result["status"] == "not_implemented" and result["benchmarks_added"] == 0
    count = (await db_session.execute(select(func.count(STIGBenchmark.id)).where(
        STIGBenchmark.organization_id == org_id))).scalar()
    assert count == 1
