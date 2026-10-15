"""Wave 4 (W4-C): Zero Trust maturity, device posture and per-tenant device ids.

docs/audit/2026-10-08/posture-risk.md (ZeroTrustDashboard): the maturity
scorer granted free baseline points to every pillar, the device list had no
compliance fields (every card rendered red "Non-Compliant"), agent posture
carried hard-coded ``certificate_valid=True`` / ``jailbroken=False``, and
``device_trust_profiles.device_id`` was globally unique, so the compliance
upsert had to be removed.
"""

from __future__ import annotations

import json
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent
from src.models.audit import AuditLog
from src.models.organization import Organization
from src.zerotrust.engine import DeviceTrustAssessor, ZeroTrustScorer, device_posture
from src.zerotrust.models import DeviceTrustProfile, MicroSegment, ZeroTrustPolicy

API = "/api/v1/zerotrust"
FULL_POSTURE = {"os_patched": True, "av_active": True, "encryption_enabled": True, "firewall_on": True}


async def test_unconfigured_tenant_scores_zero_everywhere(db_session: AsyncSession, org_a: Organization) -> None:
    maturity = await ZeroTrustScorer(db_session, org_a.id).calculate_maturity_score()
    assert maturity["overall_score"] == 0
    assert maturity["maturity_level"] == "traditional"
    assert maturity["configured_pillars"] == 0
    for name, pillar in maturity["pillars"].items():
        assert pillar["score"] == 0, name
        assert pillar["status"] == "not_configured", name
        assert sum(c["weight"] for c in pillar["criteria"]) == 100, name


async def test_maturity_follows_real_configuration(db_session: AsyncSession, org_a: Organization) -> None:
    org_id = org_a.id
    segment = MicroSegment(organization_id=org_id, name="ot", segment_type="network",
                           cidr_ranges=json.dumps(["10.0.0.0/24"]))
    db_session.add(segment)
    await db_session.flush()
    db_session.add(ZeroTrustPolicy(organization_id=org_id, name="idp", policy_type="identity", requires_mfa=True,
                                   microsegment_id=segment.id))
    db_session.add(ZeroTrustPolicy(organization_id=org_id, name="app", policy_type="access", requires_mfa=False,
                                   requires_device_trust=True, conditions=json.dumps([{"attribute": "a"}])))
    await db_session.commit()

    scorer = ZeroTrustScorer(db_session, org_id)
    identity = await scorer.assess_pillar("identity")
    # identity policy present (30) + MFA on 1 of 2 enabled policies (20); no sessions evaluated.
    assert identity["score"] == 50.0
    assert identity["status"] == "assessed"
    networks = await scorer.assess_pillar("networks")
    assert networks["score"] == 100.0
    applications = await scorer.assess_pillar("applications")
    assert applications["score"] == 100.0
    devices = await scorer.assess_pillar("devices")
    assert devices["score"] == 0 and devices["status"] == "not_configured"


async def test_device_without_posture_is_not_reported_not_non_compliant(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_headers: dict[str, str],
) -> None:
    device = DeviceTrustProfile(organization_id=org_a.id, device_id=f"d-{uuid.uuid4().hex[:6]}",
                                device_type="laptop", trust_level="untrusted")
    db_session.add(device)
    await db_session.commit()
    device_id = device.device_id

    assessed = await client.post(f"{API}/devices/{device_id}/assess", headers=org_a_headers)
    assert assessed.status_code == 200, assessed.text
    body = assessed.json()
    assert body["trust_level"] == "unknown"
    assert body["posture_status"] == "not_reported"
    assert body["is_compliant"] is None
    assert set(body["compliance_checks"].values()) == {"not_reported"}

    listed = (await client.get(f"{API}/devices", headers=org_a_headers)).json()["devices"]
    row = next(d for d in listed if d["device_id"] == device_id)
    assert row["is_compliant"] is None and row["posture_status"] == "not_reported"
    assert "compliance_checks" in row and "os_type" in row and "last_seen_at" in row

    stats = (await client.get(f"{API}/device-stats", headers=org_a_headers)).json()
    assert stats["not_reported"] == 1
    dash = (await client.get(f"{API}/dashboard", headers=org_a_headers)).json()
    assert dash["not_reported_devices"] == 1
    assert dash["non_compliant_devices"] == 0
    noncompliant = (await client.get(f"{API}/devices/non-compliant", headers=org_a_headers)).json()
    assert noncompliant["count"] == 0


async def test_agent_posture_upserts_in_tenant_and_ignores_unmeasured_checks(
    db_session: AsyncSession, org_a: Organization,
) -> None:
    agent = EndpointAgent(hostname="ws-1", os_type="linux", os_version="6.1", status="active",
                          capabilities=["ir"], organization_id=org_a.id)
    db_session.add(agent)
    await db_session.commit()
    agent_id = agent.id

    # Exactly what the heartbeat handler sends (agents.py): two constants it never measured.
    device = await DeviceTrustAssessor(db_session, org_a.id).update_device_compliance(
        device_id=agent_id,
        compliance_data={**FULL_POSTURE, "certificate_valid": True, "jailbroken": False, "last_posture_at": "x"},
    )
    posture = device_posture(device)
    assert device.organization_id == org_a.id
    assert device.hostname == "ws-1" and device.os_type == "linux"
    assert device.last_seen_at is not None
    assert posture["posture_source"] == "agent"
    assert posture["compliance_checks"]["certificate_valid"] == "not_reported"
    assert posture["compliance_checks"]["jailbroken"] == "not_reported"
    assert posture["is_compliant"] is True
    assert device.trust_score == 90.0  # the 10 certificate points are not earned
    assert device.trust_level == "trusted"


async def test_device_id_is_unique_per_organisation(
    db_session: AsyncSession, org_a: Organization, org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    db_session.add(DeviceTrustProfile(organization_id=org_a_id, device_id="shared-host", device_type="server"))
    db_session.add(DeviceTrustProfile(organization_id=org_b_id, device_id="shared-host", device_type="server"))
    await db_session.commit()
    db_session.add(DeviceTrustProfile(organization_id=org_a_id, device_id="shared-host", device_type="server"))
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


async def test_admin_override_upserts_within_tenant_and_is_audited(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    device_id = f"new-{uuid.uuid4().hex[:6]}"
    resp = await client.put(f"{API}/devices/{device_id}/compliance",
                            json={**FULL_POSTURE, "certificate_valid": True}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["device_id"] == device_id
    assert body["posture_source"] == "admin_override"
    assert body["compliance_checks"]["certificate_valid"] is True
    assert body["trust_score"] == 100.0
    rows = (await db_session.execute(
        select(DeviceTrustProfile).where(DeviceTrustProfile.device_id == device_id),
    )).scalars().all()
    assert [r.organization_id for r in rows] == [org_a_id]
    audit = (await db_session.execute(
        select(AuditLog).where(AuditLog.action == "zerotrust_device_compliance_override",
                               AuditLog.organization_id == org_a_id),
    )).scalars().all()
    assert len(audit) == 1

    detail = await client.get(f"{API}/devices/{device_id}", headers=org_a_admin_headers)
    assert detail.status_code == 200
    assert detail.json()["is_compliant"] is True
    assert "_source" not in detail.json()["compliance_status"]
