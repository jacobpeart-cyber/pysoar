"""Wave 1 tenancy / RBAC conversion of the Zero Trust router and engine.

docs/audit/2026-10-08/posture-risk.md: the maturity scorer counted every
tenant's detection rules, logs and playbooks; continuous evaluation found
sessions across organisations; any user could override a device's
compliance posture (a PDP device-trust bypass) or rewrite access policies
and segments; assessing an unknown device created a phantom "blocked"
profile; and ``/step-up`` returned a challenge id although no challenge was
ever issued. The ``/evaluate-access`` alias must pass the caller's
organisation into the PDP so decisions are recorded for, and policies are
drawn from, the caller's tenant only.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.organization import Organization
from src.models.playbook import Playbook
from src.siem.models import DetectionRule, RuleStatus
from src.zerotrust.engine import ZeroTrustScorer
from src.zerotrust.models import AccessDecision, DeviceTrustProfile, MicroSegment, ZeroTrustPolicy
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/zerotrust"

ACCESS_REQUEST: dict[str, Any] = {
    "subject_type": "user",
    "subject_id": "alice",
    "resource_type": "application",
    "resource_id": "payroll",
    "context": {},
}
POLICY_BODY: dict[str, Any] = {"name": "allow-all", "policy_type": "access"}
SEGMENT_BODY: dict[str, Any] = {"name": "dmz", "segment_type": "network", "cidr_ranges": ["10.0.0.0/24"]}


@pytest.fixture(autouse=True)
def _no_session_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Evaluations must never touch the session gate; keep Redis out of it."""
    import src.zerotrust.session_gate as gate

    async def _noop(*_args: Any) -> None:
        return None

    monkeypatch.setattr(gate, "invalidate_session_cache", _noop)


async def _allow_policy(db: AsyncSession, org_id: str) -> str:
    policy = ZeroTrustPolicy(
        organization_id=org_id, name="allow everything", policy_type="access",
        conditions="[]", actions='["allow"]', risk_threshold=100.0,
        requires_mfa=False, requires_device_trust=False, priority=100,
    )
    db.add(policy)
    await db.commit()
    return policy.id


async def _device(db: AsyncSession, org_id: str) -> str:
    device = DeviceTrustProfile(
        organization_id=org_id, device_id=f"dev-{uuid.uuid4().hex[:10]}", device_type="laptop",
    )
    db.add(device)
    await db.commit()
    return device.device_id


async def _segment(db: AsyncSession, org_id: str) -> str:
    segment = MicroSegment(
        organization_id=org_id, name="seg", segment_type="network", cidr_ranges='["10.1.0.0/24"]',
    )
    db.add(segment)
    await db.commit()
    return segment.id


# ---------------------------------------------------------------------------
# /evaluate-access alias is tenant-scoped
# ---------------------------------------------------------------------------


async def test_evaluate_access_alias_records_and_decides_in_callers_tenant(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    b_policy = await _allow_policy(db_session, org_b_id)

    # Sanity: org B's own policy allows this request for org B.
    as_b = await client.post(f"{API}/evaluate-access", json=ACCESS_REQUEST, headers=org_b_headers)
    assert as_b.status_code == 200, as_b.text
    assert as_b.json()["decision"] == "allow"

    # Org A has no policies: org B's allow policy must not apply.
    as_a = await client.post(f"{API}/evaluate-access", json=ACCESS_REQUEST, headers=org_a_headers)
    assert as_a.status_code == 200, as_a.text
    assert as_a.json()["decision"] == "deny"
    decision_id = as_a.json()["id"]

    row = (await db_session.execute(select(AccessDecision).where(AccessDecision.id == decision_id))).scalar_one()
    assert row.organization_id == org_a_id
    assert row.policy_id is None

    await db_session.refresh(await db_session.get(ZeroTrustPolicy, b_policy))
    assert (await db_session.get(ZeroTrustPolicy, b_policy)).hit_count == 1

    b_decisions = await client.get(f"{API}/decisions", headers=org_b_headers)
    assert decision_id not in {d["id"] for d in b_decisions.json()["decisions"]}
    a_decisions = await client.get(f"{API}/decisions", headers=org_a_headers)
    assert decision_id in {d["id"] for d in a_decisions.json()["decisions"]}


async def test_continuous_eval_does_not_find_other_tenants_sessions(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_headers: dict[str, str],
) -> None:
    db_session.add(AccessDecision(
        organization_id=org_b.id, subject_type="user", subject_id="bob", resource_type="application",
        resource_id="crm", decision="allow", risk_score=0.0, context="{}", session_id="b-session",
        decision_reason="seeded",
    ))
    await db_session.commit()
    resp = await client.post(f"{API}/continuous-eval/b-session", headers=org_a_headers)
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# isolation of policies, devices and segments
# ---------------------------------------------------------------------------


async def test_policy_created_by_admin_is_stamped_and_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_admin_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    resp = await client.post(f"{API}/policies", json=POLICY_BODY, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    policy_id = resp.json()["id"]
    row = await db_session.get(ZeroTrustPolicy, policy_id)
    assert row is not None and row.organization_id == org_a_id

    listing = await client.get(f"{API}/policies", headers=org_b_headers)
    assert policy_id not in {p["id"] for p in listing.json()["policies"]}
    await assert_tenant_isolated(client, "GET", f"{API}/policies/{policy_id}", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{API}/policies/{policy_id}/test", org_b_headers,
                                 json=ACCESS_REQUEST)


async def test_policy_cannot_reference_another_tenants_segment(
    client: AsyncClient,
    db_session: AsyncSession,
    org_b: Organization,
    org_a_admin_headers: dict[str, str],
) -> None:
    foreign = await _segment(db_session, org_b.id)
    resp = await client.post(
        f"{API}/policies", json={**POLICY_BODY, "microsegment_id": foreign}, headers=org_a_admin_headers,
    )
    assert resp.status_code == 422, resp.text
    assert resp.json()["detail"]["field"] == "microsegment_id"


async def test_devices_and_segments_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
    org_b_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    org_a_id = org_a.id
    org_b_id = org_b.id
    device_id = await _device(db_session, org_a_id)
    segment_id = await _segment(db_session, org_a_id)

    devices = await client.get(f"{API}/devices", headers=org_b_headers)
    assert device_id not in {d["device_id"] for d in devices.json()["devices"]}
    segments = await client.get(f"{API}/segments", headers=org_b_headers)
    assert segment_id not in {s["id"] for s in segments.json()["segments"]}

    await assert_tenant_isolated(client, "GET", f"{API}/devices/{device_id}", org_b_headers)
    await assert_tenant_isolated(client, "POST", f"{API}/devices/{device_id}/assess", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{API}/segments/{segment_id}", org_b_headers)
    await assert_tenant_isolated(client, "GET", f"{API}/segments/{segment_id}/violations", org_b_headers)
    await assert_tenant_isolated(
        client, "POST", f"{API}/segments/{segment_id}/evaluate-traffic", org_b_headers,
        json={"source": "10.1.0.5", "destination": "10.1.0.6", "protocol": "tcp", "port": 22},
    )

    # Org B's admin-only writes against org A's rows are isolated as well.
    from tests.helpers.tenancy import bearer, make_user

    b_admin_user = await make_user(db_session, role="admin", organization_id=org_b_id, label="admin-b")
    b_admin = bearer(b_admin_user)
    await assert_tenant_isolated(client, "PUT", f"{API}/segments/{segment_id}", b_admin, json={"name": "x"})
    await assert_tenant_isolated(client, "DELETE", f"{API}/segments/{segment_id}", b_admin)
    a_policy = await _allow_policy(db_session, org_a_id)
    await assert_tenant_isolated(client, "PUT", f"{API}/policies/{a_policy}", b_admin, json={"name": "x"})
    await assert_tenant_isolated(client, "DELETE", f"{API}/policies/{a_policy}", b_admin)
    # Device compliance for org A's device id: since migration 032 device ids
    # are unique per organisation and the override is an upsert within the
    # caller's tenant, so org B's admin creates org B's own profile and org A's
    # row is untouched (wave 4; previously a 404 because the id was global).
    a_before = (await db_session.execute(
        select(DeviceTrustProfile.compliance_status).where(
            DeviceTrustProfile.device_id == device_id, DeviceTrustProfile.organization_id == org_a_id,
        ),
    )).scalar_one()
    foreign = await client.put(f"{API}/devices/{device_id}/compliance", json={"av_active": True}, headers=b_admin)
    assert foreign.status_code == 200, foreign.text
    rows = (await db_session.execute(
        select(DeviceTrustProfile).where(DeviceTrustProfile.device_id == device_id),
    )).scalars().all()
    assert sorted(r.organization_id for r in rows) == sorted([org_a_id, org_b_id])
    a_after = (await db_session.execute(
        select(DeviceTrustProfile.compliance_status).where(
            DeviceTrustProfile.device_id == device_id, DeviceTrustProfile.organization_id == org_a_id,
        ),
    )).scalar_one()
    assert a_after == a_before
    _ = org_a_admin_headers


async def test_assessing_unknown_device_does_not_create_a_phantom(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a_headers: dict[str, str],
) -> None:
    ghost = f"ghost-{uuid.uuid4().hex[:8]}"
    resp = await client.post(f"{API}/devices/{ghost}/assess", headers=org_a_headers)
    assert resp.status_code == 404, resp.text
    rows = (await db_session.execute(
        select(DeviceTrustProfile).where(DeviceTrustProfile.device_id == ghost),
    )).scalars().all()
    assert rows == []


# ---------------------------------------------------------------------------
# maturity scorer counts only the caller's tenant
# ---------------------------------------------------------------------------


async def test_maturity_does_not_count_other_tenants_rules_or_playbooks(
    db_session: AsyncSession,
    org_a: Organization,
    org_b: Organization,
) -> None:
    org_a_id, org_b_id = org_a.id, org_b.id
    for i in range(3):
        db_session.add(DetectionRule(
            organization_id=org_b_id, name=f"b-rule-{i}-{uuid.uuid4().hex[:6]}", title="t",
            rule_yaml="title: t", status=RuleStatus.ACTIVE.value,
        ))
        db_session.add(Playbook(organization_id=org_b_id, name=f"b-pb-{i}", is_enabled=True, steps="[]"))
    await db_session.commit()

    scorer = ZeroTrustScorer(db_session, org_a_id)
    visibility = await scorer.assess_pillar("visibility")
    automation = await scorer.assess_pillar("automation")
    assert visibility["details"]["active_detection_rules"] == 0
    assert automation["details"]["enabled_playbooks"] == 0

    b_visibility = await ZeroTrustScorer(db_session, org_b_id).assess_pillar("visibility")
    assert b_visibility["details"]["active_detection_rules"] == 3


# ---------------------------------------------------------------------------
# roles
# ---------------------------------------------------------------------------


ANALYST_WRITES = [
    ("POST", "evaluate", ACCESS_REQUEST),
    ("POST", "evaluate-access", ACCESS_REQUEST),
    ("POST", "continuous-eval/s1", None),
    ("POST", "policies/x/test", ACCESS_REQUEST),
    ("POST", "assess-devices", {}),
    ("POST", "devices/x/assess", None),
    ("POST", "verify", {"user_id": "u", "verification_type": "mfa"}),
]
ADMIN_WRITES = [
    ("POST", "policies", POLICY_BODY),
    ("PUT", "policies/x", {"name": "y"}),
    ("DELETE", "policies/x", None),
    ("PUT", "devices/x/compliance", {"av_active": True}),
    ("POST", "segments", SEGMENT_BODY),
    ("PUT", "segments/x", {"name": "y"}),
    ("DELETE", "segments/x", None),
]


@pytest.mark.parametrize(("method", "path", "body"), ANALYST_WRITES + ADMIN_WRITES)
async def test_viewer_cannot_write(
    client: AsyncClient, viewer_headers: dict[str, str], method: str, path: str, body: Any,
) -> None:
    resp = await client.request(method, f"{API}/{path}", json=body, headers=viewer_headers)
    assert resp.status_code == 403, resp.text


@pytest.mark.parametrize(("method", "path", "body"), ADMIN_WRITES)
async def test_analyst_cannot_configure(
    client: AsyncClient, org_a_headers: dict[str, str], method: str, path: str, body: Any,
) -> None:
    resp = await client.request(method, f"{API}/{path}", json=body, headers=org_a_headers)
    assert resp.status_code == 403, resp.text


async def test_device_compliance_override_is_admin_only(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    device_id = await _device(db_session, org_a.id)
    body = {"os_patched": True, "av_active": True, "encryption_enabled": True, "firewall_on": True}
    refused = await client.put(f"{API}/devices/{device_id}/compliance", json=body, headers=org_a_headers)
    assert refused.status_code == 403, refused.text
    ok = await client.put(f"{API}/devices/{device_id}/compliance", json=body, headers=org_a_admin_headers)
    assert ok.status_code == 200, ok.text


async def test_viewer_can_read_and_evaluate_traffic(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    viewer_headers: dict[str, str],
) -> None:
    segment_id = await _segment(db_session, org_a.id)
    for path in ("decisions", "policies", "devices", "device-stats", "segments", "topology",
                 "verifications", "maturity", "dashboard"):
        resp = await client.get(f"{API}/{path}", headers=viewer_headers)
        assert resp.status_code == 200, (path, resp.text)
    # Read-only computation: persists nothing.
    traffic = await client.post(
        f"{API}/segments/{segment_id}/evaluate-traffic", headers=viewer_headers,
        json={"source": "10.1.0.5", "destination": "10.9.0.6", "protocol": "tcp", "port": 22},
    )
    assert traffic.status_code == 200, traffic.text


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    resp = await client.get(f"{API}/policies", headers=superuser_headers)
    assert resp.status_code == 403, resp.text
    assert resp.json()["detail"]["error"] == "organization_required"


# ---------------------------------------------------------------------------
# honest 501
# ---------------------------------------------------------------------------


async def test_step_up_is_honest_not_implemented(client: AsyncClient, org_a_headers: dict[str, str]) -> None:
    resp = await client.post(f"{API}/step-up/s1", params={"required_level": "mfa"}, headers=org_a_headers)
    assert resp.status_code == 501, resp.text
    assert resp.json()["detail"]["error"] == "not_implemented"
