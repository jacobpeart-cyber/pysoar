"""Tenancy and RBAC for the DFIR router (wave 1, docs/audit/2026-10-08/PLAN.md).

Covers: cases, evidence, timeline, artifacts and legal holds are scoped to the
caller's organisation; the case-number check no longer leaks which tenant
holds a number and a collision is a 409, not a 500; chain-of-custody actors,
case creators and hold issuers come from the session user, never the body;
legal holds can be created without ``data_sources``; releasing a hold is
admin-only; viewers are read-only; an org-less platform superuser is
refused; artifact analysis and the case report are honest 501s.
"""

from __future__ import annotations

import uuid
from typing import Any

from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.dfir.models import ForensicCase
from src.models.organization import Organization
from tests.helpers.tenancy import assert_tenant_isolated

BASE = "/api/v1/dfir"


def _case_number() -> str:
    return f"CASE-{uuid.uuid4().hex[:10]}"


async def _case(client: AsyncClient, headers: dict[str, str], number: str | None = None) -> str:
    resp = await client.post(
        f"{BASE}/cases",
        json={"case_number": number or _case_number(), "title": "tenancy", "severity": "medium"},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _evidence(client: AsyncClient, case_id: str, headers: dict[str, str]) -> str:
    resp = await client.post(
        f"{BASE}/evidence",
        json={
            "case_id": case_id,
            "evidence_type": "file",
            "source_device": "host-1",
            "storage_location": "https://evidence.example.test/obj",
            "original_hash_sha256": "a" * 64,
        },
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def _hold(client: AsyncClient, case_id: str, headers: dict[str, str]) -> str:
    resp = await client.post(
        f"{BASE}/cases/{case_id}/legal-holds",
        json={"hold_type": "litigation", "custodians": ["alice"], "data_sources": ["mailbox"]},
        headers=headers,
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def _error_key(resp: Any) -> str:
    detail = resp.json().get("detail")
    return detail.get("error", "") if isinstance(detail, dict) else str(detail)


def _entries(evidence_json: dict[str, Any]) -> list[dict[str, Any]]:
    log = evidence_json["chain_of_custody_log"]
    return log["entries"] if isinstance(log, dict) else log


async def test_dfir_routes_are_tenant_isolated(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str]
) -> None:
    case_id = await _case(client, org_a_headers)
    evidence_id = await _evidence(client, case_id, org_a_headers)
    hold_id = await _hold(client, case_id, org_a_headers)

    for method, path, body in [
        ("GET", f"{BASE}/cases/{case_id}", None),
        ("PUT", f"{BASE}/cases/{case_id}", {"title": "stolen"}),
        ("POST", f"{BASE}/cases/{case_id}/close", None),
        ("GET", f"{BASE}/cases/{case_id}/evidence", None),
        ("POST", f"{BASE}/evidence", {"case_id": case_id, "evidence_type": "file", "source_device": "x"}),
        ("GET", f"{BASE}/evidence/{evidence_id}", None),
        ("GET", f"{BASE}/evidence/{evidence_id}/download", None),
        ("POST", f"{BASE}/evidence/{evidence_id}/verify", {"evidence_hash": "a" * 64}),
        ("POST", f"{BASE}/evidence/{evidence_id}/chain-of-custody", {"action": "x"}),
        ("GET", f"{BASE}/evidence/{evidence_id}/chain-of-custody", None),
        ("GET", f"{BASE}/cases/{case_id}/timeline", None),
        ("POST", f"{BASE}/cases/{case_id}/timeline/events", {"event_type": "x", "source": "y", "description": "z"}),
        ("POST", f"{BASE}/cases/{case_id}/timeline/export", None),
        ("GET", f"{BASE}/cases/{case_id}/artifacts", None),
        ("POST", f"{BASE}/cases/{case_id}/artifacts/extract-iocs", None),
        ("GET", f"{BASE}/cases/{case_id}/legal-holds", None),
        ("POST", f"{BASE}/cases/{case_id}/legal-holds", {"custodians": ["x"]}),
        ("PUT", f"{BASE}/legal-holds/{hold_id}", {"status": "released"}),
        ("GET", f"{BASE}/cases/{case_id}/report", None),
        ("GET", f"{BASE}/cases/{case_id}/metrics", None),
    ]:
        await assert_tenant_isolated(client, method, path, org_b_headers, json=body)

    listing = await client.get(f"{BASE}/cases", headers=org_b_headers)
    assert listing.status_code == 200
    assert case_id not in {c["id"] for c in listing.json()["items"]}
    dash_b = await client.get(f"{BASE}/dashboard/metrics", headers=org_b_headers)
    dash_a = await client.get(f"{BASE}/dashboard/metrics", headers=org_a_headers)
    assert dash_b.status_code == dash_a.status_code == 200
    assert dash_b.json()["total_cases"] == 0
    assert dash_a.json()["total_cases"] >= 1


async def test_case_number_collision_across_tenants_is_a_409_not_a_500(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str]
) -> None:
    number = _case_number()
    await _case(client, org_a_headers, number)

    own = await client.post(
        f"{BASE}/cases", json={"case_number": number, "title": "dup"}, headers=org_a_headers
    )
    other = await client.post(
        f"{BASE}/cases", json={"case_number": number, "title": "dup"}, headers=org_b_headers
    )
    assert own.status_code == other.status_code == 409
    # Same message whichever tenant holds the number: nothing about the other
    # tenant's case is revealed.
    assert own.json() == other.json()
    assert "tenancy" not in other.text


async def test_case_creator_comes_from_the_session(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_user: Any,
    org_b_user: Any,
    org_a_headers: dict[str, str],
) -> None:
    org_a_id, user_id, foreign_user = org_a.id, org_a_user.id, org_b_user.id
    resp = await client.post(
        f"{BASE}/cases",
        json={"case_number": _case_number(), "title": "t", "created_by": "forged"},
        headers=org_a_headers,
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["created_by"] == user_id
    row = (await db_session.execute(select(ForensicCase).where(ForensicCase.id == resp.json()["id"]))).scalar_one()
    assert row.organization_id == org_a_id

    # A lead investigator from another tenant is refused.
    resp = await client.post(
        f"{BASE}/cases",
        json={"case_number": _case_number(), "title": "t", "lead_investigator_id": foreign_user},
        headers=org_a_headers,
    )
    assert resp.status_code == 400, resp.text


async def test_custody_actor_is_the_session_user(
    client: AsyncClient, org_a_user: Any, org_a_headers: dict[str, str]
) -> None:
    actor = org_a_user.full_name or org_a_user.email
    case_id = await _case(client, org_a_headers)
    evidence_id = await _evidence(client, case_id, org_a_headers)

    resp = await client.post(
        f"{BASE}/evidence/{evidence_id}/chain-of-custody",
        json={"actor": "Forged Person", "action": "transferred", "details": "to lab"},
        headers=org_a_headers,
    )
    assert resp.status_code == 200, resp.text
    entries = _entries(resp.json())
    assert entries[-1]["action"] == "transferred"
    assert entries[-1]["actor"] == actor
    assert all(e["actor"] != "Forged Person" for e in entries)

    report = await client.get(f"{BASE}/evidence/{evidence_id}/chain-of-custody", headers=org_a_headers)
    assert report.status_code == 200, report.text
    assert [e["actor"] for e in report.json()["log_entries"]][-1] == actor


async def test_legal_hold_without_data_sources_and_release_is_admin_only(
    client: AsyncClient,
    org_a_admin: Any,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    admin_actor = org_a_admin.full_name or org_a_admin.email
    case_id = await _case(client, org_a_headers)

    # The UI's payload (no data_sources, extra fields) is accepted.
    resp = await client.post(
        f"{BASE}/cases/{case_id}/legal-holds",
        json={"hold_type": "litigation", "custodians": ["alice"], "issued_by": "forged", "scope": "all"},
        headers=org_a_admin_headers,
    )
    assert resp.status_code == 201, resp.text
    hold = resp.json()
    assert hold["data_sources"] == []
    assert hold["issued_by"] == admin_actor
    hold_id = hold["id"]

    # Analysts may edit a hold but not release it, nor clear the case flag.
    edit = await client.put(f"{BASE}/legal-holds/{hold_id}", json={"custodians": ["alice", "bob"]}, headers=org_a_headers)
    assert edit.status_code == 200, edit.text
    release = await client.put(f"{BASE}/legal-holds/{hold_id}", json={"status": "released"}, headers=org_a_headers)
    assert release.status_code == 403, release.text
    clear = await client.put(f"{BASE}/cases/{case_id}", json={"legal_hold_active": False}, headers=org_a_headers)
    assert clear.status_code == 403, clear.text

    release = await client.put(f"{BASE}/legal-holds/{hold_id}", json={"status": "released"}, headers=org_a_admin_headers)
    assert release.status_code == 200, release.text
    assert release.json()["status"] == "released"


async def test_viewers_cannot_write(
    client: AsyncClient, org_a_headers: dict[str, str], viewer_headers: dict[str, str]
) -> None:
    case_id = await _case(client, org_a_headers)
    evidence_id = await _evidence(client, case_id, org_a_headers)
    hold_id = await _hold(client, case_id, org_a_headers)

    for method, path, body in [
        ("POST", f"{BASE}/cases", {"case_number": _case_number(), "title": "v"}),
        ("PUT", f"{BASE}/cases/{case_id}", {"title": "v"}),
        ("POST", f"{BASE}/cases/{case_id}/close", None),
        ("POST", f"{BASE}/evidence", {"case_id": case_id, "evidence_type": "file", "source_device": "x"}),
        ("POST", f"{BASE}/evidence/{evidence_id}/verify", {"evidence_hash": "a" * 64}),
        ("POST", f"{BASE}/evidence/{evidence_id}/chain-of-custody", {"action": "x"}),
        ("POST", f"{BASE}/cases/{case_id}/timeline/events", {"event_type": "x", "source": "y", "description": "z"}),
        ("POST", f"{BASE}/cases/{case_id}/artifacts", {"evidence_id": evidence_id, "artifact_type": "x"}),
        ("POST", f"{BASE}/artifacts/analyze", {"artifact_type": "disk_mft_entry", "artifact_data": {}}),
        ("POST", f"{BASE}/cases/{case_id}/legal-holds", {"custodians": ["x"]}),
        ("PUT", f"{BASE}/legal-holds/{hold_id}", {"custodians": ["x"]}),
    ]:
        resp = await client.request(method, path, json=body, headers=viewer_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code} {resp.text[:200]}"

    for path in (f"{BASE}/cases", f"{BASE}/cases/{case_id}", f"{BASE}/cases/{case_id}/evidence", f"{BASE}/dashboard/metrics"):
        assert (await client.get(path, headers=viewer_headers)).status_code == 200, path


async def test_orgless_superuser_is_refused(client: AsyncClient, superuser_headers: dict[str, str]) -> None:
    for method, path, body in [
        ("GET", f"{BASE}/cases", None),
        ("GET", f"{BASE}/dashboard/metrics", None),
        ("POST", f"{BASE}/cases", {"case_number": _case_number(), "title": "su"}),
    ]:
        resp = await client.request(method, path, json=body, headers=superuser_headers)
        assert resp.status_code == 403, f"{method} {path}: {resp.status_code}"
        assert _error_key(resp) == "organization_required"


async def test_fake_routes_are_honest_501s(client: AsyncClient, org_a_headers: dict[str, str]) -> None:
    case_id = await _case(client, org_a_headers)

    resp = await client.post(
        f"{BASE}/artifacts/analyze",
        json={"artifact_type": "disk_mft_entry", "artifact_data": {"entries": []}},
        headers=org_a_headers,
    )
    assert resp.status_code == 501, resp.text
    assert _error_key(resp) == "not_implemented"

    resp = await client.get(f"{BASE}/cases/{case_id}/report", headers=org_a_headers)
    assert resp.status_code == 501, resp.text
    assert _error_key(resp) == "not_implemented"
