"""Wave 4 (W4-E): privacy workflows over stored rows.

DSRs are request rows with deadlines and a status workflow; identity
verification is a recorded attestation; search / export read the subject's
rows from every model holding personal data (tenant-scoped, secrets never
exported, CSV formula-safe); erasure anonymises / redacts / deletes per
source with an audit trail and retains what the law requires; PIA / ROPA /
incident fields the forms send are stored; notification deadlines follow
the recorded regulations; the dashboard compliance rate is computed from
closed requests against their deadlines; the deadline sweep stamps breaches.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.darkweb.models import CredentialLeak
from src.itdr.models import IdentityProfile
from src.models.alert import Alert
from src.models.audit import AuditLog
from src.models.user import User
from src.phishing_sim.models import PhishingTarget, SecurityAwarenessScore
from src.privacy.models import ConsentRecord, DataSubjectRequest
from src.privacy.tasks import _dsr_deadline_sweep
from src.workers.celery_app import celery_app
from tests.helpers.tenancy import make_user

BASE = "/api/v1/privacy"


async def _dsr(client: AsyncClient, headers: dict[str, str], email: str, request_type: str = "access",
               **extra) -> dict:
    body = {"request_type": request_type, "regulation": "gdpr", "subject_name": "Jane Subject",
            "subject_email": email}
    body.update(extra)
    resp = await client.post(f"{BASE}/dsr/requests", json=body, headers=headers)
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _verify(client: AsyncClient, headers: dict[str, str], dsr_id: str) -> dict:
    resp = await client.post(
        f"{BASE}/dsr/requests/{dsr_id}/verify-identity",
        json={"verification_method": "email_challenge", "evidence": "ticket SEC-42"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _seed_subject(db: AsyncSession, org_id: str, email: str) -> dict[str, str]:
    user = await make_user(db, role="analyst", organization_id=org_id, label="subject")
    user.email = email
    identity = IdentityProfile(id=str(uuid.uuid4()), organization_id=org_id, user_id="jsubject",
                               username="jsubject", email=email, display_name="Jane Subject")
    alert = Alert(id=str(uuid.uuid4()), title=f"Suspicious login for {email}",
                  description=f"user {email} logged in from a new country", organization_id=org_id)
    target = PhishingTarget(id=str(uuid.uuid4()), campaign_id=str(uuid.uuid4()), recipient_email=email,
                            recipient_name="Jane Subject", tracking_id=uuid.uuid4().hex,
                            organization_id=org_id)
    score = SecurityAwarenessScore(id=str(uuid.uuid4()), user_email=email, user_name="Jane Subject",
                                   organization_id=org_id)
    leak = CredentialLeak(id=str(uuid.uuid4()), organization_id=org_id, finding_id=str(uuid.uuid4()),
                          email=email)
    consent = ConsentRecord(id=str(uuid.uuid4()), organization_id=org_id, subject_id=email,
                            purpose="newsletter", legal_basis="consent")
    db.add_all([identity, alert, target, score, leak, consent])
    ids = {"user": user.id, "identity": identity.id, "alert": alert.id, "target": target.id,
           "score": score.id, "leak": leak.id, "consent": consent.id}
    await db.commit()
    return ids


# ---------------------------------------------------------------------------
# DSR rows, deadlines and the workflow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_stores_description_deadline_and_audit(
    client: AsyncClient, db_session: AsyncSession, org_a_headers: dict[str, str],
) -> None:
    dsr = await _dsr(client, org_a_headers, "jane@example.com", description="Wants a copy of her data")
    assert dsr["processing_notes"] == "Wants a copy of her data"
    assert dsr["deadline"] and dsr["days_remaining"] in (29, 30) and dsr["overdue"] is False
    audits = (await db_session.execute(
        select(func.count(AuditLog.id)).where(AuditLog.action == "privacy.dsr_create")
    )).scalar()
    assert audits == 1


@pytest.mark.asyncio
async def test_status_workflow_is_enforced(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    dsr = await _dsr(client, org_a_headers, "flow@example.com")
    url = f"{BASE}/dsr/requests/{dsr['id']}"
    # identity_verified only through verify-identity (with evidence)
    resp = await client.patch(url, json={"status": "identity_verified"}, headers=org_a_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "verification_required"
    resp = await client.post(f"{url}/verify-identity", params={"verification_method": "email"},
                             headers=org_a_headers)
    assert resp.status_code == 422
    # skipping steps is refused
    resp = await client.patch(url, json={"status": "completed"}, headers=org_a_headers)
    assert resp.status_code == 409 and resp.json()["detail"]["error"] == "invalid_transition"
    verified = await _verify(client, org_a_headers, dsr["id"])
    assert verified["status"] == "identity_verified" and verified["identity_verified_at"]
    assert verified["identity_verification_method"] == "email_challenge"
    # denial needs a reason
    resp = await client.patch(url, json={"status": "denied"}, headers=org_a_headers)
    assert resp.status_code == 422
    resp = await client.patch(url, json={"status": "denied", "denial_reason": "manifestly unfounded"},
                              headers=org_a_headers)
    assert resp.status_code == 200 and resp.json()["completed_at"]


@pytest.mark.asyncio
async def test_export_requires_verification_and_returns_only_this_tenants_rows(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a,
    org_b,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    email = f"jane-{uuid.uuid4().hex[:6]}@example.com"
    org_a_id, org_b_id = org_a.id, org_b.id
    ids_a = await _seed_subject(db_session, org_a_id, email)
    db_session.add(CredentialLeak(id=str(uuid.uuid4()), organization_id=org_b_id,
                                  finding_id=str(uuid.uuid4()), email=email))
    await db_session.commit()

    dsr = await _dsr(client, org_a_headers, email)
    url = f"{BASE}/dsr/requests/{dsr['id']}"
    early = await client.post(f"{url}/compile-data", headers=org_a_headers)
    assert early.status_code == 409 and early.json()["detail"]["error"] == "identity_not_verified"
    await _verify(client, org_a_headers, dsr["id"])

    assert (await client.post(f"{url}/search-systems", headers=viewer_headers)).status_code == 403
    assert (await client.post(f"{url}/search-systems", headers=org_b_headers)).status_code in (403, 404)
    search = await client.post(f"{url}/search-systems", headers=org_a_headers)
    assert search.status_code == 200, search.text
    found = search.json()["sources"]
    for key in ("users", "identities", "phishing_targets", "awareness_scores",
                "darkweb_credential_leaks", "consent_records"):
        assert found[key]["records"] == 1, key
    # The seeded alert, plus any the DSR automation raised naming the subject.
    assert found["alerts"]["records"] >= 1
    assert search.json()["status"] == "processing"

    export = await client.post(f"{url}/compile-data", headers=org_a_headers)
    assert export.status_code == 200, export.text
    body = export.json()
    pkg = body["package"]
    assert pkg["sources"]["users"]["records"][0]["id"] == ids_a["user"]
    assert "hashed_password" not in pkg["sources"]["users"]["records"][0]
    assert pkg["sources"]["darkweb_credential_leaks"]["record_count"] == 1  # org B's row excluded
    assert ids_a["alert"] in {r["id"] for r in pkg["sources"]["alerts"]["records"]}
    stored = (await client.get(url, headers=org_a_headers)).json()
    assert stored["export_sha256"] == body["sha256"] and stored["export_record_count"] == pkg["record_count"]

    csv_resp = await client.post(f"{url}/compile-data", params={"format_type": "csv"}, headers=org_a_headers)
    assert csv_resp.status_code == 200 and csv_resp.headers["content-type"].startswith("text/csv")
    assert csv_resp.headers["x-export-sha256"]
    assert csv_resp.text.splitlines()[0] == "source,record_id,field,value"


@pytest.mark.asyncio
async def test_csv_cells_are_formula_safe() -> None:
    from src.privacy.dsr import package_to_csv

    pkg = {"sources": {"users": {"records": [{"id": "u1", "full_name": "=HYPERLINK(\"x\")"}]}}}
    out = package_to_csv(pkg)
    assert "'=HYPERLINK" in out


@pytest.mark.asyncio
async def test_erasure_anonymises_redacts_deletes_and_retains_with_audit(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a,
    org_b,
    org_a_headers: dict[str, str],
    org_a_admin_headers: dict[str, str],
) -> None:
    email = f"erase-{uuid.uuid4().hex[:6]}@example.com"
    org_a_id, org_b_id = org_a.id, org_b.id
    ids = await _seed_subject(db_session, org_a_id, email)
    other = CredentialLeak(id=str(uuid.uuid4()), organization_id=org_b_id,
                           finding_id=str(uuid.uuid4()), email=email)
    db_session.add(other)
    other_id = other.id
    await db_session.commit()

    dsr = await _dsr(client, org_a_headers, email, request_type="erasure")
    url = f"{BASE}/dsr/requests/{dsr['id']}/execute-erasure"
    assert (await client.post(url, json={"confirm": True}, headers=org_a_headers)).status_code == 403
    assert (await client.post(url, json={"confirm": True}, headers=org_a_admin_headers)).status_code == 409
    await _verify(client, org_a_headers, dsr["id"])
    assert (await client.post(url, json={"confirm": False}, headers=org_a_admin_headers)).status_code == 422

    resp = await client.post(url, json={"confirm": True}, headers=org_a_admin_headers)
    assert resp.status_code == 200, resp.text
    done = resp.json()
    assert done["status"] == "completed" and done["completed_at"] and done["erasure_executed_at"]
    log = done["erasure_log"]
    assert log["sources"]["users"] == {"action": "anonymise", "records": 1, "remaining": 0,
                                       "note": log["sources"]["users"]["note"]}
    assert log["sources"]["consent_records"]["action"] == "retained"

    db_session.expire_all()
    user = await db_session.get(User, ids["user"])
    assert user.email.endswith("@erased.invalid") and user.is_active is False and user.full_name is None
    alert = await db_session.get(Alert, ids["alert"])
    assert email not in alert.title and "[erased-subject]" in alert.title
    assert await db_session.get(SecurityAwarenessScore, ids["score"]) is None
    assert await db_session.get(CredentialLeak, ids["leak"]) is None
    target = await db_session.get(PhishingTarget, ids["target"])
    assert target.recipient_email.endswith("@erased.invalid") and target.recipient_name is None
    identity = await db_session.get(IdentityProfile, ids["identity"])
    assert identity.email.endswith("@erased.invalid")
    assert await db_session.get(ConsentRecord, ids["consent"]) is not None  # retained
    assert await db_session.get(CredentialLeak, other_id) is not None  # other tenant untouched

    actions = set((await db_session.execute(
        select(AuditLog.action).where(AuditLog.resource_id == dsr["id"])
    )).scalars().all())
    assert {"privacy.dsr_erasure", "privacy.dsr_erasure.anonymise", "privacy.dsr_erasure.delete",
            "privacy.dsr_erasure.redact", "privacy.dsr_erasure.retained"} <= actions


@pytest.mark.asyncio
async def test_export_refused_for_erasure_requests_and_unknown_source(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    dsr = await _dsr(client, org_a_headers, "x@example.com", request_type="erasure")
    await _verify(client, org_a_headers, dsr["id"])
    url = f"{BASE}/dsr/requests/{dsr['id']}"
    assert (await client.post(f"{url}/compile-data", headers=org_a_headers)).status_code == 409
    resp = await client.post(f"{url}/search-systems", params={"systems": ["mainframe"]}, headers=org_a_headers)
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# PIA / ROPA / incidents / dashboard
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_pia_stores_form_fields_and_patch(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    resp = await client.post(f"{BASE}/pia/assessments", json={
        "name": "CRM", "project_name": "crm", "assessment_type": "dpia",
        "data_types_processed": ["email", "health"], "processing_purposes": ["support"],
        "legal_basis": "contract", "data_subjects_affected": 1200,
    }, headers=org_a_headers)
    assert resp.status_code == 201, resp.text
    pia = resp.json()
    assert pia["data_types_processed"] == ["email", "health"] and pia["legal_basis"] == "contract"
    assert pia["risk_level"] == "not_assessed" and pia["data_subjects_affected"] == 1200
    patched = await client.patch(f"{BASE}/pia/assessments/{pia['id']}",
                                 json={"mitigations": ["pseudonymise exports"], "cross_border_transfers": ["US"]},
                                 headers=org_a_headers)
    assert patched.status_code == 200, patched.text
    assert patched.json()["mitigations"] == ["pseudonymise exports"]
    assert patched.json()["cross_border_transfers"] == ["US"]
    removed = await client.post(f"{BASE}/pia/assessments/{pia['id']}/mitigations", headers=org_a_headers)
    assert removed.status_code == 501


@pytest.mark.asyncio
async def test_ropa_stores_article_30_fields_and_retention_review(
    client: AsyncClient, org_a_admin_headers: dict[str, str],
) -> None:
    resp = await client.post(f"{BASE}/ropa/processing-records", json={
        "name": "Payroll", "purpose": "pay staff", "legal_basis": "contract",
        "data_categories": ["bank"], "data_subjects": ["employees"], "recipients": ["bank"],
        "retention_period_days": 365, "dpo_contact": "dpo@example.com",
    }, headers=org_a_admin_headers)
    assert resp.status_code == 201, resp.text
    rec = resp.json()
    assert rec["data_subjects"] == ["employees"] and rec["recipients"] == ["bank"]
    assert rec["retention_period_days"] == 365 and rec["dpo_contact"] == "dpo@example.com"

    findings = (await client.post(f"{BASE}/ropa/retention-violations", headers=org_a_admin_headers)).json()
    assert [f["status"] for f in findings] == ["NOT_REVIEWED"]
    bad = await client.patch(f"{BASE}/ropa/processing-records/{rec['id']}",
                             json={"last_reviewed": "yesterday"}, headers=org_a_admin_headers)
    assert bad.status_code == 422
    ok = await client.patch(f"{BASE}/ropa/processing-records/{rec['id']}",
                            json={"last_reviewed": datetime.now(timezone.utc).isoformat()},
                            headers=org_a_admin_headers)
    assert ok.status_code == 200 and ok.json()["last_reviewed"]
    assert (await client.post(f"{BASE}/ropa/retention-violations", headers=org_a_admin_headers)).json() == []


@pytest.mark.asyncio
async def test_notification_deadlines_follow_recorded_regulations(
    client: AsyncClient, org_a_headers: dict[str, str],
) -> None:
    base = {"title": "Laptop lost", "incident_type": "loss_of_data", "severity": "high",
            "subjects_affected_count": 10}
    none = (await client.post(f"{BASE}/incidents/report", json=base, headers=org_a_headers)).json()
    d = (await client.post(f"{BASE}/incidents/reports/{none['id']}/notification-deadlines",
                           headers=org_a_headers)).json()
    assert d["status"] == "not_assessed" and "gdpr_authority" not in d

    gdpr = (await client.post(f"{BASE}/incidents/report", json={**base, "regulations_implicated": ["GDPR"]},
                              headers=org_a_headers)).json()
    assert gdpr["regulations_implicated"] == ["gdpr"]
    d1 = (await client.post(f"{BASE}/incidents/reports/{gdpr['id']}/notification-deadlines",
                            headers=org_a_headers)).json()
    d2 = (await client.post(f"{BASE}/incidents/reports/{gdpr['id']}/notification-deadlines",
                            headers=org_a_headers)).json()
    assert d1["gdpr_authority"] == d2["gdpr_authority"]  # anchored, does not move
    assert "ccpa_subjects" not in d1


@pytest.mark.asyncio
async def test_dashboard_rate_from_closed_requests_and_overdue(
    client: AsyncClient, db_session: AsyncSession, org_a, org_a_headers: dict[str, str],
) -> None:
    stats = (await client.get(f"{BASE}/dashboard/stats", headers=org_a_headers)).json()
    assert stats["dsr_compliance_rate"] is None and stats["avg_incident_resolution_days"] is None

    on_time = await _dsr(client, org_a_headers, "a@example.com")
    await _verify(client, org_a_headers, on_time["id"])
    url = f"{BASE}/dsr/requests/{on_time['id']}"
    await client.patch(url, json={"status": "processing"}, headers=org_a_headers)
    assert (await client.patch(url, json={"status": "completed"}, headers=org_a_headers)).status_code == 200

    late = await _dsr(client, org_a_headers, "b@example.com")
    row = await db_session.get(DataSubjectRequest, late["id"])
    row.deadline = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    await db_session.commit()

    stats = (await client.get(f"{BASE}/dashboard/stats", headers=org_a_headers)).json()
    assert stats["dsr_compliance_rate"] == 100.0 and stats["closed_dsrs"] == 1
    assert stats["pending_dsrs"] == 1 and stats["overdue_dsrs"] == 1
    overdue = (await client.get(f"{BASE}/dsr/requests", params={"overdue": "true"}, headers=org_a_headers)).json()
    assert [i["id"] for i in overdue["items"]] == [late["id"]] and overdue["items"][0]["overdue"] is True
    alerts = (await client.get(f"{BASE}/dsr/deadline-alerts", headers=org_a_headers)).json()
    assert [a["status"] for a in alerts] == ["BREACHED"]

    result = await _dsr_deadline_sweep()
    assert result["breached"] == 1 and not result["failures"]
    db_session.expire_all()
    assert (await db_session.get(DataSubjectRequest, late["id"])).deadline_breached_at is not None


@pytest.mark.asyncio
async def test_tenant_isolation_and_viewer_writes(
    client: AsyncClient, org_a_headers: dict[str, str], org_b_headers: dict[str, str],
    viewer_headers: dict[str, str],
) -> None:
    dsr = await _dsr(client, org_a_headers, "iso@example.com")
    assert (await client.get(f"{BASE}/dsr/requests/{dsr['id']}", headers=org_b_headers)).status_code == 404
    listed = (await client.get(f"{BASE}/dsr/requests", headers=org_b_headers)).json()
    assert listed["total"] == 0
    resp = await client.post(f"{BASE}/dsr/requests", json={"request_type": "access", "regulation": "gdpr",
                                                            "subject_name": "x", "subject_email": "v@example.com"},
                             headers=viewer_headers)
    assert resp.status_code == 403
    sources = (await client.get(f"{BASE}/dsr/sources", headers=viewer_headers)).json()
    assert {s["key"] for s in sources["sources"]} >= {"users", "identities", "darkweb_credential_leaks"}


def test_deadline_sweep_scheduled() -> None:
    tasks = {cfg["task"] for cfg in celery_app.conf.beat_schedule.values()}
    assert "src.privacy.tasks.privacy_dsr_deadline_sweep" in tasks
    assert "src.privacy.tasks.privacy_dsr_deadline_sweep" in celery_app.conf.task_annotations
