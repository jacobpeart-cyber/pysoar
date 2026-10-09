"""Compliance evidence is not an arbitrary-file-read primitive.

Found in the 2026-10-08 feature audit: ``POST /compliance/evidence`` stored any
client-supplied ``file_path`` and ``GET /audit-evidence/evidence/{id}/download``
streamed it with ``FileResponse``, so any authenticated user could register
``/opt/pysoar/.env`` as evidence and download it.
"""

from __future__ import annotations

from typing import Optional

import pytest
from sqlalchemy import select

from src.api.v1.endpoints import audit_evidence as audit_evidence_endpoints
from src.compliance.models import ComplianceControl, ComplianceEvidence, ComplianceFramework

ORG = "cev-org-0000-4000-8000-000000000001"
OTHER_ORG = "cev-org-0000-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str = ORG, role: str = "analyst") -> tuple[object, dict]:
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"ORG-{org[-2:]}", slug=f"cev-{org[-2:]}"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


def _row(file_path: Optional[str], org: str = ORG) -> ComplianceEvidence:
    return ComplianceEvidence(
        control_id_ref="AC-3",
        evidence_type="document",
        title="evidence path test",
        file_path=file_path,
        collected_by="tests",
        organization_id=org,
    )


@pytest.mark.asyncio
async def test_local_paths_cannot_be_registered(client, db_session):
    _, headers = await _org_user(db_session, email="cev1@cev-org.io")
    for bad in ("/opt/pysoar/.env", r"C:\Windows\win.ini", "../../etc/passwd", "file:///etc/passwd", "http://evil.example/x"):
        resp = await client.post(
            "/api/v1/compliance/evidence",
            headers=headers,
            params={"control_id_ref": "AC-3", "evidence_type": "document", "title": "t", "file_path": bad},
        )
        assert resp.status_code == 400, (bad, resp.text)
        assert resp.json()["detail"]["error"] == "invalid_evidence_location"

    stored = (await db_session.execute(select(ComplianceEvidence).where(ComplianceEvidence.organization_id == ORG))).scalars().all()
    assert stored == []


@pytest.mark.asyncio
async def test_object_urls_and_no_path_are_accepted(client, db_session):
    _, headers = await _org_user(db_session, email="cev2@cev-org.io")
    resp = await client.post(
        "/api/v1/compliance/evidence",
        headers=headers,
        params={"control_id_ref": "AC-3", "evidence_type": "document", "title": "remote",
                "file_path": "https://evidence.example.io/bucket/report.pdf"},
    )
    assert resp.status_code == 200, resp.text
    evidence_id = resp.json()["id"]

    dl = await client.get(f"/api/v1/audit-evidence/evidence/{evidence_id}/download", headers=headers, follow_redirects=False)
    assert dl.status_code in (302, 307), dl.text
    assert dl.headers["location"] == "https://evidence.example.io/bucket/report.pdf"

    resp = await client.post(
        "/api/v1/compliance/evidence",
        headers=headers,
        params={"control_id_ref": "AC-3", "evidence_type": "attestation", "title": "text only", "content": "signed"},
    )
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_download_refuses_paths_outside_the_org_root(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "evidence-root"
    (root / ORG).mkdir(parents=True)
    (root / OTHER_ORG).mkdir(parents=True)
    monkeypatch.setattr(audit_evidence_endpoints, "EVIDENCE_UPLOAD_ROOT", str(root))
    secret = tmp_path / "secret.env"
    secret.write_text("SECRET_KEY=should-never-be-served\n")
    other_tenant_file = root / OTHER_ORG / "theirs.pdf"
    other_tenant_file.write_text("other tenant evidence")

    _, headers = await _org_user(db_session, email="cev3@cev-org.io")
    # Rows that pre-date the fix: an absolute path, a traversal starting inside
    # the root, a file in another tenant's directory, and a plain-http URL.
    rows = [
        _row(str(secret)),
        _row(str(root / ORG / ".." / ".." / "secret.env")),
        _row(str(other_tenant_file)),
    ]
    http_row = _row("http://evil.example/x")
    db_session.add_all([*rows, http_row])
    await db_session.commit()
    targets = [(row.id, row.file_path) for row in rows]
    http_row_id = http_row.id

    for row_id, path in targets:
        dl = await client.get(f"/api/v1/audit-evidence/evidence/{row_id}/download", headers=headers)
        assert dl.status_code == 403, (path, dl.text)
        assert dl.json()["detail"]["error"] == "evidence_path_outside_storage_root"
        assert b"should-never-be-served" not in dl.content
        assert b"other tenant evidence" not in dl.content

    dl = await client.get(f"/api/v1/audit-evidence/evidence/{http_row_id}/download", headers=headers, follow_redirects=False)
    assert dl.status_code == 400
    assert dl.json()["detail"]["error"] == "invalid_storage_location"


@pytest.mark.asyncio
async def test_uploaded_evidence_is_downloadable_and_tenant_scoped(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "evidence-root"
    monkeypatch.setattr(audit_evidence_endpoints, "EVIDENCE_UPLOAD_ROOT", str(root))
    _, headers = await _org_user(db_session, email="cev4@cev-org.io")

    framework = ComplianceFramework(name="NIST 800-53", short_name="nist_800_53", version="5", authority="NIST", organization_id=ORG)
    db_session.add(framework)
    await db_session.flush()
    control = ComplianceControl(
        framework_id=framework.id, control_id="AC-3", control_family="AC", title="Access Enforcement", organization_id=ORG,
    )
    db_session.add(control)
    await db_session.commit()

    up = await client.post(
        "/api/v1/audit-evidence/evidence/upload",
        headers=headers,
        data={"control_id": control.id, "title": "policy", "evidence_type": "document"},
        files={"file": ("policy.pdf", b"%PDF-1.4 synthetic policy bytes", "application/pdf")},
    )
    assert up.status_code == 200, up.text
    evidence_id = up.json()["evidence_id"]

    dl = await client.get(f"/api/v1/audit-evidence/evidence/{evidence_id}/download", headers=headers)
    assert dl.status_code == 200, dl.text
    assert dl.content == b"%PDF-1.4 synthetic policy bytes"

    _, outsider = await _org_user(db_session, email="cev5@cev-other.io", org=OTHER_ORG, role="admin")
    dl = await client.get(f"/api/v1/audit-evidence/evidence/{evidence_id}/download", headers=outsider)
    assert dl.status_code == 404
