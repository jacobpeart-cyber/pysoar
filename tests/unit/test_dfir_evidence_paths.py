"""Evidence storage locations are not an arbitrary-file-read primitive.

Found in the 2026-10-08 feature audit: ``POST /dfir/evidence`` stored any
client-supplied ``storage_location`` and ``GET .../download`` served it with
``FileResponse`` and no root check, so any authenticated user could register
``/opt/pysoar/.env`` as evidence and download it. ``POST .../verify`` compared
two client-sent strings and then overwrote the stored hash with one of them.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
from sqlalchemy import select

from src.api.v1.endpoints import dfir as dfir_endpoints
from src.dfir.models import ForensicEvidence

ORG = "dfir-org-0000-4000-8000-000000000001"


async def _org_user(db_session, *, email: str, role: str = "analyst"):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="DFIR-ORG", slug="dfir-org"))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=ORG,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _case(client, headers) -> str:
    resp = await client.post(
        "/api/v1/dfir/cases",
        headers=headers,
        json={"case_number": f"CASE-{uuid.uuid4().hex[:8]}", "title": "evidence path tests", "severity": "medium"},
    )
    assert resp.status_code in (200, 201), resp.text
    return resp.json()["id"]


def _evidence_payload(case_id: str, location: str) -> dict:
    return {
        "case_id": case_id,
        "evidence_type": "file",
        "source_device": "host-1",
        "acquisition_method": "manual",
        "storage_location": location,
    }


@pytest.mark.asyncio
async def test_local_paths_cannot_be_registered_by_clients(client, db_session):
    _, headers = await _org_user(db_session, email="dfir1@dfir-org.test")
    case_id = await _case(client, headers)

    for bad in ("/opt/pysoar/.env", "C:\\Windows\\win.ini", "../../etc/passwd", "file:///etc/passwd", "http://evil.example/x"):
        resp = await client.post("/api/v1/dfir/evidence", headers=headers, json=_evidence_payload(case_id, bad))
        assert resp.status_code == 400, (bad, resp.text)
        assert resp.json()["detail"]["error"] == "invalid_storage_location"

    stored = (await db_session.execute(select(ForensicEvidence).where(ForensicEvidence.case_id == case_id))).scalars().all()
    assert stored == []


@pytest.mark.asyncio
async def test_remote_object_urls_are_accepted_and_served_as_redirects(client, db_session):
    _, headers = await _org_user(db_session, email="dfir2@dfir-org.test")
    case_id = await _case(client, headers)

    resp = await client.post(
        "/api/v1/dfir/evidence",
        headers=headers,
        json=_evidence_payload(case_id, "https://evidence.example.test/bucket/object.bin"),
    )
    assert resp.status_code == 201, resp.text
    evidence_id = resp.json()["id"]

    dl = await client.get(f"/api/v1/dfir/evidence/{evidence_id}/download", headers=headers, follow_redirects=False)
    assert dl.status_code in (302, 307), dl.text
    assert dl.headers["location"].startswith("https://evidence.example.test/")


@pytest.mark.asyncio
async def test_download_refuses_a_path_outside_the_storage_root(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "evidence-root"
    root.mkdir()
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(root))
    outside = tmp_path / "secret.env"
    outside.write_text("SECRET_KEY=should-never-be-served\n")

    user, headers = await _org_user(db_session, email="dfir3@dfir-org.test")
    case_id = await _case(client, headers)
    # A row that pre-dates the fix (or was written by some other path).
    row = ForensicEvidence(
        case_id=case_id,
        evidence_type="file",
        source_device="host-1",
        acquisition_method="manual",
        storage_location=str(outside),
        organization_id=ORG,
        chain_of_custody_log={"entries": []},
    )
    db_session.add(row)
    await db_session.commit()

    dl = await client.get(f"/api/v1/dfir/evidence/{row.id}/download", headers=headers)
    assert dl.status_code == 403, dl.text
    assert dl.json()["detail"]["error"] == "evidence_path_outside_storage_root"
    assert b"should-never-be-served" not in dl.content


@pytest.mark.asyncio
async def test_download_serves_a_file_inside_the_storage_root(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "evidence-root"
    (root / ORG).mkdir(parents=True)
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(root))
    blob = root / ORG / "capture.bin"
    blob.write_bytes(b"\x00\x01evidence bytes\x02")

    _, headers = await _org_user(db_session, email="dfir4@dfir-org.test")
    case_id = await _case(client, headers)
    row = ForensicEvidence(
        case_id=case_id,
        evidence_type="file",
        source_device="host-1",
        acquisition_method="upload",
        storage_location=str(blob),
        organization_id=ORG,
        original_hash_sha256=hashlib.sha256(blob.read_bytes()).hexdigest(),
        chain_of_custody_log={"entries": []},
    )
    db_session.add(row)
    await db_session.commit()

    dl = await client.get(f"/api/v1/dfir/evidence/{row.id}/download", headers=headers)
    assert dl.status_code == 200, dl.text
    assert dl.content == blob.read_bytes()

    # A traversal that *starts* inside the root but escapes it is still refused.
    row.storage_location = str(root / ORG / ".." / ".." / "secret.env")
    await db_session.commit()
    (tmp_path / "secret.env").write_text("nope")
    dl = await client.get(f"/api/v1/dfir/evidence/{row.id}/download", headers=headers)
    assert dl.status_code == 403


@pytest.mark.asyncio
async def test_verify_uses_the_file_or_stored_hash_and_never_overwrites_it(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "evidence-root"
    (root / ORG).mkdir(parents=True)
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(root))
    blob = root / ORG / "image.dd"
    blob.write_bytes(b"disk image bytes")
    real_hash = hashlib.sha256(blob.read_bytes()).hexdigest()

    _, headers = await _org_user(db_session, email="dfir5@dfir-org.test")
    case_id = await _case(client, headers)
    row = ForensicEvidence(
        case_id=case_id,
        evidence_type="disk_image",
        source_device="host-1",
        acquisition_method="upload",
        storage_location=str(blob),
        organization_id=ORG,
        original_hash_sha256=real_hash,
        chain_of_custody_log={"entries": []},
    )
    db_session.add(row)
    await db_session.commit()

    # Wrong hash: not verified, and the stored hash is untouched (the old code
    # would have replaced it with the attacker's value).
    bad = "0" * 64
    resp = await client.post(
        f"/api/v1/dfir/evidence/{row.id}/verify",
        headers=headers,
        json={"evidence_hash": bad, "hash_algorithm": "sha256", "original_hash": bad},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_verified"] is False
    await db_session.refresh(row)
    assert row.original_hash_sha256 == real_hash

    # Right hash: verified, custody log records that the file itself was the reference.
    resp = await client.post(
        f"/api/v1/dfir/evidence/{row.id}/verify",
        headers=headers,
        json={"evidence_hash": real_hash.upper(), "hash_algorithm": "sha256"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_verified"] is True
    await db_session.refresh(row)
    entries = row.chain_of_custody_log["entries"]
    assert entries[-1]["action"] == "verified" and entries[-1]["reference"] == "file"
    assert row.original_hash_sha256 == real_hash


@pytest.mark.asyncio
async def test_another_organization_cannot_reach_the_evidence(client, db_session, tmp_path, monkeypatch):
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(tmp_path))
    _, headers = await _org_user(db_session, email="dfir6@dfir-org.test")
    case_id = await _case(client, headers)
    resp = await client.post(
        "/api/v1/dfir/evidence", headers=headers, json=_evidence_payload(case_id, "s3://bucket/object"),
    )
    assert resp.status_code == 201, resp.text
    evidence_id = resp.json()["id"]

    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    other_org = "dfir-org-0000-4000-8000-000000000002"
    db_session.add(Organization(id=other_org, name="OTHER", slug="dfir-other"))
    outsider = User(
        email="outsider@dfir-other.test",
        hashed_password=get_password_hash("pw-for-tests"),
        full_name="outsider",
        role="admin",
        is_active=True,
        organization_id=other_org,
    )
    db_session.add(outsider)
    await db_session.commit()
    other_headers = {"Authorization": f"Bearer {create_access_token(subject=outsider.id)}"}

    dl = await client.get(f"/api/v1/dfir/evidence/{evidence_id}/download", headers=other_headers, follow_redirects=False)
    assert dl.status_code == 404, dl.text


def test_local_path_helper_rejects_symlink_escape(tmp_path, monkeypatch):
    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setattr(dfir_endpoints, "DFIR_UPLOAD_ROOT", str(root))
    assert dfir_endpoints._local_evidence_path(str(root / "a.bin")) == os.path.realpath(root / "a.bin")
    with pytest.raises(Exception) as exc:
        dfir_endpoints._local_evidence_path(str(tmp_path / "outside.bin"))
    assert getattr(exc.value, "status_code", None) == 403
