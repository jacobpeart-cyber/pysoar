"""SCAP import reads only files under the STIG content directory.

Found in the 2026-10-08 feature audit: ``POST /stig/scap/import`` handed any
client-supplied ``content_path`` to the XCCDF parser, so a user could make the
server open and parse arbitrary files (``/opt/pysoar/.env``), leaking existence
and parse errors. Paths must now resolve inside ``STIG_CONTENT_DIR``, the
directory ``POST /stig/scap/upload`` writes to.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from src.api.v1.endpoints import stig as stig_endpoints
from src.stig.models import STIGBenchmark

ORG = "stig-org-0000-4000-8000-000000000001"

XCCDF = b"""<?xml version="1.0" encoding="UTF-8"?>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.1" id="Synthetic_Test_STIG">
  <title>Synthetic Test STIG</title>
  <version>1</version>
  <Group id="V-000001">
    <Rule id="SV-000001r1_rule" severity="high">
      <title>Synthetic rule for tests</title>
      <description>test only</description>
      <fixtext>do the thing</fixtext>
    </Rule>
  </Group>
</Benchmark>
"""


async def _org_user(db_session, *, email: str, role: str = "analyst") -> tuple[object, dict]:
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, ORG) is None:
        db_session.add(Organization(id=ORG, name="STIG-ORG", slug="stig-org"))
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


@pytest.mark.asyncio
async def test_paths_outside_the_content_dir_are_refused(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "xccdf"
    root.mkdir()
    monkeypatch.setattr(stig_endpoints, "STIG_CONTENT_DIR", str(root))
    outside = tmp_path / "outside.xml"
    outside.write_bytes(XCCDF)

    _, headers = await _org_user(db_session, email="stig1@stig-org.io")
    for bad in (str(outside), str(root / ".." / "outside.xml"), "/opt/pysoar/.env", r"C:\Windows\win.ini", "", str(root)):
        resp = await client.post("/api/v1/stig/scap/import", headers=headers, json={"content_path": bad})
        assert resp.status_code == 403, (bad, resp.text)
        assert resp.json()["detail"]["error"] == "content_path_outside_stig_root"

    assert not (await db_session.execute(select(STIGBenchmark))).scalars().all()


@pytest.mark.asyncio
async def test_uploaded_content_can_still_be_imported(client, db_session, tmp_path, monkeypatch):
    root = tmp_path / "xccdf"
    monkeypatch.setattr(stig_endpoints, "STIG_CONTENT_DIR", str(root))
    _, headers = await _org_user(db_session, email="stig2@stig-org.io")

    up = await client.post(
        "/api/v1/stig/scap/upload",
        headers=headers,
        files={"file": ("synthetic.xccdf.xml", XCCDF, "application/xml")},
    )
    assert up.status_code == 200, up.text
    uploaded = [p for p in root.iterdir() if p.name.endswith("synthetic.xccdf.xml")]
    assert len(uploaded) == 1

    resp = await client.post("/api/v1/stig/scap/import", headers=headers, json={"content_path": str(uploaded[0])})
    assert resp.status_code == 200, resp.text
    benches = (await db_session.execute(select(STIGBenchmark).where(STIGBenchmark.organization_id == ORG))).scalars().all()
    assert benches
