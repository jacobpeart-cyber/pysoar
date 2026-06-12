"""Real report export — CSV and PDF.

The README claims "Exportable alert, incident, and executive reports in
CSV/JSON/PDF". Before this feature: no backend export endpoints existed,
the frontend PDF button opened a browser print dialog, and CSV was a
client-side string join over the stats blob.
"""

import csv
import io

import pytest

from src.models.alert import Alert
from src.models.incident import Incident


@pytest.fixture
async def seeded_alerts(db_session, test_user):
    org = test_user.organization_id
    alerts = [
        Alert(
            title=f"Suspicious login burst {i}",
            severity="high" if i % 2 else "low",
            status="new",
            source="siem",
            organization_id=org,
        )
        for i in range(3)
    ]
    other_tenant = Alert(
        title="OTHER TENANT SECRET",
        severity="critical",
        status="new",
        source="siem",
        organization_id="some-other-org",
    )
    db_session.add_all(alerts + [other_tenant])
    await db_session.commit()
    return alerts


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_alerts_csv_contains_rows_and_headers(db_session, test_user, seeded_alerts):
    from src.services.report_generator import ReportGenerator

    gen = ReportGenerator(db_session)
    out = await gen.alerts_csv(organization_id=test_user.organization_id, days=30)

    rows = list(csv.DictReader(io.StringIO(out)))
    assert len(rows) == 3
    assert "title" in rows[0] and "severity" in rows[0] and "created_at" in rows[0]
    assert {r["title"] for r in rows} == {f"Suspicious login burst {i}" for i in range(3)}


@pytest.mark.asyncio
async def test_alerts_csv_is_tenant_scoped(db_session, test_user, seeded_alerts):
    from src.services.report_generator import ReportGenerator

    out = await ReportGenerator(db_session).alerts_csv(
        organization_id=test_user.organization_id, days=30
    )
    assert "OTHER TENANT SECRET" not in out


@pytest.mark.asyncio
async def test_alerts_pdf_is_real_pdf(db_session, test_user, seeded_alerts):
    from src.services.report_generator import ReportGenerator

    pdf = await ReportGenerator(db_session).alerts_pdf(
        organization_id=test_user.organization_id, days=30
    )
    assert isinstance(pdf, (bytes, bytearray))
    assert pdf[:5] == b"%PDF-"
    assert len(pdf) > 500


@pytest.mark.asyncio
async def test_incidents_csv_and_pdf(db_session, test_user):
    from src.services.report_generator import ReportGenerator

    db_session.add(
        Incident(
            title="Ransomware on FS-01",
            severity="critical",
            status="open",
            organization_id=test_user.organization_id,
        )
    )
    await db_session.commit()

    gen = ReportGenerator(db_session)
    out = await gen.incidents_csv(organization_id=test_user.organization_id, days=30)
    assert "Ransomware on FS-01" in out

    pdf = await gen.incidents_pdf(organization_id=test_user.organization_id, days=30)
    assert pdf[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_executive_pdf_builds_from_real_counts(db_session, test_user, seeded_alerts):
    from src.services.report_generator import ReportGenerator

    pdf = await ReportGenerator(db_session).executive_pdf(
        organization_id=test_user.organization_id, days=30
    )
    assert pdf[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_endpoint_csv(client, auth_headers, db_session, test_user, seeded_alerts):
    resp = await client.get(
        "/api/v1/reports/alerts/export?format=csv&days=30", headers=auth_headers
    )
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert "Suspicious login burst" in resp.text


@pytest.mark.asyncio
async def test_export_endpoint_pdf(client, auth_headers, db_session, test_user, seeded_alerts):
    resp = await client.get(
        "/api/v1/reports/alerts/export?format=pdf&days=30", headers=auth_headers
    )
    assert resp.status_code == 200
    assert "application/pdf" in resp.headers["content-type"]
    assert resp.content[:5] == b"%PDF-"


@pytest.mark.asyncio
async def test_export_endpoint_rejects_unknown(client, auth_headers):
    resp = await client.get(
        "/api/v1/reports/alerts/export?format=docx", headers=auth_headers
    )
    assert resp.status_code == 422

    resp = await client.get(
        "/api/v1/reports/nonsense/export?format=csv", headers=auth_headers
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_export_requires_auth(client):
    resp = await client.get("/api/v1/reports/alerts/export?format=csv")
    assert resp.status_code in (401, 403)
