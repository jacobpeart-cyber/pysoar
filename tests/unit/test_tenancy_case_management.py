"""Wave 1 tenancy / RBAC for incident case management (case_management.py).

* every route loads the parent incident inside the caller's organisation
  (``OrganizationId``; the optional ``org_id=None`` helper is gone), so another
  tenant's notes, tasks, attachments and timeline are 404;
* writes need analyst or admin; authors / uploaders / actors come from the
  session; a task can only be assigned to a user of the same organisation;
* attachment download and delete stay inside ``UPLOAD_DIR`` (realpath check).
"""

from __future__ import annotations

import os

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.v1.endpoints import case_management
from src.models.case import CaseAttachment, CaseNote, CaseTimeline, Task
from src.models.incident import Incident
from src.models.organization import Organization
from src.models.user import User
from tests.helpers.tenancy import assert_tenant_isolated

API = "/api/v1/incidents"


@pytest.fixture(autouse=True)
def _upload_root(tmp_path, monkeypatch):
    root = tmp_path / "attachments"
    root.mkdir()
    monkeypatch.setattr(case_management, "UPLOAD_DIR", str(root))
    return root


async def _incident(db: AsyncSession, org_id: str) -> str:
    incident = Incident(title="case", severity="high", status="open", organization_id=org_id)
    db.add(incident)
    await db.commit()
    return incident.id


async def _populate(client: AsyncClient, incident_id: str, headers: dict[str, str]) -> dict[str, str]:
    note = await client.post(f"{API}/{incident_id}/notes", headers=headers, json={"content": "n1"})
    assert note.status_code == 201, note.text
    task = await client.post(f"{API}/{incident_id}/tasks", headers=headers, json={"title": "t1"})
    assert task.status_code == 201, task.text
    att = await client.post(
        f"{API}/{incident_id}/attachments",
        headers=headers,
        files={"file": ("evidence.txt", b"hello evidence", "text/plain")},
    )
    assert att.status_code == 201, att.text
    event = await client.post(f"{API}/{incident_id}/timeline", headers=headers, json={"title": "e1"})
    assert event.status_code == 201, event.text
    return {"note": note.json()["id"], "task": task.json()["id"], "attachment": att.json()["id"]}


async def test_child_routes_are_isolated(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    org_b_headers: dict[str, str],
) -> None:
    inc = await _incident(db_session, org_a.id)
    ids = await _populate(client, inc, org_a_headers)
    note, task, att = ids["note"], ids["task"], ids["attachment"]

    for method, path, json in (
        ("GET", f"{API}/{inc}/notes", None),
        ("POST", f"{API}/{inc}/notes", {"content": "x"}),
        ("PATCH", f"{API}/{inc}/notes/{note}", {"content": "pwned"}),
        ("DELETE", f"{API}/{inc}/notes/{note}", None),
        ("GET", f"{API}/{inc}/tasks", None),
        ("POST", f"{API}/{inc}/tasks", {"title": "x"}),
        ("PATCH", f"{API}/{inc}/tasks/{task}", {"title": "pwned"}),
        ("DELETE", f"{API}/{inc}/tasks/{task}", None),
        ("GET", f"{API}/{inc}/attachments", None),
        ("GET", f"{API}/{inc}/attachments/{att}/download", None),
        ("DELETE", f"{API}/{inc}/attachments/{att}", None),
        ("GET", f"{API}/{inc}/timeline", None),
        ("POST", f"{API}/{inc}/timeline", {"title": "x"}),
    ):
        resp = await assert_tenant_isolated(client, method, path, org_b_headers, json=json)
        assert resp.status_code == 404, (method, path, resp.text)

    resp = await client.post(
        f"{API}/{inc}/attachments", headers=org_b_headers,
        files={"file": ("x.txt", b"x", "text/plain")},
    )
    assert resp.status_code == 404, resp.text

    # Nothing of A's changed.
    db_session.expire_all()
    assert (await db_session.get(CaseNote, note)).content == "n1"
    assert (await db_session.get(Task, task)).title == "t1"
    assert await db_session.get(CaseAttachment, att) is not None
    resp = await client.get(f"{API}/{inc}/attachments/{att}/download", headers=org_a_headers)
    assert resp.status_code == 200, resp.text
    assert resp.content == b"hello evidence"


@pytest.mark.parametrize(
    "method,suffix,json",
    [
        ("POST", "/notes", {"content": "x"}),
        ("PATCH", "/notes/{note}", {"content": "x"}),
        ("DELETE", "/notes/{note}", None),
        ("POST", "/tasks", {"title": "x"}),
        ("PATCH", "/tasks/{task}", {"title": "x"}),
        ("DELETE", "/tasks/{task}", None),
        ("DELETE", "/attachments/{attachment}", None),
        ("POST", "/timeline", {"title": "x"}),
    ],
)
async def test_viewer_cannot_write(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    viewer_headers: dict[str, str],
    method: str,
    suffix: str,
    json,
) -> None:
    inc = await _incident(db_session, org_a.id)
    ids = await _populate(client, inc, org_a_headers)
    path = f"{API}/{inc}" + suffix.format(**ids)
    resp = await client.request(method, path, headers=viewer_headers, json=json)
    assert resp.status_code == 403, resp.text

    # Reads stay open to the viewer.
    for read in ("notes", "tasks", "attachments", "timeline"):
        assert (await client.get(f"{API}/{inc}/{read}", headers=viewer_headers)).status_code == 200


async def test_viewer_cannot_upload(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, viewer_headers: dict[str, str],
) -> None:
    inc = await _incident(db_session, org_a.id)
    resp = await client.post(
        f"{API}/{inc}/attachments", headers=viewer_headers,
        files={"file": ("e.txt", b"x", "text/plain")},
    )
    assert resp.status_code == 403, resp.text


async def test_admin_can_write(
    client: AsyncClient, db_session: AsyncSession, org_a: Organization, org_a_admin_headers: dict[str, str],
) -> None:
    inc = await _incident(db_session, org_a.id)
    await _populate(client, inc, org_a_admin_headers)


async def test_writes_carry_the_session_actor_and_stay_on_the_incident(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_user: User,
    org_a_headers: dict[str, str],
) -> None:
    inc, me = await _incident(db_session, org_a.id), org_a_user.id
    ids = await _populate(client, inc, org_a_headers)
    db_session.expire_all()
    note = await db_session.get(CaseNote, ids["note"])
    task = await db_session.get(Task, ids["task"])
    att = await db_session.get(CaseAttachment, ids["attachment"])
    assert (note.author_id, note.incident_id) == (me, inc)
    assert (task.created_by, task.incident_id) == (me, inc)
    assert (att.uploaded_by, att.incident_id) == (me, inc)
    events = (await db_session.execute(select(CaseTimeline).where(CaseTimeline.incident_id == inc))).scalars().all()
    assert events and all(e.actor_id == me for e in events)


async def test_task_assignee_must_be_in_the_same_org(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_b_user: User,
    org_a_admin: User,
    org_a_headers: dict[str, str],
) -> None:
    inc, outsider, colleague = await _incident(db_session, org_a.id), org_b_user.id, org_a_admin.id
    resp = await client.post(f"{API}/{inc}/tasks", headers=org_a_headers, json={"title": "x", "assigned_to": outsider})
    assert resp.status_code == 400, resp.text
    resp = await client.post(f"{API}/{inc}/tasks", headers=org_a_headers, json={"title": "x", "assigned_to": colleague})
    assert resp.status_code == 201, resp.text
    task_id = resp.json()["id"]
    resp = await client.patch(f"{API}/{inc}/tasks/{task_id}", headers=org_a_headers, json={"assigned_to": outsider})
    assert resp.status_code == 400, resp.text


async def test_download_refuses_paths_outside_the_upload_root(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    org_a_headers: dict[str, str],
    tmp_path,
) -> None:
    inc = await _incident(db_session, org_a.id)
    ids = await _populate(client, inc, org_a_headers)
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"host secret")
    att = await db_session.get(CaseAttachment, ids["attachment"])
    att.file_path = str(secret)
    await db_session.commit()
    att_id = ids["attachment"]

    resp = await client.get(f"{API}/{inc}/attachments/{att_id}/download", headers=org_a_headers)
    assert resp.status_code == 404, resp.text
    assert b"host secret" not in resp.content

    resp = await client.delete(f"{API}/{inc}/attachments/{att_id}", headers=org_a_headers)
    assert resp.status_code == 204, resp.text
    assert os.path.exists(secret)  # deleting the row never removes a file outside the root


async def test_orgless_callers_get_organization_required(
    client: AsyncClient,
    db_session: AsyncSession,
    org_a: Organization,
    orgless_headers: dict[str, str],
    superuser_headers: dict[str, str],
) -> None:
    inc = await _incident(db_session, org_a.id)
    for headers in (orgless_headers, superuser_headers):
        resp = await client.get(f"{API}/{inc}/notes", headers=headers)
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "organization_required"
