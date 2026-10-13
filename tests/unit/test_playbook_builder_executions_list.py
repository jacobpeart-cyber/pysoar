"""GET /playbook-builder/executions: org-scoped execution history.

PlaybookBuilder.tsx loads the execution history from this path. Before it
existed the literal ``executions`` segment was captured by
``/{playbook_id}`` and the page got a silent 404.
"""

from __future__ import annotations

import pytest

from src.playbook_builder.models import (
    PlaybookNode,
    PlaybookNodeExecution,
    VisualPlaybook,
    VisualPlaybookExecution,
)

ORG_A = "pbexorg-a0-4000-8000-000000000001"
ORG_B = "pbexorg-b0-4000-8000-000000000002"


async def _org_user(db_session, *, email: str, org: str):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"PBEX-{org[:9]}", slug=org[:12]))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role="analyst",
        is_active=True,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.commit()
    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _playbook_with_execution(db_session, org: str, name: str, status: str) -> tuple[str, str]:
    pb = VisualPlaybook(organization_id=org, name=name, category="custom", status="active", trigger_type="manual")
    db_session.add(pb)
    await db_session.flush()
    for i in range(3):
        db_session.add(
            PlaybookNode(
                playbook_id=pb.id, organization_id=org, node_id=f"n{i}", node_type="action",
                display_name=f"step {i}", position_x=0.0, position_y=float(i),
            ),
        )
    ex = VisualPlaybookExecution(playbook_id=pb.id, organization_id=org, status=status, duration_ms=1500)
    db_session.add(ex)
    await db_session.flush()
    db_session.add(
        PlaybookNodeExecution(execution_id=ex.id, organization_id=org, node_id="n0", status="completed"),
    )
    db_session.add(
        PlaybookNodeExecution(execution_id=ex.id, organization_id=org, node_id="n1", status="failed"),
    )
    await db_session.commit()
    return pb.id, ex.id


@pytest.mark.asyncio
async def test_lists_only_callers_org_executions(client, db_session):
    headers_a = await _org_user(db_session, email="pbex-a@example.com", org=ORG_A)
    headers_b = await _org_user(db_session, email="pbex-b@example.com", org=ORG_B)
    pb_a, ex_a = await _playbook_with_execution(db_session, ORG_A, "Contain host", "completed")
    await _playbook_with_execution(db_session, ORG_B, "Other tenant", "failed")

    resp = await client.get("/api/v1/playbook-builder/executions", headers=headers_a)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 1
    assert body["page"] == 1
    [row] = body["items"]
    assert row["id"] == ex_a
    assert row["playbook_id"] == pb_a
    assert row["playbook_name"] == "Contain host"
    assert row["organization_id"] == ORG_A
    assert row["total_nodes"] == 3
    assert row["nodes_executed"] == 1
    assert row["duration_ms"] == 1500

    resp_b = await client.get("/api/v1/playbook-builder/executions", headers=headers_b)
    assert resp_b.status_code == 200
    assert [r["playbook_name"] for r in resp_b.json()["items"]] == ["Other tenant"]


@pytest.mark.asyncio
async def test_pagination_and_status_filter(client, db_session):
    headers = await _org_user(db_session, email="pbex-page@example.com", org=ORG_A)
    for i in range(3):
        await _playbook_with_execution(db_session, ORG_A, f"pb {i}", "completed" if i else "failed")

    page = await client.get("/api/v1/playbook-builder/executions", params={"size": 2, "page": 2}, headers=headers)
    assert page.status_code == 200
    body = page.json()
    assert body["total"] == 3
    assert body["pages"] == 2
    assert len(body["items"]) == 1

    failed = await client.get("/api/v1/playbook-builder/executions", params={"status": "failed"}, headers=headers)
    assert failed.status_code == 200
    assert failed.json()["total"] == 1
    assert failed.json()["items"][0]["status"] == "failed"


@pytest.mark.asyncio
async def test_requires_authentication(client):
    resp = await client.get("/api/v1/playbook-builder/executions")
    assert resp.status_code in (401, 403)
