"""WebSocket channel subscriptions are confined to the caller's organization.

Found in the 2026-10-08 feature audit: ``subscribe`` accepted any channel
name, so a user of one tenant could join ``agents:<other org>`` and receive
that tenant's agent / live-response command events.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import select

from src.api.v1.endpoints.websocket import handle_subscribe, resolve_ws_principal
from src.models.audit import AuditLog
from src.services.websocket_manager import ConnectionManager

ORG_A = "wsorg-a000-4000-8000-000000000001"
ORG_B = "wsorg-b000-4000-8000-000000000002"


class _FakeSocket:
    """Records frames sent by the server; enough for the manager and handler."""

    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def accept(self) -> None:
        return None

    async def send_json(self, data: dict[str, Any]) -> None:
        self.sent.append(data)


async def _org_user(db_session, *, email: str, org: str | None, role: str = "analyst", superuser: bool = False):
    from src.core.security import create_access_token, get_password_hash
    from src.models.organization import Organization
    from src.models.user import User

    if org is not None and await db_session.get(Organization, org) is None:
        db_session.add(Organization(id=org, name=f"WS-{org[:7]}", slug=org[:12]))
        await db_session.flush()
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        is_superuser=superuser,
        organization_id=org,
    )
    db_session.add(user)
    await db_session.flush()
    await db_session.commit()
    return user, create_access_token(subject=user.id)


def test_authorize_channel_rules() -> None:
    allow = ConnectionManager.authorize_channel
    # Default channels are open to every authenticated user.
    for channel in ("alerts", "incidents", "playbooks", "system"):
        assert allow(channel, organization_id=ORG_A, is_superuser=False)
    # Own-org channels are allowed, other orgs are not.
    assert allow(f"agents:{ORG_A}", organization_id=ORG_A, is_superuser=False)
    assert allow(f"purple:{ORG_A}:sim-1", organization_id=ORG_A, is_superuser=False)
    assert not allow(f"agents:{ORG_B}", organization_id=ORG_A, is_superuser=False)
    assert not allow(f"purple:{ORG_B}:sim-1", organization_id=ORG_A, is_superuser=False)
    # Users with no organization only see the 'global' scope.
    assert allow("agents:global", organization_id=None, is_superuser=False)
    assert not allow("agents:global", organization_id=ORG_A, is_superuser=False)
    assert not allow(f"agents:{ORG_A}", organization_id=None, is_superuser=False)
    # Unknown or malformed channels are refused, even for superusers.
    for bad in ("", "agents", "agents:", f"agents:{ORG_A}:extra", f"purple:{ORG_A}", "warroom:1", "secret"):
        assert not allow(bad, organization_id=ORG_A, is_superuser=False), bad
        assert not allow(bad, organization_id=ORG_A, is_superuser=True), bad
    # Superusers may join any well-formed org channel.
    assert allow(f"agents:{ORG_B}", organization_id=ORG_A, is_superuser=True)
    assert allow(f"purple:{ORG_B}:sim-9", organization_id=None, is_superuser=True)


@pytest.mark.asyncio
async def test_manager_refuses_other_tenant_channel_and_does_not_deliver() -> None:
    mgr = ConnectionManager()
    attacker_ws, victim_ws = _FakeSocket(), _FakeSocket()
    await mgr.connect(attacker_ws, "attacker", organization_id=ORG_A, is_superuser=False)
    await mgr.connect(victim_ws, "victim", organization_id=ORG_B, is_superuser=False)

    assert await mgr.subscribe("attacker", f"agents:{ORG_B}") is False
    assert await mgr.subscribe("victim", f"agents:{ORG_B}") is True
    assert mgr.channels[f"agents:{ORG_B}"] == {"victim"}

    attacker_ws.sent.clear()
    await mgr.broadcast_channel(f"agents:{ORG_B}", {"type": "command_result", "data": {"x": 1}})
    assert attacker_ws.sent == []
    assert any(m.get("type") == "command_result" for m in victim_ws.sent)


@pytest.mark.asyncio
async def test_manager_refuses_unknown_user_and_allows_superuser() -> None:
    mgr = ConnectionManager()
    assert await mgr.subscribe("never-connected", "alerts") is False
    await mgr.connect(_FakeSocket(), "root", organization_id=None, is_superuser=True)
    assert await mgr.subscribe("root", f"agents:{ORG_B}") is True


@pytest.mark.asyncio
async def test_principal_resolution_and_denied_subscription_is_audited(db_session, monkeypatch) -> None:
    import src.api.v1.endpoints.websocket as ws_endpoint

    user, token = await _org_user(db_session, email="ws-a@wsorg-a.io", org=ORG_A)
    principal = await resolve_ws_principal(token)
    assert principal is not None
    assert principal.user_id == str(user.id)
    assert principal.organization_id == ORG_A
    assert principal.is_superuser is False
    assert await resolve_ws_principal("not-a-jwt") is None

    mgr = ConnectionManager()
    monkeypatch.setattr(ws_endpoint, "manager", mgr)
    sock = _FakeSocket()
    await mgr.connect(sock, principal.user_id, organization_id=principal.organization_id)
    sock.sent.clear()

    assert await handle_subscribe(sock, principal, f"agents:{ORG_B}") is False
    assert sock.sent[-1]["type"] == "error"
    assert sock.sent[-1]["error"] == "channel_not_permitted"
    assert f"agents:{ORG_B}" not in mgr.channels

    rows = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.user_id == principal.user_id,
                AuditLog.action == "websocket_subscribe_denied",
            )
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].success is False
    assert ORG_B in (rows[0].new_value or "")

    assert await handle_subscribe(sock, principal, f"agents:{ORG_A}") is True
    assert sock.sent[-1] == {"type": "subscribed", "channel": f"agents:{ORG_A}"}


@pytest.mark.asyncio
async def test_superuser_principal_may_subscribe_to_any_org(db_session, monkeypatch) -> None:
    import src.api.v1.endpoints.websocket as ws_endpoint

    _, token = await _org_user(db_session, email="ws-root@wsorg-a.io", org=ORG_A, role="admin", superuser=True)
    principal = await resolve_ws_principal(token)
    assert principal is not None and principal.is_superuser is True

    mgr = ConnectionManager()
    monkeypatch.setattr(ws_endpoint, "manager", mgr)
    sock = _FakeSocket()
    await mgr.connect(sock, principal.user_id, organization_id=principal.organization_id, is_superuser=True)
    assert await handle_subscribe(sock, principal, f"agents:{ORG_B}") is True
