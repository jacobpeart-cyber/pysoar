"""Per-tenant default WebSocket channels (wave 1, docs/audit/2026-10-08/PLAN.md).

The four default channels (``alerts``, ``incidents``, ``playbooks``,
``system``) used to be single global channels every connection joined, so a
new alert, incident, playbook step or LLM budget event in one tenant was pushed
to every tenant. They are now ``<prefix>:<org>`` and every emitter publishes
to the owning tenant's channel only.
"""

from __future__ import annotations

from typing import Any

import pytest

import src.services.websocket_manager as wsm
from src.services.websocket_manager import ConnectionManager

ORG_A = "wsten-a000-4000-8000-000000000001"
ORG_B = "wsten-b000-4000-8000-000000000002"


class _FakeSocket:
    def __init__(self) -> None:
        self.sent: list[dict[str, Any]] = []

    async def accept(self) -> None:
        return None

    async def send_json(self, data: dict[str, Any]) -> None:
        self.sent.append(data)

    def types(self) -> list[str]:
        return [m.get("type", "") for m in self.sent]


@pytest.fixture
async def two_tenants(monkeypatch: pytest.MonkeyPatch) -> tuple[ConnectionManager, _FakeSocket, _FakeSocket]:
    mgr = ConnectionManager()
    monkeypatch.setattr(wsm, "manager", mgr)
    sock_a, sock_b = _FakeSocket(), _FakeSocket()
    await mgr.connect(sock_a, "user-a", organization_id=ORG_A)
    await mgr.connect(sock_b, "user-b", organization_id=ORG_B)
    sock_a.sent.clear()
    sock_b.sent.clear()
    return mgr, sock_a, sock_b


async def test_connect_joins_only_own_tenant_default_channels() -> None:
    mgr = ConnectionManager()
    sock = _FakeSocket()
    await mgr.connect(sock, "user-a", organization_id=ORG_A)
    expected = [f"{p}:{ORG_A}" for p in ("alerts", "incidents", "playbooks", "system")]
    assert sock.sent[0]["type"] == "connected"
    assert sock.sent[0]["channels"] == expected
    assert set(mgr.channels) == set(expected)
    for bare in ("alerts", "incidents", "playbooks", "system"):
        assert bare not in mgr.channels

    mgr.disconnect(sock, "user-a")
    assert mgr.channels == {}


async def test_orgless_user_joins_global_scope_only() -> None:
    mgr = ConnectionManager()
    await mgr.connect(_FakeSocket(), "lonely", organization_id=None)
    assert "alerts:global" in mgr.channels
    assert await mgr.subscribe("lonely", f"alerts:{ORG_A}") is False


async def test_new_alert_reaches_only_owning_tenant(two_tenants) -> None:
    _, sock_a, sock_b = two_tenants
    await wsm.notify_new_alert({"id": "al-1", "organization_id": ORG_A})
    assert "alert_created" in sock_a.types()
    assert sock_a.sent[-1]["channel"] == f"alerts:{ORG_A}"
    assert sock_b.sent == []

    await wsm.notify_alert_updated("al-1", {"status": "closed"}, ORG_B)
    assert "alert_updated" in sock_b.types()
    assert "alert_updated" not in sock_a.types()


async def test_incident_playbook_and_system_events_are_tenant_scoped(two_tenants) -> None:
    _, sock_a, sock_b = two_tenants
    await wsm.notify_new_incident({"id": "inc-1"}, ORG_A)
    await wsm.notify_incident_updated("inc-1", {"status": "closed"}, ORG_A)
    await wsm.notify_playbook_execution("step_started", {"execution_id": "e1"}, ORG_A)
    await wsm.notify_system_event("llm_budget", "budget at 90%", {"pct": 90}, organization_id=ORG_A)
    assert sock_a.types() == [
        "incident_created", "incident_updated", "playbook_step_started", "system_llm_budget",
    ]
    assert sock_b.sent == []


async def test_notification_callback_targets_tenant_channel(two_tenants) -> None:
    _, sock_a, sock_b = two_tenants
    callback = wsm.create_notification_callback("playbooks", ORG_B)
    await callback("execution_started", {"execution_id": "e2"})
    assert sock_b.sent[-1]["channel"] == f"playbooks:{ORG_B}"
    assert sock_a.sent == []


async def test_orgless_event_goes_to_global_scope_not_tenants(two_tenants) -> None:
    _, sock_a, sock_b = two_tenants
    await wsm.notify_new_alert({"id": "al-2", "organization_id": None})
    assert sock_a.sent == [] and sock_b.sent == []


async def test_superuser_may_subscribe_to_a_tenant_default_channel(two_tenants) -> None:
    mgr, _, _ = two_tenants
    root = _FakeSocket()
    await mgr.connect(root, "root", organization_id=None, is_superuser=True)
    assert await mgr.subscribe("root", f"alerts:{ORG_B}") is True
    root.sent.clear()
    await wsm.notify_new_alert({"id": "al-3"}, ORG_B)
    assert root.types() == ["alert_created"]
