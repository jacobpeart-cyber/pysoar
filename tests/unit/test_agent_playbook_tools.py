"""Read-only playbook tools for the autonomous investigator.

The SOC-analyst system prompt requires the agent to consult the matching
PySOAR playbook BEFORE issuing a verdict and to cite it in conclusions.
That is only honest if the registry exposes read-only playbook retrieval —
previously the sole playbook tool was execute_playbook, which is blocked
during autonomous runs.
"""

import json

import pytest

from src.models.playbook import Playbook
from src.services.agent_tools import AgentToolRegistry


@pytest.fixture
async def seeded_playbooks(db_session):
    pbs = [
        Playbook(
            name="Credential Stuffing Response",
            description="Containment steps for credential stuffing attacks",
            status="active",
            category="identity",
            steps=json.dumps([
                {"order": 1, "action": "Confirm failed-login pattern across IPs"},
                {"order": 2, "action": "Force password reset for targeted accounts"},
            ]),
        ),
        Playbook(
            name="Phishing Triage",
            description="Standard phishing email triage",
            status="active",
            category="email",
            steps=json.dumps([{"order": 1, "action": "Detonate URL in sandbox"}]),
        ),
        Playbook(
            name="Old Draft",
            description="Unfinished draft",
            status="draft",
            is_enabled=False,
            steps=json.dumps([]),
        ),
    ]
    db_session.add_all(pbs)
    await db_session.commit()
    for pb in pbs:
        await db_session.refresh(pb)
    return pbs


@pytest.mark.asyncio
async def test_list_playbooks_registered_as_readonly_query(db_session):
    registry = AgentToolRegistry(db_session)
    tool = registry.tools.get("list_playbooks")
    assert tool is not None
    assert tool.category == "query"


@pytest.mark.asyncio
async def test_list_playbooks_returns_seeded_rows(db_session, seeded_playbooks):
    registry = AgentToolRegistry(db_session)
    out = await registry.execute("list_playbooks", {})
    assert out["success"] is True
    names = {p["name"] for p in out["result"]}
    assert "Credential Stuffing Response" in names
    assert "Phishing Triage" in names


@pytest.mark.asyncio
async def test_list_playbooks_keyword_filter(db_session, seeded_playbooks):
    registry = AgentToolRegistry(db_session)
    out = await registry.execute("list_playbooks", {"keyword": "credential"})
    assert out["success"] is True
    assert [p["name"] for p in out["result"]] == ["Credential Stuffing Response"]


@pytest.mark.asyncio
async def test_get_playbook_returns_parsed_steps(db_session, seeded_playbooks):
    registry = AgentToolRegistry(db_session)
    pb = seeded_playbooks[0]
    out = await registry.execute("get_playbook", {"playbook_id": pb.id})
    assert out["success"] is True
    detail = out["result"]
    assert detail["name"] == "Credential Stuffing Response"
    assert isinstance(detail["steps"], list)
    assert detail["steps"][0]["action"].startswith("Confirm failed-login")


@pytest.mark.asyncio
async def test_get_playbook_unknown_id_is_clean_error(db_session):
    registry = AgentToolRegistry(db_session)
    out = await registry.execute("get_playbook", {"playbook_id": "nope"})
    assert out["success"] is True
    assert "error" in out["result"]


@pytest.mark.asyncio
async def test_investigator_allows_new_tools_and_still_blocks_execute(db_session):
    from src.agentic.investigator import (
        AUTONOMOUS_BLOCKED_TOOLS,
        INVESTIGATOR_READONLY_TOOLS,
    )

    assert "list_playbooks" in INVESTIGATOR_READONLY_TOOLS
    assert "get_playbook" in INVESTIGATOR_READONLY_TOOLS
    assert "execute_playbook" in AUTONOMOUS_BLOCKED_TOOLS
