"""Agent-hosted honeypots — audit gap #9.

Before: deploy_honeypot created a Decoy row and the UI showed it as
deployed; no listener existed anywhere. Now honeypot decoys dispatch a
deploy command to a deception-capable endpoint agent which runs a REAL
TCP listener; interactions flow back as DecoyInteraction rows (which the
agentic broad sweep already investigates). Without an agent the decoy is
honestly labeled record_only.

Spec: docs/superpowers/specs/2026-06-11-agent-hosted-honeypots-design.md
"""

import importlib.util
import socket
import sys
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from src.agents.capabilities import capability_allows
from src.agents.models import AgentCommand, EndpointAgent
from src.deception.models import Decoy, DecoyInteraction

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load_agent_module():
    spec = importlib.util.spec_from_file_location(
        "pysoar_agent_test", REPO_ROOT / "agent" / "pysoar_agent.py"
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["pysoar_agent_test"] = mod
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Capability gating
# ---------------------------------------------------------------------------

def test_deception_capability_gates_honeypot_actions():
    assert capability_allows(["deception"], "deploy_honeypot") is True
    assert capability_allows(["deception"], "stop_honeypot") is True
    assert capability_allows(["bas", "ir"], "deploy_honeypot") is False
    # deception capability must not unlock anything else
    assert capability_allows(["deception"], "kill_process") is False


# ---------------------------------------------------------------------------
# Agent-side listener (real socket on an ephemeral port)
# ---------------------------------------------------------------------------

def test_honeypot_listener_serves_banner_and_records_interaction():
    agent = _load_agent_module()
    manager = agent.HoneypotManager()

    # Find a free port
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    if port <= 1024:
        pytest.skip("ephemeral port unexpectedly privileged")

    result = manager.deploy("decoy-1", port, service="ssh")
    assert result["status"] == "success", result

    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=5)
        client.sendall(b"SSH-2.0-attacker\r\n")
        banner = client.recv(256)
        client.close()
        assert b"SSH-2.0-OpenSSH" in banner

        deadline = time.time() + 5
        interactions = []
        while time.time() < deadline and not interactions:
            interactions = manager.drain_interactions()
            if not interactions:
                time.sleep(0.1)
        assert interactions, "interaction was not recorded"
        hit = interactions[0]
        assert hit["decoy_id"] == "decoy-1"
        assert hit["source_ip"] == "127.0.0.1"
        assert "attacker" in hit["data_sample"]
    finally:
        stop = manager.stop("decoy-1")
        assert stop["status"] == "success"

    # Port is actually released
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1)


def test_honeypot_rejects_privileged_and_duplicate_ports():
    agent = _load_agent_module()
    manager = agent.HoneypotManager()
    assert manager.deploy("d1", 80)["status"] == "error"
    assert manager.deploy("d2", "not-a-port")["status"] == "error"
    assert manager.stop("never-deployed")["status"] == "error"


# ---------------------------------------------------------------------------
# Server-side dispatch
# ---------------------------------------------------------------------------

def _decoy(org="org-1", **overrides):
    fields = dict(
        name="ssh-trap",
        decoy_type="honeypot",
        category="network",
        status="deploying",
        emulated_service="SSH",
        configuration={},
        organization_id=org,
    )
    fields.update(overrides)
    return Decoy(**fields)


@pytest.mark.asyncio
async def test_dispatch_issues_agent_command(db_session):
    from src.deception.engine import dispatch_honeypot_to_agent

    agent = EndpointAgent(
        hostname="trap-host",
        status="active",
        capabilities=["deception"],
        organization_id="org-1",
    )
    decoy = _decoy()
    db_session.add_all([agent, decoy])
    await db_session.flush()

    out = await dispatch_honeypot_to_agent(db_session, decoy)
    await db_session.commit()

    assert out["dispatched"] is True
    assert decoy.status == "deploying"
    listener = decoy.configuration["listener"]
    assert listener["agent_id"] == agent.id
    cmd = (
        await db_session.execute(
            select(AgentCommand).where(AgentCommand.id == listener["command_id"])
        )
    ).scalar_one()
    assert cmd.action == "deploy_honeypot"
    assert cmd.payload["decoy_id"] == decoy.id
    assert cmd.payload["port"] > 1024


@pytest.mark.asyncio
async def test_dispatch_without_agent_is_honest(db_session):
    from src.deception.engine import dispatch_honeypot_to_agent

    decoy = _decoy(org="org-lonely")
    db_session.add(decoy)
    await db_session.flush()

    out = await dispatch_honeypot_to_agent(db_session, decoy)

    assert out["dispatched"] is False
    assert decoy.status == "record_only"
    assert "no listener is running" in decoy.configuration["listener"]["note"]


# ---------------------------------------------------------------------------
# Interaction ingest endpoint (agent auth via dependency override)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_interaction_endpoint_creates_rows_and_blocks_cross_tenant(
    client, db_session
):
    from src.api.v1.endpoints.agents import _require_agent
    from src.main import app

    agent = EndpointAgent(
        hostname="trap-host",
        status="active",
        capabilities=["deception"],
        organization_id="org-1",
    )
    own_decoy = _decoy(org="org-1")
    foreign_decoy = _decoy(org="org-2", name="foreign-trap")
    db_session.add_all([agent, own_decoy, foreign_decoy])
    await db_session.commit()

    app.dependency_overrides[_require_agent] = lambda: agent
    try:
        resp = await client.post(
            "/api/v1/agents/_agent/honeypot-interactions",
            json={
                "interactions": [
                    {"decoy_id": own_decoy.id, "source_ip": "203.0.113.9",
                     "source_port": 50123, "data_sample": "SSH-2.0-attacker"},
                    {"decoy_id": foreign_decoy.id, "source_ip": "203.0.113.9"},
                    {"decoy_id": "nonexistent", "source_ip": "203.0.113.9"},
                ]
            },
        )
    finally:
        app.dependency_overrides.pop(_require_agent, None)

    assert resp.status_code == 200
    body = resp.json()
    assert body["created"] == 1
    assert body["skipped"] == 2

    rows = (
        await db_session.execute(
            select(DecoyInteraction).where(DecoyInteraction.decoy_id == own_decoy.id)
        )
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].source_ip == "203.0.113.9"
    assert rows[0].organization_id == "org-1"
