"""Seed a local simulation EndpointAgent per organization.

The Purple Team / Live Response / BAS features all require an enrolled
agent to target. Rather than ask the operator to hand-enroll an agent
(which is the real-production path — run pysoar_agent.py --enroll on a
customer host), this seeder boots a co-deployed agent container that
lives inside the same docker-compose stack so the platform works out of
the box.

Contract:

1. For every organization, ensure there is exactly one active
   EndpointAgent with hostname 'pysoar-sim-host' and capabilities
   {bas, purple_team, live_response, stig_scan}. Idempotent — reuses
   the row on every boot.
2. Mint a fresh long-lived token on first creation and persist it to
   /app/data/agent/<org_id>.token with 0600 perms. The pysoar-agent
   docker service reads this file and passes it to pysoar_agent.py.
3. If the row already exists with a valid token_hash on disk, do not
   re-issue — token rotation is a separate operation.

No shortcuts: the agent this seeds is a *real* agent that polls the
real API, executes real subprocess commands, and posts real results.
It is not a mock.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from pathlib import Path
from typing import Any

from sqlalchemy import select

from src.core.database import async_session_factory
from src.core.logging import get_logger
from src.models.organization import Organization
from src.agents.capabilities import AgentCapability
from src.agents.models import EndpointAgent

logger = get_logger(__name__)

AGENT_TOKEN_DIR = os.environ.get("PYSOAR_AGENT_TOKEN_DIR", "/app/data/agent")
SIM_HOSTNAME = "pysoar-sim-host"
SIM_CAPABILITIES = [
    AgentCapability.BAS.value,
    AgentCapability.PURPLE_TEAM.value,
    AgentCapability.LIVE_RESPONSE.value,
    AgentCapability.COMPLIANCE.value,
]


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def seed_sim_agents() -> dict[str, Any]:
    created = 0
    tokens_written = 0

    Path(AGENT_TOKEN_DIR).mkdir(parents=True, exist_ok=True)

    async with async_session_factory() as db:
        orgs = list(await db.scalars(select(Organization)))
        for org in orgs:
            token_file = Path(AGENT_TOKEN_DIR) / f"{org.id}.token"

            existing = (await db.execute(
                select(EndpointAgent).where(
                    EndpointAgent.organization_id == org.id,
                    EndpointAgent.hostname == SIM_HOSTNAME,
                )
            )).scalar_one_or_none()

            if existing is None:
                # First boot for this org — mint an agent and token.
                agent_token = f"pst_{secrets.token_urlsafe(48)}"
                agent = EndpointAgent(
                    hostname=SIM_HOSTNAME,
                    display_name="Simulation Host",
                    os_type="linux",
                    capabilities=SIM_CAPABILITIES,
                    status="active",
                    token_hash=_sha256(agent_token),
                    organization_id=org.id,
                    tags=["simulation", "bas", "purple-team"],
                )
                db.add(agent)
                await db.flush()
                token_file.write_text(agent_token)
                # Write the capability list next to the token so the
                # agent's poll loop can build its action handler table.
                # Without this the agent refuses every action.
                caps_file = Path(str(token_file) + ".caps")
                caps_file.write_text(json.dumps(SIM_CAPABILITIES))
                try:
                    os.chmod(token_file, 0o600)
                    os.chmod(caps_file, 0o600)
                except OSError:
                    pass
                created += 1
                tokens_written += 1
                logger.info(
                    "Seeded simulation agent",
                    org_id=org.id,
                    agent_id=agent.id,
                    token_file=str(token_file),
                )
            else:
                # Agent exists. If the token file is missing but status
                # is active, rotate the token so the co-deployed agent
                # container has something to read after a volume wipe.
                if not token_file.exists():
                    agent_token = f"pst_{secrets.token_urlsafe(48)}"
                    existing.token_hash = _sha256(agent_token)
                    existing.capabilities = SIM_CAPABILITIES
                    existing.status = "active"
                    token_file.write_text(agent_token)
                    caps_file = Path(str(token_file) + ".caps")
                    caps_file.write_text(json.dumps(SIM_CAPABILITIES))
                    try:
                        os.chmod(token_file, 0o600)
                        os.chmod(caps_file, 0o600)
                    except OSError:
                        pass
                    tokens_written += 1
                    logger.info(
                        "Rotated simulation agent token (file was missing)",
                        org_id=org.id,
                        agent_id=existing.id,
                    )

        await db.commit()

    return {"created": created, "tokens_written": tokens_written}
