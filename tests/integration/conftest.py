"""Integration test fixtures: org + user + endpoint agent enrolled with all capabilities.

Used by test_action_executors.py, test_password_reset_endpoints.py, and
test_action_handlers_are_real.py. The async `db_session` fixture is supplied
by the parent tests/conftest.py — we just consume it here.
"""

from __future__ import annotations

import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.security import get_password_hash
from src.models.user import User
from src.models.organization import Organization
from src.agents.models import EndpointAgent


@pytest_asyncio.fixture
async def default_org(db_session: AsyncSession) -> Organization:
    org = Organization(
        name="ExecutorTestOrg",
        slug="executor-test-org",
        plan="enterprise",
        is_active=True,
    )
    db_session.add(org)
    await db_session.flush()
    return org


@pytest_asyncio.fixture
async def default_user(db_session: AsyncSession, default_org: Organization) -> User:
    user = User(
        email="target@executor-test.local",
        hashed_password=get_password_hash("not-used-in-tests"),
        full_name="Executor Test Target",
        is_active=True,
        is_superuser=False,
        organization_id=default_org.id,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def default_agent(db_session: AsyncSession, default_org: Organization) -> EndpointAgent:
    """Endpoint agent enrolled with all capabilities the executors might need."""
    agent = EndpointAgent(
        hostname="executor-test-host-01",
        os_type="linux",
        agent_version="0.1.0",
        capabilities=["bas", "ir", "purple"],
        status="active",
        organization_id=default_org.id,
        last_command_hash=None,  # genesis
    )
    db_session.add(agent)
    await db_session.flush()
    return agent
