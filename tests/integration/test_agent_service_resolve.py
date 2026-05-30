"""Tests for AgentService.resolve_for_target."""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent
from src.agents.service import AgentService
from src.models.organization import Organization


class TestResolveForTarget:
    async def test_resolves_by_hostname(
        self,
        db_session: AsyncSession,
        default_agent: EndpointAgent,
        default_org: Organization,
    ):
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            default_agent.hostname, organization_id=default_org.id
        )
        assert resolved is not None
        assert resolved.id == default_agent.id

    async def test_resolves_by_ip(
        self,
        db_session: AsyncSession,
        default_agent: EndpointAgent,
        default_org: Organization,
    ):
        # Set an IP on the agent
        default_agent.ip_address = "10.0.0.42"
        await db_session.flush()
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            "10.0.0.42", organization_id=default_org.id
        )
        assert resolved is not None
        assert resolved.id == default_agent.id

    async def test_returns_none_for_unknown_target(
        self,
        db_session: AsyncSession,
        default_agent: EndpointAgent,
        default_org: Organization,
    ):
        svc = AgentService(db_session)
        resolved = await svc.resolve_for_target(
            "nonexistent-host-99", organization_id=default_org.id
        )
        assert resolved is None

    async def test_scopes_to_caller_org(
        self,
        db_session: AsyncSession,
        default_agent: EndpointAgent,
        default_org: Organization,
    ):
        """The agent belongs to default_org. Resolving the same hostname under a
        DIFFERENT org's id MUST return None — never leak across tenants."""
        from src.models.organization import Organization as OrgModel

        other_org = OrgModel(
            name="OtherOrg", slug="other-org", plan="enterprise", is_active=True
        )
        db_session.add(other_org)
        await db_session.flush()
        svc = AgentService(db_session)
        # Hostname matches but org doesn't — must NOT return the agent
        resolved = await svc.resolve_for_target(
            default_agent.hostname, organization_id=other_org.id
        )
        assert resolved is None

    async def test_organization_id_is_keyword_only(
        self,
        db_session: AsyncSession,
        default_org: Organization,
    ):
        """organization_id MUST be keyword-only — protects against positional
        argument shuffling that could silently drop the tenant filter."""
        svc = AgentService(db_session)
        with pytest.raises(TypeError):
            # Passing organization_id positionally must fail
            await svc.resolve_for_target("some-host", default_org.id)  # type: ignore[misc]
