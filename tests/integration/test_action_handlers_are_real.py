"""Capability gate: every ActionType enum value MUST map to a real, observable
handler that produces DB-side-effects. If any test in this file fails, the
corresponding enum value cannot ship in src/agentic/action_classifier.py.

This is the Rule 3 enforcer from the sub-project E spec.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent, AgentCommand
from src.agentic.action_classifier import ActionType
from src.models.organization import Organization
from src.models.user import User
from src.intel.models import ThreatIndicator
from src.models.asset import Asset
from src.remediation.engine import (
    AccountActionExecutor,
    FileActionExecutor,
    FirewallBlockExecutor,
    ForensicsCollectionExecutor,
    HostIsolationExecutor,
    ProcessActionExecutor,
)


def _ctx(user_id: str, org_id: str) -> dict:
    return {
        "execution_id": f"gate-{org_id[:8]}",
        "organization_id": org_id,
        "initiated_by": user_id,
        "trigger_data": {},
    }


class TestCapabilityGate:
    """One test per ActionType enum value. Each proves observable state change."""

    async def test_firewall_block(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        assert ActionType.FIREWALL_BLOCK.value == "firewall_block"
        executor = FirewallBlockExecutor(db_session)
        result = await executor.execute(
            target="203.0.113.42",
            parameters={"duration_hours": 12},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        # Verify the ThreatIndicator was written
        stmt = select(ThreatIndicator).where(
            ThreatIndicator.value == "203.0.113.42",
            ThreatIndicator.is_active == True,  # noqa: E712
        )
        ioc = (await db_session.execute(stmt)).scalars().first()
        assert ioc is not None
        assert ioc.indicator_type == "ipv4"
        assert ioc.severity == "high"

    async def test_host_isolate(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        assert ActionType.HOST_ISOLATE.value == "host_isolate"
        # Need an Asset to isolate
        asset = Asset(
            name="gate-test-host",
            hostname="gate-test-host",
            asset_type="server",
            status="active",
            organization_id=default_org.id,
        )
        db_session.add(asset)
        await db_session.flush()
        executor = HostIsolationExecutor(db_session)
        result = await executor.execute(
            target="gate-test-host",
            parameters={},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(asset)
        assert asset.status == "maintenance"

    async def test_account_disable(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        assert ActionType.ACCOUNT_DISABLE.value == "account_disable"
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=default_user.email,
            parameters={"action": "disable"},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(default_user)
        assert default_user.is_active is False

    async def test_password_reset(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        assert ActionType.PASSWORD_RESET.value == "password_reset"
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=default_user.email,
            parameters={"action": "password_reset"},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        await db_session.refresh(default_user)
        assert default_user.password_reset_token is not None
        assert default_user.password_reset_token_expires_at is not None
        # SQLite returns naive; normalize for the comparison.
        expires_at = default_user.password_reset_token_expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        assert expires_at > datetime.now(timezone.utc)

    async def test_password_reset_end_to_end_through_endpoints(
        self,
        client,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        """End-to-end gate for password_reset: executor issues a token,
        /validate sees it as valid, /consume burns it and changes the
        password, repeated /consume gets 404/410. This is the proof that
        the full reset flow is real, not just that the executor wrote a
        token the rest of the system can't actually do anything with.

        Manually replicating /consume's logic in a test would prove the
        executor's token is well-formed but NOT prove the URL flow works
        end-to-end. The gate exists to catch the case where the executor
        is right but the consumption endpoints are broken or missing.

        Uses the `client` fixture from tests/conftest.py which overrides
        get_db so the endpoint sees the same in-memory session as the
        test (StaticPool keeps connections to the same :memory: DB).
        """
        # Step 1: executor sets the token
        executor = AccountActionExecutor(db_session)
        await executor.execute(
            target=default_user.email,
            parameters={"action": "password_reset"},
            context=_ctx(default_user.id, default_org.id),
        )
        await db_session.commit()
        await db_session.refresh(default_user)
        token = default_user.password_reset_token
        original_hash = default_user.hashed_password
        assert token is not None

        # Step 2: /validate returns 200
        r = await client.post(
            "/api/v1/auth/password-reset/validate",
            json={"token": token},
        )
        assert r.status_code == 200, r.text

        # Step 3: /consume burns the token + sets new password
        r = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "GateTestStr0ng!2026"},
        )
        assert r.status_code == 200, r.text

        # Step 4: second /consume must fail (token burned)
        r = await client.post(
            "/api/v1/auth/password-reset/consume",
            json={"token": token, "new_password": "DifferentStr0ng!2026"},
        )
        assert r.status_code in (404, 410)

        await db_session.refresh(default_user)
        assert default_user.password_reset_token is None
        assert default_user.hashed_password != original_hash

    async def test_process_kill(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        default_agent: EndpointAgent,
    ):
        assert ActionType.PROCESS_KILL.value == "process_kill"
        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target=default_agent.hostname,
            parameters={"action": "kill", "pid": 999, "process_name": "evil.exe"},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd = (await db_session.execute(stmt)).scalars().first()
        assert cmd is not None
        assert cmd.action == "kill_process"
        assert cmd.chain_hash  # hash chain populated

    async def test_file_quarantine(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        default_agent: EndpointAgent,
    ):
        assert ActionType.FILE_QUARANTINE.value == "file_quarantine"
        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target=default_agent.hostname,
            parameters={"file_path": "/tmp/evil.bin"},
            context=_ctx(default_user.id, default_org.id),
        )
        assert result["success"] is True
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd = (await db_session.execute(stmt)).scalars().first()
        assert cmd is not None
        assert cmd.action == "quarantine_file"

    async def test_collect_forensics(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        default_agent: EndpointAgent,
    ):
        assert ActionType.COLLECT_FORENSICS.value == "collect_forensics"
        executor = ForensicsCollectionExecutor(db_session)
        result = await executor.execute(
            target=default_agent.hostname,
            parameters={},
            context=_ctx(default_user.id, default_org.id),
        )
        # Per-sub-result reporting - each sub-command is independent
        assert "sub_results" in result
        assert len(result["sub_results"]) == 3
        # Gate asserts all three queued for the all-capabilities agent
        for sub in result["sub_results"]:
            assert sub["success"] is True
            assert sub["command_id"] is not None
        cmd_ids = [sub["command_id"] for sub in result["sub_results"]]
        stmt = select(AgentCommand).where(AgentCommand.id.in_(cmd_ids))
        cmds = (await db_session.execute(stmt)).scalars().all()
        actions = {c.action for c in cmds}
        assert actions == {
            "collect_process_list",
            "collect_network_connections",
            "collect_memory_dump",
        }


class TestEnumCoverage:
    """Meta-test: if ActionType grows, this test surfaces the new value
    forcing the gate to expand. Catches the regression where someone adds
    an enum value without adding the corresponding test method above."""

    def test_every_enum_has_a_test_method(self):
        existing_tests = {
            name for name in dir(TestCapabilityGate) if name.startswith("test_")
        }
        # Each enum value must have a test method whose name ends with the value
        for action in ActionType:
            expected = f"test_{action.value}"
            assert expected in existing_tests, (
                f"ActionType.{action.name} ({action.value}) has no test method "
                f"'{expected}' in TestCapabilityGate. Add one before this "
                f"enum value can ship — it is not capability-gated."
            )
