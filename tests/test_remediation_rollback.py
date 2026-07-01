"""Tests for real remediation rollback, retry policy, rate limiting,
and the agentic action rollback endpoint.

These exercise the actual engine + executors against the test database:
rollback must really mutate state (deactivate IOCs, re-enable accounts,
restore asset status) and must honestly report actions it cannot reverse.
"""

import json
from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.intel.models import ThreatIndicator
from src.models.asset import Asset, AssetStatus
from src.models.base import utc_now
from src.models.organization import Organization
from src.models.user import User
from src.remediation.engine import (
    RemediationEngine,
    FirewallBlockExecutor,
    AccountActionExecutor,
    HostIsolationExecutor,
)
from src.remediation.models import RemediationExecution, RemediationPolicy


@pytest_asyncio.fixture
async def org(db_session: AsyncSession) -> Organization:
    org = Organization(name="Rollback Test Org", slug="rollback-test-org")
    db_session.add(org)
    await db_session.commit()
    await db_session.refresh(org)
    return org


async def _make_execution(
    db_session: AsyncSession,
    org: Organization,
    target: str,
    actions_completed: list[dict],
    target_type: str = "ip",
    status: str = "completed",
) -> RemediationExecution:
    execution = RemediationExecution(
        trigger_source="manual",
        trigger_details={},
        status=status,
        target_entity=target,
        target_type=target_type,
        actions_planned=[{"type": a.get("action_type")} for a in actions_completed],
        actions_completed=actions_completed,
        organization_id=org.id,
    )
    db_session.add(execution)
    await db_session.commit()
    await db_session.refresh(execution)
    return execution


class TestFirewallBlockHonesty:
    """FirewallBlockExecutor must not imply enforcement it doesn't do."""

    async def test_firewall_block_reports_detection_only(
        self, db_session: AsyncSession, org: Organization
    ):
        executor = FirewallBlockExecutor(db_session)
        result = await executor.execute(
            "203.0.113.7", {"duration_hours": 4}, {"execution_id": "unknown"}
        )
        assert result["success"] is True
        assert result["mode"] == "detection_only"
        assert "no network" in result["detail"].lower() or "enforcement" in result["detail"].lower()

        # The IOC write is real
        ioc = await db_session.get(ThreatIndicator, result["ioc_id"])
        assert ioc is not None
        assert ioc.is_active is True
        assert ioc.value == "203.0.113.7"


class TestRollbackExecution:
    """rollback_execution must actually reverse state, not flip flags."""

    async def test_firewall_block_rollback_deactivates_ioc(
        self, db_session: AsyncSession, org: Organization
    ):
        executor = FirewallBlockExecutor(db_session)
        fwd = await executor.execute(
            "198.51.100.9", {"duration_hours": 24}, {"execution_id": "unknown"}
        )
        execution = await _make_execution(db_session, org, "198.51.100.9", [{
            "action_type": "firewall_block",
            "target": "198.51.100.9",
            "success": True,
            "details": {"ioc_id": fwd["ioc_id"]},
        }])

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        assert result["rollback_status"] == "completed"
        assert result["results"][0]["rolled_back"] is True
        assert result["results"][0]["ioc_id"] == fwd["ioc_id"]

        ioc = await db_session.get(ThreatIndicator, fwd["ioc_id"])
        assert ioc.is_active is False

        await db_session.refresh(execution)
        assert execution.rollback_status == "completed"
        assert execution.status == "rolled_back"
        assert execution.rolled_back_at is not None

    async def test_account_disable_rollback_reenables_user(
        self, db_session: AsyncSession, org: Organization
    ):
        user = User(
            email="victim@example.com",
            hashed_password="x",
            full_name="Victim",
            is_active=True,
            organization_id=org.id,
        )
        db_session.add(user)
        await db_session.commit()

        executor = AccountActionExecutor(db_session)
        fwd = await executor.execute(
            "victim@example.com", {"action": "disable"}, {"execution_id": "unknown"}
        )
        assert fwd["success"] is True
        await db_session.refresh(user)
        assert user.is_active is False

        execution = await _make_execution(
            db_session, org, "victim@example.com",
            [{
                "action_type": "account_disable",
                "target": "victim@example.com",
                "success": True,
                "details": fwd,
            }],
            target_type="user",
        )

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        assert result["rollback_status"] == "completed"
        assert result["results"][0]["rolled_back"] is True

        await db_session.refresh(user)
        assert user.is_active is True
        assert user.force_password_change is False

    async def test_host_isolate_rollback_restores_asset_status(
        self, db_session: AsyncSession, org: Organization
    ):
        asset = Asset(
            name="ws-042",
            hostname="ws-042",
            status=AssetStatus.ACTIVE.value,
            organization_id=org.id,
        )
        db_session.add(asset)
        await db_session.commit()

        executor = HostIsolationExecutor(db_session)
        fwd = await executor.execute("ws-042", {}, {"execution_id": "unknown"})
        assert fwd["success"] is True
        await db_session.refresh(asset)
        assert asset.status == AssetStatus.MAINTENANCE.value
        assert "isolated" in json.loads(asset.tags)

        execution = await _make_execution(
            db_session, org, "ws-042",
            [{
                "action_type": "host_isolate",
                "target": "ws-042",
                "success": True,
                "details": fwd,
            }],
            target_type="host",
        )

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        assert result["rollback_status"] == "completed"
        assert result["results"][0]["rolled_back"] is True
        assert result["results"][0]["restored_status"] == AssetStatus.ACTIVE.value

        await db_session.refresh(asset)
        assert asset.status == AssetStatus.ACTIVE.value
        assert "isolated" not in json.loads(asset.tags)

    async def test_irreversible_action_reported_honestly(
        self, db_session: AsyncSession, org: Organization
    ):
        execution = await _make_execution(
            db_session, org, "srv-01",
            [{
                "action_type": "process_kill",
                "target": "srv-01",
                "success": True,
                "details": {"command_id": "cmd-1"},
            }],
            target_type="host",
        )

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        entry = result["results"][0]
        assert entry["rolled_back"] is False
        assert entry["reversible"] is False
        assert "not reversible" in entry["reason"]
        # Nothing was reversed → the rollback must not claim success
        assert result["rollback_status"] == "failed"

        await db_session.refresh(execution)
        assert execution.status != "rolled_back"
        assert execution.rollback_status == "failed"

    async def test_mixed_rollback_reports_partial(
        self, db_session: AsyncSession, org: Organization
    ):
        executor = FirewallBlockExecutor(db_session)
        fwd = await executor.execute(
            "192.0.2.55", {"duration_hours": 1}, {"execution_id": "unknown"}
        )
        execution = await _make_execution(db_session, org, "192.0.2.55", [
            {
                "action_type": "firewall_block",
                "target": "192.0.2.55",
                "success": True,
                "details": {"ioc_id": fwd["ioc_id"]},
            },
            {
                "action_type": "process_kill",
                "target": "192.0.2.55",
                "success": True,
                "details": {},
            },
        ])

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        assert result["rollback_status"] == "partial"
        by_action = {r["action"]: r for r in result["results"]}
        assert by_action["firewall_block"]["rolled_back"] is True
        assert by_action["process_kill"]["rolled_back"] is False
        assert by_action["process_kill"]["reversible"] is False

    async def test_failed_forward_action_is_skipped(
        self, db_session: AsyncSession, org: Organization
    ):
        execution = await _make_execution(db_session, org, "10.0.0.1", [{
            "action_type": "firewall_block",
            "target": "10.0.0.1",
            "success": False,
            "error": "boom",
        }])

        engine = RemediationEngine(db_session)
        result = await engine.rollback_execution(execution.id)

        entry = result["results"][0]
        assert entry["skipped"] is True
        assert entry["rolled_back"] is False
        # Nothing needed reversing → completed, but no fake reversal claim
        assert result["rollback_status"] == "completed"


class _FlakyExecutor:
    """Test double: fails N times then succeeds."""

    def __init__(self, fail_times: int):
        self.fail_times = fail_times
        self.calls = 0

    async def execute(self, target, parameters, context):
        self.calls += 1
        if self.calls <= self.fail_times:
            return {"success": False, "error": "transient failure"}
        return {"success": True, "action": "flaky"}


class TestRetryPolicy:
    """on_failure=retry must actually re-invoke the executor."""

    async def test_retry_reinvokes_until_success(
        self, db_session: AsyncSession, org: Organization
    ):
        execution = RemediationExecution(
            trigger_source="manual",
            trigger_details={},
            status="approved",
            target_entity="10.1.1.1",
            target_type="ip",
            actions_planned=[{
                "type": "flaky_test",
                "on_failure": "retry",
                "max_retries": 2,
                "retry_backoff_seconds": 0,
            }],
            actions_completed=[],
            organization_id=org.id,
        )
        db_session.add(execution)
        await db_session.commit()

        engine = RemediationEngine(db_session)
        flaky = _FlakyExecutor(fail_times=2)
        engine.executors["flaky_test"] = flaky

        run = await engine._run_actions(execution.id)

        assert flaky.calls == 3  # initial attempt + 2 retries
        result = run["results"][0]
        assert result["success"] is True
        assert result["attempts"] == 3

        await db_session.refresh(execution)
        assert execution.overall_result == "success"
        assert execution.actions_completed[0]["attempts"] == 3

    async def test_retry_exhaustion_reported(
        self, db_session: AsyncSession, org: Organization
    ):
        execution = RemediationExecution(
            trigger_source="manual",
            trigger_details={},
            status="approved",
            target_entity="10.1.1.2",
            target_type="ip",
            actions_planned=[{
                "type": "flaky_test",
                "on_failure": "retry",
                "max_retries": 1,
                "retry_backoff_seconds": 0,
            }],
            actions_completed=[],
            organization_id=org.id,
        )
        db_session.add(execution)
        await db_session.commit()

        engine = RemediationEngine(db_session)
        flaky = _FlakyExecutor(fail_times=99)
        engine.executors["flaky_test"] = flaky

        run = await engine._run_actions(execution.id)

        assert flaky.calls == 2  # initial attempt + 1 retry
        result = run["results"][0]
        assert result["success"] is False
        assert result["retries_exhausted"] is True

        await db_session.refresh(execution)
        assert execution.overall_result == "partial_success"


class TestRateLimitWindow:
    """_check_rate_limit must count real executions in the last hour."""

    async def test_rate_limit_counts_last_hour_window(
        self, db_session: AsyncSession, org: Organization
    ):
        user = User(
            email="owner@example.com",
            hashed_password="x",
            full_name="Owner",
            is_active=True,
            organization_id=org.id,
        )
        db_session.add(user)
        await db_session.commit()

        policy = RemediationPolicy(
            name="rate-limit-test-policy",
            policy_type="auto_block",
            trigger_type="alert_severity",
            trigger_conditions={},
            actions=[],
            max_executions_per_hour=1,
            created_by=user.id,
            organization_id=org.id,
        )
        db_session.add(policy)
        await db_session.commit()

        engine = RemediationEngine(db_session)

        # No executions yet → allowed
        assert await engine._check_rate_limit(policy) is True

        execution = RemediationExecution(
            policy_id=policy.id,
            trigger_source="alert",
            trigger_details={},
            status="completed",
            target_entity="1.2.3.4",
            target_type="ip",
            actions_planned=[],
            actions_completed=[],
            organization_id=org.id,
        )
        db_session.add(execution)
        await db_session.commit()

        # One execution inside the window → limit of 1/hr is hit
        assert await engine._check_rate_limit(policy) is False

        # Age the execution out of the 1-hour window → allowed again
        execution.created_at = utc_now() - timedelta(hours=2)
        await db_session.commit()
        assert await engine._check_rate_limit(policy) is True


class TestAgenticActionRollback:
    """POST /agentic/actions/{id}/rollback must reverse real state."""

    @pytest_asyncio.fixture
    async def org_user(self, db_session: AsyncSession, org: Organization) -> User:
        from src.core.security import get_password_hash

        user = User(
            email="analyst@rollback.test",
            hashed_password=get_password_hash("password12345"),
            full_name="Rollback Analyst",
            role="admin",
            is_active=True,
            organization_id=org.id,
        )
        db_session.add(user)
        await db_session.commit()
        await db_session.refresh(user)
        return user

    @pytest_asyncio.fixture
    async def org_auth_headers(self, org_user: User) -> dict:
        from src.core.security import create_access_token

        token = create_access_token(subject=org_user.id)
        return {"Authorization": f"Bearer {token}"}

    async def _make_action(
        self,
        db_session: AsyncSession,
        org: Organization,
        *,
        action_type: str,
        target: str,
        execution_status: str = "completed",
        parameters: dict | None = None,
        rollback_available: bool = True,
    ):
        from src.agentic.models import AgentAction
        from uuid import uuid4

        action = AgentAction(
            investigation_id=str(uuid4()),
            organization_id=org.id,
            action_type=action_type,
            target=target,
            parameters=json.dumps(parameters or {}),
            requires_approval=True,
            execution_status=execution_status,
            rollback_available=rollback_available,
        )
        db_session.add(action)
        await db_session.commit()
        await db_session.refresh(action)
        return action

    async def test_block_ip_rollback_deactivates_indicator(
        self, client, db_session: AsyncSession, org: Organization, org_auth_headers: dict
    ):
        ioc = ThreatIndicator(
            value="203.0.113.99",
            indicator_type="ipv4",
            severity="high",
            confidence=80,
            is_active=True,
            is_whitelisted=False,
            source="agent_block",
        )
        db_session.add(ioc)
        await db_session.commit()

        action = await self._make_action(
            db_session, org,
            action_type="block_ip",
            target="203.0.113.99",
            parameters={"_tool": "block_ip"},
        )

        resp = await client.post(
            f"/api/v1/agentic/actions/{action.id}/rollback",
            headers=org_auth_headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "rolled_back"
        assert ioc.id in body["detail"]["indicators_deactivated"]

        await db_session.refresh(ioc)
        assert ioc.is_active is False

        await db_session.refresh(action)
        assert action.rollback_executed is True
        assert action.execution_status == "rolled_back"

    async def test_disable_account_rollback_reenables_user(
        self, client, db_session: AsyncSession, org: Organization, org_auth_headers: dict
    ):
        disabled = User(
            email="disabled@rollback.test",
            hashed_password="x",
            full_name="Disabled User",
            is_active=False,
            organization_id=org.id,
        )
        db_session.add(disabled)
        await db_session.commit()

        action = await self._make_action(
            db_session, org,
            action_type="disable_account",
            target="disabled@rollback.test",
            parameters={"_tool": "disable_user", "user_email": "disabled@rollback.test"},
        )

        resp = await client.post(
            f"/api/v1/agentic/actions/{action.id}/rollback",
            headers=org_auth_headers,
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "rolled_back"

        await db_session.refresh(disabled)
        assert disabled.is_active is True

    async def test_not_reversible_action_reported_honestly(
        self, client, db_session: AsyncSession, org: Organization, org_auth_headers: dict
    ):
        action = await self._make_action(
            db_session, org,
            action_type="create_ticket",
            target="TICKET-1",
        )

        resp = await client.post(
            f"/api/v1/agentic/actions/{action.id}/rollback",
            headers=org_auth_headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "not_reversible"
        assert "no automated inverse" in body["reason"]

        await db_session.refresh(action)
        # Not marked rolled back, and no longer advertised as reversible
        assert action.rollback_executed is False
        assert action.execution_status == "completed"
        assert action.rollback_available is False

    async def test_unexecuted_action_cannot_be_rolled_back(
        self, client, db_session: AsyncSession, org: Organization, org_auth_headers: dict
    ):
        action = await self._make_action(
            db_session, org,
            action_type="block_ip",
            target="203.0.113.100",
            execution_status="pending_approval",
        )

        resp = await client.post(
            f"/api/v1/agentic/actions/{action.id}/rollback",
            headers=org_auth_headers,
        )
        assert resp.status_code == 400
        assert "only" in resp.json()["detail"].lower()

    async def test_block_ip_rollback_fails_when_no_indicator(
        self, client, db_session: AsyncSession, org: Organization, org_auth_headers: dict
    ):
        action = await self._make_action(
            db_session, org,
            action_type="block_ip",
            target="198.18.0.1",  # never blocked — no IOC exists
        )

        resp = await client.post(
            f"/api/v1/agentic/actions/{action.id}/rollback",
            headers=org_auth_headers,
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "failed"
        assert "no active threat indicator" in body["reason"]

        await db_session.refresh(action)
        assert action.rollback_executed is False
