"""Per-executor integration tests for the fixed action executors in PR 2.

Each test class corresponds to one ActionType enum value (PR 3 will add).
Tests assert observable DB side-effects, never just that the function returned
success=True.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.models import EndpointAgent, AgentCommand
from src.models.base import utc_now
from src.models.organization import Organization
from src.models.user import User
from src.remediation.engine import (
    AccountActionExecutor,
    FirewallBlockExecutor,
    HostIsolationExecutor,
)


def _context_for(user_id: str, org_id: str) -> dict:
    """Shared helper to build the executor context dict."""
    return {
        "execution_id": "test-exec-" + org_id[:8],
        "organization_id": org_id,
        "initiated_by": user_id,
        "trigger_data": {},
    }


class TestPasswordResetGeneratesRealToken:
    async def test_token_is_set_and_indexed(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=default_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(default_user.id, default_org.id),
        )

        assert result["success"] is True

        await db_session.refresh(default_user)
        assert default_user.password_reset_token is not None
        assert len(default_user.password_reset_token) >= 40  # 48-byte url-safe is ~64 chars
        assert default_user.password_reset_token_expires_at is not None

        # Compare as datetime objects, making both naive for SQLite compatibility
        expires = default_user.password_reset_token_expires_at
        if expires.tzinfo is not None:
            expires = expires.replace(tzinfo=None)
        now = utc_now().replace(tzinfo=None)
        later = (utc_now() + timedelta(hours=25)).replace(tzinfo=None)

        assert expires > now
        assert expires < later
        assert default_user.force_password_change is True

    async def test_token_is_NOT_returned_in_result(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        """The plaintext token must not leak through the executor's return
        value — only the User row carries it."""
        executor = AccountActionExecutor(db_session)
        result = await executor.execute(
            target=default_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(default_user.id, default_org.id),
        )
        await db_session.refresh(default_user)
        # The full plaintext token must not be in the result dict
        result_str = str(result)
        assert default_user.password_reset_token not in result_str

    async def test_audit_row_carries_no_token_material(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        monkeypatch,
    ):
        """The TicketActivity audit row must contain NO token-identifying
        material — not the plaintext token, not a sha256 prefix, not a
        suffix, not anything an attacker with audit-log read access could
        correlate to the specific token.

        Uses monkeypatch to force the executor's token to a recognizable
        deterministic value. This removes the flake risk of asserting that
        a random base64 slice doesn't coincidentally appear in audit text —
        the test now checks an exact, never-coincidentally-present string.
        """
        import hashlib
        import json
        from src.tickethub.models import TicketActivity

        # Force the token to a known recognizable value so the absence
        # assertion below is exact, not probabilistic.
        FIXED_TOKEN = "GUARD-CANARY-NEVER-IN-AUDIT-ROWS-" + "Z" * 30
        monkeypatch.setattr(
            "secrets.token_urlsafe",
            lambda nbytes=None: FIXED_TOKEN,
        )

        executor = AccountActionExecutor(db_session)
        await executor.execute(
            target=default_user.email,
            parameters={"action": "password_reset"},
            context=_context_for(default_user.id, default_org.id),
        )
        await db_session.refresh(default_user)
        assert default_user.password_reset_token == FIXED_TOKEN

        # Fetch the most recent activity row for this execution
        stmt = (
            select(TicketActivity)
            .where(TicketActivity.source_id == _context_for(default_user.id, default_org.id)["execution_id"])
            .order_by(TicketActivity.created_at.desc())
        )
        activity = (await db_session.execute(stmt)).scalars().first()
        assert activity is not None

        # Serialize the whole row to a string and assert no token derivatives
        row_dump = json.dumps(
            {
                "description": activity.description,
                "extra_metadata": activity.extra_metadata,
            },
            default=str,
        )
        # Exact deterministic-token assertions (no random-slice false positives)
        assert FIXED_TOKEN not in row_dump
        assert "GUARD-CANARY" not in row_dump
        sha_full = hashlib.sha256(FIXED_TOKEN.encode()).hexdigest()
        for length in (8, 16, 24, 32, 64):
            assert sha_full[:length] not in row_dump
            assert sha_full[-length:] not in row_dump
        # And the prefix/suffix slices specifically — won't coincide because
        # the canary contains "GUARD-CANARY" which appears nowhere else.
        assert FIXED_TOKEN[:16] not in row_dump
        assert FIXED_TOKEN[-16:] not in row_dump


class TestProcessKillIssuesAgentCommand:
    async def test_writes_agent_commands_row(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        default_agent: EndpointAgent,
    ):
        from src.remediation.engine import ProcessActionExecutor

        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target=default_agent.hostname,
            parameters={"action": "kill", "pid": 1234, "process_name": "malware.exe"},
            context=_context_for(default_user.id, default_org.id),
        )

        assert result["success"] is True
        assert "command_id" in result
        # Now verify a real agent_commands row was written
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd_row = (await db_session.execute(stmt)).scalars().first()
        assert cmd_row is not None
        assert cmd_row.action == "kill_process"
        assert cmd_row.agent_id == default_agent.id
        assert cmd_row.payload.get("pid") == 1234
        assert cmd_row.payload.get("process_name") == "malware.exe"
        # Hash chain must be populated
        assert cmd_row.command_hash
        assert cmd_row.chain_hash
        # Status: queued or awaiting_approval (high-blast); never "fake-success"
        assert cmd_row.status in ("queued", "awaiting_approval")

    async def test_returns_failure_when_no_agent(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        """No agent enrolled for the target → executor returns success=False
        with a real error. Never returns success=True with a placeholder."""
        from src.remediation.engine import ProcessActionExecutor

        executor = ProcessActionExecutor(db_session)
        result = await executor.execute(
            target="no-such-host-12345",
            parameters={"action": "kill", "pid": 1, "process_name": "x"},
            context=_context_for(default_user.id, default_org.id),
        )
        assert result["success"] is False
        assert "no agent" in result["error"].lower()


class TestFileQuarantineIssuesAgentCommand:
    async def test_writes_agent_commands_row(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
        default_agent: EndpointAgent,
    ):
        from src.remediation.engine import FileActionExecutor

        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target=default_agent.hostname,
            parameters={"file_path": "/tmp/malware.bin", "file_hash": "abc123"},
            context=_context_for(default_user.id, default_org.id),
        )

        assert result["success"] is True
        assert "command_id" in result
        stmt = select(AgentCommand).where(AgentCommand.id == result["command_id"])
        cmd_row = (await db_session.execute(stmt)).scalars().first()
        assert cmd_row is not None
        assert cmd_row.action == "quarantine_file"
        assert cmd_row.payload.get("file_path") == "/tmp/malware.bin"

    async def test_returns_failure_when_no_agent(
        self,
        db_session: AsyncSession,
        default_org: Organization,
        default_user: User,
    ):
        from src.remediation.engine import FileActionExecutor

        executor = FileActionExecutor(db_session)
        result = await executor.execute(
            target="no-such-host-12345",
            parameters={"file_path": "/tmp/x"},
            context=_context_for(default_user.id, default_org.id),
        )
        assert result["success"] is False
        assert "no agent" in result["error"].lower()

    async def test_router_dispatches_file_quarantine_to_file_executor(
        self,
        db_session: AsyncSession,
        default_org: Organization,
    ):
        """The RemediationEngine's executors dict must map 'file_quarantine'
        to FileActionExecutor (not ProcessActionExecutor) — otherwise the
        Task 8 rewrite of ProcessActionExecutor would break file_quarantine."""
        from src.remediation.engine import (
            FileActionExecutor,
            ProcessActionExecutor,
            RemediationEngine,
        )

        engine = RemediationEngine(db_session)
        assert isinstance(engine.executors["file_quarantine"], FileActionExecutor)
        # ProcessActionExecutor only handles process_kill now
        assert isinstance(engine.executors["process_kill"], ProcessActionExecutor)
        assert not isinstance(engine.executors["process_kill"], FileActionExecutor)
