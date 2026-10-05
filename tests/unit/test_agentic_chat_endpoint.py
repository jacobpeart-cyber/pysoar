"""POST /agentic/chat runs through the guarded agent runtime (work package 5A).

Covers design v2 sections 1 and 9 at the HTTP boundary: the context comes
from the JWT, viewers cannot ask for proposals, sessions are scoped to the
organization *and* the user, a client-supplied agent id is validated in-org,
destructive tools become approval-gated proposals instead of executing, and
an unconfigured provider is an honest 503 with the user's message persisted
as failed so the UI can retry.
"""
from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Optional

import pytest
from sqlalchemy import func, select

from src.agentic.models import (
    ActionExecutionStatus,
    AgentAction,
    AgentChatMessage,
    AgentChatSession,
    SOCAgent,
)
from src.core.security import get_password_hash
from src.intel.models import ThreatIndicator
from src.llm.base import LLMTurn, Message, ToolCall, ToolSpecForLLM, Usage
from src.models.alert import Alert
from src.models.organization import Organization
from src.models.settings import AppSetting
from src.models.user import User

ORG_A = "aaaaaaaa-0000-4000-8000-000000000001"
ORG_B = "bbbbbbbb-0000-4000-8000-000000000002"


# ---------------------------------------------------------------------------
# Test doubles: a scripted provider and a permissive quota backend
# ---------------------------------------------------------------------------


class FakeProvider:
    """Scripted ``LLMProvider``: each ``complete`` pops the next turn/error."""

    name = "fake"
    model = "fake-1"
    credential_source = "org"

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.requests: list[dict[str, Any]] = []

    async def __aenter__(self) -> "FakeProvider":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: Optional[list[ToolSpecForLLM]],
        max_tokens: int,
        response_schema: Any = None,
    ) -> LLMTurn:
        self.requests.append({"system": system, "messages": messages, "tools": tools})
        if not self.script:
            raise AssertionError("FakeProvider script exhausted")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def list_models(self) -> list[str]:
        return [self.model]

    def estimate_input_tokens(
        self, system: str, messages: list[Message], tools: Optional[list[ToolSpecForLLM]]
    ) -> int:
        return 100


def turn(
    text: str = "",
    calls: Optional[list[tuple[str, str, dict[str, Any]]]] = None,
    stop: Optional[str] = None,
) -> LLMTurn:
    tool_calls = [ToolCall(id=i, name=n, input=a) for i, n, a in (calls or [])]
    return LLMTurn(
        text=text,
        tool_calls=tool_calls,
        stop_reason=stop or ("tool_use" if tool_calls else "end_turn"),
        usage=Usage(input_uncached=20, output=8),
        provider="fake",
        model="fake-1",
        request_id="req-test",
        provider_native=None,
    )


@dataclass
class PermissiveQuota:
    """Budget/admission/breaker stand-in: always admits, never opens."""

    reserved: list[int] = field(default_factory=list)
    settled: list[int] = field(default_factory=list)

    @contextlib.asynccontextmanager
    async def admit(self, org_id: str, actor_key: str, bucket: str) -> Any:
        yield SimpleNamespace(org_id=org_id, actor_key=actor_key, bucket=bucket)

    async def reserve(self, org_id: str, bucket: str, tokens: int, *, credential_source: str = "org") -> Any:
        self.reserved.append(tokens)
        return SimpleNamespace(org_id=org_id, bucket=bucket, reserved=tokens, degraded=False, settled=False)

    async def settle(self, reservation: Any, actual_tokens: int) -> None:
        self.settled.append(actual_tokens)

    async def breaker_check(self, provider: str, credential_source: str, org_id: str) -> None:
        return None

    async def breaker_record_failure(self, provider: str, credential_source: str, org_id: str) -> bool:
        return False

    async def breaker_record_success(self, provider: str, credential_source: str, org_id: str) -> None:
        return None


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


def _token(user: User) -> dict[str, str]:
    from src.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


async def _orgs(db) -> None:
    for org_id, slug in ((ORG_A, "org-a"), (ORG_B, "org-b")):
        if await db.get(Organization, org_id) is None:
            db.add(Organization(id=org_id, name=slug.upper(), slug=slug))
    await db.flush()


async def _ai_settings(db, org_id: str = ORG_A) -> None:
    """A keyless provider so ``resolve_llm_config`` succeeds without secrets."""
    db.add(AppSetting(organization_id=org_id, section="ai", value={"provider": "ollama", "model": "llama3.1"}))
    await db.flush()


async def _user(db, *, email: str, role: str, org_id: str = ORG_A) -> User:
    user = User(
        email=email,
        hashed_password=get_password_hash("pw-for-tests"),
        full_name=email.split("@")[0],
        role=role,
        is_active=True,
        organization_id=org_id,
    )
    db.add(user)
    await db.flush()
    return user


async def _soc_agent(db, org_id: str = ORG_A) -> SOCAgent:
    agent = SOCAgent(
        organization_id=org_id,
        name="Tier-1 triage",
        agent_type="triage_analyst",
        llm_model="fake-1",
    )
    db.add(agent)
    await db.flush()
    return agent


async def _alert(db, org_id: str = ORG_A) -> Alert:
    alert = Alert(
        title="Repeated failed logins",
        description="48 failures for svc-backup from 198.51.100.24",
        severity="high",
        source="siem",
        status="new",
        organization_id=org_id,
        source_ip="198.51.100.24",
    )
    db.add(alert)
    await db.flush()
    return alert


def patch_llm_runtime(monkeypatch, script: list[Any]) -> SimpleNamespace:
    """Patch the provider factory, the quota backend and the call-log writer.

    The call-log writer is the one real collaborator that cannot run here:
    it commits ``llm_call_logs`` in its own session, and under the test
    SQLite StaticPool every session shares a single connection, so its
    commit/rollback would tear down the request's open transaction. Its
    records are collected instead, which still proves the wiring (production
    gets a separate connection per session and commits independently).
    """
    provider = FakeProvider(script)
    quota = PermissiveQuota()
    call_log: list[Any] = []

    async def _collect(record: Any) -> None:
        call_log.append(record)

    import src.api.v1.endpoints.agentic as endpoint
    import src.llm.factory as factory

    monkeypatch.setattr(factory, "build_provider", lambda *a, **k: provider, raising=True)
    monkeypatch.setattr(endpoint, "_agent_quota", lambda redis: quota, raising=True)
    monkeypatch.setattr(endpoint, "_call_log_writer", lambda: _collect, raising=True)
    return SimpleNamespace(provider=provider, quota=quota, call_log=call_log)


@pytest.fixture
def patched_runtime(monkeypatch):
    """Patch the provider factory and the quota backend for one test."""

    def _apply(script: list[Any]) -> SimpleNamespace:
        return patch_llm_runtime(monkeypatch, script)

    return _apply


# ---------------------------------------------------------------------------
# Role gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_viewer_cannot_request_proposals(client, db_session, patched_runtime):
    await _orgs(db_session)
    await _ai_settings(db_session)
    viewer = await _user(db_session, email="viewer@org-a.test", role="viewer")
    await db_session.commit()
    patched_runtime([turn(text="unused")])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(viewer),
        json={"query": "block 198.51.100.24", "propose_actions": True},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "role_not_permitted"


# ---------------------------------------------------------------------------
# Read path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_analyst_read_tool_run_returns_tool_log_and_no_proposals(
    client, db_session, patched_runtime
):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    await _alert(db_session)
    await db_session.commit()

    wired = patched_runtime([
        turn(calls=[("tu-1", "list_alerts", {"limit": 5})]),
        turn(text="One high-severity alert is open: repeated failed logins for svc-backup."),
    ])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "What alerts are open?"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposals"] == []
    assert body["run_id"]
    assert body["provider"] == "fake"
    assert body["model"] == "fake-1"
    assert body["usage"]["total_billable"] > 0
    tools = body["interpretation"]["tools_invoked"]
    assert [t["tool"] for t in tools] == ["list_alerts"]
    assert tools[0]["blocked"] is False
    assert "result" in tools[0]
    assert wired.quota.settled == [body["usage"]["total_billable"]]
    # One llm_call_logs record per provider turn, carrying the run id.
    assert [r.run_id for r in wired.call_log] == [body["run_id"], body["run_id"]]

    # Both turns are persisted and the assistant row carries the tool log.
    rows = (await db_session.execute(
        select(AgentChatMessage).order_by(AgentChatMessage.created_at.asc())
    )).scalars().all()
    assert [r.role for r in rows] == ["user", "assistant"]
    assert rows[1].tool_calls["tools_invoked"][0]["tool"] == "list_alerts"


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_destructive_tool_becomes_a_proposal_and_is_not_executed(
    client, db_session, patched_runtime
):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst2@org-a.test", role="analyst")
    await _soc_agent(db_session)
    await db_session.commit()

    patched_runtime([
        turn(calls=[("tu-1", "block_ip", {"ip": "198.51.100.24", "reason": "brute force source"})]),
        turn(text="I proposed blocking 198.51.100.24; it is pending your approval."),
    ])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "Block the brute force source", "propose_actions": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["proposals"]) == 1
    proposal = body["proposals"][0]
    assert proposal["tool"] == "block_ip"
    assert proposal["params_sha256"] and proposal["evidence_sha256"]
    assert proposal["effective_targets"][0]["value"] == "198.51.100.24"

    action = (await db_session.execute(select(AgentAction))).scalars().one()
    assert action.id == proposal["id"]
    assert action.tool_name == "block_ip"
    assert action.requires_approval is True
    assert action.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value
    assert action.params_sha256 == proposal["params_sha256"]
    assert action.evidence_sha256 == proposal["evidence_sha256"]
    assert action.proposed_by_user_id == analyst.id
    assert action.expires_at is not None

    # Nothing was executed: block_ip's forward effect is an active indicator.
    iocs = (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar()
    assert iocs == 0


@pytest.mark.asyncio
async def test_destructive_tool_without_propose_actions_is_denied_not_executed(
    client, db_session, patched_runtime
):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst3@org-a.test", role="analyst")
    await db_session.commit()

    patched_runtime([
        turn(calls=[("tu-1", "block_ip", {"ip": "198.51.100.24", "reason": "brute force source"})]),
        turn(text="I cannot act: proposing actions is disabled for this turn."),
    ])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "Block the brute force source"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["proposals"] == []
    tools = body["interpretation"]["tools_invoked"]
    assert tools[0]["blocked"] is True
    assert tools[0]["reason_code"] == "proposal_disabled"
    assert (await db_session.execute(select(func.count()).select_from(ThreatIndicator))).scalar() == 0


# ---------------------------------------------------------------------------
# Tenancy
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_session_from_another_tenant_is_not_found(client, db_session, patched_runtime):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst4@org-a.test", role="analyst")
    other = await _user(db_session, email="analyst@org-b.test", role="analyst", org_id=ORG_B)
    session = AgentChatSession(user_id=other.id, organization_id=ORG_B, title="theirs")
    db_session.add(session)
    await db_session.commit()
    patched_runtime([turn(text="unused")])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "what did we discuss?", "session_id": session.id},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["error"] == "session_not_found"


@pytest.mark.asyncio
async def test_agent_id_from_another_tenant_is_rejected(client, db_session, patched_runtime):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst5@org-a.test", role="analyst")
    foreign_agent = await _soc_agent(db_session, org_id=ORG_B)
    await db_session.commit()
    patched_runtime([turn(text="unused")])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "status?", "agent_id": foreign_agent.id},
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "unknown_agent"


# ---------------------------------------------------------------------------
# Honest failures
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unconfigured_llm_is_503_and_persists_the_user_message(client, db_session):
    await _orgs(db_session)  # deliberately no ai settings for this org
    analyst = await _user(db_session, email="analyst6@org-a.test", role="analyst")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "summarize today"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["error"] == "llm_not_configured"
    assert detail["source"]

    rows = (await db_session.execute(select(AgentChatMessage))).scalars().all()
    assert len(rows) == 1
    assert rows[0].role == "user"
    assert rows[0].tool_calls["status"] == "failed"
    assert rows[0].tool_calls["error"] == "llm_not_configured"


@pytest.mark.asyncio
async def test_provider_error_is_503_and_marks_the_turn_failed(client, db_session, patched_runtime):
    from src.llm.base import LLMAuthError

    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst7@org-a.test", role="analyst")
    await db_session.commit()
    # A non-retryable provider failure: the run ends in stop_reason=error.
    patched_runtime([LLMAuthError("provider rejected the credential", request_id="req-boom")])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "summarize today"},
    )
    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["error"] == "llm_provider_error"
    assert detail["error_code"] == "llm_auth"
    assert detail["request_id"] == "req-boom"

    rows = (await db_session.execute(select(AgentChatMessage))).scalars().all()
    assert [r.role for r in rows] == ["user"]
    assert rows[0].tool_calls["status"] == "failed"


@pytest.mark.asyncio
async def test_budget_exhaustion_is_429_with_retry_after(client, db_session, monkeypatch):
    from src.llm.base import LLMQuotaExceeded

    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst8@org-a.test", role="analyst")
    await db_session.commit()

    class ExhaustedQuota(PermissiveQuota):
        async def reserve(self, org_id, bucket, tokens, *, credential_source="org"):
            err = LLMQuotaExceeded("interactive token budget exhausted", retry_after=30)
            err.bucket = bucket
            raise err

    import src.api.v1.endpoints.agentic as endpoint
    import src.llm.factory as factory

    monkeypatch.setattr(factory, "build_provider", lambda *a, **k: FakeProvider([]), raising=True)
    monkeypatch.setattr(endpoint, "_agent_quota", lambda redis: ExhaustedQuota(), raising=True)

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "summarize today"},
    )
    assert resp.status_code == 429
    assert resp.json()["detail"]["error"] == "llm_quota_exceeded"
    assert resp.headers["retry-after"] == "30"
    rows = (await db_session.execute(select(AgentChatMessage))).scalars().all()
    assert rows[0].tool_calls["status"] == "failed"


# ---------------------------------------------------------------------------
# Deprecated alias
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorize_actions_alias_still_enables_proposals(client, db_session, patched_runtime):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst9@org-a.test", role="analyst")
    await _soc_agent(db_session)
    await db_session.commit()

    patched_runtime([
        turn(calls=[("tu-1", "block_ip", {"ip": "203.0.113.7", "reason": "c2 callback"})]),
        turn(text="Proposed a block on 203.0.113.7 for your approval."),
    ])

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "Block the c2 address", "authorize_actions": True},
    )
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["proposals"]) == 1
