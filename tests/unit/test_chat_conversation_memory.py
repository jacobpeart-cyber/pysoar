"""The SOC chat agent must carry conversation history across turns.

Each /agentic/chat message was processed in isolation — prior turns were
stored but never fed back to the LLM, so "go ahead and act on them" had
no referent and the agent replied with filler. The endpoint now loads the
recent transcript into the prompt.
"""

import pytest

from src.agentic.models import AgentChatSession, AgentChatMessage


@pytest.mark.asyncio
async def test_prior_turns_are_included_in_llm_context(client, db_session, test_user, monkeypatch):
    # Seed a session with a prior assistant turn that listed an incident.
    session = AgentChatSession(
        user_id=test_user.id, organization_id=(test_user.organization_id or "org-1"), title="t",
    )
    db_session.add(session)
    await db_session.flush()
    db_session.add_all([
        AgentChatMessage(session_id=session.id, role="user", content="What open incidents are there?"),
        AgentChatMessage(
            session_id=session.id, role="assistant",
            content="Open incidents: Ransomware on file-share-01 (ID inc-abc-123).",
        ),
    ])
    await db_session.commit()

    captured = {}

    def fake_call(self, system_prompt, user_prompt, tools):
        captured["user_prompt"] = user_prompt
        return {"type": "text", "text": "ok"}

    import src.ai.engine as ai_engine
    monkeypatch.setattr(ai_engine.AIAnalyzer, "call_llm_with_tools", fake_call, raising=True)

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers={"Authorization": f"Bearer {_token(test_user)}"},
        json={"query": "Go ahead and remediate them", "session_id": session.id},
    )
    assert resp.status_code == 200
    # The LLM must have seen the prior turn — so "them" resolves to inc-abc-123.
    up = captured.get("user_prompt", "")
    assert "inc-abc-123" in up
    assert "file-share-01" in up
    assert "CURRENT REQUEST: Go ahead and remediate them" in up


def _token(user):
    from src.core.security import create_access_token
    return create_access_token(subject=user.id)
