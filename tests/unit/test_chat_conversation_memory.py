"""The SOC chat agent must carry conversation history across turns.

Each /agentic/chat message was once processed in isolation - prior turns
were stored but never fed back to the LLM, so "go ahead and act on them"
had no referent and the agent replied with filler. The endpoint now loads
the recent transcript and hands it to the provider as replayed messages
(design v2: the runtime replays history, it never re-stringifies it into
the prompt).
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from src.agentic.models import AgentChatMessage, AgentChatSession
from src.llm.base import TextBlock
from tests.unit.test_agentic_chat_endpoint import (
    ORG_A,
    _ai_settings,
    _orgs,
    _token,
    _user,
    patch_llm_runtime,
    turn,
)


def _all_text(messages) -> str:
    out = []
    for message in messages:
        for block in message.content:
            if isinstance(block, TextBlock):
                out.append(block.text)
            else:
                out.append(str(getattr(block, "content", "")))
    return "\n".join(out)


@pytest.mark.asyncio
async def test_prior_turns_are_replayed_to_the_provider(client, db_session, monkeypatch):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="memory@org-a.test", role="analyst")

    session = AgentChatSession(user_id=analyst.id, organization_id=ORG_A, title="t")
    db_session.add(session)
    await db_session.flush()
    db_session.add_all([
        AgentChatMessage(session_id=session.id, role="user", content="What open incidents are there?"),
        AgentChatMessage(
            session_id=session.id,
            role="assistant",
            content="Open incidents: Ransomware on file-share-01 (ID inc-abc-123).",
        ),
    ])
    await db_session.commit()

    wired = patch_llm_runtime(
        monkeypatch, [turn(text="Working the ransomware incident on file-share-01 now.")]
    )
    provider = wired.provider

    resp = await client.post(
        "/api/v1/agentic/chat",
        headers=_token(analyst),
        json={"query": "Go ahead and look at them", "session_id": session.id},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["session_id"] == session.id

    # The provider saw the prior turn, so "them" resolves to inc-abc-123.
    assert provider.requests, "the provider was never called"
    sent = _all_text(provider.requests[0]["messages"])
    assert "inc-abc-123" in sent
    assert "file-share-01" in sent
    assert "Go ahead and look at them" in sent

    # The new turn is persisted alongside the prior ones.
    rows = (await db_session.execute(
        select(AgentChatMessage).where(AgentChatMessage.session_id == session.id)
    )).scalars().all()
    assert len(rows) == 4
    assert sum(1 for r in rows if r.role == "user") == 2
    assert any(r.content == "Go ahead and look at them" for r in rows)
    assert any(r.role == "assistant" and "file-share-01" in r.content for r in rows)
