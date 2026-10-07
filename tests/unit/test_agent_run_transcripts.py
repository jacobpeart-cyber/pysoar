"""Every agent run writes one ``AgentRunTranscript`` (AU-3 / AU-12 evidence).

Covers ``src.agentic.transcript.persist_run_transcript`` and its two call
sites: a chat turn (``POST /agentic/chat``) and an autonomous investigation
(``AutonomousInvestigator``). The row is organization-scoped, its expiry
comes from the organization's ``agent_transcript_retention_days``, secrets in
tool arguments/results are redacted in the stored steps, the step payload is
capped with the cut recorded, a failing write never fails the run, and
``GET /agentic/runs/{run_id}`` returns the stored transcript (another tenant
gets 404). All data below is synthetic.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import func, select

from src.agentic.context import AgentContext, Mode, UserRole
from src.agentic.decisions import TrustState
from src.agentic.models import AgentChatMessage
from src.agentic.policy import AGENTIC_POLICY_SECTION
from src.agentic.runtime import RunResult, StepRecord, ToolLogEntry
from src.agentic.transcript import (
    TRANSCRIPT_MAX_STEPS,
    TRANSCRIPT_PREVIEW_MAX_CHARS,
    TRANSCRIPT_STEPS_MAX_BYTES,
    AgentRunTranscript,
    build_transcript_payload,
    persist_run_transcript,
)
from src.core import metrics as agent_metrics
from src.llm.base import Usage
from src.models.settings import AppSetting
from tests.unit.test_agentic_chat_endpoint import (
    ORG_A,
    ORG_B,
    _ai_settings,
    _alert,
    _orgs,
    _token,
    _user,
    patch_llm_runtime,
    turn,
)
from tests.unit.test_autonomous_investigator import (
    ORG as INV_ORG,
)
from tests.unit.test_autonomous_investigator import (
    _agent,
    _investigation,
    _patch_provider,
    _run,
    verdict_turn,
)
from tests.unit.test_autonomous_investigator import (
    _ai_settings as _inv_ai_settings,
)
from tests.unit.test_autonomous_investigator import (
    _alert as _inv_alert,
)
from tests.unit.test_autonomous_investigator import (
    _org as _inv_org,
)

# Synthetic credential shapes (never real keys).
FAKE_SK = "sk-" + "A1b2C3d4E5f6G7h8J9k0"
FAKE_GH = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0"
FAKE_PLAIN = "plain-secret-value-123"


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


async def _set_retention(db, org_id: str, days: int) -> None:
    db.add(AppSetting(
        organization_id=org_id, section=AGENTIC_POLICY_SECTION,
        value={"agent_transcript_retention_days": days},
    ))
    await db.flush()


async def _transcripts(db, org_id: str | None = None) -> list[AgentRunTranscript]:
    stmt = select(AgentRunTranscript)
    if org_id is not None:
        stmt = stmt.where(AgentRunTranscript.organization_id == org_id)
    return list((await db.execute(stmt)).scalars().all())


def _entry(step: int, *, args: dict[str, Any], preview: str | None) -> ToolLogEntry:
    return ToolLogEntry(
        step=step, tool="list_alerts", tool_use_id=f"tu-{step}", args=args,
        allowed=True, success=True, decision="allow", reason_code="ok", tier="read",
        is_error=False, duration_ms=3, result_preview=preview, result_sha256="0" * 64,
    )


def _result(entries: list[ToolLogEntry], *, final_text: str = "done") -> RunResult:
    return RunResult(
        run_id=uuid.uuid4().hex,
        final_text=final_text,
        stop_reason="end_turn",
        steps=[StepRecord(step=1, stop_reason="end_turn", text_preview=final_text[:100], tool_calls=[], usage_total=10)],
        tool_log=entries,
        proposals=[],
        policy_events=[],
        usage=Usage(input_uncached=7, output=3),
        provider="fake",
        model="fake-1",
        credential_source="org",
        trust=TrustState(),
    )


def _ctx(org_id: str, user_id: str) -> AgentContext:
    return AgentContext(org_id=org_id, role=UserRole.ANALYST, mode=Mode.INTERACTIVE, actor_user_id=user_id)


# ---------------------------------------------------------------------------
# Chat turn
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_chat_turn_writes_one_org_scoped_transcript_with_org_retention(client, db_session, monkeypatch):
    await _orgs(db_session)
    await _ai_settings(db_session)
    await _set_retention(db_session, ORG_A, 30)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    await _alert(db_session)
    await db_session.commit()

    patch_llm_runtime(monkeypatch, [
        turn(calls=[("tu-1", "list_alerts", {"limit": 5})]),
        turn(text="One high-severity alert is open."),
    ])
    before = datetime.now(timezone.utc)
    resp = await client.post("/api/v1/agentic/chat", headers=_token(analyst), json={"query": "What alerts are open?"})
    assert resp.status_code == 200, resp.text
    run_id = resp.json()["run_id"]

    rows = await _transcripts(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.run_id == run_id
    assert row.organization_id == ORG_A
    assert row.mode == "interactive"
    assert row.actor_user_id == analyst.id and row.soc_agent_id is None
    assert row.session_id == resp.json()["session_id"]
    assert row.step_count == 1
    assert row.steps and row.steps[0]["tool"] == "list_alerts"
    assert row.steps[0]["tier"] == "read" and row.steps[0]["decision"] == "allow"
    assert row.provider == "fake" and row.model == "fake-1"
    assert row.tokens_used and row.tokens_used > 0
    assert row.outcome == "end_turn"
    assert row.finished_at is not None
    summary = row.summary or {}
    assert summary["prompt_version"]
    assert summary["final_text"] == "One high-severity alert is open."
    assert summary["usage"]["total_billable"] == row.tokens_used
    assert summary["trust"]["tier"] == "clean"
    assert summary["honesty_note_applied"] in (True, False)
    assert summary["truncation"]["truncated"] is False

    # Expiry comes from the organization's 30-day setting, not the 365 default.
    expiry = _aware(row.retention_until) - before
    assert timedelta(days=30) - timedelta(minutes=5) < expiry < timedelta(days=30, minutes=5)
    assert await _transcripts(db_session, ORG_B) == []


@pytest.mark.asyncio
async def test_secrets_in_tool_args_and_results_are_redacted_in_stored_steps(client, db_session, monkeypatch):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    await _alert(db_session)
    await db_session.commit()

    patch_llm_runtime(monkeypatch, [
        turn(calls=[("tu-1", "list_alerts", {"limit": 5, "api_key": FAKE_PLAIN, "note": f"use {FAKE_SK}"})]),
        turn(text=f"Done. The key {FAKE_GH} was in the log."),
    ])
    resp = await client.post("/api/v1/agentic/chat", headers=_token(analyst), json={"query": "list alerts"})
    assert resp.status_code == 200, resp.text

    (row,) = await _transcripts(db_session, ORG_A)
    stored = json.dumps({"steps": row.steps, "summary": row.summary})
    for secret in (FAKE_PLAIN, FAKE_SK, FAKE_GH):
        assert secret not in stored
    assert "[REDACTED" in stored


def test_payload_redacts_raw_secrets_even_if_upstream_did_not():
    entries = [_entry(
        1,
        args={"api_key": FAKE_PLAIN, "query": f"Bearer {FAKE_SK}"},
        preview=f'{{"password": "{FAKE_PLAIN}", "token": "{FAKE_GH}", "max_tokens": 4096',  # truncated JSON
    )]
    steps, summary = build_transcript_payload(_result(entries, final_text=f'api_key="{FAKE_PLAIN}"'))
    stored = json.dumps({"steps": steps, "summary": summary})
    for secret in (FAKE_PLAIN, FAKE_SK, FAKE_GH):
        assert secret not in stored
    assert '"max_tokens": 4096' in steps[0]["result_preview"]  # counters are not secrets
    assert summary["redactions_applied"] > 0


def test_steps_are_capped_by_count_and_size_and_truncation_is_recorded():
    big = "x" * (TRANSCRIPT_PREVIEW_MAX_CHARS * 4)
    entries = [_entry(i, args={"q": big}, preview=big) for i in range(TRANSCRIPT_MAX_STEPS + 50)]
    steps, summary = build_transcript_payload(_result(entries))

    cut = summary["truncation"]
    assert cut["truncated"] is True
    assert cut["tool_steps_total"] == TRANSCRIPT_MAX_STEPS + 50
    assert cut["tool_steps_dropped_over_count"] == 50
    assert cut["tool_steps_dropped_over_size"] > 0
    assert cut["tool_steps_kept"] == len(steps) < TRANSCRIPT_MAX_STEPS
    assert cut["previews_truncated"] > 0
    assert len(json.dumps(steps)) <= TRANSCRIPT_STEPS_MAX_BYTES
    assert all(len(s["result_preview"]) <= TRANSCRIPT_PREVIEW_MAX_CHARS for s in steps)
    assert all(len(s["args_preview"]) <= TRANSCRIPT_PREVIEW_MAX_CHARS for s in steps)


# ---------------------------------------------------------------------------
# Failure never fails the run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failing_transcript_write_does_not_fail_the_chat_turn(client, db_session, monkeypatch):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    await db_session.commit()

    import src.agentic.transcript as transcript_module

    async def _boom(*_args: Any, **_kwargs: Any) -> datetime:
        raise RuntimeError("settings store unavailable")

    monkeypatch.setattr(transcript_module, "transcript_retention_until", _boom)
    agent_metrics.reset([agent_metrics.AGENT_TRANSCRIPTS_TOTAL])
    patch_llm_runtime(monkeypatch, [turn(text="Nothing to report.")])

    resp = await client.post("/api/v1/agentic/chat", headers=_token(analyst), json={"query": "status?"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["response"] == "Nothing to report."
    assert await _transcripts(db_session) == []
    assistant = (await db_session.execute(
        select(func.count()).select_from(AgentChatMessage).where(AgentChatMessage.role == "assistant"),
    )).scalar_one()
    assert assistant == 1
    assert agent_metrics.value(
        agent_metrics.AGENT_TRANSCRIPTS_TOTAL, {"mode": "interactive", "outcome": "failed"},
    ) == 1


@pytest.mark.asyncio
async def test_flush_failure_rolls_back_to_savepoint_and_session_stays_usable(db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    await db_session.commit()

    result = _result([_entry(1, args={"limit": 1}, preview="[]")])
    ctx = _ctx(ORG_A, analyst.id)
    first = await persist_run_transcript(db_session, ctx, result, mode=Mode.INTERACTIVE)
    assert first is not None
    # Same run id again: the unique constraint fails on flush inside the savepoint.
    second = await persist_run_transcript(db_session, ctx, result, mode=Mode.INTERACTIVE)
    assert second is None
    await db_session.commit()  # the outer unit of work is intact
    rows = await _transcripts(db_session, ORG_A)
    assert [r.run_id for r in rows] == [result.run_id]


# ---------------------------------------------------------------------------
# Autonomous investigation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_autonomous_investigation_writes_one_transcript(db_session, monkeypatch):
    await _inv_org(db_session)
    await _inv_ai_settings(db_session)
    await _set_retention(db_session, INV_ORG, 90)
    agent = await _agent(db_session)
    alert = await _inv_alert(db_session)
    inv = await _investigation(db_session, agent, alert)
    await db_session.commit()

    _patch_provider(monkeypatch, [verdict_turn()])
    before = datetime.now(timezone.utc)
    await _run(db_session, inv)

    rows = await _transcripts(db_session)
    assert len(rows) == 1
    row = rows[0]
    assert row.organization_id == INV_ORG
    assert row.run_id == inv.run_ids[-1]
    assert row.mode == "autonomous"
    assert row.soc_agent_id == agent.id and row.actor_user_id is None
    assert row.investigation_id == inv.id
    assert row.outcome == "verdict"
    assert row.steps and row.steps[0]["tool"] == "submit_verdict"
    assert (row.summary or {})["verdict_submitted"] is True
    expiry = _aware(row.retention_until) - before
    assert timedelta(days=90) - timedelta(minutes=5) < expiry < timedelta(days=90, minutes=5)


# ---------------------------------------------------------------------------
# GET /agentic/runs/{run_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_endpoint_returns_the_stored_transcript_and_other_org_gets_404(client, db_session, monkeypatch):
    await _orgs(db_session)
    await _ai_settings(db_session)
    analyst = await _user(db_session, email="analyst@org-a.test", role="analyst")
    other = await _user(db_session, email="analyst@org-b.test", role="analyst", org_id=ORG_B)
    await _alert(db_session)
    await db_session.commit()

    patch_llm_runtime(monkeypatch, [
        turn(calls=[("tu-1", "list_alerts", {"limit": 5, "api_key": FAKE_PLAIN})]),
        turn(text="One alert."),
    ])
    chat = await client.post("/api/v1/agentic/chat", headers=_token(analyst), json={"query": "alerts?"})
    assert chat.status_code == 200, chat.text
    run_id = chat.json()["run_id"]

    resp = await client.get(f"/api/v1/agentic/runs/{run_id}", headers=_token(analyst))
    assert resp.status_code == 200, resp.text
    transcript = resp.json()["transcript"]
    assert transcript is not None
    assert transcript["mode"] == "interactive"
    assert transcript["step_count"] == 1
    assert transcript["steps"][0]["tool"] == "list_alerts"
    assert transcript["summary"]["final_text"] == "One alert."
    assert transcript["retention_until"]
    assert FAKE_PLAIN not in json.dumps(transcript)
    assert "[REDACTED]" in transcript["steps"][0]["args_preview"]

    cross = await client.get(f"/api/v1/agentic/runs/{run_id}", headers=_token(other))
    assert cross.status_code == 404
