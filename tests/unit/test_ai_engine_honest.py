"""``AIAnalyzer`` tells the truth when the LLM is not there (work package 6).

The old engine posted to a hardcoded Gemini URL with an env key and, on any
failure, returned a success-shaped dict: ``priority: p3``, ``confidence:
0.7``, ``threat_level: medium``, ``"AI analysis unavailable"`` as the
analysis. Those payloads are now gone. Every call resolves the
organization's provider through ``src/llm`` and a failure is reported as
``{"status": "unavailable", "error_code": ...}``.

The four ``src/api/v1/endpoints/ai.py`` call sites surface that honestly: no
provider configured falls back to the DB-derived ``rule_based`` analysis, a
failing provider is a 503 carrying the provider's error code.
"""
from __future__ import annotations

import inspect
from typing import Any, Optional

import pytest

from src.ai.engine import AIAnalyzer
from src.llm.base import (
    LLMAuthError,
    LLMInvalidResponse,
    LLMNotConfigured,
    LLMTransientError,
    LLMTurn,
    Message,
    ToolSpecForLLM,
    Usage,
)
from src.models.incident import Incident
from src.models.organization import Organization
from src.models.settings import AppSetting
from src.models.user import User

ORG = "a1a1a1a1-0000-4000-8000-000000000001"

FORBIDDEN_FABRICATIONS = [
    '"priority": "p3"',
    "'priority': 'p3'",
    '"confidence": 0.7',
    "'confidence': 0.7",
    '"threat_level": "medium"',
    "AI analysis unavailable",
    "AI analysis could not be completed",
    "Manual review required",
    "Review manually",
    '"analysis_complete": True',
    "Analysis incomplete",
    "GEMINI_URL",
    "GEMINI_API_KEY",
    "_heuristic_tool_pick",
    "model_map",
]


class ScriptedProvider:
    name = "fake"
    model = "fake-1"
    credential_source = "org"

    def __init__(self, script: list[Any]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    async def __aenter__(self) -> "ScriptedProvider":
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
        self.calls.append({"system": system, "tools": tools, "response_schema": response_schema})
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    async def list_models(self) -> list[str]:
        return [self.model]

    def estimate_input_tokens(self, system: str, messages: list[Message], tools: Any) -> int:
        return 10


def _turn(text: str, stop: str = "end_turn") -> LLMTurn:
    return LLMTurn(
        text=text,
        tool_calls=[],
        stop_reason=stop,
        usage=Usage(input_uncached=10, output=10),
        provider="fake",
        model="fake-1",
        request_id="req-ai",
        provider_native=None,
    )


def _patch_provider(monkeypatch, script: list[Any]) -> ScriptedProvider:
    import src.llm.factory as factory

    provider = ScriptedProvider(script)
    monkeypatch.setattr(factory, "build_provider", lambda *a, **k: provider, raising=True)
    return provider


async def _org(db) -> None:
    if await db.get(Organization, ORG) is None:
        db.add(Organization(id=ORG, name="AI org", slug="ai-org"))
    await db.flush()


async def _ai_settings(db) -> None:
    db.add(AppSetting(organization_id=ORG, section="ai", value={"provider": "ollama", "model": "llama3.1"}))
    await db.flush()


# ---------------------------------------------------------------------------
# Source-level guard
# ---------------------------------------------------------------------------


def test_no_fabricated_defaults_in_ai_engine():
    import src.ai.engine as engine

    source = inspect.getsource(engine)
    offenders = [p for p in FORBIDDEN_FABRICATIONS if p in source]
    assert not offenders, (
        f"src/ai/engine.py reintroduced fabricated-default patterns: {offenders}"
    )


def test_no_fabricated_defaults_in_investigator():
    import src.agentic.investigator as investigator

    source = inspect.getsource(investigator)
    offenders = [p for p in FORBIDDEN_FABRICATIONS if p in source]
    assert not offenders, (
        f"src/agentic/investigator.py reintroduced fabricated-default patterns: {offenders}"
    )


def test_deleted_llm_plumbing_is_gone():
    for name in (
        "_call_llm",
        "call_llm_with_tools",
        "call_llm_with_tools_chain",
        "call_llm_followup",
        "_heuristic_tool_pick",
    ):
        assert not hasattr(AIAnalyzer, name), f"AIAnalyzer.{name} must be deleted"
    assert not hasattr(AIAnalyzer, "GEMINI_URL")
    assert not hasattr(AIAnalyzer, "GEMINI_API_KEY")


# ---------------------------------------------------------------------------
# Behaviour
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provider_failure_reports_unavailable(db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [LLMTransientError("502 bad gateway")])
    out = await AIAnalyzer(db=db_session).triage_alert({"title": "x"}, org_id=ORG)

    assert out["status"] == "unavailable"
    assert out["error_code"] == LLMTransientError.code
    assert "priority" not in out
    assert "confidence" not in out


@pytest.mark.asyncio
async def test_revoked_key_reports_the_auth_code(db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [LLMAuthError("401 invalid key")])
    out = await AIAnalyzer(db=db_session).assess_threat({"ip": "1.2.3.4"}, {}, org_id=ORG)

    assert out["status"] == "unavailable"
    assert out["error_code"] == LLMAuthError.code
    assert "threat_level" not in out


@pytest.mark.asyncio
async def test_unconfigured_org_reports_not_configured(db_session, monkeypatch):
    await _org(db_session)  # no ai section
    await db_session.commit()

    provider = _patch_provider(monkeypatch, [_turn("{}")])
    out = await AIAnalyzer(db=db_session).summarize_incident({}, [], [], org_id=ORG)

    assert provider.calls == []
    assert out["status"] == "unavailable"
    assert out["error_code"] == LLMNotConfigured.code


@pytest.mark.asyncio
async def test_missing_organization_is_refused(db_session):
    out = await AIAnalyzer(db=db_session).triage_alert({"title": "x"}, org_id=None)
    assert out["status"] == "unavailable"
    assert out["error_code"] == LLMNotConfigured.code


@pytest.mark.asyncio
async def test_unparsable_response_is_not_salvaged(db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [_turn("I think it is probably fine, honestly")])
    out = await AIAnalyzer(db=db_session).triage_alert({"title": "x"}, org_id=ORG)

    assert out["status"] == "unavailable"
    assert out["error_code"] == LLMInvalidResponse.code


@pytest.mark.asyncio
async def test_refusal_is_not_reported_as_analysis(db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [_turn("no", stop="refusal")])
    out = await AIAnalyzer(db=db_session).analyze_root_cause({}, [], [], org_id=ORG)

    assert out["status"] == "unavailable"
    assert out["error_code"] == "llm_refusal"
    assert "root_cause" not in out


@pytest.mark.asyncio
async def test_valid_json_is_returned_with_no_invented_fields(db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    await db_session.commit()

    provider = _patch_provider(monkeypatch, [_turn(
        '{"priority": "p1", "reasoning": "known C2 address", "confidence": 0.9}'
    )])
    out = await AIAnalyzer(db=db_session).triage_alert({"title": "beaconing"}, org_id=ORG)

    assert out["status"] == "ok"
    assert out["priority"] == "p1"
    assert out["confidence"] == 0.9
    assert out["false_positive_probability"] is None, "an omitted field stays None"
    assert out["recommended_actions"] == []
    assert out["model_used"] == "fake-1"
    # Tool-less, schema-guided single shot.
    assert provider.calls[0]["tools"] is None
    assert provider.calls[0]["response_schema"] is not None


# ---------------------------------------------------------------------------
# The ai.py call sites
# ---------------------------------------------------------------------------


async def _incident(db) -> Incident:
    incident = Incident(
        title="Suspicious outbound traffic",
        description="beaconing from ws-4",
        severity="high",
        status="open",
        incident_type="malware",
        organization_id=ORG,
    )
    db.add(incident)
    await db.flush()
    return incident


async def _user(db) -> User:
    from src.core.security import get_password_hash

    user = User(
        email="ai-analyst@org.test",
        hashed_password=get_password_hash("pw-for-tests"),
        full_name="AI Analyst",
        role="analyst",
        is_active=True,
        organization_id=ORG,
    )
    db.add(user)
    await db.flush()
    return user


def _token(user: User) -> dict[str, str]:
    from src.core.security import create_access_token

    return {"Authorization": f"Bearer {create_access_token(subject=user.id)}"}


@pytest.mark.asyncio
async def test_endpoint_returns_503_with_the_error_code(client, db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    user = await _user(db_session)
    incident = await _incident(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [LLMTransientError("502 bad gateway")])
    resp = await client.post(
        f"/api/v1/ai/analyze/incident/{incident.id}",
        headers=_token(user),
        json={"incident_id": incident.id, "include_related": False},
    )

    assert resp.status_code == 503
    detail = resp.json()["detail"]
    assert detail["error"] == "llm_provider_error"
    assert detail["error_code"] == LLMTransientError.code


@pytest.mark.asyncio
async def test_endpoint_without_a_provider_stays_rule_based(client, db_session, monkeypatch):
    await _org(db_session)  # no ai section for this org
    user = await _user(db_session)
    incident = await _incident(db_session)
    await db_session.commit()

    provider = _patch_provider(monkeypatch, [_turn("{}")])
    resp = await client.post(
        f"/api/v1/ai/analyze/incident/{incident.id}",
        headers=_token(user),
        json={"incident_id": incident.id, "include_related": False},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert provider.calls == []
    # The response is labelled as derived from the database, not from an LLM.
    assert "AI analysis unavailable" not in str(body)
    assert "llm" not in str(body.get("model_used", "")).lower()


@pytest.mark.asyncio
async def test_root_cause_endpoint_returns_503_on_provider_failure(client, db_session, monkeypatch):
    await _org(db_session)
    await _ai_settings(db_session)
    user = await _user(db_session)
    incident = await _incident(db_session)
    await db_session.commit()

    _patch_provider(monkeypatch, [LLMAuthError("401 invalid key")])
    resp = await client.post(
        f"/api/v1/ai/analyze/root-cause/{incident.id}",
        headers=_token(user),
        json={},
    )

    assert resp.status_code == 503
    assert resp.json()["detail"]["error_code"] == LLMAuthError.code
