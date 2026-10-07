"""Per-organization retention for LLM call logs and agent run transcripts.

Decision 2026-10-06: default 365 days, per-organization setting bounded to
30..1095 days in the ``agentic_policy`` section, honoured by the nightly
purge, every change audited. Covers the section parsing, the settings
surface (``GET/PUT /settings/agentic-policy``), write-time transcript expiry
and the purge (per-org cutoffs, rollup before delete, windows, cap, counts).
All rows are synthetic and created inside the tests.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

import src.agentic.retention as retention
from src.agentic.policy import (
    AGENTIC_POLICY_SECTION,
    RETENTION_DEFAULT_DAYS,
    RETENTION_MAX_DAYS,
    RETENTION_MIN_DAYS,
    load_org_policy_settings,
    org_policy_settings_from_section,
    platform_call_log_retention_days,
    retention_days_or_default,
)
from src.agentic.retention import call_log_cutoff, run_retention_purge
from src.agentic.transcript import AgentRunTranscript, transcript_retention_until
from src.audit_evidence.models import AuditTrail
from src.core.config import settings as app_settings
from src.core.database import async_session_factory
from src.llm.models import LLMCallLog, LLMUsageDaily
from src.models.settings import AppSetting
from src.workers.celery_app import celery_app
from tests.unit.test_agentic_approval_endpoints import ORG_A, ORG_B, _orgs, _token, _user
from tests.unit.test_task_memory_bounds import _bulk_insert

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
POLICY_URL = "/api/v1/settings/agentic-policy"


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------


def test_defaults_and_bounds() -> None:
    assert (RETENTION_DEFAULT_DAYS, RETENTION_MIN_DAYS, RETENTION_MAX_DAYS) == (365, 30, 1095)
    empty = org_policy_settings_from_section(None)
    assert empty.llm_call_log_retention_days == 365
    assert empty.agent_transcript_retention_days == 365
    assert empty.require_second_approver is False


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(30, 30), (1095, 1095), (180, 180), (29, 365), (1096, 365), ("60", 365), (True, 365), (None, 365), (60.0, 365)],
)
def test_retention_value_is_strict(raw: Any, expected: int) -> None:
    assert retention_days_or_default(raw) == expected
    section = org_policy_settings_from_section({"agent_transcript_retention_days": raw})
    assert section.agent_transcript_retention_days == expected


def test_platform_call_log_default_is_clamped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(app_settings, "llm_log_retention_days", 365)
    assert platform_call_log_retention_days() == 365
    monkeypatch.setattr(app_settings, "llm_log_retention_days", 7)
    assert platform_call_log_retention_days() == 30
    assert org_policy_settings_from_section({}).llm_call_log_retention_days == 30
    monkeypatch.setattr(app_settings, "llm_log_retention_days", 5000)
    assert platform_call_log_retention_days() == 1095


def test_call_log_cutoff_is_utc_midnight() -> None:
    assert call_log_cutoff(NOW, 30) == datetime(2026, 9, 6, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Settings surface
# ---------------------------------------------------------------------------


async def _audit_rows(db: AsyncSession, org_id: str = ORG_A) -> list[AuditTrail]:
    rows = await db.execute(
        select(AuditTrail).where(AuditTrail.organization_id == org_id, AuditTrail.action == "agentic_policy.set"),
    )
    return list(rows.scalars().all())


@pytest.mark.asyncio
async def test_settings_default_read_write_and_audit(client, db_session):
    await _orgs(db_session)
    admin = await _user(db_session, email="ret-admin@org-c.test", role="admin")
    await db_session.commit()
    auth = _token(admin)

    resp = await client.get(POLICY_URL, headers=auth)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["llm_call_log_retention_days"] == 365
    assert body["agent_transcript_retention_days"] == 365
    assert (body["retention_min_days"], body["retention_max_days"]) == (30, 1095)

    resp = await client.put(
        POLICY_URL, headers=auth, json={"llm_call_log_retention_days": 30, "agent_transcript_retention_days": 1095},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["llm_call_log_retention_days"] == 30
    assert resp.json()["agent_transcript_retention_days"] == 1095
    # Partial update: the second-approver flag is untouched.
    assert resp.json()["require_second_approver"] is False

    stored = await load_org_policy_settings(db_session, ORG_A)
    assert (stored.llm_call_log_retention_days, stored.agent_transcript_retention_days) == (30, 1095)
    # Organization-scoped: the other tenant keeps the default.
    other = await load_org_policy_settings(db_session, ORG_B)
    assert (other.llm_call_log_retention_days, other.agent_transcript_retention_days) == (365, 365)

    audit = await _audit_rows(db_session)
    assert len(audit) == 1
    assert audit[0].actor_id == admin.id
    assert audit[0].old_value == {"llm_call_log_retention_days": 365, "agent_transcript_retention_days": 365}
    assert audit[0].new_value == {"llm_call_log_retention_days": 30, "agent_transcript_retention_days": 1095}
    assert audit[0].risk_level == "medium"  # call-log retention was shortened
    assert await _audit_rows(db_session, ORG_B) == []

    # Lengthening only, together with the flag, in one call: one more audit row.
    resp = await client.put(
        POLICY_URL, headers=auth, json={"require_second_approver": True, "llm_call_log_retention_days": 90},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["require_second_approver"] is True
    assert resp.json()["llm_call_log_retention_days"] == 90
    assert resp.json()["agent_transcript_retention_days"] == 1095
    audit = await _audit_rows(db_session)
    assert len(audit) == 2
    latest = max(audit, key=lambda r: r.created_at)
    assert latest.old_value == {"require_second_approver": False, "llm_call_log_retention_days": 30}
    assert latest.new_value == {"require_second_approver": True, "llm_call_log_retention_days": 90}
    assert latest.risk_level == "low"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [
        {"llm_call_log_retention_days": 29},
        {"llm_call_log_retention_days": 1096},
        {"agent_transcript_retention_days": 0},
        {"agent_transcript_retention_days": -30},
        {"agent_transcript_retention_days": "90"},
        {"llm_call_log_retention_days": True},
        {"llm_call_log_retention_days": 90.5},
        {},
        {"llm_call_log_retention_days": 90, "purge_now": True},
    ],
)
async def test_settings_rejects_out_of_range_and_unknown(client, db_session, body):
    await _orgs(db_session)
    admin = await _user(db_session, email="ret-422@org-c.test", role="admin")
    await db_session.commit()

    resp = await client.put(POLICY_URL, headers=_token(admin), json=body)
    assert resp.status_code == 422, resp.text
    assert await _audit_rows(db_session) == []
    stored = (
        await db_session.execute(
            select(AppSetting).where(AppSetting.organization_id == ORG_A, AppSetting.section == AGENTIC_POLICY_SECTION),
        )
    ).scalar_one_or_none()
    assert stored is None


@pytest.mark.asyncio
async def test_settings_analyst_forbidden(client, db_session):
    await _orgs(db_session)
    analyst = await _user(db_session, email="ret-analyst@org-c.test", role="analyst")
    await db_session.commit()
    auth = _token(analyst)
    assert (await client.get(POLICY_URL, headers=auth)).status_code == 403
    resp = await client.put(POLICY_URL, headers=auth, json={"llm_call_log_retention_days": 30})
    assert resp.status_code == 403
    assert (await load_org_policy_settings(db_session, ORG_A)).llm_call_log_retention_days == 365


# ---------------------------------------------------------------------------
# Write-time transcript expiry
# ---------------------------------------------------------------------------


async def _set_policy(db: AsyncSession, org_id: str, **values: Any) -> None:
    db.add(AppSetting(organization_id=org_id, section=AGENTIC_POLICY_SECTION, value=values))
    await db.flush()


@pytest.mark.asyncio
async def test_transcript_expiry_stamped_from_org_setting(db_session):
    await _orgs(db_session)
    await _set_policy(db_session, ORG_A, agent_transcript_retention_days=30)
    assert await transcript_retention_until(db_session, ORG_A, now=NOW) == NOW + timedelta(days=30)
    assert await transcript_retention_until(db_session, ORG_B, now=NOW) == NOW + timedelta(days=365)

    # The column default (a writer that bypasses the helper) is the 365-day platform default.
    row = AgentRunTranscript(run_id=f"run-{uuid.uuid4().hex}", organization_id=ORG_B, mode="autonomous")
    db_session.add(row)
    await db_session.flush()
    stamped = row.retention_until if row.retention_until.tzinfo else row.retention_until.replace(tzinfo=timezone.utc)
    assert abs((stamped - datetime.now(timezone.utc)) - timedelta(days=365)) < timedelta(minutes=5)


# ---------------------------------------------------------------------------
# Purge
# ---------------------------------------------------------------------------


def _call_log(org_id: str, created_at: datetime, **extra: Any) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "run_id": f"run-{uuid.uuid4().hex[:12]}",
        "organization_id": org_id,
        "purpose": "triage",
        "mode": "autonomous",
        "provider": "anthropic",
        "model": "synthetic-model",
        "credential_source": "org",
        "propose_actions": False,
        "input_uncached_tokens": 10,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "output_tokens": 5,
        "thinking_tokens": 0,
        "total_billable_tokens": 15,
        "usage_estimated": False,
        "redactions_applied": 0,
        "stop_reason": "end_turn",
        "created_at": created_at,
        "updated_at": created_at,
        **extra,
    }


def _transcript(org_id: str, started_at: datetime, retention_until: datetime) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "run_id": f"run-{uuid.uuid4().hex}",
        "organization_id": org_id,
        "mode": "autonomous",
        "step_count": 0,
        "started_at": started_at,
        "retention_until": retention_until,
        "created_at": started_at,
        "updated_at": started_at,
    }


async def _count(db: AsyncSession, model: Any, org_id: str) -> int:
    return int((await db.execute(select(func.count()).select_from(model).where(model.organization_id == org_id))).scalar() or 0)


async def _call_log_ages(db: AsyncSession, org_id: str) -> list[int]:
    rows = (await db.execute(select(LLMCallLog.created_at).where(LLMCallLog.organization_id == org_id))).scalars().all()
    return sorted((NOW - (r if r.tzinfo else r.replace(tzinfo=timezone.utc))).days for r in rows)


@pytest.mark.asyncio
async def test_purge_honours_per_org_retention(db_session):
    await _orgs(db_session)
    await _set_policy(db_session, ORG_A, llm_call_log_retention_days=30, agent_transcript_retention_days=30)
    await db_session.commit()  # ORG_B has no setting: 365 days

    ages = (1, 29, 40, 200, 400)
    await _bulk_insert(
        db_session, LLMCallLog, [_call_log(org, NOW - timedelta(days=d)) for org in (ORG_A, ORG_B) for d in ages],
    )
    await _bulk_insert(
        db_session,
        AgentRunTranscript,
        [
            # Stamped expiry passed: purged for both orgs.
            _transcript(ORG_A, NOW - timedelta(days=40), NOW - timedelta(days=10)),
            _transcript(ORG_B, NOW - timedelta(days=400), NOW - timedelta(days=35)),
            # Old run but stamped with a longer window before ORG_A lowered its
            # setting: keeps its own expiry.
            _transcript(ORG_A, NOW - timedelta(days=200), NOW + timedelta(days=165)),
            _transcript(ORG_B, NOW - timedelta(days=1), NOW + timedelta(days=364)),
        ],
    )

    result = (await run_retention_purge(async_session_factory, now=NOW)).as_dict()

    assert await _call_log_ages(db_session, ORG_A) == [1, 29]
    assert await _call_log_ages(db_session, ORG_B) == [1, 29, 40, 200]
    assert await _count(db_session, AgentRunTranscript, ORG_A) == 1
    assert await _count(db_session, AgentRunTranscript, ORG_B) == 1

    assert result["status"] == "completed"
    assert result["organizations"] == 2
    assert result["call_logs_deleted"] == 4
    assert result["transcripts_deleted"] == 2
    assert result["truncated"] is False
    assert result["failed_organizations"] == 0
    assert result["per_org"][ORG_A]["call_logs"] == 3
    assert result["per_org"][ORG_A]["transcripts"] == 1
    assert result["per_org"][ORG_B]["call_logs"] == 1
    assert result["per_org"][ORG_B]["transcripts"] == 1

    # Every purged day was rolled up first, for its own organization only.
    days_a = set((await db_session.execute(
        select(LLMUsageDaily.day).where(LLMUsageDaily.organization_id == ORG_A),
    )).scalars().all())
    days_b = set((await db_session.execute(
        select(LLMUsageDaily.day).where(LLMUsageDaily.organization_id == ORG_B),
    )).scalars().all())
    assert days_a == {(NOW - timedelta(days=d)).date() for d in (40, 200, 400)}
    assert days_b == {(NOW - timedelta(days=400)).date()}
    assert result["days_rolled_up"] == 4

    # A second run is a no-op.
    again = (await run_retention_purge(async_session_factory, now=NOW)).as_dict()
    assert again["call_logs_deleted"] == again["transcripts_deleted"] == again["days_rolled_up"] == 0
    assert again["per_org"] == {}


@pytest.mark.asyncio
async def test_rollup_is_not_rewritten_from_a_partly_purged_day(db_session, monkeypatch):
    await _orgs(db_session)
    await _set_policy(db_session, ORG_A, llm_call_log_retention_days=30)
    await db_session.commit()
    old_day = NOW - timedelta(days=50)
    await _bulk_insert(db_session, LLMCallLog, [_call_log(ORG_A, old_day + timedelta(seconds=i)) for i in range(7)])

    monkeypatch.setattr(retention, "PURGE_BATCH_SIZE", 3)
    first = await run_retention_purge(async_session_factory, now=NOW, max_batches=1)
    assert first.truncated is True
    assert first.call_logs_deleted == 3
    assert await _count(db_session, LLMCallLog, ORG_A) == 4

    second = await run_retention_purge(async_session_factory, now=NOW)
    assert second.days_rolled_up == 0  # the day already has its rollup
    assert await _count(db_session, LLMCallLog, ORG_A) == 0
    calls = (await db_session.execute(
        select(func.sum(LLMUsageDaily.calls)).where(LLMUsageDaily.organization_id == ORG_A),
    )).scalar()
    assert calls == 7


@pytest.mark.asyncio
async def test_purge_deletes_in_committed_windows_and_caps_the_run(db_session, monkeypatch):
    from sqlalchemy.ext.asyncio import AsyncSession as _Session

    await _orgs(db_session)
    await _set_policy(db_session, ORG_A, llm_call_log_retention_days=30)
    await db_session.commit()
    await _bulk_insert(
        db_session, LLMCallLog, [_call_log(ORG_A, NOW - timedelta(days=60, seconds=i)) for i in range(23)],
    )
    await _bulk_insert(db_session, LLMCallLog, [_call_log(ORG_B, NOW - timedelta(days=60)) for _ in range(4)])

    commits = {"n": 0}
    real_commit = _Session.commit

    async def counting_commit(self):  # type: ignore[no-untyped-def]
        commits["n"] += 1
        return await real_commit(self)

    monkeypatch.setattr(_Session, "commit", counting_commit)
    monkeypatch.setattr(retention, "PURGE_BATCH_SIZE", 5)

    capped = await run_retention_purge(async_session_factory, now=NOW, max_batches=3)
    assert capped.truncated is True
    assert capped.batches == 3
    assert capped.call_logs_deleted == 15
    assert await _count(db_session, LLMCallLog, ORG_A) == 8
    assert await _count(db_session, LLMCallLog, ORG_B) == 4  # 365 days: not due
    assert commits["n"] >= 3  # every window committed on its own

    rest = await run_retention_purge(async_session_factory, now=NOW)
    assert rest.truncated is False
    assert rest.call_logs_deleted == 8
    assert await _count(db_session, LLMCallLog, ORG_A) == 0
    assert await _count(db_session, LLMCallLog, ORG_B) == 4


def test_default_window_and_cap() -> None:
    assert retention.PURGE_BATCH_SIZE == 10_000
    assert retention.MAX_PURGE_BATCHES_PER_RUN >= 1


def test_purge_task_is_scheduled_daily_with_wall_clock_limits() -> None:
    entry = celery_app.conf.beat_schedule["agentic-retention-purge"]
    assert entry["task"] == "src.agentic.tasks.purge_agentic_retention"
    assert entry["schedule"].hour == {5} and entry["schedule"].minute == {15}
    limits = celery_app.conf.task_annotations["src.agentic.tasks.purge_agentic_retention"]
    assert limits["soft_time_limit"] <= 900 and limits["time_limit"] <= 960
    import src.agentic.tasks as agentic_tasks

    assert agentic_tasks.purge_agentic_retention.name == "src.agentic.tasks.purge_agentic_retention"


def test_rollup_day_helper_types() -> None:
    # call_log_cutoff returns an aware datetime whose date is a whole day.
    cutoff = call_log_cutoff(NOW.replace(tzinfo=None), 365)
    assert cutoff.tzinfo is not None and isinstance(cutoff.date(), date)
