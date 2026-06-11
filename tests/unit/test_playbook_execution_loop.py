"""The playbook execution loop: scheduler due-logic, worker runner, and
agent-tool dispatch.

Before this loop existed, `check_scheduled_playbooks` was a stub that
always returned executed=0 and the agent's execute_playbook tool created
`pending` execution rows that nothing ever consumed — playbooks simply
never ran unless a human clicked Execute in the UI.

Spec: docs/superpowers/specs/2026-06-11-playbook-execution-loop-design.md
"""

import json
from datetime import datetime, timedelta
from unittest.mock import patch

import pytest

from src.models.playbook import (
    ExecutionStatus,
    Playbook,
    PlaybookExecution,
)


# ---------------------------------------------------------------------------
# Due-logic (pure function)
# ---------------------------------------------------------------------------

NOW = datetime(2026, 6, 11, 12, 0, 0)


def _due(conditions, last_run):
    from src.playbooks.tasks import schedule_is_due
    return schedule_is_due(conditions, last_run, NOW)


def test_interval_never_ran_is_due():
    assert _due({"interval_minutes": 30}, None) is True


def test_interval_recent_run_not_due():
    assert _due({"interval_minutes": 30}, NOW - timedelta(minutes=10)) is False


def test_interval_elapsed_is_due():
    assert _due({"interval_minutes": 30}, NOW - timedelta(minutes=31)) is True


def test_cron_never_ran_is_due():
    assert _due({"cron": "0 8 * * *"}, None) is True


def test_cron_fire_time_passed_since_last_run_is_due():
    # Last ran yesterday 08:00; today's 08:00 fire has passed by NOW=12:00.
    assert _due({"cron": "0 8 * * *"}, NOW - timedelta(days=1, hours=4)) is True


def test_cron_already_ran_after_fire_time_not_due():
    # Last ran today 08:05; next fire is tomorrow 08:00.
    assert _due({"cron": "0 8 * * *"}, NOW - timedelta(hours=3, minutes=55)) is False


@pytest.mark.parametrize("conditions", [
    None,
    {},
    {"interval_minutes": "soon"},
    {"interval_minutes": -5},
    {"cron": "not a cron"},
    {"cron": ""},
    "not even a dict",
])
def test_malformed_conditions_never_due(conditions):
    assert _due(conditions, None) is False


# ---------------------------------------------------------------------------
# Scheduler sweep
# ---------------------------------------------------------------------------

def _scheduled_playbook(**overrides) -> Playbook:
    fields = dict(
        name="Nightly IOC sweep",
        status="active",
        trigger_type="scheduled",
        trigger_conditions=json.dumps({"interval_minutes": 30}),
        steps=json.dumps([{"name": "wait", "action": "wait", "parameters": {"seconds": 0}}]),
        is_enabled=True,
    )
    fields.update(overrides)
    return Playbook(**fields)


@pytest.mark.asyncio
async def test_sweep_creates_execution_and_dispatches(db_session):
    from src.playbooks.tasks import sweep_scheduled_playbooks

    pb = _scheduled_playbook()
    db_session.add(pb)
    await db_session.commit()

    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        result = await sweep_scheduled_playbooks(db_session)

    assert result["executed"] == 1
    from sqlalchemy import select
    rows = (await db_session.execute(
        select(PlaybookExecution).where(PlaybookExecution.playbook_id == pb.id)
    )).scalars().all()
    assert len(rows) == 1
    assert rows[0].status == ExecutionStatus.PENDING.value
    assert rows[0].trigger_source == "schedule"
    task.delay.assert_called_once_with(rows[0].id)


@pytest.mark.asyncio
async def test_sweep_skips_disabled_and_nonscheduled(db_session):
    from src.playbooks.tasks import sweep_scheduled_playbooks

    db_session.add_all([
        _scheduled_playbook(name="disabled", is_enabled=False),
        _scheduled_playbook(name="manual", trigger_type="manual"),
        _scheduled_playbook(name="malformed", trigger_conditions="{nope"),
    ])
    await db_session.commit()

    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        result = await sweep_scheduled_playbooks(db_session)

    assert result["executed"] == 0
    task.delay.assert_not_called()


@pytest.mark.asyncio
async def test_sweep_respects_recent_schedule_run(db_session):
    from src.playbooks.tasks import sweep_scheduled_playbooks

    pb = _scheduled_playbook()
    db_session.add(pb)
    await db_session.flush()
    db_session.add(PlaybookExecution(
        playbook_id=pb.id,
        status=ExecutionStatus.COMPLETED.value,
        trigger_source="schedule",
    ))
    await db_session.commit()

    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        result = await sweep_scheduled_playbooks(db_session)

    assert result["executed"] == 0
    task.delay.assert_not_called()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

async def _seed_execution(db_session, *, steps=None, status=ExecutionStatus.PENDING.value):
    pb = _scheduled_playbook(
        trigger_type="manual",
        steps=steps if steps is not None else json.dumps(
            [{"name": "wait", "action": "wait", "parameters": {"seconds": 0}}]
        ),
    )
    db_session.add(pb)
    await db_session.flush()
    execution = PlaybookExecution(playbook_id=pb.id, status=status, trigger_source="test")
    db_session.add(execution)
    await db_session.commit()
    return execution


@pytest.mark.asyncio
async def test_runner_completes_pending_execution(db_session):
    from src.playbooks.tasks import _run_playbook_execution

    execution = await _seed_execution(db_session)
    result = await _run_playbook_execution(execution.id)

    assert result["status"] == ExecutionStatus.COMPLETED.value
    await db_session.refresh(execution)
    assert execution.status == ExecutionStatus.COMPLETED.value
    assert execution.completed_at is not None


@pytest.mark.asyncio
async def test_runner_marks_failed_on_engine_error(db_session):
    from src.playbooks.tasks import _run_playbook_execution

    execution = await _seed_execution(db_session, steps="{not json at all")
    result = await _run_playbook_execution(execution.id)

    assert result["status"] == ExecutionStatus.FAILED.value
    await db_session.refresh(execution)
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.error_message


@pytest.mark.asyncio
async def test_runner_skips_non_pending(db_session):
    from src.playbooks.tasks import _run_playbook_execution

    execution = await _seed_execution(db_session, status=ExecutionStatus.COMPLETED.value)
    result = await _run_playbook_execution(execution.id)

    assert result.get("skipped") is True


@pytest.mark.asyncio
async def test_runner_unknown_execution_is_clean(db_session):
    from src.playbooks.tasks import _run_playbook_execution

    result = await _run_playbook_execution("does-not-exist")
    assert "error" in result


# ---------------------------------------------------------------------------
# Agent tool dispatch
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_agent_execute_playbook_dispatches_runner(db_session):
    from src.services.agent_tools import AgentToolRegistry

    pb = _scheduled_playbook(trigger_type="manual")
    db_session.add(pb)
    await db_session.commit()

    registry = AgentToolRegistry(db_session)
    with patch("src.playbooks.tasks.run_playbook_execution") as task:
        out = await registry.execute("execute_playbook", {"playbook_id": pb.id})

    assert out["success"] is True
    execution_id = out["result"]["execution_id"]
    task.delay.assert_called_once_with(execution_id)
