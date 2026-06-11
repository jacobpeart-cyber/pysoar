# Playbook Execution Loop — Design

**Date:** 2026-06-11
**Status:** Approved

## Problem

PySOAR advertises playbook orchestration ("schedule triggers", agent-driven
playbook execution, an 8-step action library), but the execution loop is
broken in three places:

1. `check_scheduled_playbooks` (Celery beat, every 60s) is a stub that
   always returns `executed: 0`. Scheduled playbooks never run.
2. The AI agent's `execute_playbook` tool creates a `PlaybookExecution`
   row with status `pending` and returns "queued" — but nothing consumes
   pending rows. Agent-triggered playbooks never run.
3. Two rival engines exist: `src/services/playbook_engine.py` (1,077
   lines, real — used by the API execute endpoint and alert correlation)
   and `src/playbooks/engine.py` (213 lines, vestigial — referenced only
   by `execute_playbook_task`, which itself has zero callers).

## Design

### One engine

`src/services/playbook_engine.py` is the only execution path. Delete
`src/playbooks/engine.py` and the dead `execute_playbook_task` in
`src/workers/tasks.py`. (`src/playbooks/actions.py` stays — the real
engine and others import from it.)

### Component 1: worker runner task

New Celery task `playbooks.run_playbook_execution(execution_id)` in
`src/playbooks/tasks.py`:

- Opens an async DB session (same pattern as `src/agentic/tasks.py`).
- Idempotency guard: only proceeds if the execution status is `pending`;
  otherwise logs and returns `{"skipped": true}`.
- Calls `PlaybookEngine(db).execute(execution_id)` and commits.
- On exception: marks the execution `failed` with `error_message`,
  commits, re-raises nothing (no Celery retry — a playbook is not
  guaranteed idempotent).
- Registered in `celery_app.include`.

### Component 2: agent tool dispatches

`AgentToolRegistry._execute_playbook` keeps creating the row, then after
flush dispatches `run_playbook_execution.delay(execution.id)`. The tool
remains on `AUTONOMOUS_BLOCKED_TOOLS` — this fixes the analyst/chat path
only.

### Component 3: real scheduler

Implement `check_scheduled_playbooks`:

- Query playbooks where `trigger_type == "scheduled"` and `is_enabled`.
- Parse `trigger_conditions` JSON. Supported schedule forms (this design
  defines the format; none existed before):
  - `{"interval_minutes": N}` — due when the last schedule-triggered
    execution is older than N minutes (or none exists).
  - `{"cron": "m h dom mon dow"}` — evaluated via
    `celery.schedules.crontab.remaining_estimate` relative to the last
    schedule-triggered execution (or due immediately if none exists).
- Due-ness derives from the most recent `PlaybookExecution` with
  `trigger_source == "schedule"` for that playbook — no new columns.
- For each due playbook: create a `pending` execution with
  `trigger_source="schedule"`, commit, dispatch the runner task.
- Malformed/missing `trigger_conditions` → log warning, skip (never
  crash the sweep).

## Error handling

- Runner failures land on the execution row (`failed` + message), visible
  in the existing execution-history UI.
- Scheduler never raises: per-playbook try/except so one bad playbook
  can't starve the rest.

## Testing

TDD throughout:
- Scheduler due-logic: interval due / not due, cron, never-ran, disabled,
  malformed conditions.
- Agent tool: dispatches Celery task after creating the row (mocked
  `.delay`).
- Runner: executes a seeded pending execution end-to-end against the real
  engine in SQLite; failure path marks the row failed; idempotency guard
  skips non-pending rows.

## Out of scope

Frontend schedule-editor UI, remediation dispatch (`block_ip` et al.),
real connector adapters, EDR telemetry — next gaps after this.
