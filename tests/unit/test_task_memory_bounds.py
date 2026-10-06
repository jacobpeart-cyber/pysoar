"""Memory bounds for the scheduled Celery sweeps (prod OOM post-mortem 2026-09-01).

Prod (t3.medium, 4 GB; worker container ``mem_limit: 1536m``, concurrency 2)
froze after dozens of kernel OOM kills of celery children at 0.7-1.36 GB
anon-RSS. ``worker_max_memory_per_child`` only recycles a child *between*
tasks, so the thing that killed the host was a **single task** whose working
set grew past the container limit. Every sweep in the beat schedule used to
run one unfiltered ``SELECT`` and materialise it with ``.scalars().all()``.

The three worst offenders by maximum rows loaded were:

1. ``automation.periodic_ioc_sweep`` (every 15 min) - every alert from the
   last 24 h as full ORM objects **plus the entire ``threat_indicators``
   table** as ORM objects, just to build a set of strings.
2. ``intel.poll_threat_feeds`` -> ``FeedManager.poll_feed`` (every 30 min) -
   the whole HTTP body with no size ceiling, one SELECT per parsed
   indicator, and every new ``ThreatIndicator`` held in one session until a
   single commit at the very end.
3. ``src.ueba.tasks.update_entity_baselines`` (daily) - per entity, every
   ``behavior_events`` row in a 30-day window as a full ORM object, never
   expunged between entities.

These tests seed a large synthetic set (synthetic rows live only here, never
in the repo), run the real task, and assert two things: the ``tracemalloc``
peak stays well under the per-child recycle threshold, and no single query
materialises more than its module's batch size (asserted from the
statement's ``LIMIT`` / ``yield_per`` / expanded ``IN`` list, which is what
actually bounds the read).
"""

import math
import tracemalloc
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest
import yaml
from sqlalchemy import func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select, visitors
from sqlalchemy.sql.elements import BindParameter

from src.intel.feeds import FEED_INGEST_BATCH, FeedManager
from src.intel.models import ThreatFeed, ThreatIndicator
from src.models.alert import Alert
from src.services.automation import AutomationService
from src.tasks.automation_tasks import (
    BATCH_SIZE as AUTOMATION_BATCH_SIZE,
    _IOC_ALERT_FIELDS,
    _periodic_ioc_sweep_async,
)
from src.ueba.models import BehaviorEvent, EntityProfile
from src.ueba.tasks import UEBA_BATCH_SIZE, _update_entity_baselines_async
from src.workers.celery_app import celery_app

# Peak Python allocations any one sweep may reach. The worker recycles a
# child at 300 MB RSS and the container limit is 1536 MB for two children,
# so 150 MB of traced allocations is a deliberately generous ceiling that
# still fails loudly on an O(table) read.
PEAK_LIMIT_BYTES = 150 * 1024 * 1024

# Synthetic row counts. Large enough that an O(table) read is unmistakable
# in both peak memory and query count, small enough to keep each test well
# inside a minute on in-memory SQLite.
SEEDED_ALERTS = 40_000
SEEDED_FEED_LINES = 40_000
SEEDED_BEHAVIOR_EVENTS = 40_000
SEEDED_ENTITIES = 4

ORG = "org-memory-bounds"

REPO_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Statement recording: what each query could materialise
# ---------------------------------------------------------------------------
class _RecordedStatement:
    """One statement the task issued, plus how it was issued."""

    def __init__(self, statement: Any, via_stream: bool) -> None:
        self.statement = statement
        self.via_stream = via_stream
        self.text = str(statement)

    def touches(self, table: str) -> bool:
        return isinstance(self.statement, Select) and f" {table}" in self.text

    def row_bound(self) -> float:
        """Upper bound on rows this statement can materialise in Python.

        ``inf`` means "nothing bounds this read" - the pre-change pattern.
        """
        stmt = self.statement
        if not isinstance(stmt, Select):
            # INSERT/UPDATE/DELETE return no rows to Python.
            return 0.0

        yield_per = stmt.get_execution_options().get("yield_per")
        if self.via_stream and yield_per:
            # Streamed: the driver hands back `yield_per` rows at a time and
            # the task drops each partition before asking for the next.
            return float(yield_per)

        limit = getattr(stmt, "_limit", None)
        if limit is None:
            limit = getattr(getattr(stmt, "_limit_clause", None), "value", None)
        if limit is not None:
            return float(limit)

        if "count(" in self.text.lower():
            return 1.0

        in_size = _expanded_in_size(stmt)
        if in_size is not None:
            return float(in_size)

        return math.inf


def _expanded_in_size(stmt: Select) -> Optional[int]:
    """Largest expanded ``IN (...)`` list in the statement's WHERE clause."""
    where = stmt.whereclause
    if where is None:
        return None
    sizes = [
        len(el.value)
        for el in visitors.iterate(where)
        if isinstance(el, BindParameter)
        and getattr(el, "expanding", False)
        and isinstance(el.value, (list, tuple, set))
    ]
    return max(sizes) if sizes else None


class StatementRecorder:
    """Records every statement a task runs through ``AsyncSession``."""

    def __init__(self) -> None:
        self.statements: list[_RecordedStatement] = []
        self.commits = 0

    def for_table(self, table: str) -> list[_RecordedStatement]:
        return [s for s in self.statements if s.touches(table)]

    def max_bound_for(self, table: str) -> float:
        reads = self.for_table(table)
        return max((s.row_bound() for s in reads), default=0.0)

    def unbounded_for(self, table: str) -> list[str]:
        return [s.text for s in self.for_table(table) if s.row_bound() == math.inf]


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> StatementRecorder:
    """Record statements + commits without changing their behaviour."""
    rec = StatementRecorder()
    real_execute = AsyncSession.execute
    real_stream = AsyncSession.stream
    real_commit = AsyncSession.commit

    async def execute(self, statement, *args, **kwargs):  # type: ignore[no-untyped-def]
        rec.statements.append(_RecordedStatement(statement, via_stream=False))
        return await real_execute(self, statement, *args, **kwargs)

    async def stream(self, statement, *args, **kwargs):  # type: ignore[no-untyped-def]
        rec.statements.append(_RecordedStatement(statement, via_stream=True))
        return await real_stream(self, statement, *args, **kwargs)

    async def commit(self):  # type: ignore[no-untyped-def]
        rec.commits += 1
        return await real_commit(self)

    monkeypatch.setattr(AsyncSession, "execute", execute)
    monkeypatch.setattr(AsyncSession, "stream", stream)
    monkeypatch.setattr(AsyncSession, "commit", commit)
    return rec


async def _bulk_insert(
    db: AsyncSession, model: Any, rows: list[dict[str, Any]], chunk: int = 5_000
) -> None:
    """Core-level executemany: no ORM objects for the seed itself."""
    for offset in range(0, len(rows), chunk):
        await db.execute(insert(model), rows[offset : offset + chunk])
    await db.commit()


async def _measure(coro) -> tuple[Any, int]:
    """Run a coroutine under tracemalloc, returning (result, peak bytes)."""
    tracemalloc.start()
    try:
        result = await coro
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    return result, peak


# ---------------------------------------------------------------------------
# Suspect 1: automation.periodic_ioc_sweep
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_periodic_ioc_sweep_is_bounded(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """40k recent alerts + 40k active IOCs must not be loaded in one go."""
    now = datetime.now(timezone.utc)
    matching_ips = [f"203.0.113.{n}" for n in range(1, 6)]

    alerts: list[dict[str, Any]] = []
    for i in range(SEEDED_ALERTS):
        alerts.append(
            {
                "id": str(uuid.uuid4()),
                "organization_id": None,
                "title": f"seeded alert {i}",
                "description": None,
                "severity": "low",
                "status": "new",
                "source": "siem",
                "priority": 3,
                "confidence": 50,
                "source_ip": f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                "created_at": now - timedelta(minutes=30),
                "updated_at": now - timedelta(minutes=30),
            }
        )
    for ip in matching_ips:
        alerts.append(
            {
                "id": str(uuid.uuid4()),
                "organization_id": None,
                "title": f"seeded alert {ip}",
                "description": None,
                "severity": "low",
                "status": "new",
                "source": "siem",
                "priority": 3,
                "confidence": 50,
                "source_ip": ip,
                "created_at": now - timedelta(minutes=30),
                "updated_at": now - timedelta(minutes=30),
            }
        )
    await _bulk_insert(db_session, Alert, alerts)

    iocs: list[dict[str, Any]] = []
    for i in range(SEEDED_ALERTS):
        iocs.append(
            {
                "id": str(uuid.uuid4()),
                "indicator_type": "ipv4",
                "value": f"198.51.{i // 256}.{i % 256}",
                "is_active": True,
                "is_whitelisted": False,
                "mitre_tactics": [],
                "mitre_techniques": [],
                "tags": [],
                "context": {},
                "related_indicators": [],
                "sighting_count": 0,
                "false_positive_count": 0,
                "created_at": now,
                "updated_at": now,
            }
        )
    for ip in matching_ips:
        iocs.append(
            {
                "id": str(uuid.uuid4()),
                "indicator_type": "ipv4",
                "value": ip,
                "is_active": True,
                "is_whitelisted": False,
                "mitre_tactics": [],
                "mitre_techniques": [],
                "tags": [],
                "context": {},
                "related_indicators": [],
                "sighting_count": 0,
                "false_positive_count": 0,
                "created_at": now,
                "updated_at": now,
            }
        )
    await _bulk_insert(db_session, ThreatIndicator, iocs)

    # The pipeline itself is another module's concern; stub it so this test
    # measures the sweep's own working set.
    pipeline_calls: list[str] = []

    async def fake_on_alert_created(self, alert, organization_id=None, created_by=None):
        pipeline_calls.append(alert.id)
        return {"ioc_matches": [alert.source_ip], "incident_created": False}

    monkeypatch.setattr(AutomationService, "on_alert_created", fake_on_alert_created)

    result, peak = await _measure(_periodic_ioc_sweep_async())

    assert result["checked"] == SEEDED_ALERTS + len(matching_ips)
    assert result["matched"] == len(matching_ips)
    assert result["escalated"] == len(matching_ips)
    assert result["truncated"] is False
    assert len(pipeline_calls) == len(matching_ips)

    assert peak < PEAK_LIMIT_BYTES, (
        f"periodic_ioc_sweep peaked at {peak / 1024 / 1024:.1f} MB"
    )

    # Alerts are walked in keyset-paginated windows...
    assert not recorder.unbounded_for("alerts")
    assert recorder.max_bound_for("alerts") <= AUTOMATION_BATCH_SIZE
    # ...and the IOC side is resolved with a per-window `value IN (...)`
    # lookup, never the whole threat_indicators table (which is what the
    # pre-change `select(IOC)` did).
    assert not recorder.unbounded_for("threat_indicators")
    assert recorder.max_bound_for("threat_indicators") <= AUTOMATION_BATCH_SIZE * len(
        _IOC_ALERT_FIELDS
    )
    # One window per BATCH_SIZE alerts, not one query per alert.
    assert len(recorder.for_table("threat_indicators")) <= math.ceil(
        (SEEDED_ALERTS + len(matching_ips)) / AUTOMATION_BATCH_SIZE
    )


# ---------------------------------------------------------------------------
# Suspect 2: intel.poll_threat_feeds -> FeedManager.poll_feed
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_poll_feed_ingest_is_batched(
    db_session: AsyncSession, recorder: StatementRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 40k-line feed body ingests in committed windows, not one transaction."""
    feed_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await _bulk_insert(
        db_session,
        ThreatFeed,
        [
            {
                "id": feed_id,
                "name": "memory-bounds synthetic plain list",
                "feed_type": "plain",
                "url": "https://feed.invalid/list.txt",
                "is_enabled": True,
                "is_builtin": False,
                "poll_interval_minutes": 60,
                "total_indicators": 0,
                "confidence_weight": 1.0,
                "tags": [],
                "created_at": now,
                "updated_at": now,
            }
        ],
    )

    body = "\n".join(
        f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}"
        for i in range(SEEDED_FEED_LINES)
    ).encode()

    async def fake_fetch(self, feed):
        return body

    monkeypatch.setattr(FeedManager, "_fetch_feed_data", fake_fetch)

    new_count, peak = await _measure(FeedManager().poll_feed(feed_id))
    # Snapshot before the verification query below joins the recording.
    reads = recorder.for_table("threat_indicators")
    commits = recorder.commits
    unbounded = recorder.unbounded_for("threat_indicators")
    max_bound = recorder.max_bound_for("threat_indicators")

    assert new_count == SEEDED_FEED_LINES
    assert peak < PEAK_LIMIT_BYTES, (
        f"poll_feed peaked at {peak / 1024 / 1024:.1f} MB"
    )

    db_session.expire_all()
    persisted = (
        await db_session.execute(
            select(func.count(ThreatIndicator.id)).where(
                ThreatIndicator.feed_id == feed_id
            )
        )
    ).scalar_one()
    assert persisted == SEEDED_FEED_LINES

    expected_windows = math.ceil(SEEDED_FEED_LINES / FEED_INGEST_BATCH)
    # One existence query per window (the old loop ran one per indicator)...
    assert len(reads) == expected_windows
    assert not unbounded
    assert max_bound <= FEED_INGEST_BATCH
    # ...and a commit per window, so the session never holds the whole feed.
    assert commits >= expected_windows


# ---------------------------------------------------------------------------
# Suspect 3: src.ueba.tasks.update_entity_baselines
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_entity_baselines_streams_behavior_events(
    db_session: AsyncSession, recorder: StatementRecorder
) -> None:
    """A 30-day behavior_events window is streamed, never materialised whole."""
    now = datetime.now(timezone.utc)
    entity_ids = [str(uuid.uuid4()) for _ in range(SEEDED_ENTITIES)]
    await _bulk_insert(
        db_session,
        EntityProfile,
        [
            {
                "id": eid,
                "entity_type": "user",
                "entity_id": f"user-{n}",
                "display_name": f"User {n}",
                "risk_score": 0.0,
                "risk_level": "low",
                "baseline_data": {},
                "current_behavior": {},
                "anomaly_count_30d": 0,
                "organization_id": ORG,
                "created_at": now,
                "updated_at": now,
            }
            for n, eid in enumerate(entity_ids)
        ],
    )

    per_entity = SEEDED_BEHAVIOR_EVENTS // SEEDED_ENTITIES
    events: list[dict[str, Any]] = []
    for n, eid in enumerate(entity_ids):
        for i in range(per_entity):
            events.append(
                {
                    "id": str(uuid.uuid4()),
                    "entity_profile_id": eid,
                    "event_type": "authentication",
                    "event_data": {},
                    "source_ip": f"10.{n}.{(i // 256) % 256}.{i % 256}",
                    "risk_contribution": 0.0,
                    "is_anomalous": False,
                    "anomaly_reasons": [],
                    "organization_id": ORG,
                    "created_at": now - timedelta(days=(i % 28) + 1),
                    "updated_at": now,
                }
            )
    await _bulk_insert(db_session, BehaviorEvent, events)

    result, peak = await _measure(_update_entity_baselines_async(ORG))

    assert result["status"] == "completed"
    assert result["entities_processed"] == SEEDED_ENTITIES
    assert result["baselines_updated"] == SEEDED_ENTITIES
    assert peak < PEAK_LIMIT_BYTES, (
        f"update_entity_baselines peaked at {peak / 1024 / 1024:.1f} MB"
    )

    # Every read of the hot table is streamed with yield_per, so no single
    # query materialises more than one batch.
    reads = recorder.for_table("behavior_events")
    assert reads, "expected the baseline rebuild to read behavior_events"
    assert not recorder.unbounded_for("behavior_events")
    assert recorder.max_bound_for("behavior_events") <= UEBA_BATCH_SIZE
    assert all(
        r.via_stream and r.statement.get_execution_options().get("yield_per")
        for r in reads
    )
    # Entities are walked in keyset batches too.
    assert not recorder.unbounded_for("entity_profiles")
    assert recorder.max_bound_for("entity_profiles") <= UEBA_BATCH_SIZE


# ---------------------------------------------------------------------------
# Self-check: the detector above must call the pre-change reads unbounded
# ---------------------------------------------------------------------------
def test_detector_flags_the_pre_change_read_patterns() -> None:
    """Guards the guard: the exact shapes that OOM-killed prod score ``inf``.

    If these ever stopped scoring as unbounded the three tests above would
    pass against the pre-change code, which is the whole point of them.
    """
    whole_table = _RecordedStatement(
        select(ThreatIndicator).where(ThreatIndicator.is_active == True),  # noqa: E712
        via_stream=False,
    )
    assert whole_table.row_bound() == math.inf
    assert whole_table.touches("threat_indicators")

    whole_window = _RecordedStatement(
        select(BehaviorEvent).where(BehaviorEvent.organization_id == ORG),
        via_stream=False,
    )
    assert whole_window.row_bound() == math.inf

    # yield_per only bounds a read when it is actually streamed.
    not_streamed = _RecordedStatement(
        select(BehaviorEvent).execution_options(yield_per=UEBA_BATCH_SIZE),
        via_stream=False,
    )
    assert not_streamed.row_bound() == math.inf


# ---------------------------------------------------------------------------
# The backstop: per-child recycle thresholds must actually be declared
# ---------------------------------------------------------------------------
def test_worker_max_memory_per_child_is_300mb() -> None:
    """A child is recycled at 300 MB, ~1.2 GB below the container limit."""
    assert celery_app.conf.worker_max_memory_per_child == 300_000
    assert celery_app.conf.worker_max_tasks_per_child == 50


def test_compose_worker_command_declares_the_recycle_threshold() -> None:
    """The CLI flag is the copy that survives config drift - keep it."""
    compose = yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text())
    command = compose["services"]["worker"]["command"]
    if isinstance(command, list):
        command = " ".join(command)

    assert "--max-memory-per-child=300000" in command
    assert "--max-tasks-per-child=50" in command
    assert "--concurrency=2" in command


def test_heavy_sweeps_have_wall_clock_limits() -> None:
    """Every sweep bounded above also gets a time limit as a backstop."""
    annotations = celery_app.conf.task_annotations
    for name in (
        "automation.periodic_ioc_sweep",
        "intel.poll_threat_feeds",
        "src.ueba.tasks.update_entity_baselines",
        "src.exposure.tasks.run_asset_discovery",
        "src.itdr.tasks.scheduled_identity_threat_sweep",
    ):
        assert name in annotations, f"{name} has no task annotation"
        limits = annotations[name]
        assert limits["soft_time_limit"] <= 900
        assert limits["time_limit"] > limits["soft_time_limit"]
        assert limits["time_limit"] < celery_app.conf.task_time_limit
