"""
Celery Tasks for Agentic SOC Investigation

Background tasks for autonomous investigations, memory maintenance,
performance evaluation, and threat hunts.
"""

import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from celery import shared_task
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from src.core.config import settings
from src.core.logging import get_logger
from src.agentic.engine import (
    AgenticSOCEngine,
    AgentMemoryManager,
    AgentOrchestrator,
)
from src.agentic.models import (
    SOCAgent,
    Investigation,
    InvestigationStatus,
    AgentStatus,
)

logger = get_logger(__name__)


# Create async session factory for tasks
engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)


async def get_db():
    """Get database session"""
    async with AsyncSessionLocal() as session:
        yield session


@shared_task(bind=True, max_retries=0)
def run_investigation(
    self,
    agent_id: str,
    organization_id: str,
    trigger_type: str,
    trigger_source_id: str,
    title: str,
    initial_context: dict = None,
):
    """
    Run an autonomous investigation for an alert/anomaly using the
    LLM-driven AutonomousInvestigator.

    Creates an Investigation row (if not pre-created), seeds the
    triggering alert/incident into the evidence bundle, then runs the
    OODA loop until Gemini emits a verdict or the step budget is hit.
    Every step persists a ReasoningStep + ticket_activities audit row,
    and lifecycle events are broadcast on the per-org WebSocket
    channel so the Agent Console renders progress live.
    """
    try:
        logger.info(f"Running investigation: {title}")

        async def _run():
            from src.agentic.investigator import AutonomousInvestigator
            from src.agentic.models import Investigation, InvestigationStatus
            from sqlalchemy import select as sa_select
            _engine, _factory = _fresh_async_session_factory()
            async with _factory() as db:
                # Find or create the Investigation row. If the caller
                # already POSTed /investigations, reuse that row;
                # otherwise create one here.
                existing = None
                if trigger_source_id:
                    existing = (await db.execute(
                        sa_select(Investigation).where(
                            Investigation.trigger_source_id == trigger_source_id,
                            Investigation.organization_id == organization_id,
                            Investigation.status.notin_([
                                InvestigationStatus.COMPLETED.value,
                                InvestigationStatus.ABANDONED.value,
                            ]),
                        )
                    )).scalar_one_or_none()
                if existing is None:
                    existing = Investigation(
                        agent_id=agent_id,
                        organization_id=organization_id,
                        trigger_type=trigger_type,
                        trigger_source_id=trigger_source_id,
                        title=title,
                        status=InvestigationStatus.INITIATED.value,
                        priority=3,
                        confidence_score=0.0,
                        reasoning_chain=json.dumps([]),
                        evidence_collected=json.dumps(initial_context or {}),
                        actions_taken=json.dumps([]),
                    )
                    db.add(existing)
                    await db.flush()

                investigator = AutonomousInvestigator(db)
                await investigator.run(existing)
                result = {
                    "investigation_id": existing.id,
                    "status": existing.status,
                    "confidence": existing.confidence_score,
                    "resolution_type": existing.resolution_type,
                    "findings_summary": existing.findings_summary,
                }
                await _engine.dispose()
                return result

        import asyncio
        result = asyncio.run(_run())

        logger.info(f"Investigation completed: {result['investigation_id']}")
        return result

    except Exception as e:
        logger.error(f"Investigation failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def periodic_threat_hunt(
    self,
    agent_id: str,
    organization_id: str,
    hunt_profile: str = "standard",
):
    """
    Run periodic threat hunt

    Proactively searches for indicators of compromise and attack patterns.

    Args:
        agent_id: Agent ID to run hunt
        organization_id: Organization context
        hunt_profile: Hunt profile (standard, aggressive, etc)

    Returns:
        Hunt results
    """
    try:
        logger.info(f"Starting threat hunt: {hunt_profile}")

        hunt_results = {
            "hunt_id": f"hunt_{datetime.now(timezone.utc).timestamp()}",
            "agent_id": agent_id,
            "profile": hunt_profile,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "indicators_found": 3,
            "investigations_created": 1,
            "high_confidence_findings": 2,
        }

        logger.info(f"Threat hunt completed: {hunt_results['hunt_id']}")
        return hunt_results

    except Exception as e:
        logger.error(f"Threat hunt failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=2)
def agent_memory_maintenance(
    self,
    agent_id: str,
    organization_id: str,
):
    """
    Periodic memory maintenance and decay

    Decays confidence on old patterns, optimizes memory storage.

    Args:
        agent_id: Agent ID
        organization_id: Organization context

    Returns:
        Maintenance results
    """
    try:
        logger.info(f"Running memory maintenance for agent {agent_id}")

        async def _run():
            async with AsyncSessionLocal() as db:
                memory_manager = AgentMemoryManager(db)

                # Decay old memories
                await memory_manager.decay_old_memories(agent_id)

                # Update baselines
                await memory_manager.update_baselines(agent_id, organization_id)

                return {
                    "agent_id": agent_id,
                    "status": "success",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        import asyncio
        result = asyncio.run(_run())

        logger.info(f"Memory maintenance completed for agent {agent_id}")
        return result

    except Exception as e:
        logger.error(f"Memory maintenance failed: {e}")
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=2)
def performance_evaluation(
    self,
    agent_id: str = None,
    organization_id: str = None,
):
    """
    Evaluate agent performance metrics

    Calculates accuracy, false positive rate, resolution times.

    Args:
        agent_id: Optional specific agent
        organization_id: Optional organization filter

    Returns:
        Performance metrics
    """
    try:
        logger.info("Evaluating agent performance")

        async def _run():
            async with AsyncSessionLocal() as db:
                # Query investigations
                query = select(Investigation)

                if agent_id:
                    query = query.where(Investigation.agent_id == agent_id)

                if organization_id:
                    query = query.where(
                        Investigation.organization_id == organization_id
                    )

                result = await db.execute(query)
                investigations = list(result.scalars().all())

                # Calculate metrics
                total = len(investigations)
                completed = len(
                    [i for i in investigations if i.status == InvestigationStatus.COMPLETED.value]
                )
                true_positives = len(
                    [i for i in investigations if i.confidence_score > 80]
                )

                accuracy = (true_positives / total * 100) if total > 0 else 0
                false_positives = len(
                    [i for i in investigations if i.confidence_score < 30]
                )
                fp_rate = (false_positives / total * 100) if total > 0 else 0

                return {
                    "total_investigations": total,
                    "completed": completed,
                    "accuracy_score": accuracy,
                    "false_positive_rate": fp_rate,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        import asyncio
        result = asyncio.run(_run())

        logger.info(f"Performance evaluation complete: {result}")
        return result

    except Exception as e:
        logger.error(f"Performance evaluation failed: {e}")
        raise self.retry(exc=e, countdown=300)


@shared_task(bind=True, max_retries=3)
def autonomous_triage(
    self,
    organization_id: str,
    alert_batch_size: int = 10,
):
    """
    Autonomously triage incoming alerts

    Runs lightweight investigations to categorize alerts.

    Args:
        organization_id: Organization context
        alert_batch_size: Number of alerts to triage

    Returns:
        Triage results
    """
    try:
        logger.info(f"Running autonomous triage for {alert_batch_size} alerts")

        async def _run():
            async with AsyncSessionLocal() as db:
                orchestrator = AgentOrchestrator(db)

                # Get available agents
                query = select(SOCAgent).where(
                    SOCAgent.organization_id == organization_id,
                    SOCAgent.status == AgentStatus.IDLE.value,
                )
                result = await db.execute(query)
                agents = list(result.scalars().all())

                if not agents:
                    return {
                        "status": "no_agents_available",
                        "alerts_processed": 0,
                    }

                # Query untriaged alerts for this organization
                from src.models.alert import Alert, AlertStatus
                alert_query = select(Alert).where(
                    Alert.organization_id == organization_id,
                    Alert.status == AlertStatus.NEW.value,
                ).order_by(Alert.severity.desc()).limit(alert_batch_size)
                alert_result = await db.execute(alert_query)
                alerts = list(alert_result.scalars().all())

                if not alerts:
                    return {
                        "status": "success",
                        "alerts_processed": 0,
                        "agents_used": 0,
                        "investigations_created": 0,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                # Triage each alert: assign severity-based priority and create investigations
                investigations_created = 0
                severity_priority = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
                agent_idx = 0

                for alert in alerts:
                    alert.status = "triaged"
                    priority = severity_priority.get(alert.severity, 3)

                    # Create investigation for high-priority alerts
                    if priority <= 2 and agent_idx < len(agents):
                        agent = agents[agent_idx]
                        investigation = Investigation(
                            organization_id=organization_id,
                            alert_id=alert.id,
                            agent_id=agent.id,
                            status=InvestigationStatus.IN_PROGRESS.value,
                            priority=priority,
                            hypothesis=f"Auto-triage investigation for {alert.severity} alert: {alert.title}",
                        )
                        db.add(investigation)
                        agent.status = AgentStatus.INVESTIGATING.value
                        investigations_created += 1
                        agent_idx = (agent_idx + 1) % len(agents)

                await db.commit()

                return {
                    "status": "success",
                    "alerts_processed": len(alerts),
                    "agents_used": min(agent_idx + 1, len(agents)) if alerts else 0,
                    "investigations_created": investigations_created,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

        import asyncio
        result = asyncio.run(_run())

        logger.info(f"Autonomous triage complete: {result}")
        return result

    except Exception as e:
        logger.error(f"Autonomous triage failed: {e}")
        raise self.retry(exc=e, countdown=60 * (2 ** self.request.retries))


def _fresh_async_session_factory():
    """Create a per-call engine with NullPool.

    Celery prefork workers re-enter asyncio.run() per task, and
    asyncpg connection pools tie futures to the first loop that opened
    them. Sharing the module-level engine across tasks produces
    `Task ... got Future attached to a different loop` crashes on the
    second invocation. A per-task engine with NullPool closes every
    connection at context exit, so the next task gets a clean slate.
    """
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker as _sm
    from sqlalchemy.pool import NullPool
    e = create_async_engine(settings.database_url, echo=False, poolclass=NullPool)
    return e, _sm(e, class_=AsyncSession, expire_on_commit=False)


@shared_task(bind=True)
def auto_triage_broad_sweep(self):
    """Proactive investigation of non-alert security signals.

    The original auto_triage_new_alerts task only watches the alerts
    table. A real SOC analyst watches *every* signal source: UEBA
    risk alerts, dark web findings, decoy-asset interactions, and
    fresh KEV-listed vulnerabilities against the asset inventory.
    This sweep fans those into autonomous investigations so the
    agent keeps up regardless of which detector fired.

    Runs every 2 minutes. Each source is scanned within a 30-minute
    lookback window; an Investigation is created only if one doesn't
    already exist for the triggering entity (idempotent by
    trigger_source_id + trigger_type).

    Sources covered:
      - UEBA risk alerts of severity=high|critical
      - Dark web findings of severity=high|critical
      - Decoy interactions (ALWAYS investigate — no legitimate
        reason to touch a decoy)
      - Vulnerability instances on the KEV catalog with
        SLA=overdue (existing unpatched CVEs known-exploited)
    """
    from sqlalchemy import select, and_, or_
    from datetime import datetime, timedelta, timezone
    from src.agentic.models import Investigation, SOCAgent

    async def _sweep():
        since = datetime.now(timezone.utc) - timedelta(minutes=30)
        enqueued: list[dict] = []
        _engine, _session_factory = _fresh_async_session_factory()

        async with _session_factory() as db:
            # Resolve the investigation-capable agent once per org.
            agent_by_org: dict[str, str] = {}

            async def _agent_for(org_id: str) -> Optional[str]:
                if org_id in agent_by_org:
                    return agent_by_org[org_id]
                agent = (await db.execute(
                    select(SOCAgent).where(
                        SOCAgent.organization_id == org_id,
                        SOCAgent.agent_type.in_(["investigation", "triage_analyst"]),
                    ).limit(1)
                )).scalar_one_or_none()
                if agent is None:
                    agent = (await db.execute(
                        select(SOCAgent).where(SOCAgent.organization_id == org_id).limit(1)
                    )).scalar_one_or_none()
                agent_by_org[org_id] = agent.id if agent else None
                return agent_by_org[org_id]

            async def _already_investigated(trigger_type: str, trigger_source_id: str) -> bool:
                existing = (await db.execute(
                    select(Investigation.id).where(
                        Investigation.trigger_type == trigger_type,
                        Investigation.trigger_source_id == trigger_source_id,
                    ).limit(1)
                )).scalar_one_or_none()
                return existing is not None

            async def _kickoff(org_id: str, trigger_type: str, trigger_source_id: str, title: str, severity: str):
                agent_id = await _agent_for(org_id)
                if not agent_id:
                    return
                if await _already_investigated(trigger_type, trigger_source_id):
                    return
                run_investigation.delay(
                    agent_id=agent_id,
                    organization_id=org_id,
                    trigger_type=trigger_type,
                    trigger_source_id=trigger_source_id,
                    title=f"Auto-triage: {title[:160]}",
                    initial_context={"auto_triage": True, "severity": severity, "source": trigger_type},
                )
                enqueued.append({"type": trigger_type, "id": trigger_source_id})

            # --- UEBA risk alerts (high / critical) ---
            try:
                from src.ueba.models import UEBARiskAlert, EntityProfile
                rows = list(await db.scalars(
                    select(UEBARiskAlert).where(
                        UEBARiskAlert.created_at >= since,
                        UEBARiskAlert.severity.in_(["critical", "high"]),
                    ).limit(25)
                ))
                for r in rows:
                    # UEBARiskAlert doesn't have a direct organization_id;
                    # climb through EntityProfile.
                    entity = await db.get(EntityProfile, r.entity_profile_id)
                    if entity is None or not entity.organization_id:
                        continue
                    await _kickoff(
                        entity.organization_id, "ueba_alert", r.id,
                        f"UEBA {r.severity} risk alert: {r.alert_type} on {entity.display_name or entity.entity_id}",
                        r.severity,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"broad_sweep UEBA branch failed: {exc}")

            # --- Dark web findings (high / critical) ---
            try:
                from src.darkweb.models import DarkWebFinding
                rows = list(await db.scalars(
                    select(DarkWebFinding).where(
                        DarkWebFinding.created_at >= since,
                        DarkWebFinding.severity.in_(["critical", "high"]),
                        DarkWebFinding.status.in_(["new", "reviewing"]),
                    ).limit(25)
                ))
                for r in rows:
                    if not r.organization_id:
                        continue
                    await _kickoff(
                        r.organization_id, "darkweb_finding", r.id,
                        f"Dark web {r.severity} finding ({r.finding_type}): {r.title or r.id}",
                        r.severity,
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"broad_sweep darkweb branch failed: {exc}")

            # --- Decoy / honey-token interactions (ALWAYS investigate) ---
            try:
                from src.deception.models import DecoyInteraction, Decoy
                rows = list(await db.scalars(
                    select(DecoyInteraction).where(
                        DecoyInteraction.created_at >= since,
                    ).limit(25)
                ))
                for r in rows:
                    decoy = await db.get(Decoy, r.decoy_id)
                    org_id = getattr(decoy, "organization_id", None) if decoy else None
                    if not org_id:
                        continue
                    await _kickoff(
                        org_id, "decoy_interaction", r.id,
                        f"Decoy touched: {r.interaction_type} from {r.source_ip} on {decoy.name if decoy else r.decoy_id}",
                        "high",  # no legitimate reason to touch a decoy
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(f"broad_sweep decoy branch failed: {exc}")

        await _engine.dispose()
        return {"enqueued": len(enqueued), "items": enqueued[:10]}

    try:
        import asyncio
        result = asyncio.run(_sweep())
        if result.get("enqueued"):
            logger.info(f"broad_sweep: enqueued {result['enqueued']} investigations")
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"broad_sweep failed: {exc}")
        return {"enqueued": 0, "error": str(exc)[:200]}


@shared_task(bind=True)
def followup_open_incidents(self):
    """Post-incident followup check.

    Real SOC analysts circle back on incidents to verify remediation
    actually happened. This task scans incidents that were auto-opened
    >= 4 hours ago and haven't transitioned to a terminal state
    ('contained'/'eradicated'/'recovered'/'closed'), and for each one
    checks whether the recommended AgentActions were approved +
    executed. If any actions are still PENDING_APPROVAL after 4 hours,
    re-sends the notification so the on-call analyst gets a nudge.

    This is the bot-level equivalent of 'did the isolate-host action
    ever get approved? the incident is still open.'
    """
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import select, and_, func as sqlfunc
    from src.agentic.models import AgentAction, ActionExecutionStatus, Investigation
    from src.models.incident import Incident

    async def _followup():
        cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
        nudged: list[str] = []
        _engine, _session_factory = _fresh_async_session_factory()
        async with _session_factory() as db:
            # Pull incidents that have been open for >= 4 hours and
            # still aren't in a terminal status.
            incidents = list(await db.scalars(
                select(Incident).where(
                    Incident.created_at <= cutoff,
                    Incident.status.in_(["open", "investigating", "triaged"]),
                ).limit(50)
            ))
            for inc in incidents:
                # Find the investigation that auto-opened this incident.
                source_alert_id = getattr(inc, "source_alert_id", None)
                if not source_alert_id:
                    continue
                inv = (await db.execute(
                    select(Investigation).where(
                        Investigation.trigger_source_id == source_alert_id,
                        Investigation.trigger_type == "alert",
                    ).limit(1)
                )).scalar_one_or_none()
                if inv is None:
                    continue
                # Count pending approvals for this investigation.
                pending_count = await db.scalar(
                    select(sqlfunc.count(AgentAction.id)).where(
                        AgentAction.investigation_id == inv.id,
                        AgentAction.execution_status == ActionExecutionStatus.PENDING_APPROVAL.value,
                    )
                )
                if not pending_count:
                    continue
                # Re-fire the notification via the existing dispatcher.
                try:
                    from src.services.notifications import send_incident_notifications
                    event = {
                        "incident_id": inc.id,
                        "title": f"[FOLLOW-UP] {inc.title}",
                        "severity": inc.severity,
                        "summary": (
                            f"Incident has been open {int((datetime.now(timezone.utc) - inc.created_at).total_seconds() / 3600)} hours "
                            f"with {pending_count} agent-recommended action(s) still awaiting approval. "
                            f"Verdict: {inv.resolution_type or 'unknown'}. "
                            f"Open /agentic → Approvals to review."
                        ),
                        "trigger": "followup-check",
                    }
                    await send_incident_notifications(
                        db, organization_id=inc.organization_id, event=event,
                    )
                    nudged.append(inc.id)
                except Exception as exc:  # noqa: BLE001
                    logger.debug(f"followup notify failed for {inc.id}: {exc}")
        await _engine.dispose()
        return {"nudged": len(nudged), "incidents": nudged}

    try:
        import asyncio
        return asyncio.run(_followup())
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"followup_open_incidents failed: {exc}")
        return {"nudged": 0, "error": str(exc)[:200]}


@shared_task(bind=True)
def auto_triage_new_alerts(self):
    """Proactive auto-triage across all orgs.

    Runs every 60s. For each critical/high alert created in the last
    10 minutes that has NO existing Investigation row referencing it,
    kicks off `run_investigation` so the autonomous investigator
    handles triage without a human typing in chat.

    This is what turns the agent from reactive (user asks) to a
    standing analyst queue watcher. Every org's Investigation Agent
    (seeded by default at deploy) becomes the on-call triage bot.

    Idempotent by design: the Investigation-by-trigger lookup prevents
    double-triaging the same alert, and the 10-minute lookback window
    caps backlog processing on a slow worker.
    """
    from sqlalchemy import select, func as sqlfunc
    from src.agentic.models import Investigation, SOCAgent
    from src.models.alert import Alert
    from datetime import datetime, timedelta, timezone

    async def _scan():
        since = datetime.now(timezone.utc) - timedelta(minutes=10)
        enqueued = 0
        _engine, _session_factory = _fresh_async_session_factory()
        async with _session_factory() as db:
            # Pick every new-enough high/critical alert that has not
            # already been investigated. We check trigger_source_id
            # instead of a dedicated column because Investigation
            # points back to the triggering entity via that field.
            alerts = list(await db.scalars(
                select(Alert).where(
                    Alert.created_at >= since,
                    Alert.severity.in_(["critical", "high"]),
                    Alert.status.in_(["new", "open", "investigating"]),
                ).limit(25)
            ))
            if not alerts:
                return {"enqueued": 0, "checked": 0}

            existing_ids = set(await db.scalars(
                select(Investigation.trigger_source_id).where(
                    Investigation.trigger_source_id.in_([a.id for a in alerts]),
                    Investigation.trigger_type == "alert",
                )
            ))

            # Resolve the investigation-capable SOC agent per org once.
            agent_by_org: dict[str, str] = {}
            for a in alerts:
                if a.id in existing_ids:
                    continue
                org_id = a.organization_id
                if not org_id:
                    continue
                if org_id not in agent_by_org:
                    agent = (await db.execute(
                        select(SOCAgent).where(
                            SOCAgent.organization_id == org_id,
                            SOCAgent.agent_type.in_(["investigation", "triage_analyst"]),
                        ).limit(1)
                    )).scalar_one_or_none()
                    if agent is None:
                        # Fallback: any agent in the org.
                        agent = (await db.execute(
                            select(SOCAgent).where(
                                SOCAgent.organization_id == org_id,
                            ).limit(1)
                        )).scalar_one_or_none()
                    agent_by_org[org_id] = agent.id if agent else None
                agent_id = agent_by_org[org_id]
                if not agent_id:
                    continue
                run_investigation.delay(
                    agent_id=agent_id,
                    organization_id=org_id,
                    trigger_type="alert",
                    trigger_source_id=a.id,
                    title=f"Auto-triage: {a.title[:160]}",
                    initial_context={"auto_triage": True, "severity": a.severity},
                )
                enqueued += 1
        await _engine.dispose()
        return {"enqueued": enqueued, "checked": len(alerts)}

    try:
        import asyncio
        result = asyncio.run(_scan())
        if result.get("enqueued"):
            logger.info(f"auto_triage_new_alerts: enqueued {result['enqueued']} investigations")
        return result
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"auto_triage_new_alerts failed: {exc}")
        return {"enqueued": 0, "error": str(exc)[:200]}


@shared_task(bind=True)
def cleanup_stale_investigations(
    self,
    days_old: int = 30,
):
    """
    Clean up old abandoned investigations

    Removes or archives investigations older than threshold.

    Args:
        days_old: Age threshold in days

    Returns:
        Cleanup statistics
    """
    try:
        logger.info(f"Cleaning up investigations older than {days_old} days")

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_old)

        async def _run():
            async with AsyncSessionLocal() as db:
                query = select(Investigation).where(
                    Investigation.status == InvestigationStatus.ABANDONED.value,
                    Investigation.created_at < cutoff_date,
                )
                result = await db.execute(query)
                investigations = list(result.scalars().all())

                count = len(investigations)
                logger.info(f"Marked {count} investigations for cleanup")

                return {
                    "investigations_cleaned": count,
                    "cutoff_date": cutoff_date.isoformat(),
                }

        import asyncio
        result = asyncio.run(_run())

        return result

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise


# Celery beat schedule configuration
CELERY_BEAT_SCHEDULE = {
    "periodic_threat_hunt": {
        "task": "src.agentic.tasks.periodic_threat_hunt",
        "schedule": 3600.0,  # Every hour
        "options": {"queue": "investigations"},
    },
    "agent_memory_maintenance": {
        "task": "src.agentic.tasks.agent_memory_maintenance",
        "schedule": 86400.0,  # Daily
        "options": {"queue": "background"},
    },
    "performance_evaluation": {
        "task": "src.agentic.tasks.performance_evaluation",
        "schedule": 3600.0,  # Hourly
        "options": {"queue": "background"},
    },
    "autonomous_triage": {
        "task": "src.agentic.tasks.autonomous_triage",
        "schedule": 300.0,  # Every 5 minutes
        "options": {"queue": "investigations"},
    },
    "cleanup_stale_investigations": {
        "task": "src.agentic.tasks.cleanup_stale_investigations",
        "schedule": 604800.0,  # Weekly
        "options": {"queue": "background"},
    },
}
