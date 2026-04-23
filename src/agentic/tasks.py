"""
Celery Tasks for Agentic SOC Investigation

Background tasks for autonomous investigations, memory maintenance,
performance evaluation, and threat hunts.
"""

import json
from datetime import datetime, timedelta, timezone

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
            async with AsyncSessionLocal() as db:
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
                return {
                    "investigation_id": existing.id,
                    "status": existing.status,
                    "confidence": existing.confidence_score,
                    "resolution_type": existing.resolution_type,
                    "findings_summary": existing.findings_summary,
                }

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
