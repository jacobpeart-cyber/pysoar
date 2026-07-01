"""
Celery tasks for remediation engine background processing.

Handles async/deferred operations:
- Trigger evaluation and remediation startup
- Action execution
- Approval timeouts
- Effectiveness verification
- Integration health checks

Every task either performs the real operation against the database /
integration or returns an explicit honest status (e.g. "not_implemented")
— no fabricated success counts.
"""

import asyncio
from datetime import timedelta
from typing import Any

import httpx
from celery import shared_task
from sqlalchemy import select, and_, func

from src.core.logging import get_logger
from src.models.base import utc_now
from src.remediation.models import (
    RemediationPolicy,
    RemediationExecution,
    RemediationIntegration,
)
from src.remediation.engine import RemediationEngine

logger = get_logger(__name__)


def _session_factory():
    """Return the shared async session factory (lazy import so Celery
    workers don't pay the engine construction cost at module import)."""
    from src.core.database import async_session_factory

    return async_session_factory


@shared_task(bind=True, max_retries=3)
def process_remediation_trigger(
    self,
    trigger_type: str,
    trigger_data: dict,
    organization_id: str,
) -> dict:
    """
    Evaluate a trigger event against remediation policies.

    Runs the real engine: matches enabled policies (conditions,
    exclusions, cooldown, rate limit) and creates/executes a
    RemediationExecution for each match.

    Args:
        trigger_type: Type of trigger event
        trigger_data: Event data
        organization_id: Tenant organization

    Returns:
        Dictionary with matched policies and execution IDs
    """
    logger.info("Processing remediation trigger", extra={
        "trigger_type": trigger_type,
        "organization_id": organization_id,
    })

    async def _run() -> dict:
        async with _session_factory()() as session:
            engine = RemediationEngine(session)
            policies = await engine.evaluate_trigger(
                trigger_type, trigger_data, organization_id
            )
            execution_ids: list[str] = []
            for policy in policies:
                execution = await engine.execute_remediation(
                    policy_id=policy.id,
                    trigger_data=trigger_data,
                    trigger_source=trigger_type,
                    organization_id=organization_id,
                )
                execution_ids.append(execution.id)
            return {
                "trigger_type": trigger_type,
                "policies_matched": len(policies),
                "executions_created": execution_ids,
            }

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Trigger processing failed: {str(exc)}")
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


@shared_task(bind=True, max_retries=3)
def execute_remediation_async(
    self,
    execution_id: str,
    organization_id: str,
) -> dict:
    """
    Asynchronously execute a remediation.

    Runs the real action sequence (RemediationEngine._run_actions) for a
    previously created execution — the same path the synchronous
    endpoints use.

    Args:
        execution_id: RemediationExecution ID
        organization_id: Tenant organization

    Returns:
        Execution result with real per-action outcomes
    """
    logger.info("Executing remediation", extra={
        "execution_id": execution_id,
        "organization_id": organization_id,
    })

    async def _run() -> dict:
        async with _session_factory()() as session:
            execution = await session.get(RemediationExecution, execution_id)
            if not execution:
                return {
                    "execution_id": execution_id,
                    "status": "failed",
                    "error": "execution not found",
                }
            if organization_id and execution.organization_id != organization_id:
                return {
                    "execution_id": execution_id,
                    "status": "failed",
                    "error": "organization mismatch",
                }
            if execution.status == "awaiting_approval":
                # Honest no-op: nothing was executed.
                return {
                    "execution_id": execution_id,
                    "status": "awaiting_approval",
                    "detail": "not executed; approval is still pending",
                }
            if execution.status in ("completed", "cancelled", "rolled_back"):
                return {
                    "execution_id": execution_id,
                    "status": execution.status,
                    "detail": "not executed; execution already in a terminal state",
                }

            engine = RemediationEngine(session)
            run_result = await engine._run_actions(execution_id)
            results = run_result.get("results", [])
            return {
                "execution_id": execution_id,
                "status": execution.status,
                "overall_result": execution.overall_result,
                "actions_executed": len(results),
                "actions_succeeded": sum(1 for r in results if r.get("success")),
            }

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Remediation execution failed: {str(exc)}")
        raise self.retry(exc=exc, countdown=min(2 ** self.request.retries, 600))


@shared_task()
def check_approval_timeouts() -> dict:
    """
    Check pending approvals and handle timeouts.

    For every execution stuck in awaiting_approval past its policy's
    approval_timeout_minutes:
    - auto-approves and runs the actions if the policy says
      auto_approve_after_timeout
    - otherwise marks it timed_out with the reason recorded

    Returns:
        Dictionary with auto-approved and auto-rejected counts
    """
    logger.info("Checking approval timeouts")

    async def _run() -> dict:
        result: dict[str, Any] = {
            "checked": 0,
            "auto_approved": 0,
            "auto_rejected": 0,
            "errors": [],
        }
        async with _session_factory()() as session:
            engine = RemediationEngine(session)
            stmt = select(RemediationExecution).where(
                and_(
                    RemediationExecution.status == "awaiting_approval",
                    RemediationExecution.approval_status == "pending",
                )
            )
            pending = list((await session.execute(stmt)).scalars().all())
            result["checked"] = len(pending)
            now = utc_now()

            for execution in pending:
                try:
                    policy = (
                        await session.get(RemediationPolicy, execution.policy_id)
                        if execution.policy_id
                        else None
                    )
                    timeout_minutes = (
                        policy.approval_timeout_minutes if policy else 30
                    )
                    created_at = execution.created_at
                    if created_at is None:
                        continue
                    if created_at.tzinfo is None:
                        # SQLite round-trips naive datetimes
                        elapsed = now.replace(tzinfo=None) - created_at
                    else:
                        elapsed = now - created_at
                    if elapsed < timedelta(minutes=timeout_minutes):
                        continue

                    if policy and policy.auto_approve_after_timeout:
                        execution.approval_status = "auto_approved"
                        execution.approved_at = now
                        execution.status = "approved"
                        execution.notes = (
                            f"Auto-approved after {timeout_minutes} minute "
                            "approval timeout (policy setting)"
                        )
                        await session.commit()
                        await engine._run_actions(execution.id)
                        result["auto_approved"] += 1
                    else:
                        execution.approval_status = "rejected"
                        execution.status = "timed_out"
                        execution.completed_at = now
                        execution.notes = (
                            f"Approval timed out after {timeout_minutes} minutes"
                        )
                        await session.commit()
                        result["auto_rejected"] += 1
                except Exception as exc:  # noqa: BLE001
                    await session.rollback()
                    result["errors"].append(f"{execution.id}: {exc}")
        return result

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Approval timeout check failed: {str(exc)}")
        return {
            "checked": 0,
            "auto_approved": 0,
            "auto_rejected": 0,
            "errors": [str(exc)],
        }


@shared_task()
def run_scheduled_remediations() -> dict:
    """
    Trigger remediations scheduled for specific times.

    HONEST STATUS: not implemented. Neither RemediationPolicy nor
    RemediationPlaybook carries any schedule/cron fields, so there is
    nothing in the data model to run on a timer. Returning zeros here
    would fabricate a capability that doesn't exist.
    """
    logger.warning(
        "run_scheduled_remediations is not implemented: no schedule fields "
        "exist on remediation policies/playbooks"
    )
    return {
        "status": "not_implemented",
        "reason": (
            "remediation policies and playbooks have no schedule definition; "
            "scheduled remediation requires new data model support"
        ),
    }


@shared_task()
def verify_remediation_effectiveness(
    execution_id: str,
    organization_id: str,
) -> dict:
    """
    Verify if a remediation actually achieved its goal.

    HONEST STATUS: not implemented. Real verification requires
    post-remediation telemetry (traffic from a blocked IP, process
    activity from an isolated host, login attempts from a disabled
    account) that this platform does not yet correlate back to
    executions. Returning effective=False as a hardcoded value would
    be as fake as returning True.
    """
    logger.warning(
        "verify_remediation_effectiveness is not implemented: no "
        "post-remediation telemetry correlation exists",
        extra={"execution_id": execution_id},
    )
    return {
        "execution_id": execution_id,
        "status": "not_implemented",
        "reason": (
            "effectiveness verification requires telemetry correlation "
            "(SIEM events per target after remediation) that is not built"
        ),
    }


@shared_task()
def generate_remediation_report(
    organization_id: str,
    period: str = "daily",
) -> dict:
    """
    Generate remediation activity report from real execution records.

    Args:
        organization_id: Tenant organization
        period: Report period (hourly, daily, weekly, monthly)

    Returns:
        Report dictionary aggregated from the database
    """
    logger.info("Generating remediation report", extra={
        "organization_id": organization_id,
        "period": period,
    })

    period_deltas = {
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(days=7),
        "monthly": timedelta(days=30),
    }
    delta = period_deltas.get(period, timedelta(days=1))

    async def _run() -> dict:
        cutoff = utc_now() - delta
        async with _session_factory()() as session:
            stmt = select(RemediationExecution).where(
                RemediationExecution.created_at >= cutoff,
            )
            if organization_id:
                stmt = stmt.where(
                    RemediationExecution.organization_id == organization_id
                )
            executions = list((await session.execute(stmt)).scalars().all())

            total = len(executions)
            successful = sum(1 for e in executions if e.overall_result == "success")
            failed = sum(1 for e in executions if e.overall_result == "failure")
            durations = [
                (e.completed_at - e.started_at).total_seconds() / 60.0
                for e in executions
                if e.started_at and e.completed_at and e.completed_at > e.started_at
            ]

            by_policy: dict[str, int] = {}
            by_action: dict[str, int] = {}
            by_trigger: dict[str, int] = {}
            target_counts: dict[str, int] = {}
            for e in executions:
                if e.policy_id:
                    by_policy[e.policy_id] = by_policy.get(e.policy_id, 0) + 1
                by_trigger[e.trigger_source] = by_trigger.get(e.trigger_source, 0) + 1
                target_counts[e.target_entity] = target_counts.get(e.target_entity, 0) + 1
                for a in (e.actions_planned or []):
                    at = (a or {}).get("action_type") or (a or {}).get("type") or "unknown"
                    by_action[at] = by_action.get(at, 0) + 1

            return {
                "period": period,
                "generated_at": utc_now().isoformat(),
                "organization_id": organization_id,
                "summary": {
                    "total_executions": total,
                    "successful": successful,
                    "failed": failed,
                    "success_rate": round(successful / total * 100, 2) if total else 0.0,
                    "avg_execution_time_minutes": (
                        round(sum(durations) / len(durations), 2) if durations else 0.0
                    ),
                },
                "by_policy": by_policy,
                "by_action": by_action,
                "by_trigger_type": by_trigger,
                "top_targets": [
                    {"target": t, "count": c}
                    for t, c in sorted(target_counts.items(), key=lambda x: -x[1])[:10]
                ],
            }

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Report generation failed: {str(exc)}")
        return {
            "period": period,
            "organization_id": organization_id,
            "status": "failed",
            "error": str(exc),
        }


@shared_task()
def health_check_integrations(organization_id: str) -> dict:
    """
    Check health of all remediation integrations.

    Really probes each integration's endpoint_url over HTTP and updates
    health_status / is_connected / last_health_check. Integrations
    without an endpoint are reported as not_configured — never healthy.

    Args:
        organization_id: Tenant organization

    Returns:
        Health status for each integration
    """
    logger.info("Running integration health checks", extra={
        "organization_id": organization_id,
    })

    async def _run() -> dict:
        results: dict[str, Any] = {
            "checked_at": utc_now().isoformat(),
            "organization_id": organization_id,
            "integrations": {},
        }
        async with _session_factory()() as session:
            stmt = select(RemediationIntegration)
            if organization_id:
                stmt = stmt.where(
                    RemediationIntegration.organization_id == organization_id
                )
            integrations = list((await session.execute(stmt)).scalars().all())

            for integration in integrations:
                entry: dict[str, Any] = {"name": integration.name}
                if not integration.endpoint_url:
                    integration.health_status = "unknown"
                    integration.is_connected = False
                    entry["status"] = "not_configured"
                    entry["detail"] = "no endpoint_url configured"
                else:
                    try:
                        async with httpx.AsyncClient(
                            timeout=httpx.Timeout(10.0, connect=5.0)
                        ) as client:
                            resp = await client.get(integration.endpoint_url)
                        if resp.status_code < 500:
                            integration.health_status = "healthy"
                            integration.is_connected = True
                            entry["status"] = "healthy"
                        else:
                            integration.health_status = "degraded"
                            integration.is_connected = False
                            entry["status"] = "degraded"
                        entry["detail"] = f"HTTP {resp.status_code}"
                    except httpx.HTTPError as exc:
                        integration.health_status = "unavailable"
                        integration.is_connected = False
                        entry["status"] = "unavailable"
                        entry["detail"] = str(exc)
                # Column is DateTime without timezone — store naive UTC.
                integration.last_health_check = utc_now().replace(tzinfo=None)
                results["integrations"][integration.id] = entry

            await session.commit()
        return results

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Integration health check failed: {str(exc)}")
        return {
            "checked_at": utc_now().isoformat(),
            "organization_id": organization_id,
            "integrations": {},
            "error": str(exc),
        }


@shared_task()
def cleanup_expired_blocks(organization_id: str) -> dict:
    """
    Deactivate temporary blocks that have expired.

    Firewall blocks are ThreatIndicator IOCs with an expires_at set by
    the executor — deactivate the ones past expiry. Host isolation and
    account disablement carry no expiry in the data model, so there is
    nothing to auto-revert there; that is reported honestly instead of
    as a fake count.

    Args:
        organization_id: Tenant organization

    Returns:
        Count of cleaned up blocks
    """
    logger.info("Cleaning up expired blocks", extra={
        "organization_id": organization_id,
    })

    async def _run() -> dict:
        from src.intel.models import ThreatIndicator

        result: dict[str, Any] = {
            "unblocked_ips": 0,
            "deisolated_hosts": 0,
            "note": (
                "host isolation and account disablement have no expiry "
                "records in the data model; only IOC-backed blocks are cleaned"
            ),
            "errors": [],
        }
        async with _session_factory()() as session:
            now = utc_now()
            stmt = select(ThreatIndicator).where(
                and_(
                    ThreatIndicator.is_active == True,  # noqa: E712
                    ThreatIndicator.expires_at.isnot(None),
                    ThreatIndicator.expires_at < now,
                    ThreatIndicator.source.in_(
                        ("remediation_engine", "remediation_quick_action")
                    ),
                )
            )
            if organization_id:
                stmt = stmt.where(
                    (ThreatIndicator.organization_id == organization_id)
                    | (ThreatIndicator.organization_id.is_(None))
                )
            expired = list((await session.execute(stmt)).scalars().all())
            for ioc in expired:
                ioc.is_active = False
                if "expired" not in (ioc.tags or []):
                    ioc.tags = [*(ioc.tags or []), "expired"]
            await session.commit()
            result["unblocked_ips"] = len(expired)
        return result

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Cleanup failed: {str(exc)}")
        return {
            "unblocked_ips": 0,
            "deisolated_hosts": 0,
            "errors": [str(exc)],
        }


@shared_task()
def register_builtin_policies(organization_id: str) -> dict:
    """
    Register default remediation policies for a new organization.

    Creates the standard starter policies (disabled + approval-required
    by default so nothing auto-fires until an admin reviews them).
    Policies whose names already exist are skipped, not double-created.

    Returns:
        Count of registered policies
    """
    logger.info("Registering builtin policies", extra={
        "organization_id": organization_id,
    })

    builtin_specs = [
        {
            "name": "Block Malicious IPs",
            "description": "Auto-block IPs matched by threat intel",
            "policy_type": "auto_block",
            "trigger_type": "threat_intel_match",
            "trigger_conditions": {"severity": {"operator": "in", "value": ["high", "critical"]}},
            "actions": [{"type": "firewall_block", "parameters": {"duration_hours": 24}}],
        },
        {
            "name": "Isolate Compromised Hosts",
            "description": "Isolate hosts with confirmed malware",
            "policy_type": "auto_isolate",
            "trigger_type": "alert_severity",
            "trigger_conditions": {"severity": "critical"},
            "actions": [{"type": "host_isolate", "parameters": {}}],
        },
        {
            "name": "Disable Compromised Accounts",
            "description": "Disable accounts with impossible travel",
            "policy_type": "auto_disable",
            "trigger_type": "ueba_risk",
            "trigger_conditions": {"risk_score": {"operator": "greater_than", "value": 80}},
            "actions": [{"type": "account_disable", "parameters": {"action": "disable"}}],
        },
    ]

    async def _run() -> dict:
        from src.models.user import User

        async with _session_factory()() as session:
            # created_by is a non-null FK — attribute ownership to an
            # admin (or any) user in the org. Without one, we cannot
            # create policies and say so instead of faking a count.
            stmt = (
                select(User)
                .where(User.organization_id == organization_id)
                .order_by(User.is_superuser.desc())
            )
            owner = (await session.execute(stmt)).scalars().first()
            if owner is None:
                return {
                    "organization_id": organization_id,
                    "status": "failed",
                    "policies_created": 0,
                    "reason": "no user exists in organization to own the policies",
                }

            created = 0
            skipped: list[str] = []
            for spec in builtin_specs:
                exists_stmt = select(func.count()).select_from(RemediationPolicy).where(
                    RemediationPolicy.name == spec["name"]
                )
                if ((await session.execute(exists_stmt)).scalar() or 0) > 0:
                    skipped.append(spec["name"])
                    continue
                session.add(RemediationPolicy(
                    name=spec["name"],
                    description=spec["description"],
                    policy_type=spec["policy_type"],
                    trigger_type=spec["trigger_type"],
                    trigger_conditions=spec["trigger_conditions"],
                    actions=spec["actions"],
                    # Safe defaults: disabled + approval required until
                    # an admin reviews and turns them on.
                    is_enabled=False,
                    requires_approval=True,
                    created_by=owner.id,
                    organization_id=organization_id,
                ))
                created += 1
            await session.commit()
            return {
                "organization_id": organization_id,
                "policies_created": created,
                "skipped_existing": skipped,
            }

    try:
        return asyncio.run(_run())
    except Exception as exc:
        logger.error(f"Builtin policy registration failed: {str(exc)}")
        return {
            "organization_id": organization_id,
            "status": "failed",
            "policies_created": 0,
            "error": str(exc),
        }
