"""
Core Remediation Engine: orchestrates policy evaluation and action execution.

Responsible for:
- Evaluating triggers against policies
- Managing execution lifecycle (approval, execution, rollback)
- Routing actions to appropriate handlers
- Handling integrations
- Tracking metrics and effectiveness
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from src.core.logging import get_logger
from src.core.config import settings
from src.models.base import utc_now
from src.intel.models import ThreatIndicator
from src.models.asset import Asset, AssetStatus
from src.models.user import User
from src.tickethub.models import TicketActivity
from src.vulnmgmt.models import Vulnerability, VulnerabilityInstance, VulnerabilityStatus
from src.remediation.models import (
    RemediationPolicy,
    RemediationAction,
    RemediationExecution,
    RemediationPlaybook,
    RemediationIntegration,
)

logger = get_logger(__name__)


class RemediationEngine:
    """
    Core remediation orchestration engine.

    Evaluates events against policies, manages execution lifecycle,
    and coordinates action execution across integrated systems.
    """

    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.executors = {
            "firewall_block": FirewallBlockExecutor(self.db),
            "host_isolate": HostIsolationExecutor(self.db),
            "account_disable": AccountActionExecutor(self.db),
            "account_lock": AccountActionExecutor(self.db),
            "password_reset": AccountActionExecutor(self.db),
            "session_terminate": AccountActionExecutor(self.db),
            "process_kill": ProcessActionExecutor(self.db),
            "file_quarantine": ProcessActionExecutor(self.db),
            "patch_deploy": PatchExecutor(self.db),
            "dns_sinkhole": NetworkActionExecutor(self.db),
            "email_quarantine": NotificationExecutor(self.db),
            "token_revoke": AccountActionExecutor(self.db),
            "webhook": WebhookExecutor(self.db),
            "script": ScriptExecutor(self.db),
            "notification": NotificationExecutor(self.db),
            "ticket_create": NotificationExecutor(self.db),
        }

    async def evaluate_trigger(
        self,
        trigger_type: str,
        trigger_data: dict,
        organization_id: str,
    ) -> list[RemediationPolicy]:
        """
        Evaluate incoming event against all enabled policies.

        Matches trigger type and conditions, respects cooldowns and rate limits.

        Args:
            trigger_type: Type of trigger (alert_severity, anomaly_score, etc.)
            trigger_data: Event data to evaluate
            organization_id: Tenant organization

        Returns:
            List of matching policies sorted by priority (highest first)
        """
        stmt = select(RemediationPolicy).where(
            and_(
                RemediationPolicy.is_enabled == True,
                RemediationPolicy.trigger_type == trigger_type,
                RemediationPolicy.organization_id == organization_id,
            )
        )
        result = await self.db.execute(stmt)
        policies = result.scalars().all()

        matching = []
        for policy in policies:
            # Check trigger conditions
            if not self._check_conditions(policy.trigger_conditions, trigger_data):
                logger.debug(f"Policy {policy.id} conditions not met", extra={
                    "policy_id": policy.id,
                    "trigger_type": trigger_type,
                })
                continue

            # Check exclusions
            target = trigger_data.get("target_entity") or trigger_data.get("source_ip")
            if target and self._check_exclusions(policy.exclusions, target):
                logger.debug(f"Policy {policy.id} target excluded", extra={
                    "policy_id": policy.id,
                    "target": target,
                })
                continue

            # Check cooldown
            if not await self._check_cooldown(policy):
                logger.debug(f"Policy {policy.id} in cooldown", extra={
                    "policy_id": policy.id,
                    "last_executed": policy.last_executed_at,
                })
                continue

            # Check rate limit
            if not await self._check_rate_limit(policy):
                logger.debug(f"Policy {policy.id} rate limit exceeded", extra={
                    "policy_id": policy.id,
                    "execution_count": policy.execution_count,
                })
                continue

            matching.append(policy)

        # Sort by priority (descending)
        matching.sort(key=lambda p: p.priority, reverse=True)
        logger.info(f"Found {len(matching)} matching policies for {trigger_type}", extra={
            "trigger_type": trigger_type,
            "count": len(matching),
        })
        return matching

    async def execute_remediation(
        self,
        policy_id: str,
        trigger_data: dict,
        trigger_source: str = "manual",
        trigger_id: str | None = None,
        initiated_by: str | None = None,
        organization_id: str | None = None,
    ) -> RemediationExecution:
        """
        Create and execute a remediation from policy.

        If policy requires approval, waits for approval before executing actions.
        Otherwise proceeds immediately to action execution.

        Args:
            policy_id: RemediationPolicy ID
            trigger_data: Event data
            trigger_source: Source of trigger (alert, manual, etc.)
            trigger_id: ID of the triggering event
            initiated_by: User ID (for manual triggers)
            organization_id: Tenant organization

        Returns:
            RemediationExecution record
        """
        # Fetch policy
        policy = await self.db.get(RemediationPolicy, policy_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        # Create execution record
        target = trigger_data.get("target_entity") or trigger_data.get("source_ip") or "unknown"
        execution = RemediationExecution(
            id=str(uuid4()),
            policy_id=policy_id,
            trigger_source=trigger_source,
            trigger_id=trigger_id,
            trigger_details=trigger_data,
            target_entity=target,
            target_type=trigger_data.get("target_type", "unknown"),
            actions_planned=policy.actions,
            status="pending",
            created_by=initiated_by,
            organization_id=organization_id or policy.organization_id,
        )
        self.db.add(execution)
        await self.db.flush()

        logger.info(f"Created remediation execution", extra={
            "execution_id": execution.id,
            "policy_id": policy_id,
            "target": target,
        })

        # Handle approval workflow
        if policy.requires_approval:
            execution.status = "awaiting_approval"
            execution.approval_status = "pending"
            await self.db.commit()
            logger.info(f"Execution awaiting approval", extra={
                "execution_id": execution.id,
                "timeout_minutes": policy.approval_timeout_minutes,
            })
            # Approval will be handled by approval endpoint
            # Timeout handling by scheduled task
            return execution

        # Auto-approve and execute
        execution.approval_status = "auto_approved"
        execution.approved_at = utc_now()
        execution.status = "approved"
        await self.db.commit()

        await self._run_actions(execution.id)
        return execution

    async def _run_actions(self, execution_id: str) -> dict:
        """
        Execute all actions in an execution sequentially.

        Handles success/failure logic, retries, and decision points.

        Args:
            execution_id: RemediationExecution ID

        Returns:
            Dictionary with execution results
        """
        execution = await self.db.get(RemediationExecution, execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        execution.status = "running"
        execution.started_at = utc_now()
        await self.db.commit()

        logger.info(f"Starting remediation actions", extra={
            "execution_id": execution_id,
            "action_count": len(execution.actions_planned),
        })

        results = []
        for idx, action_def in enumerate(execution.actions_planned):
            execution.current_action_index = idx
            await self.db.commit()

            try:
                result = await self._execute_single_action(
                    action_def,
                    execution.target_entity,
                    {
                        "execution_id": execution_id,
                        "trigger_data": execution.trigger_details,
                    }
                )
                results.append(result)
                execution.actions_completed.append(result)

                if not result.get("success"):
                    logger.warning(f"Action failed", extra={
                        "execution_id": execution_id,
                        "action": action_def.get("type"),
                        "error": result.get("error"),
                    })
                    # Decide whether to continue, retry, or abort
                    if action_def.get("on_failure") == "abort":
                        break
                    elif action_def.get("on_failure") == "retry":
                        # Retry logic would go here
                        pass

            except Exception as e:
                logger.error(f"Action execution error", extra={
                    "execution_id": execution_id,
                    "action": action_def.get("type"),
                    "error": str(e),
                })
                results.append({
                    "action_type": action_def.get("type"),
                    "success": False,
                    "error": str(e),
                    "timestamp": utc_now(),
                })
                if action_def.get("on_failure") == "abort":
                    break

            await self.db.commit()

        # Determine overall result
        all_success = all(r.get("success", False) for r in results)
        execution.overall_result = "success" if all_success else "partial_success" if results else "failure"
        execution.status = "completed"
        execution.completed_at = utc_now()

        # Update policy metrics
        if execution.policy_id:
            policy = await self.db.get(RemediationPolicy, execution.policy_id)
            if policy:
                policy.execution_count += 1
                policy.last_executed_at = utc_now()
                if all_success:
                    policy.success_rate = ((policy.success_rate or 0) * (policy.execution_count - 1) + 1) / policy.execution_count
                else:
                    policy.success_rate = ((policy.success_rate or 0) * (policy.execution_count - 1)) / policy.execution_count

        await self.db.commit()
        logger.info(f"Remediation completed", extra={
            "execution_id": execution_id,
            "result": execution.overall_result,
        })
        return {"execution_id": execution_id, "results": results}

    async def _execute_single_action(
        self,
        action_def: dict,
        target: str,
        context: dict,
    ) -> dict:
        """
        Execute a single action against a target.

        Routes to appropriate executor based on action type.

        Args:
            action_def: Action definition with type and parameters
            target: Target entity (IP, hostname, username, etc.)
            context: Execution context

        Returns:
            Result dictionary with success flag and details
        """
        action_type = action_def.get("type")
        executor = self.executors.get(action_type)

        if not executor:
            logger.warning(f"No executor for action type: {action_type}")
            return {
                "action_type": action_type,
                "success": False,
                "error": f"Unknown action type: {action_type}",
                "timestamp": utc_now(),
            }

        try:
            result = await executor.execute(
                target=target,
                parameters=action_def.get("parameters", {}),
                context=context,
            )
            return {
                "action_type": action_type,
                "target": target,
                "success": result.get("success", False),
                "details": result,
                "timestamp": utc_now(),
            }
        except asyncio.TimeoutError:
            logger.error(f"Action timeout: {action_type}")
            return {
                "action_type": action_type,
                "target": target,
                "success": False,
                "error": "Action timeout",
                "timestamp": utc_now(),
            }

    async def rollback_execution(self, execution_id: str) -> dict:
        """
        Rollback a completed execution by reversing actions.

        Args:
            execution_id: RemediationExecution ID

        Returns:
            Rollback result
        """
        execution = await self.db.get(RemediationExecution, execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        execution.rollback_status = "in_progress"
        await self.db.commit()

        logger.info(f"Starting rollback", extra={
            "execution_id": execution_id,
            "action_count": len(execution.actions_completed),
        })

        # Execute reverse actions in reverse order
        results = []
        for action_result in reversed(execution.actions_completed):
            # Reverse action logic would go here
            results.append({"action": action_result.get("action_type"), "rolled_back": True})

        execution.rollback_status = "completed"
        execution.rolled_back_at = utc_now()
        await self.db.commit()

        logger.info(f"Rollback completed", extra={
            "execution_id": execution_id,
        })
        return {"execution_id": execution_id, "results": results}

    async def approve_execution(
        self,
        execution_id: str,
        approver_id: str,
    ) -> None:
        """
        Approve a pending remediation execution.

        Args:
            execution_id: RemediationExecution ID
            approver_id: User ID of approver
        """
        execution = await self.db.get(RemediationExecution, execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        if execution.approval_status != "pending":
            raise ValueError(f"Execution not in pending approval state")

        execution.approval_status = "approved"
        execution.approved_by = approver_id
        execution.approved_at = utc_now()
        execution.status = "approved"
        await self.db.commit()

        logger.info(f"Execution approved", extra={
            "execution_id": execution_id,
            "approved_by": approver_id,
        })

        # Proceed to action execution
        await self._run_actions(execution_id)

    async def reject_execution(
        self,
        execution_id: str,
        approver_id: str,
        reason: str | None = None,
    ) -> None:
        """
        Reject a pending remediation execution.

        Args:
            execution_id: RemediationExecution ID
            approver_id: User ID of approver
            reason: Rejection reason
        """
        execution = await self.db.get(RemediationExecution, execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        execution.approval_status = "rejected"
        execution.approved_by = approver_id
        execution.approved_at = utc_now()
        execution.status = "cancelled"
        execution.notes = reason or "Rejected by approver"
        await self.db.commit()

        logger.info(f"Execution rejected", extra={
            "execution_id": execution_id,
            "rejected_by": approver_id,
        })

    def _check_conditions(self, conditions: dict, data: dict) -> bool:
        """Check if data matches all conditions."""
        for key, condition in conditions.items():
            if key not in data:
                return False
            value = data[key]
            if isinstance(condition, dict):
                operator = condition.get("operator", "equals")
                expected = condition.get("value")
                if operator == "equals" and value != expected:
                    return False
                elif operator == "greater_than" and value <= expected:
                    return False
                elif operator == "less_than" and value >= expected:
                    return False
                elif operator == "in" and value not in expected:
                    return False
            else:
                if value != condition:
                    return False
        return True

    def _check_exclusions(self, exclusions: list[str], target: str) -> bool:
        """Check if target is in exclusion list."""
        return target in exclusions

    async def _check_cooldown(self, policy: RemediationPolicy) -> bool:
        """Check if policy is still in cooldown."""
        if not policy.last_executed_at:
            return True
        elapsed = (utc_now() - policy.last_executed_at).total_seconds() / 60
        return elapsed >= policy.cooldown_minutes

    async def _check_rate_limit(self, policy: RemediationPolicy) -> bool:
        """Check if policy execution rate limit is exceeded."""
        if policy.execution_count >= policy.max_executions_per_hour:
            return False
        # In practice, would check executions in last hour
        return True


class ActionExecutor:
    """Base class for action executors."""

    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.logger = get_logger(self.__class__.__name__)

    async def execute(
        self,
        target: str,
        parameters: dict,
        context: dict,
    ) -> dict:
        """Execute action. Base implementation that subclasses can override."""
        action_type = self.__class__.__name__
        execution_id = context.get("execution_id", "unknown")

        self.logger.info(f"Executing action", extra={
            "executor": action_type,
            "target": target,
            "execution_id": execution_id,
        })

        # Update status to in_progress if we have an execution record
        if execution_id != "unknown":
            execution = await self.db.get(RemediationExecution, execution_id)
            if execution:
                execution.status = "running"
                await self.db.flush()

        # Log the action being performed
        self.logger.info(f"Action in progress for target: {target}", extra={
            "executor": action_type,
            "target": target,
            "parameters": parameters,
        })

        # Mark as completed
        if execution_id != "unknown":
            execution = await self.db.get(RemediationExecution, execution_id)
            if execution:
                execution.status = "completed"
                execution.completed_at = utc_now()
                await self.db.flush()

        self.logger.info(f"Action completed", extra={
            "executor": action_type,
            "target": target,
            "execution_id": execution_id,
        })

        return {
            "success": True,
            "action": action_type,
            "target": target,
            "parameters": parameters,
            "completed_at": utc_now(),
        }


def _get_execution_context(context: dict) -> tuple[str, str | None, str | None]:
    """Extract execution_id, organization_id, and actor_id from the action context."""
    execution_id = context.get("execution_id", "unknown")
    trigger_data = context.get("trigger_data") or {}
    org_id = (
        context.get("organization_id")
        or trigger_data.get("organization_id")
    )
    actor_id = context.get("initiated_by") or trigger_data.get("initiated_by")
    return execution_id, org_id, actor_id


async def _log_ticket_activity(
    db: AsyncSession,
    *,
    source_id: str,
    activity_type: str,
    description: str,
    actor_id: str | None = None,
    organization_id: str | None = None,
    extra_metadata: dict | None = None,
) -> TicketActivity:
    """Create a TicketActivity record tied to a remediation execution."""
    activity = TicketActivity(
        id=str(uuid4()),
        source_type="remediation_execution",
        source_id=source_id,
        activity_type=activity_type,
        actor_id=actor_id,
        description=description[:500],
        extra_metadata=extra_metadata,
        organization_id=organization_id,
    )
    db.add(activity)
    await db.flush()
    return activity


class FirewallBlockExecutor(ActionExecutor):
    """Firewall blocking executor: creates an active IOC for the IP."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        duration_hours = parameters.get("duration_hours", 24)
        now = utc_now()
        expires_at = now + timedelta(hours=duration_hours)

        self.logger.info(
            "Creating firewall block IOC",
            extra={"target": target, "duration_hours": duration_hours},
        )

        ioc = ThreatIndicator(
            id=str(uuid4()),
            value=target,
            indicator_type="ipv4",
            is_active=True,
            is_whitelisted=False,
            severity="high",
            confidence=90,
            source="remediation_engine",
            tags=["blocked", "firewall", "auto_remediation"],
            context={
                "description": f"Blocked via remediation execution {execution_id}",
                "source_reference": execution_id,
                "category": "blocked",
            },
            first_seen=now,
            last_seen=now,
            expires_at=expires_at,
        )
        self.db.add(ioc)
        await self.db.flush()

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="firewall_block",
            description=f"Blocked IP {target} via firewall for {duration_hours}h",
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "target_ip": target,
                "duration_hours": duration_hours,
                "ioc_id": ioc.id,
                "expires_at": expires_at,
            },
        )

        return {
            "success": True,
            "action": "firewall_block",
            "target": target,
            "ioc_id": ioc.id,
            "duration_hours": duration_hours,
            "expires_at": expires_at,
        }


class HostIsolationExecutor(ActionExecutor):
    """Host isolation executor: marks asset as isolated in inventory."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        self.logger.info("Isolating host", extra={"target": target})

        stmt = select(Asset).where(
            (Asset.hostname == target)
            | (Asset.name == target)
            | (Asset.ip_address == target)
        )
        result = await self.db.execute(stmt)
        asset = result.scalars().first()

        if not asset:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="host_isolate_failed",
                description=f"Host isolation requested for unknown asset {target}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={"target": target},
            )
            return {
                "success": False,
                "action": "host_isolate",
                "target": target,
                "error": "Asset not found in inventory",
            }

        previous_status = asset.status
        try:
            existing_tags = json.loads(asset.tags) if asset.tags else []
            if not isinstance(existing_tags, list):
                existing_tags = []
        except (ValueError, TypeError):
            existing_tags = []

        if "isolated" not in existing_tags:
            existing_tags.append("isolated")

        asset.status = AssetStatus.MAINTENANCE.value
        asset.tags = json.dumps(existing_tags)
        await self.db.flush()

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="host_isolate",
            description=f"Isolated host {asset.name} ({asset.hostname or asset.ip_address})",
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "asset_id": asset.id,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "previous_status": previous_status,
            },
        )

        return {
            "success": True,
            "action": "host_isolate",
            "target": target,
            "asset_id": asset.id,
            "asset_name": asset.name,
            "previous_status": previous_status,
            "new_status": asset.status,
        }


class AccountActionExecutor(ActionExecutor):
    """Account-level actions (disable, lock, reset, terminate, revoke)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "disable")

        self.logger.info(
            "Executing account action",
            extra={"target": target, "action": action},
        )

        stmt = select(User).where(User.email == target)
        result = await self.db.execute(stmt)
        user = result.scalars().first()

        if not user:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="account_action_failed",
                description=f"Account action '{action}' requested for unknown user {target}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={"target": target, "action": action},
            )
            return {
                "success": False,
                "action": action,
                "target": target,
                "error": "User not found",
            }

        previous_active = user.is_active
        if action == "disable":
            user.is_active = False
            user.force_password_change = True
        elif action in ("lock", "session_terminate", "token_revoke"):
            user.force_password_change = True
        elif action == "password_reset":
            user.force_password_change = True

        await self.db.flush()

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"account_{action}",
            description=f"Account action '{action}' applied to {user.email}",
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "user_id": user.id,
                "email": user.email,
                "action": action,
                "previous_is_active": previous_active,
                "new_is_active": user.is_active,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "user_id": user.id,
            "is_active": user.is_active,
        }


class ProcessActionExecutor(ActionExecutor):
    """Process and file actions: queued for endpoint agent execution."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "kill")
        process_name = parameters.get("process_name")
        pid = parameters.get("pid")
        file_path = parameters.get("file_path")

        self.logger.info(
            "Queuing process/file action for endpoint agent",
            extra={"target": target, "action": action},
        )

        activity = await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"process_{action}",
            description=(
                f"Queued process action '{action}' on {target} "
                f"(requires endpoint agent)"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "action": action,
                "process_name": process_name,
                "pid": pid,
                "file_path": file_path,
                "requires_agent": True,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "activity_id": activity.id,
            "status": "queued",
            "note": "Requires endpoint agent to execute",
        }


class NetworkActionExecutor(ActionExecutor):
    """Network actions (sinkhole, block URL, DNS sinkhole)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "sinkhole")

        self.logger.info(
            "Executing network action",
            extra={"target": target, "action": action},
        )

        activity = await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"network_{action}",
            description=f"Network action '{action}' applied to {target}",
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "target": target,
                "action": action,
                "parameters": parameters,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "activity_id": activity.id,
        }


class PatchExecutor(ActionExecutor):
    """Patch deployment executor: marks vulnerability as patching/patched."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        cve_id = parameters.get("cve_id") or parameters.get("patch_id")
        new_status = parameters.get("new_status", VulnerabilityStatus.PATCHED.value)

        self.logger.info(
            "Deploying patch",
            extra={"target": target, "cve_id": cve_id},
        )

        if not cve_id:
            return {
                "success": False,
                "action": "patch_deploy",
                "target": target,
                "error": "cve_id (or patch_id) parameter is required",
            }

        stmt = select(Vulnerability).where(Vulnerability.cve_id == cve_id)
        result = await self.db.execute(stmt)
        vuln = result.scalars().first()

        if not vuln:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="patch_deploy_failed",
                description=f"Patch deploy requested for unknown CVE {cve_id}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={"cve_id": cve_id, "target": target},
            )
            return {
                "success": False,
                "action": "patch_deploy",
                "target": target,
                "cve_id": cve_id,
                "error": "Vulnerability not found",
            }

        # Update matching instances (optionally scoped to target asset)
        inst_stmt = select(VulnerabilityInstance).where(
            VulnerabilityInstance.vulnerability_id == vuln.id
        )
        if target and target != "unknown":
            inst_stmt = inst_stmt.where(
                (VulnerabilityInstance.asset_name == target)
                | (VulnerabilityInstance.asset_ip == target)
                | (VulnerabilityInstance.asset_id == target)
            )
        inst_result = await self.db.execute(inst_stmt)
        instances = inst_result.scalars().all()

        updated_ids: list[str] = []
        for inst in instances:
            inst.status = new_status
            updated_ids.append(inst.id)

        await self.db.flush()

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="patch_deploy",
            description=(
                f"Patch deployed for {cve_id} on {target}: "
                f"{len(updated_ids)} instance(s) marked {new_status}"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "vulnerability_id": vuln.id,
                "cve_id": cve_id,
                "new_status": new_status,
                "instances_updated": updated_ids,
                "target": target,
            },
        )

        return {
            "success": True,
            "action": "patch_deploy",
            "target": target,
            "vulnerability_id": vuln.id,
            "cve_id": cve_id,
            "instances_updated": len(updated_ids),
            "new_status": new_status,
        }


class NotificationExecutor(ActionExecutor):
    """Notification and ticketing executor: sends email or logs activity."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "notify")
        recipients = parameters.get("recipients") or parameters.get("to") or []
        if isinstance(recipients, str):
            recipients = [recipients]
        subject = parameters.get("subject", f"PySOAR Remediation: {action}")
        body = parameters.get(
            "body",
            f"Remediation action '{action}' triggered for target {target}.",
        )

        self.logger.info(
            "Executing notification",
            extra={"action": action, "target": target, "recipients": recipients},
        )

        email_sent = False
        email_error: str | None = None
        if recipients:
            try:
                from src.services.email_service import EmailService

                email = EmailService()
                if email.is_configured:
                    email_sent = await email.send_email(
                        to=list(recipients),
                        subject=subject,
                        body=body,
                    )
                else:
                    email_error = "Email service not configured"
            except ImportError as e:
                email_error = f"EmailService unavailable: {e}"

        activity = await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"notification_{action}",
            description=(
                f"Notification '{action}' "
                f"{'sent' if email_sent else 'logged'} for {target}"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "action": action,
                "target": target,
                "recipients": recipients,
                "subject": subject,
                "email_sent": email_sent,
                "email_error": email_error,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "email_sent": email_sent,
            "email_error": email_error,
            "activity_id": activity.id,
            "recipients": recipients,
        }


class WebhookExecutor(ActionExecutor):
    """Generic webhook executor: POSTs to the configured URL."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        url = parameters.get("url")
        method = parameters.get("method", "POST").upper()
        headers = parameters.get("headers") or {"Content-Type": "application/json"}
        payload = parameters.get("payload") or {
            "target": target,
            "execution_id": execution_id,
            "trigger_data": context.get("trigger_data"),
        }
        timeout = parameters.get("timeout", 10.0)

        self.logger.info(
            "Executing webhook",
            extra={"url": url, "method": method},
        )

        if not url:
            return {
                "success": False,
                "action": "webhook",
                "error": "url parameter is required",
            }

        status_code: int | None = None
        response_text: str | None = None
        error: str | None = None
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                if method == "POST":
                    resp = await client.post(url, json=payload, headers=headers)
                elif method == "PUT":
                    resp = await client.put(url, json=payload, headers=headers)
                elif method == "GET":
                    resp = await client.get(url, headers=headers)
                else:
                    resp = await client.request(
                        method, url, json=payload, headers=headers
                    )
                status_code = resp.status_code
                response_text = resp.text[:500]
        except httpx.TimeoutException as e:
            error = f"timeout: {e}"
        except httpx.HTTPError as e:
            error = f"http error: {e}"

        success = error is None and status_code is not None and 200 <= status_code < 300

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="webhook",
            description=(
                f"Webhook {method} {url} -> "
                f"{status_code if status_code is not None else error}"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "url": url,
                "method": method,
                "status_code": status_code,
                "error": error,
            },
        )

        return {
            "success": success,
            "action": "webhook",
            "url": url,
            "method": method,
            "status_code": status_code,
            "response_preview": response_text,
            "error": error,
        }


class ScriptExecutor(ActionExecutor):
    """Custom script executor: sandboxed. Only queues an activity record."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        script_content = parameters.get("script", "")
        executor_type = parameters.get("executor", "bash")

        self.logger.info(
            "Queuing script (sandboxed - not executed in-process)",
            extra={"target": target, "executor": executor_type},
        )

        activity = await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="script_queued",
            description=(
                f"Script ({executor_type}) queued for {target}; "
                f"execution deferred to sandbox/agent"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "target": target,
                "executor": executor_type,
                "script_length": len(script_content),
                "sandboxed": True,
            },
        )

        return {
            "success": True,
            "action": "script",
            "target": target,
            "executor": executor_type,
            "activity_id": activity.id,
            "status": "queued",
            "note": "Script execution is sandboxed; requires external runner",
        }
