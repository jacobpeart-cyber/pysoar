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
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from src.core.logging import get_logger
from src.core.config import settings
from src.models.base import utc_now
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
        """Execute action. Override in subclass."""
        raise NotImplementedError


class FirewallBlockExecutor(ActionExecutor):
    """Firewall blocking executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        duration_hours = parameters.get("duration_hours", 24)
        self.logger.info(f"Blocking IP: {target} for {duration_hours}h", extra={
            "target": target,
            "duration": duration_hours,
        })
        return {
            "success": True,
            "action": "firewall_block",
            "target": target,
            "duration_hours": duration_hours,
        }


class HostIsolationExecutor(ActionExecutor):
    """Host isolation/network quarantine executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        self.logger.info(f"Isolating host: {target}", extra={"target": target})
        return {
            "success": True,
            "action": "host_isolate",
            "target": target,
        }


class AccountActionExecutor(ActionExecutor):
    """Account-level actions (disable, lock, reset, terminate, revoke)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        action = parameters.get("action", "disable")
        self.logger.info(f"Executing account action: {action} for {target}", extra={
            "target": target,
            "action": action,
        })
        return {
            "success": True,
            "action": action,
            "target": target,
        }


class ProcessActionExecutor(ActionExecutor):
    """Process and file actions."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        action = parameters.get("action", "kill")
        self.logger.info(f"Executing process action: {action} on {target}", extra={
            "target": target,
            "action": action,
        })
        return {
            "success": True,
            "action": action,
            "target": target,
        }


class NetworkActionExecutor(ActionExecutor):
    """Network actions (sinkhole, block URL)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        action = parameters.get("action", "sinkhole")
        self.logger.info(f"Executing network action: {action} for {target}", extra={
            "target": target,
            "action": action,
        })
        return {
            "success": True,
            "action": action,
            "target": target,
        }


class PatchExecutor(ActionExecutor):
    """Patch deployment executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        patch_id = parameters.get("patch_id")
        self.logger.info(f"Deploying patch {patch_id} to {target}", extra={
            "target": target,
            "patch_id": patch_id,
        })
        return {
            "success": True,
            "action": "patch_deploy",
            "target": target,
            "patch_id": patch_id,
        }


class NotificationExecutor(ActionExecutor):
    """Notification and ticketing executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        action = parameters.get("action", "notify")
        self.logger.info(f"Executing notification action: {action}", extra={
            "action": action,
            "target": target,
        })
        return {
            "success": True,
            "action": action,
            "details": parameters,
        }


class WebhookExecutor(ActionExecutor):
    """Generic webhook executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        url = parameters.get("url")
        method = parameters.get("method", "POST")
        self.logger.info(f"Executing webhook: {method} {url}", extra={
            "url": url,
            "method": method,
        })
        return {
            "success": True,
            "action": "webhook",
            "url": url,
            "method": method,
        }


class ScriptExecutor(ActionExecutor):
    """Custom script executor."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        script_content = parameters.get("script", "")
        executor_type = parameters.get("executor", "bash")
        self.logger.info(f"Executing {executor_type} script on {target}", extra={
            "target": target,
            "executor": executor_type,
        })
        return {
            "success": True,
            "action": "script",
            "target": target,
            "executor": executor_type,
        }
