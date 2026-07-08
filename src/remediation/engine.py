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
from sqlalchemy import select, and_, func

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


def _json_safe(value: Any) -> Any:
    """Recursively convert datetimes to ISO strings so action results can
    be persisted into JSON columns (no custom json_serializer is
    configured on the engine)."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    return value


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
            "file_quarantine": FileActionExecutor(self.db),
            "collect_forensics": ForensicsCollectionExecutor(self.db),
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

                # Bounded retry: re-invoke the executor with a small
                # backoff, recording every attempt so the execution row
                # tells the truth about how many times we tried.
                if not result.get("success") and action_def.get("on_failure") == "retry":
                    max_retries = max(0, int(action_def.get("max_retries", 2)))
                    backoff_seconds = float(action_def.get("retry_backoff_seconds", 1.0))
                    attempts = 1
                    while not result.get("success") and attempts <= max_retries:
                        await asyncio.sleep(backoff_seconds * attempts)
                        logger.info(f"Retrying failed action", extra={
                            "execution_id": execution_id,
                            "action": action_def.get("type"),
                            "attempt": attempts + 1,
                            "max_retries": max_retries,
                        })
                        result = await self._execute_single_action(
                            action_def,
                            execution.target_entity,
                            {
                                "execution_id": execution_id,
                                "trigger_data": execution.trigger_details,
                            }
                        )
                        attempts += 1
                    result["attempts"] = attempts
                    if not result.get("success"):
                        result["retries_exhausted"] = True

                result = _json_safe(result)
                results.append(result)
                # Reassign (not append in place) so SQLAlchemy sees the
                # JSON column as dirty and actually persists the result.
                execution.actions_completed = [*(execution.actions_completed or []), result]

                if not result.get("success"):
                    logger.warning(f"Action failed", extra={
                        "execution_id": execution_id,
                        "action": action_def.get("type"),
                        "error": result.get("error"),
                    })
                    if action_def.get("on_failure") == "abort":
                        break

            except Exception as e:
                logger.error(f"Action execution error", extra={
                    "execution_id": execution_id,
                    "action": action_def.get("type"),
                    "error": str(e),
                })
                error_result = {
                    "action_type": action_def.get("type"),
                    "success": False,
                    "error": str(e),
                    "timestamp": utc_now().isoformat(),
                }
                results.append(error_result)
                execution.actions_completed = [*(execution.actions_completed or []), error_result]
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

    # Action types that have no automated inverse in this platform.
    # Each maps to the honest reason we report instead of a fake success.
    IRREVERSIBLE_ACTIONS: dict[str, str] = {
        "process_kill": "a terminated process cannot be restarted by the platform",
        "collect_forensics": "forensic collection is a read-only capture; there is nothing to reverse",
        "notification": "a delivered notification cannot be unsent",
        "ticket_create": "a delivered notification/ticket cannot be unsent",
        "email_quarantine": "email quarantine is handled by the notification path; no reversible state was recorded",
        "webhook": "the remote side effect of a webhook is outside PySOAR's control",
        "script": "queued script side effects are outside PySOAR's control",
    }

    async def rollback_execution(self, execution_id: str) -> dict:
        """
        Rollback a completed execution by actually reversing each
        completed action, in reverse order.

        Per-action outcomes are truthful:
        - ``rolled_back: True`` only when the inverse operation really
          mutated state (IOC deactivated, asset status restored, account
          re-enabled, unquarantine command queued, ...).
        - ``rolled_back: False, reversible: False`` for action types
          with no automated inverse (process kill, notifications, ...).
        - ``rolled_back: False`` with an ``error``/``reason`` when the
          inverse was attempted but could not be applied.

        Overall ``rollback_status`` is "completed", "partial", or
        "failed" based on the real outcomes.

        Args:
            execution_id: RemediationExecution ID

        Returns:
            Rollback result with per-action details
        """
        execution = await self.db.get(RemediationExecution, execution_id)
        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        execution.rollback_status = "in_progress"
        await self.db.commit()

        completed_actions = execution.actions_completed or []
        logger.info(f"Starting rollback", extra={
            "execution_id": execution_id,
            "action_count": len(completed_actions),
        })

        # Reverse actions in reverse order of execution
        results = []
        reversed_count = 0
        irreversible_count = 0
        failed_count = 0
        for action_result in reversed(completed_actions):
            action_type = action_result.get("action_type")

            # collect_forensics reports per-sub-command results with no
            # composite success flag — route it straight to the handler
            # (it is irreversible either way and reported as such).
            if not action_result.get("success") and action_type != "collect_forensics":
                # Forward action never succeeded — nothing to reverse.
                results.append({
                    "action": action_type,
                    "rolled_back": False,
                    "skipped": True,
                    "reason": "forward action did not succeed; nothing to reverse",
                })
                continue

            try:
                outcome = await self._rollback_single_action(
                    action_type, action_result, execution
                )
            except Exception as e:
                logger.error(f"Rollback action error", extra={
                    "execution_id": execution_id,
                    "action": action_type,
                    "error": str(e),
                })
                outcome = {
                    "action": action_type,
                    "rolled_back": False,
                    "error": str(e),
                }

            results.append(outcome)
            if outcome.get("rolled_back"):
                reversed_count += 1
            elif outcome.get("reversible") is False:
                irreversible_count += 1
            else:
                failed_count += 1

        attempted = reversed_count + irreversible_count + failed_count
        if attempted == 0 or (failed_count == 0 and irreversible_count == 0):
            rollback_status = "completed"
        elif reversed_count > 0:
            rollback_status = "partial"
        else:
            rollback_status = "failed"

        execution.rollback_status = rollback_status
        execution.rolled_back_at = utc_now()
        if rollback_status == "completed" and reversed_count > 0:
            execution.status = "rolled_back"
        metrics = dict(execution.metrics or {})
        metrics["rollback_results"] = results
        execution.metrics = metrics
        await self.db.commit()

        logger.info(f"Rollback finished", extra={
            "execution_id": execution_id,
            "rollback_status": rollback_status,
            "reversed": reversed_count,
            "irreversible": irreversible_count,
            "failed": failed_count,
        })
        return {
            "execution_id": execution_id,
            "rollback_status": rollback_status,
            "results": results,
        }

    async def _rollback_single_action(
        self,
        action_type: str | None,
        action_result: dict,
        execution: RemediationExecution,
    ) -> dict:
        """Dispatch the inverse of one completed action.

        Reads the artifacts each forward executor recorded in its result
        (``details``) to find exactly what state to restore.
        """
        details = action_result.get("details") or {}
        target = action_result.get("target") or execution.target_entity

        # --- IOC-backed actions: deactivate the indicator ---------------
        if action_type in ("firewall_block", "dns_sinkhole"):
            # Layer 1: deactivate the detection IOC.
            ioc = None
            ioc_id = details.get("ioc_id")
            if ioc_id:
                ioc = await self.db.get(ThreatIndicator, ioc_id)
            if ioc is None and target:
                # Legacy executions that predate ioc_id recording
                stmt = select(ThreatIndicator).where(
                    and_(
                        ThreatIndicator.value == target,
                        ThreatIndicator.is_active == True,
                        ThreatIndicator.source == "remediation_engine",
                    )
                )
                ioc = (await self.db.execute(stmt)).scalars().first()

            if ioc is None:
                ioc_ok = False
                ioc_detail = f"IOC for {target} not found; could not deactivate"
            elif not ioc.is_active:
                ioc_ok = True
                ioc_detail = "IOC was already inactive"
            else:
                ioc.is_active = False
                if "rolled_back" not in (ioc.tags or []):
                    ioc.tags = [*(ioc.tags or []), "rolled_back"]
                await self.db.flush()
                ioc_ok = True
                ioc_detail = f"IOC {ioc.id} deactivated"

            # Layer 2: reverse real host-firewall enforcement by queuing an
            # unblock_ip to every agent that actually got a block_ip. The
            # forward executor recorded these in ``block_commands``.
            unblock_results = await self._rollback_ip_blocks(
                details.get("block_commands") or [], target, execution
            )
            enforced = [u for u in unblock_results if u.get("success")]
            enforce_failed = [u for u in unblock_results if not u.get("success")]

            await _log_ticket_activity(
                self.db,
                source_id=execution.id,
                activity_type=f"rollback_{action_type}",
                description=(
                    f"Rollback {target}: {ioc_detail}; "
                    f"unblock_ip queued to {len(enforced)} agent(s)"
                    + (f", {len(enforce_failed)} failed" if enforce_failed else "")
                ),
                organization_id=execution.organization_id,
                extra_metadata={
                    "ioc_id": ioc.id if ioc else None,
                    "target": target,
                    "unblock_results": unblock_results,
                },
            )

            # Truthful outcome: reversed only if the IOC came down AND every
            # agent that blocked has an unblock queued.
            rolled_back = ioc_ok and not enforce_failed
            result = {
                "action": action_type,
                "rolled_back": rolled_back,
                "ioc_id": ioc.id if ioc else None,
                "detail": ioc_detail,
                "unblock_commands": unblock_results,
            }
            if not rolled_back:
                reasons = []
                if not ioc_ok:
                    reasons.append(ioc_detail)
                if enforce_failed:
                    reasons.append(
                        f"{len(enforce_failed)} agent unblock(s) failed"
                    )
                result["reason"] = "; ".join(reasons)
            return result

        # --- Host isolation: restore previous asset status --------------
        if action_type == "host_isolate":
            asset = None
            asset_id = details.get("asset_id")
            if asset_id:
                asset = await self.db.get(Asset, asset_id)
            if asset is None and target:
                stmt = select(Asset).where(
                    (Asset.hostname == target)
                    | (Asset.name == target)
                    | (Asset.ip_address == target)
                )
                asset = (await self.db.execute(stmt)).scalars().first()
            if asset is None:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": f"Asset for {target} not found; cannot restore status",
                }
            previous_status = details.get("previous_status") or AssetStatus.ACTIVE.value
            asset.status = previous_status
            try:
                tags = json.loads(asset.tags) if asset.tags else []
                if isinstance(tags, list) and "isolated" in tags:
                    tags.remove("isolated")
                    asset.tags = json.dumps(tags)
            except (ValueError, TypeError):
                pass
            await self.db.flush()
            await _log_ticket_activity(
                self.db,
                source_id=execution.id,
                activity_type="rollback_host_isolate",
                description=(
                    f"Rollback: restored asset {asset.name} to status "
                    f"'{previous_status}' and removed isolation tag"
                ),
                organization_id=execution.organization_id,
                extra_metadata={"asset_id": asset.id, "restored_status": previous_status},
            )
            return {
                "action": action_type,
                "rolled_back": True,
                "asset_id": asset.id,
                "restored_status": previous_status,
            }

        # --- Account actions: re-enable / clear forced resets -----------
        if action_type in (
            "account_disable", "account_lock", "password_reset",
            "session_terminate", "token_revoke",
        ):
            user = None
            user_id = details.get("user_id")
            if user_id:
                user = await self.db.get(User, user_id)
            if user is None and target:
                stmt = select(User).where(User.email == target)
                user = (await self.db.execute(stmt)).scalars().first()
            if user is None:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": f"User {target} not found; cannot restore account state",
                }
            applied = details.get("action") or action_type.replace("account_", "")
            if applied == "disable":
                # Restore the recorded prior state; legacy records
                # (no previous_is_active) default to re-enabling.
                user.is_active = bool(details.get("previous_is_active", True))
                user.force_password_change = False
            elif applied == "password_reset":
                user.password_reset_token = None
                user.password_reset_token_expires_at = None
                user.force_password_change = False
            else:  # lock / session_terminate / token_revoke
                user.force_password_change = False
            await self.db.flush()
            await _log_ticket_activity(
                self.db,
                source_id=execution.id,
                activity_type=f"rollback_{action_type}",
                description=f"Rollback: reversed account action '{applied}' for {user.email}",
                organization_id=execution.organization_id,
                extra_metadata={
                    "user_id": user.id,
                    "reversed_action": applied,
                    "is_active": user.is_active,
                },
            )
            return {
                "action": action_type,
                "rolled_back": True,
                "user_id": user.id,
                "is_active": user.is_active,
            }

        # --- File quarantine: queue the inverse agent command -----------
        if action_type == "file_quarantine":
            from src.agents.service import AgentService, AgentServiceError
            from src.agents.models import EndpointAgent

            agent_id = details.get("agent_id")
            file_path = details.get("file_path")
            if not agent_id or not file_path:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": (
                        "quarantine record lacks agent_id/file_path; "
                        "cannot dispatch unquarantine command"
                    ),
                }
            agent = await self.db.get(EndpointAgent, agent_id)
            if agent is None:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": f"agent {agent_id} no longer enrolled",
                }
            svc = AgentService(self.db)
            try:
                cmd = await svc.issue_command(
                    agent=agent,
                    action="unquarantine_file",
                    payload={"path": file_path},
                )
            except AgentServiceError as exc:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": f"agent rejected unquarantine: {exc}",
                }
            await _log_ticket_activity(
                self.db,
                source_id=execution.id,
                activity_type="rollback_file_quarantine",
                description=(
                    f"Rollback: unquarantine queued for {file_path} "
                    f"(command_id={cmd.id})"
                ),
                organization_id=execution.organization_id,
                extra_metadata={
                    "agent_id": agent.id,
                    "file_path": file_path,
                    "command_id": cmd.id,
                },
            )
            return {
                "action": action_type,
                "rolled_back": True,
                "command_id": cmd.id,
                "detail": (
                    "unquarantine_file command queued to agent; "
                    "completion depends on agent execution"
                ),
            }

        # --- Patch deploy: restore per-instance prior statuses ----------
        if action_type == "patch_deploy":
            instances = details.get("instances")
            if not instances:
                return {
                    "action": action_type,
                    "rolled_back": False,
                    "reason": (
                        "no per-instance prior status recorded; "
                        "cannot restore vulnerability instance statuses"
                    ),
                }
            restored = 0
            for entry in instances:
                inst = await self.db.get(VulnerabilityInstance, entry.get("instance_id"))
                if inst is not None and entry.get("previous_status"):
                    inst.status = entry["previous_status"]
                    restored += 1
            await self.db.flush()
            await _log_ticket_activity(
                self.db,
                source_id=execution.id,
                activity_type="rollback_patch_deploy",
                description=f"Rollback: restored {restored} vulnerability instance status(es)",
                organization_id=execution.organization_id,
                extra_metadata={"instances_restored": restored},
            )
            return {
                "action": action_type,
                "rolled_back": restored > 0,
                "instances_restored": restored,
                **({} if restored else {"reason": "no matching instances found"}),
            }

        # --- Known-irreversible actions: report honestly ----------------
        if action_type in self.IRREVERSIBLE_ACTIONS:
            return {
                "action": action_type,
                "rolled_back": False,
                "reversible": False,
                "reason": f"not reversible: {self.IRREVERSIBLE_ACTIONS[action_type]}",
            }

        return {
            "action": action_type,
            "rolled_back": False,
            "reversible": False,
            "reason": f"not reversible: no rollback handler for action type '{action_type}'",
        }

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

    async def _rollback_ip_blocks(
        self,
        block_commands: list[dict],
        target: str,
        execution: RemediationExecution,
    ) -> list[dict]:
        """Queue an ``unblock_ip`` on every agent that got a ``block_ip``.

        Reads the ``block_commands`` the FirewallBlockExecutor recorded and,
        for each agent whose block was queued, issues the inverse command
        through ``AgentService`` (with ``approval_override`` — the rollback
        decision is itself the authorization). Returns one truthful result
        per agent so the caller can report a partial rollback honestly.
        """
        from src.agents.models import EndpointAgent
        from src.agents.service import AgentService, AgentServiceError

        results: list[dict] = []
        svc = AgentService(self.db)
        for bc in block_commands:
            # Only reverse blocks that were actually dispatched.
            if not bc.get("success"):
                continue
            agent_id = bc.get("agent_id")
            agent = (
                await self.db.get(EndpointAgent, agent_id) if agent_id else None
            )
            if agent is None:
                results.append({
                    "agent_id": agent_id,
                    "hostname": bc.get("hostname"),
                    "command_id": None,
                    "success": False,
                    "error": "agent not found; cannot queue unblock_ip",
                })
                continue
            try:
                cmd = await svc.issue_command(
                    agent=agent,
                    action="unblock_ip",
                    payload={"ip": target},
                    issued_by=execution.created_by,
                    approval_override=True,
                )
                results.append({
                    "agent_id": agent_id,
                    "hostname": agent.hostname,
                    "command_id": cmd.id,
                    "command_status": cmd.status,
                    "success": True,
                    "error": None,
                })
            except AgentServiceError as exc:
                results.append({
                    "agent_id": agent_id,
                    "hostname": agent.hostname,
                    "command_id": None,
                    "success": False,
                    "error": str(exc),
                })
        return results

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
        """Check if policy execution rate limit is exceeded.

        Counts real execution records for this policy created in the
        last hour rather than the lifetime execution_count.
        """
        window_start = utc_now() - timedelta(hours=1)
        stmt = (
            select(func.count())
            .select_from(RemediationExecution)
            .where(
                and_(
                    RemediationExecution.policy_id == policy.id,
                    RemediationExecution.created_at >= window_start,
                )
            )
        )
        recent_count = (await self.db.execute(stmt)).scalar() or 0
        return recent_count < policy.max_executions_per_hour


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
    """Firewall blocking executor: IOC write + real host-firewall enforcement.

    Two layers:

    1. **Detection** — registers the target as an active IOC so SIEM
       correlation and IOC matching flag any traffic to it (as before).
    2. **Enforcement** — dispatches a ``block_ip`` command to every
       enrolled, dispatchable, IR-capable endpoint agent in the
       organization. Each agent drops traffic to/from the IP at its own
       host firewall (Windows Firewall / iptables), rules tagged
       ``pysoar-block-<ip>`` so rollback can remove exactly them.

    Command dispatch goes through ``AgentService.issue_command`` which
    enforces capability checks, the high-blast approval gate
    (``block_ip`` requires second-user approval), and the tamper-evident
    hash chain. Per-agent outcomes are recorded in ``block_commands`` —
    rollback reads that list to queue the inverse ``unblock_ip``.

    When the target is not an IP or no eligible agents exist, the result
    honestly degrades to ``mode: detection_only``.
    """

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        import ipaddress

        from src.agents.capabilities import capability_allows
        from src.agents.models import EndpointAgent
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)
        if org_id is None and execution_id != "unknown":
            # Context often carries only trigger_data — fall back to the
            # execution row for the tenant scope.
            execution = await self.db.get(RemediationExecution, execution_id)
            if execution is not None:
                org_id = execution.organization_id

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

        # --- Enforcement: block_ip on every eligible endpoint agent ------
        try:
            ipaddress.ip_address(target)
            target_is_ip = True
        except ValueError:
            target_is_ip = False

        block_commands: list[dict] = []
        if target_is_ip and org_id:
            stmt = select(EndpointAgent).where(
                and_(
                    EndpointAgent.organization_id == org_id,
                    EndpointAgent.status.in_(("active", "offline")),
                )
            )
            agents = (await self.db.execute(stmt)).scalars().all()
            svc = AgentService(self.db)
            for agent in agents:
                if not capability_allows(agent.capabilities or [], "block_ip"):
                    continue  # agent not IR-enrolled — ineligible, not a failure
                try:
                    cmd = await svc.issue_command(
                        agent=agent,
                        action="block_ip",
                        payload={"ip": target},
                        issued_by=actor_id,
                    )
                    block_commands.append({
                        "agent_id": agent.id,
                        "hostname": agent.hostname,
                        "command_id": cmd.id,
                        "command_status": cmd.status,
                        "success": True,
                        "error": None,
                    })
                except AgentServiceError as exc:
                    block_commands.append({
                        "agent_id": agent.id,
                        "hostname": agent.hostname,
                        "command_id": None,
                        "command_status": None,
                        "success": False,
                        "error": str(exc),
                    })

        queued = sum(1 for c in block_commands if c["success"])
        rejected = len(block_commands) - queued
        if queued:
            mode = "enforced"
            detail = (
                f"Target registered as active IOC and block_ip queued to "
                f"{queued} endpoint agent(s)"
                + (f" ({rejected} rejected)" if rejected else "")
                + "; per-host firewall rules tagged pysoar-block-"
                + target
            )
        elif not target_is_ip:
            mode = "detection_only"
            detail = (
                "Target registered as active IOC for detection; no network "
                "enforcement performed (target is not an IP address, so no "
                "host-firewall block_ip could be dispatched)"
            )
        else:
            mode = "detection_only"
            detail = (
                "Target registered as active IOC for detection; no network "
                "enforcement performed (no IR-capable endpoint agent is "
                "enrolled to receive a block_ip command)"
            )

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="firewall_block",
            description=(
                f"Blocked IP {target} via firewall for {duration_hours}h "
                f"(mode={mode}, {queued} agent block command(s) queued)"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "target_ip": target,
                "duration_hours": duration_hours,
                "ioc_id": ioc.id,
                "expires_at": expires_at.isoformat(),
                "mode": mode,
                "block_commands": block_commands,
            },
        )

        return {
            "success": True,
            "action": "firewall_block",
            "mode": mode,
            "detail": detail,
            "target": target,
            "ioc_id": ioc.id,
            "duration_hours": duration_hours,
            "expires_at": expires_at,
            # Per-agent enforcement record — rollback reads this to queue
            # the inverse unblock_ip command per agent.
            "block_commands": block_commands,
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
            import secrets

            user.force_password_change = True
            user.password_reset_token = secrets.token_urlsafe(48)
            user.password_reset_token_expires_at = utc_now() + timedelta(hours=24)

        await self.db.flush()

        reset_meta = {}
        if action == "password_reset" and user.password_reset_token_expires_at:
            # Record ONLY the expiry timestamp. The token itself and any
            # hash/prefix of it stays out of the audit row — an attacker
            # with read access to ticket_activities can't correlate to a
            # specific token.
            reset_meta = {
                "reset_expires_at": user.password_reset_token_expires_at.isoformat(),
            }

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
                **reset_meta,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "user_id": user.id,
            "is_active": user.is_active,
            # Recorded so rollback can restore the exact prior state
            "previous_is_active": previous_active,
        }


class ProcessActionExecutor(ActionExecutor):
    """Process and file actions: queued for endpoint agent execution."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "kill")
        process_name = parameters.get("process_name")
        pid = parameters.get("pid")

        self.logger.info(
            "Dispatching process action to endpoint agent",
            extra={"target": target, "action": action},
        )

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)
        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type=f"process_{action}_no_agent",
                description=(
                    f"Process action '{action}' requested for {target} "
                    f"but no endpoint agent is enrolled for that target"
                ),
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "action": action,
                    "process_name": process_name,
                    "pid": pid,
                },
            )
            return {
                "success": False,
                "action": action,
                "target": target,
                "error": "no agent enrolled for target",
            }

        agent_action = "kill_process" if action == "kill" else action
        payload = {
            "pid": pid,
            "process_name": process_name,
        }
        try:
            cmd = await svc.issue_command(
                agent=agent,
                action=agent_action,
                payload=payload,
                issued_by=actor_id,
            )
        except AgentServiceError as exc:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type=f"process_{action}_rejected",
                description=f"Agent service rejected {action}: {exc}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "action": action,
                    "agent_id": agent.id,
                    "rejection_reason": str(exc),
                },
            )
            return {
                "success": False,
                "action": action,
                "target": target,
                "error": str(exc),
            }

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"process_{action}_queued",
            description=(
                f"Process action '{action}' queued to agent {agent.hostname} "
                f"(command_id={cmd.id}, status={cmd.status})"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "action": action,
                "process_name": process_name,
                "pid": pid,
                "agent_id": agent.id,
                "command_id": cmd.id,
                "command_status": cmd.status,
            },
        )

        return {
            "success": True,
            "action": action,
            "target": target,
            "command_id": cmd.id,
            "command_status": cmd.status,
            "agent_id": agent.id,
        }


class FileActionExecutor(ActionExecutor):
    """File-level actions queued for endpoint agent execution (quarantine_file)."""

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)
        file_path = parameters.get("file_path")
        file_hash = parameters.get("file_hash")

        self.logger.info(
            "Dispatching file quarantine to endpoint agent",
            extra={"target": target, "file_path": file_path},
        )

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)
        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="file_quarantine_no_agent",
                description=(
                    f"File quarantine requested for {file_path} on {target} "
                    f"but no endpoint agent is enrolled"
                ),
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "file_path": file_path,
                    "file_hash": file_hash,
                },
            )
            return {
                "success": False,
                "action": "file_quarantine",
                "target": target,
                "error": "no agent enrolled for target",
            }

        try:
            # Agent-side handler reads payload["path"]. The executor's
            # PARAMETERS still come in as file_path (policy author convention)
            # — we remap to path here for the agent contract.
            cmd = await svc.issue_command(
                agent=agent,
                action="quarantine_file",
                payload={
                    "path": file_path,
                },
                issued_by=actor_id,
            )
        except AgentServiceError as exc:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="file_quarantine_rejected",
                description=f"Agent service rejected file quarantine: {exc}",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={
                    "host": target,
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "agent_id": agent.id,
                    "rejection_reason": str(exc),
                },
            )
            return {
                "success": False,
                "action": "file_quarantine",
                "target": target,
                "error": str(exc),
            }

        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="file_quarantine_queued",
            description=(
                f"Quarantine queued for {file_path} on {agent.hostname} "
                f"(command_id={cmd.id})"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "file_path": file_path,
                "file_hash": file_hash,
                "agent_id": agent.id,
                "command_id": cmd.id,
                "command_status": cmd.status,
            },
        )

        return {
            "success": True,
            "action": "file_quarantine",
            "target": target,
            # file_path recorded so rollback can queue unquarantine_file
            "file_path": file_path,
            "command_id": cmd.id,
            "command_status": cmd.status,
            "agent_id": agent.id,
        }


class ForensicsCollectionExecutor(ActionExecutor):
    """Composite forensics collection: issues collect_process_list,
    collect_network_connections, and collect_memory_dump as three separate
    agent commands so each can be tracked individually in the audit chain.

    Per-sub-result reporting: each sub-command reports its own success
    independently in ``sub_results``. NO composite success/failure flag —
    that would conflate "all queued" with "two queued, one rejected" and
    hide the partial-execution reality from the caller. Callers that need
    a roll-up should compute it from sub_results themselves.
    """

    SUB_COMMANDS = (
        "collect_process_list",
        "collect_network_connections",
        "collect_memory_dump",
    )

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        from src.agents.service import AgentService, AgentServiceError

        execution_id, org_id, actor_id = _get_execution_context(context)

        svc = AgentService(self.db)
        agent = await svc.resolve_for_target(target, organization_id=org_id)

        if agent is None:
            await _log_ticket_activity(
                self.db,
                source_id=execution_id,
                activity_type="collect_forensics_no_agent",
                description=f"Forensics collection requested for {target} but no agent enrolled",
                actor_id=actor_id,
                organization_id=org_id,
                extra_metadata={"host": target},
            )
            no_agent_err = "no agent enrolled for target"
            return {
                "action": "collect_forensics",
                "target": target,
                "agent_id": None,
                "sub_results": [
                    {
                        "sub_action": sub,
                        "success": False,
                        "command_id": None,
                        "error": no_agent_err,
                    }
                    for sub in self.SUB_COMMANDS
                ],
            }

        sub_results: list[dict] = []
        for sub_action in self.SUB_COMMANDS:
            try:
                cmd = await svc.issue_command(
                    agent=agent,
                    action=sub_action,
                    payload=parameters or {},
                    issued_by=actor_id,
                )
                sub_results.append({
                    "sub_action": sub_action,
                    "success": True,
                    "command_id": cmd.id,
                    "error": None,
                })
            except AgentServiceError as exc:
                sub_results.append({
                    "sub_action": sub_action,
                    "success": False,
                    "command_id": None,
                    "error": str(exc),
                })

        queued = sum(1 for s in sub_results if s["success"])
        rejected = len(self.SUB_COMMANDS) - queued
        await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type="collect_forensics_dispatched",
            description=(
                f"Forensics dispatched on {agent.hostname}: "
                f"{queued} queued, {rejected} rejected (per sub-command, see metadata)"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "host": target,
                "agent_id": agent.id,
                "sub_results": sub_results,
            },
        )

        return {
            "action": "collect_forensics",
            "target": target,
            "agent_id": agent.id,
            "sub_results": sub_results,
        }


class NetworkActionExecutor(ActionExecutor):
    """Network actions (sinkhole, block URL, DNS sinkhole).

    PySOAR has no enforcement point for network-level blocks (no firewall
    or DNS integration dispatches from here, and the endpoint agent has
    no block action). What this executor CAN honestly do is detective:
    register the target as an active IOC so SIEM correlation and IOC
    matching flag any traffic to it. The result says so explicitly —
    ``mode: detection_only`` — instead of claiming the network changed.
    """

    async def execute(self, target: str, parameters: dict, context: dict) -> dict:
        execution_id, org_id, actor_id = _get_execution_context(context)
        action = parameters.get("action", "sinkhole")

        self.logger.info(
            "Executing network action (detection-only)",
            extra={"target": target, "action": action},
        )

        # Pick an indicator type that matches the target shape.
        indicator_type = "ipv4"
        if "://" in target:
            indicator_type = "url"
        elif any(c.isalpha() for c in target.replace(".", "")):
            indicator_type = "domain"

        now = utc_now()
        ioc = ThreatIndicator(
            id=str(uuid4()),
            value=target,
            indicator_type=indicator_type,
            is_active=True,
            is_whitelisted=False,
            severity="high",
            confidence=85,
            source="remediation_engine",
            tags=["network_action", action, "detection_only"],
            context={
                "description": (
                    f"Network action '{action}' recorded for {target}. "
                    "Detection-only: no enforcement point is integrated, "
                    "traffic is flagged via IOC matching but NOT blocked."
                ),
                "source_reference": execution_id,
                "category": "network_action",
            },
            first_seen=now,
            last_seen=now,
        )
        self.db.add(ioc)
        await self.db.flush()

        activity = await _log_ticket_activity(
            self.db,
            source_id=execution_id,
            activity_type=f"network_{action}",
            description=(
                f"Network action '{action}' recorded for {target} "
                "(detection-only — no enforcement point integrated)"
            ),
            actor_id=actor_id,
            organization_id=org_id,
            extra_metadata={
                "target": target,
                "action": action,
                "parameters": parameters,
                "ioc_id": ioc.id,
                "mode": "detection_only",
            },
        )

        return {
            "success": True,
            "action": action,
            "mode": "detection_only",
            "detail": (
                "Target registered as active IOC for detection; no network "
                "enforcement performed (no firewall/DNS integration configured)"
            ),
            "target": target,
            "ioc_id": ioc.id,
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
        # Per-instance prior statuses recorded so rollback can restore them
        updated_instances: list[dict] = []
        for inst in instances:
            updated_instances.append({
                "instance_id": inst.id,
                "previous_status": inst.status,
            })
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
            "instances": updated_instances,
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
