"""Playbook Execution Engine - Executes playbook steps"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.logging import get_logger
from src.models.playbook import ExecutionStatus, Playbook, PlaybookExecution

logger = get_logger(__name__)


class PlaybookAction:
    """Base class for playbook actions"""

    @staticmethod
    async def execute(
        action: str,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute an action and return results"""
        action_handlers = {
            "send_email": PlaybookAction._send_email,
            "send_slack": PlaybookAction._send_slack,
            "block_ip": PlaybookAction._block_ip,
            "isolate_host": PlaybookAction._isolate_host,
            "disable_user": PlaybookAction._disable_user,
            "create_ticket": PlaybookAction._create_ticket,
            "enrich_ioc": PlaybookAction._enrich_ioc,
            "run_script": PlaybookAction._run_script,
            "http_request": PlaybookAction._http_request,
            "update_alert": PlaybookAction._update_alert,
            "update_incident": PlaybookAction._update_incident,
            "add_comment": PlaybookAction._add_comment,
            "assign_to": PlaybookAction._assign_to,
            "wait": PlaybookAction._wait,
            "condition": PlaybookAction._condition,
        }

        handler = action_handlers.get(action, PlaybookAction._unknown_action)
        return await handler(parameters, context)

    @staticmethod
    async def _send_email(params: dict, context: dict) -> dict:
        """Send email notification"""
        to = params.get("to", "")
        subject = params.get("subject", "PySOAR Notification")
        body = params.get("body", "")

        # Substitute variables from context
        subject = PlaybookAction._substitute_vars(subject, context)
        body = PlaybookAction._substitute_vars(body, context)

        logger.info(f"Sending email to {to}: {subject}")
        # In production, integrate with SMTP/email service
        return {
            "success": True,
            "action": "send_email",
            "details": {"to": to, "subject": subject},
        }

    @staticmethod
    async def _send_slack(params: dict, context: dict) -> dict:
        """Send Slack notification"""
        channel = params.get("channel", "#security-alerts")
        message = params.get("message", "")

        message = PlaybookAction._substitute_vars(message, context)

        logger.info(f"Sending Slack message to {channel}")
        # In production, integrate with Slack API
        return {
            "success": True,
            "action": "send_slack",
            "details": {"channel": channel, "message_preview": message[:100]},
        }

    @staticmethod
    async def _block_ip(params: dict, context: dict) -> dict:
        """Block IP address at firewall"""
        ip = params.get("ip", context.get("source_ip", ""))
        duration = params.get("duration_hours", 24)
        firewall = params.get("firewall", "default")

        logger.info(f"Blocking IP {ip} for {duration} hours on {firewall}")
        # In production, integrate with firewall API
        return {
            "success": True,
            "action": "block_ip",
            "details": {"ip": ip, "duration_hours": duration, "firewall": firewall},
        }

    @staticmethod
    async def _isolate_host(params: dict, context: dict) -> dict:
        """Isolate host from network"""
        hostname = params.get("hostname", context.get("hostname", ""))
        method = params.get("method", "edr")  # edr, switch, firewall

        logger.info(f"Isolating host {hostname} via {method}")
        # In production, integrate with EDR/network management
        return {
            "success": True,
            "action": "isolate_host",
            "details": {"hostname": hostname, "method": method},
        }

    @staticmethod
    async def _disable_user(params: dict, context: dict) -> dict:
        """Disable user account"""
        username = params.get("username", context.get("username", ""))
        directory = params.get("directory", "active_directory")

        logger.info(f"Disabling user {username} in {directory}")
        # In production, integrate with AD/IAM
        return {
            "success": True,
            "action": "disable_user",
            "details": {"username": username, "directory": directory},
        }

    @staticmethod
    async def _create_ticket(params: dict, context: dict) -> dict:
        """Create ticket in ticketing system"""
        system = params.get("system", "jira")
        title = params.get("title", "Security Incident")
        description = params.get("description", "")
        priority = params.get("priority", "high")

        title = PlaybookAction._substitute_vars(title, context)
        description = PlaybookAction._substitute_vars(description, context)

        logger.info(f"Creating {system} ticket: {title}")
        # In production, integrate with Jira/ServiceNow
        return {
            "success": True,
            "action": "create_ticket",
            "details": {
                "system": system,
                "title": title,
                "ticket_id": f"TICKET-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            },
        }

    @staticmethod
    async def _enrich_ioc(params: dict, context: dict) -> dict:
        """Enrich IOC with threat intelligence"""
        ioc_value = params.get("value", "")
        ioc_type = params.get("type", "ip")
        sources = params.get("sources", ["virustotal", "abuseipdb"])

        logger.info(f"Enriching {ioc_type} {ioc_value} from {sources}")
        # In production, integrate with threat intel APIs
        return {
            "success": True,
            "action": "enrich_ioc",
            "details": {
                "value": ioc_value,
                "type": ioc_type,
                "reputation": "malicious",
                "confidence": 85,
            },
        }

    @staticmethod
    async def _run_script(params: dict, context: dict) -> dict:
        """Run a script/command"""
        script_type = params.get("type", "powershell")
        script = params.get("script", "")
        target = params.get("target", "local")

        logger.info(f"Running {script_type} script on {target}")
        # In production, execute via secure runner
        return {
            "success": True,
            "action": "run_script",
            "details": {"type": script_type, "target": target, "output": "Script executed"},
        }

    @staticmethod
    async def _http_request(params: dict, context: dict) -> dict:
        """Make HTTP request to external service"""
        method = params.get("method", "GET")
        url = params.get("url", "")
        headers = params.get("headers", {})
        body = params.get("body", None)

        url = PlaybookAction._substitute_vars(url, context)

        logger.info(f"Making {method} request to {url}")
        # In production, make actual HTTP request
        return {
            "success": True,
            "action": "http_request",
            "details": {"method": method, "url": url, "status_code": 200},
        }

    @staticmethod
    async def _update_alert(params: dict, context: dict) -> dict:
        """Update alert status/fields"""
        alert_id = params.get("alert_id", context.get("alert_id", ""))
        updates = params.get("updates", {})

        logger.info(f"Updating alert {alert_id}")
        return {
            "success": True,
            "action": "update_alert",
            "details": {"alert_id": alert_id, "updates": updates},
        }

    @staticmethod
    async def _update_incident(params: dict, context: dict) -> dict:
        """Update incident status/fields"""
        incident_id = params.get("incident_id", context.get("incident_id", ""))
        updates = params.get("updates", {})

        logger.info(f"Updating incident {incident_id}")
        return {
            "success": True,
            "action": "update_incident",
            "details": {"incident_id": incident_id, "updates": updates},
        }

    @staticmethod
    async def _add_comment(params: dict, context: dict) -> dict:
        """Add comment to alert/incident"""
        target_type = params.get("target_type", "incident")
        target_id = params.get("target_id", "")
        comment = params.get("comment", "")

        comment = PlaybookAction._substitute_vars(comment, context)

        logger.info(f"Adding comment to {target_type} {target_id}")
        return {
            "success": True,
            "action": "add_comment",
            "details": {"target_type": target_type, "target_id": target_id},
        }

    @staticmethod
    async def _assign_to(params: dict, context: dict) -> dict:
        """Assign alert/incident to user"""
        target_type = params.get("target_type", "incident")
        target_id = params.get("target_id", "")
        assignee = params.get("assignee", "")

        logger.info(f"Assigning {target_type} {target_id} to {assignee}")
        return {
            "success": True,
            "action": "assign_to",
            "details": {"target_type": target_type, "assignee": assignee},
        }

    @staticmethod
    async def _wait(params: dict, context: dict) -> dict:
        """Wait for specified duration"""
        seconds = params.get("seconds", 5)

        logger.info(f"Waiting {seconds} seconds")
        await asyncio.sleep(min(seconds, 60))  # Cap at 60 seconds for safety
        return {
            "success": True,
            "action": "wait",
            "details": {"waited_seconds": seconds},
        }

    @staticmethod
    async def _condition(params: dict, context: dict) -> dict:
        """Evaluate condition"""
        field = params.get("field", "")
        operator = params.get("operator", "equals")
        value = params.get("value", "")

        actual_value = context.get(field, "")

        result = False
        if operator == "equals":
            result = str(actual_value) == str(value)
        elif operator == "not_equals":
            result = str(actual_value) != str(value)
        elif operator == "contains":
            result = str(value) in str(actual_value)
        elif operator == "greater_than":
            result = float(actual_value) > float(value)
        elif operator == "less_than":
            result = float(actual_value) < float(value)

        return {
            "success": True,
            "action": "condition",
            "details": {
                "field": field,
                "operator": operator,
                "expected": value,
                "actual": actual_value,
                "result": result,
            },
            "condition_result": result,
        }

    @staticmethod
    async def _unknown_action(params: dict, context: dict) -> dict:
        """Handle unknown actions"""
        return {
            "success": False,
            "action": "unknown",
            "error": "Unknown action type",
        }

    @staticmethod
    def _substitute_vars(text: str, context: dict) -> str:
        """Substitute {{variable}} placeholders with context values"""
        import re

        def replace(match):
            var_name = match.group(1)
            return str(context.get(var_name, match.group(0)))

        return re.sub(r"\{\{(\w+)\}\}", replace, text)


class PlaybookEngine:
    """Engine for executing playbooks"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def execute(
        self,
        execution_id: str,
        notify_callback: Optional[callable] = None,
    ) -> PlaybookExecution:
        """Execute a playbook and update execution record"""
        # Get execution record
        result = await self.db.execute(
            select(PlaybookExecution).where(PlaybookExecution.id == execution_id)
        )
        execution = result.scalar_one_or_none()

        if not execution:
            raise ValueError(f"Execution {execution_id} not found")

        # Get playbook
        result = await self.db.execute(
            select(Playbook).where(Playbook.id == execution.playbook_id)
        )
        playbook = result.scalar_one_or_none()

        if not playbook:
            raise ValueError(f"Playbook {execution.playbook_id} not found")

        # Parse steps
        steps = json.loads(playbook.steps) if playbook.steps else []
        if not steps:
            execution.status = ExecutionStatus.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            await self.db.flush()
            return execution

        # Build context from input data and playbook variables
        context = {}
        if execution.input_data:
            context.update(json.loads(execution.input_data))
        if playbook.variables:
            context.update(json.loads(playbook.variables))

        # Start execution
        execution.status = ExecutionStatus.RUNNING.value
        execution.started_at = datetime.now(timezone.utc).isoformat()
        execution.current_step = 0
        await self.db.flush()

        if notify_callback:
            await notify_callback("execution_started", {
                "execution_id": execution_id,
                "playbook_id": playbook.id,
                "playbook_name": playbook.name,
            })

        step_results = []

        try:
            for i, step in enumerate(steps):
                execution.current_step = i + 1
                await self.db.flush()

                step_name = step.get("name", f"Step {i + 1}")
                action = step.get("action", "")
                parameters = step.get("parameters", {})
                timeout = step.get("timeout_seconds", 300)
                continue_on_error = step.get("continue_on_error", False)

                logger.info(f"Executing step {i + 1}/{len(steps)}: {step_name} ({action})")

                if notify_callback:
                    await notify_callback("step_started", {
                        "execution_id": execution_id,
                        "step_number": i + 1,
                        "step_name": step_name,
                        "action": action,
                    })

                try:
                    # Execute with timeout
                    step_result = await asyncio.wait_for(
                        PlaybookAction.execute(action, parameters, context),
                        timeout=timeout,
                    )

                    step_results.append({
                        "step": i + 1,
                        "name": step_name,
                        "action": action,
                        "result": step_result,
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                    })

                    # Update context with step results
                    if step_result.get("success"):
                        context[f"step_{i + 1}_result"] = step_result.get("details", {})

                    # Handle condition branching
                    if action == "condition":
                        condition_result = step_result.get("condition_result", False)
                        next_step = step.get("on_success" if condition_result else "on_failure")
                        if next_step and isinstance(next_step, int):
                            # Skip to specific step (0-indexed)
                            # This is simplified - real impl would need better flow control
                            pass

                    if notify_callback:
                        await notify_callback("step_completed", {
                            "execution_id": execution_id,
                            "step_number": i + 1,
                            "step_name": step_name,
                            "success": step_result.get("success", False),
                        })

                except asyncio.TimeoutError:
                    error_msg = f"Step {step_name} timed out after {timeout}s"
                    logger.error(error_msg)

                    step_results.append({
                        "step": i + 1,
                        "name": step_name,
                        "action": action,
                        "error": error_msg,
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                    })

                    if not continue_on_error:
                        raise Exception(error_msg)

                except Exception as e:
                    error_msg = f"Step {step_name} failed: {str(e)}"
                    logger.error(error_msg)

                    step_results.append({
                        "step": i + 1,
                        "name": step_name,
                        "action": action,
                        "error": str(e),
                        "executed_at": datetime.now(timezone.utc).isoformat(),
                    })

                    if not continue_on_error:
                        raise

            # All steps completed successfully
            execution.status = ExecutionStatus.COMPLETED.value
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.step_results = json.dumps(step_results)
            execution.output_data = json.dumps(context)

            logger.info(f"Playbook execution {execution_id} completed successfully")

            if notify_callback:
                await notify_callback("execution_completed", {
                    "execution_id": execution_id,
                    "playbook_id": playbook.id,
                    "status": "completed",
                })

        except Exception as e:
            # Execution failed
            execution.status = ExecutionStatus.FAILED.value
            execution.completed_at = datetime.now(timezone.utc).isoformat()
            execution.error_message = str(e)
            execution.error_step = execution.current_step
            execution.step_results = json.dumps(step_results)

            logger.error(f"Playbook execution {execution_id} failed: {e}")

            if notify_callback:
                await notify_callback("execution_failed", {
                    "execution_id": execution_id,
                    "playbook_id": playbook.id,
                    "error": str(e),
                    "failed_step": execution.current_step,
                })

        await self.db.flush()
        return execution
