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

        recipients = [to] if isinstance(to, str) else to
        sent = False
        try:
            from src.services.email_service import EmailService
            email_service = EmailService()
            if email_service.is_configured:
                sent = await email_service.send_email(
                    to=recipients,
                    subject=subject,
                    body=body,
                    html_body=params.get("html_body"),
                )
            else:
                logger.warning("Email service not configured, cannot send email")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return {
                "success": False,
                "action": "send_email",
                "error": str(e),
                "details": {"to": to, "subject": subject},
            }

        return {
            "success": sent,
            "action": "send_email",
            "details": {"to": to, "subject": subject, "sent": sent},
        }

    @staticmethod
    async def _send_slack(params: dict, context: dict) -> dict:
        """Send Slack notification"""
        channel = params.get("channel", "#security-alerts")
        message = params.get("message", "")

        message = PlaybookAction._substitute_vars(message, context)

        logger.info(f"Sending Slack message to {channel}")

        sent = False
        try:
            import httpx
            from src.core.config import settings
            webhook_url = params.get("webhook_url") or settings.slack_webhook_url
            if webhook_url:
                payload = {"text": message}
                if channel:
                    payload["channel"] = channel
                async with httpx.AsyncClient() as client:
                    resp = await client.post(webhook_url, json=payload, timeout=10)
                    sent = resp.status_code == 200
            else:
                logger.warning("No Slack webhook URL configured")
        except Exception as e:
            logger.error(f"Failed to send Slack message: {e}")
            return {
                "success": False,
                "action": "send_slack",
                "error": str(e),
                "details": {"channel": channel, "message_preview": message[:100]},
            }

        return {
            "success": sent,
            "action": "send_slack",
            "details": {"channel": channel, "message_preview": message[:100], "sent": sent},
        }

    @staticmethod
    async def _block_ip(params: dict, context: dict) -> dict:
        """Block IP address at firewall"""
        ip = params.get("ip", context.get("source_ip", ""))
        duration = params.get("duration_hours", 24)
        firewall = params.get("firewall", "default")

        logger.info(f"Blocking IP {ip} for {duration} hours on {firewall}")

        try:
            from src.core.database import async_session_factory
            from src.tickethub.models import TicketActivity

            async with async_session_factory() as session:
                activity = TicketActivity(
                    source_type="remediation",
                    source_id=context.get("alert_id", context.get("incident_id", "unknown")),
                    activity_type="block_ip",
                    actor_id=context.get("user_id"),
                    description=f"Blocked IP {ip} for {duration} hours on firewall '{firewall}'",
                    extra_metadata=json.dumps({
                        "ip": ip,
                        "duration_hours": duration,
                        "firewall": firewall,
                    }),
                )
                session.add(activity)
                await session.commit()

            logger.info(f"Recorded IP block action for {ip}")
        except Exception as e:
            logger.error(f"Failed to record IP block action: {e}")
            return {
                "success": False,
                "action": "block_ip",
                "error": str(e),
                "details": {"ip": ip, "duration_hours": duration, "firewall": firewall},
            }

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

        try:
            from src.core.database import async_session_factory
            from src.tickethub.models import TicketActivity

            async with async_session_factory() as session:
                activity = TicketActivity(
                    source_type="remediation",
                    source_id=context.get("alert_id", context.get("incident_id", "unknown")),
                    activity_type="isolate_host",
                    actor_id=context.get("user_id"),
                    description=f"Isolated host {hostname} via {method}",
                    extra_metadata=json.dumps({
                        "hostname": hostname,
                        "method": method,
                    }),
                )
                session.add(activity)
                await session.commit()

            logger.info(f"Recorded host isolation action for {hostname}")
        except Exception as e:
            logger.error(f"Failed to record host isolation action: {e}")
            return {
                "success": False,
                "action": "isolate_host",
                "error": str(e),
                "details": {"hostname": hostname, "method": method},
            }

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

        disabled = False
        try:
            from src.core.database import async_session_factory
            from src.models.user import User
            from src.tickethub.models import TicketActivity

            async with async_session_factory() as session:
                # Find the user by email (username)
                result = await session.execute(
                    select(User).where(User.email == username)
                )
                user = result.scalar_one_or_none()

                if user:
                    user.is_active = False
                    disabled = True
                    logger.info(f"Disabled user account: {username}")

                    # Record the action for audit trail
                    activity = TicketActivity(
                        source_type="remediation",
                        source_id=context.get("alert_id", context.get("incident_id", "unknown")),
                        activity_type="disable_user",
                        actor_id=context.get("user_id"),
                        description=f"Disabled user {username} in {directory}",
                        old_value="active",
                        new_value="disabled",
                        extra_metadata=json.dumps({
                            "username": username,
                            "directory": directory,
                            "user_id": user.id,
                        }),
                    )
                    session.add(activity)
                    await session.commit()
                else:
                    logger.warning(f"User not found in local database: {username}")
        except Exception as e:
            logger.error(f"Failed to disable user: {e}")
            return {
                "success": False,
                "action": "disable_user",
                "error": str(e),
                "details": {"username": username, "directory": directory},
            }

        return {
            "success": True,
            "action": "disable_user",
            "details": {"username": username, "directory": directory, "disabled": disabled},
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

        ticket_id = None
        try:
            from src.core.database import async_session_factory
            from src.tickethub.models import TicketActivity, TicketComment

            source_id = context.get("alert_id", context.get("incident_id", "unknown"))
            source_type = "incident" if context.get("incident_id") else "alert"

            async with async_session_factory() as session:
                # Create a ticket activity to record ticket creation
                activity = TicketActivity(
                    source_type=source_type,
                    source_id=source_id,
                    activity_type="create_ticket",
                    actor_id=context.get("user_id"),
                    description=f"Created {system} ticket: {title} (priority: {priority})",
                    extra_metadata=json.dumps({
                        "system": system,
                        "title": title,
                        "priority": priority,
                    }),
                )
                session.add(activity)

                # Add description as a comment on the ticket
                comment = TicketComment(
                    source_type=source_type,
                    source_id=source_id,
                    content=f"[{system} Ticket] {title}\n\nPriority: {priority}\n\n{description}",
                    author_id=context.get("user_id", "system"),
                )
                session.add(comment)
                await session.commit()

                ticket_id = activity.id
                logger.info(f"Created ticket record {ticket_id} for {system}")
        except Exception as e:
            logger.error(f"Failed to create ticket: {e}")
            return {
                "success": False,
                "action": "create_ticket",
                "error": str(e),
                "details": {"system": system, "title": title},
            }

        return {
            "success": True,
            "action": "create_ticket",
            "details": {
                "system": system,
                "title": title,
                "ticket_id": ticket_id or f"TICKET-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            },
        }

    @staticmethod
    async def _enrich_ioc(params: dict, context: dict) -> dict:
        """Enrich IOC with threat intelligence"""
        ioc_value = params.get("value", "")
        ioc_type = params.get("type", "ip")
        sources = params.get("sources", ["virustotal", "abuseipdb"])

        logger.info(f"Enriching {ioc_type} {ioc_value} from {sources}")

        enrichment_results = {}
        try:
            from src.core.database import async_session_factory
            from src.intel.models import ThreatIndicator

            async with async_session_factory() as session:
                # Query the unified threat_indicators table
                ti_result = await session.execute(
                    select(ThreatIndicator).where(
                        ThreatIndicator.value == ioc_value,
                        ThreatIndicator.is_active == True,
                    )
                )
                indicators = list(ti_result.scalars().all())

                for indicator in indicators:
                    enrichment_results[f"threat_intel_{indicator.feed_id or indicator.id[:8]}"] = {
                        "confidence": indicator.confidence,
                        "severity": indicator.severity,
                        "tags": indicator.tags,
                        "context": indicator.context,
                        "source": indicator.source,
                        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
                        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
                    }

                # Stash aggregated enrichment into the first match's context
                if indicators:
                    primary = indicators[0]
                    ctx = dict(primary.context) if isinstance(primary.context, dict) else {}
                    existing_enr = dict(ctx.get("enrichment_data") or {})
                    existing_enr.update(enrichment_results)
                    ctx["enrichment_data"] = existing_enr
                    ctx["last_enriched"] = datetime.now(timezone.utc).isoformat()
                    primary.context = ctx
                    await session.commit()

        except Exception as e:
            logger.error(f"Failed to enrich IOC: {e}")
            return {
                "success": False,
                "action": "enrich_ioc",
                "error": str(e),
                "details": {"value": ioc_value, "type": ioc_type},
            }

        confidence = 50
        reputation = "unknown"
        if enrichment_results:
            scores = [r.get("confidence", 50) for r in enrichment_results.values() if r.get("confidence")]
            confidence = int(sum(scores) / len(scores)) if scores else 50
            reputation = "malicious" if confidence >= 70 else "suspicious" if confidence >= 40 else "benign"

        return {
            "success": True,
            "action": "enrich_ioc",
            "details": {
                "value": ioc_value,
                "type": ioc_type,
                "reputation": reputation,
                "confidence": confidence,
                "enrichment_sources": list(enrichment_results.keys()),
            },
        }

    @staticmethod
    async def _run_script(params: dict, context: dict) -> dict:
        """Run a script/command"""
        import subprocess
        import shlex

        script_type = params.get("type", "powershell")
        script = params.get("script", "")
        target = params.get("target", "local")
        timeout = min(params.get("timeout_seconds", 30), 60)  # Cap at 60s

        logger.info(f"Running {script_type} script on {target}")

        if target != "local":
            return {
                "success": False,
                "action": "run_script",
                "error": "Only local script execution is supported",
                "details": {"type": script_type, "target": target},
            }

        if not script:
            return {
                "success": False,
                "action": "run_script",
                "error": "No script provided",
                "details": {"type": script_type, "target": target},
            }

        try:
            # Build command based on script type
            if script_type == "powershell":
                command = ["powershell", "-NoProfile", "-NonInteractive", "-Command", script]
            elif script_type == "bash":
                command = ["bash", "-c", script]
            elif script_type == "python":
                command = ["python", "-c", script]
            else:
                command = shlex.split(script)

            result = subprocess.run(
                command,
                capture_output=True,
                timeout=timeout,
                text=True,
                shell=False,
            )

            output = result.stdout[:4096] if result.stdout else ""
            stderr = result.stderr[:2048] if result.stderr else ""

            return {
                "success": result.returncode == 0,
                "action": "run_script",
                "details": {
                    "type": script_type,
                    "target": target,
                    "return_code": result.returncode,
                    "output": output,
                    "stderr": stderr,
                },
            }
        except subprocess.TimeoutExpired:
            logger.error(f"Script execution timed out after {timeout}s")
            return {
                "success": False,
                "action": "run_script",
                "error": f"Script timed out after {timeout} seconds",
                "details": {"type": script_type, "target": target},
            }
        except Exception as e:
            logger.error(f"Script execution failed: {e}")
            return {
                "success": False,
                "action": "run_script",
                "error": str(e),
                "details": {"type": script_type, "target": target},
            }

    @staticmethod
    async def _http_request(params: dict, context: dict) -> dict:
        """Make HTTP request to external service"""
        import httpx

        method = params.get("method", "GET").upper()
        url = params.get("url", "")
        headers = params.get("headers", {})
        body = params.get("body", None)
        timeout = min(params.get("timeout_seconds", 30), 120)

        url = PlaybookAction._substitute_vars(url, context)

        logger.info(f"Making {method} request to {url}")

        if not url:
            return {
                "success": False,
                "action": "http_request",
                "error": "No URL provided",
                "details": {"method": method, "url": url},
            }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.request(
                    method=method,
                    url=url,
                    json=body if body else None,
                    headers=headers,
                    timeout=timeout,
                )

            response_body = response.text[:4096] if response.text else ""

            return {
                "success": 200 <= response.status_code < 400,
                "action": "http_request",
                "details": {
                    "method": method,
                    "url": url,
                    "status_code": response.status_code,
                    "response_body": response_body,
                    "response_headers": dict(response.headers),
                },
            }
        except httpx.TimeoutException:
            logger.error(f"HTTP request to {url} timed out")
            return {
                "success": False,
                "action": "http_request",
                "error": f"Request timed out after {timeout} seconds",
                "details": {"method": method, "url": url},
            }
        except Exception as e:
            logger.error(f"HTTP request failed: {e}")
            return {
                "success": False,
                "action": "http_request",
                "error": str(e),
                "details": {"method": method, "url": url},
            }

    @staticmethod
    async def _update_alert(params: dict, context: dict) -> dict:
        """Update alert status/fields"""
        alert_id = params.get("alert_id", context.get("alert_id", ""))
        updates = params.get("updates", {})

        logger.info(f"Updating alert {alert_id} with {updates}")

        if not alert_id:
            return {
                "success": False,
                "action": "update_alert",
                "error": "No alert_id provided",
                "details": {"updates": updates},
            }

        ALLOWED_FIELDS = {"status", "priority", "assigned_to", "severity", "resolution_notes"}
        filtered_updates = {k: v for k, v in updates.items() if k in ALLOWED_FIELDS}

        try:
            from src.core.database import async_session_factory
            from src.models.alert import Alert

            async with async_session_factory() as session:
                result = await session.execute(
                    select(Alert).where(Alert.id == alert_id)
                )
                alert = result.scalar_one_or_none()

                if not alert:
                    return {
                        "success": False,
                        "action": "update_alert",
                        "error": f"Alert {alert_id} not found",
                        "details": {"alert_id": alert_id, "updates": filtered_updates},
                    }

                for field, value in filtered_updates.items():
                    setattr(alert, field, value)

                # If status changed to resolved, set resolved_at
                if filtered_updates.get("status") == "resolved":
                    alert.resolved_at = datetime.now(timezone.utc).isoformat()

                await session.flush()
                await session.commit()
                logger.info(f"Successfully updated alert {alert_id}: {filtered_updates}")

        except Exception as e:
            logger.error(f"Failed to update alert {alert_id}: {e}")
            return {
                "success": False,
                "action": "update_alert",
                "error": str(e),
                "details": {"alert_id": alert_id, "updates": filtered_updates},
            }

        return {
            "success": True,
            "action": "update_alert",
            "details": {"alert_id": alert_id, "updates": filtered_updates},
        }

    @staticmethod
    async def _update_incident(params: dict, context: dict) -> dict:
        """Update incident status/fields"""
        incident_id = params.get("incident_id", context.get("incident_id", ""))
        updates = params.get("updates", {})

        logger.info(f"Updating incident {incident_id} with {updates}")

        if not incident_id:
            return {
                "success": False,
                "action": "update_incident",
                "error": "No incident_id provided",
                "details": {"updates": updates},
            }

        ALLOWED_FIELDS = {"status", "priority", "assigned_to", "severity", "resolution",
                          "root_cause", "impact", "lessons_learned", "recommendations"}
        filtered_updates = {k: v for k, v in updates.items() if k in ALLOWED_FIELDS}

        try:
            from src.core.database import async_session_factory
            from src.models.incident import Incident

            async with async_session_factory() as session:
                result = await session.execute(
                    select(Incident).where(Incident.id == incident_id)
                )
                incident = result.scalar_one_or_none()

                if not incident:
                    return {
                        "success": False,
                        "action": "update_incident",
                        "error": f"Incident {incident_id} not found",
                        "details": {"incident_id": incident_id, "updates": filtered_updates},
                    }

                for field, value in filtered_updates.items():
                    setattr(incident, field, value)

                # If status changed to closed, set resolved_at
                if filtered_updates.get("status") == "closed":
                    incident.resolved_at = datetime.now(timezone.utc).isoformat()

                await session.flush()
                await session.commit()
                logger.info(f"Successfully updated incident {incident_id}: {filtered_updates}")

        except Exception as e:
            logger.error(f"Failed to update incident {incident_id}: {e}")
            return {
                "success": False,
                "action": "update_incident",
                "error": str(e),
                "details": {"incident_id": incident_id, "updates": filtered_updates},
            }

        return {
            "success": True,
            "action": "update_incident",
            "details": {"incident_id": incident_id, "updates": filtered_updates},
        }

    @staticmethod
    async def _add_comment(params: dict, context: dict) -> dict:
        """Add comment to alert/incident — persists a real TicketComment row."""
        target_type = params.get("target_type", "incident")
        target_id = params.get("target_id", context.get("incident_id", context.get("alert_id", "")))
        comment_text = params.get("comment", "")
        comment_text = PlaybookAction._substitute_vars(comment_text, context)

        if not target_id or not comment_text:
            return {
                "success": False,
                "action": "add_comment",
                "error": "target_id and comment are required",
                "details": {"target_type": target_type, "target_id": target_id},
            }

        try:
            from src.core.database import async_session_factory
            from src.tickethub.models import TicketComment

            async with async_session_factory() as session:
                row = TicketComment(
                    source_type=target_type,
                    source_id=target_id,
                    content=comment_text,
                    author_id=context.get("user_id", "playbook_engine"),
                )
                session.add(row)
                await session.commit()
                logger.info(f"Added comment {row.id} to {target_type}/{target_id}")

            return {
                "success": True,
                "action": "add_comment",
                "details": {
                    "target_type": target_type,
                    "target_id": target_id,
                    "comment_id": row.id,
                    "comment_preview": comment_text[:100],
                },
            }
        except Exception as e:
            logger.error(f"Failed to add comment: {e}")
            return {
                "success": False,
                "action": "add_comment",
                "error": str(e),
                "details": {"target_type": target_type, "target_id": target_id},
            }

    @staticmethod
    async def _assign_to(params: dict, context: dict) -> dict:
        """Assign alert/incident to user — writes real assigned_to on the DB row."""
        target_type = params.get("target_type", "incident")
        target_id = params.get("target_id", context.get("incident_id", context.get("alert_id", "")))
        assignee = params.get("assignee", "")

        if not target_id or not assignee:
            return {
                "success": False,
                "action": "assign_to",
                "error": "target_id and assignee are required",
                "details": {"target_type": target_type, "assignee": assignee},
            }

        try:
            from src.core.database import async_session_factory

            async with async_session_factory() as session:
                if target_type == "incident":
                    from src.models.incident import Incident
                    result = await session.execute(
                        select(Incident).where(Incident.id == target_id)
                    )
                    record = result.scalar_one_or_none()
                elif target_type == "alert":
                    from src.models.alert import Alert
                    result = await session.execute(
                        select(Alert).where(Alert.id == target_id)
                    )
                    record = result.scalar_one_or_none()
                else:
                    record = None

                if not record:
                    return {
                        "success": False,
                        "action": "assign_to",
                        "error": f"{target_type} {target_id} not found",
                        "details": {"target_type": target_type, "target_id": target_id},
                    }

                record.assigned_to = assignee
                await session.commit()
                logger.info(f"Assigned {target_type}/{target_id} to {assignee}")

            return {
                "success": True,
                "action": "assign_to",
                "details": {
                    "target_type": target_type,
                    "target_id": target_id,
                    "assignee": assignee,
                },
            }
        except Exception as e:
            logger.error(f"Failed to assign: {e}")
            return {
                "success": False,
                "action": "assign_to",
                "error": str(e),
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
            i = 0
            while i < len(steps):
                step = steps[i]

                # Respect jump directive from a prior condition step
                jump_target = context.pop("_condition_jump_to", None)
                if jump_target is not None and isinstance(jump_target, int):
                    i = jump_target
                    if i >= len(steps):
                        break
                    step = steps[i]

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

                    # Condition branching: if the step was a condition evaluation,
                    # check for on_success / on_failure jump targets. A target of
                    # "skip" means skip the next step; an int means jump to that
                    # step index (0-based). The jump is implemented by fast-forwarding
                    # the iterator — we break out of the current step, slice the
                    # remaining steps, and re-enter the loop.
                    if action == "condition":
                        condition_result = step_result.get("condition_result", False)
                        branch_key = "on_success" if condition_result else "on_failure"
                        branch_target = step.get(branch_key)
                        if branch_target == "skip":
                            # Skip the next step by consuming it
                            context["_condition_skip_next"] = True
                        elif isinstance(branch_target, int) and 0 <= branch_target < len(steps):
                            # Jump: we can't easily re-index a for-loop in Python, so
                            # we record the jump target and the outer loop will respect it.
                            context["_condition_jump_to"] = branch_target

                    # Respect skip directive from a prior condition step
                    if context.pop("_condition_skip_next", False):
                        continue

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

                i += 1

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
