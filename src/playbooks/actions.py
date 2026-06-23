"""Playbook actions - the building blocks of automation"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from src.core.logging import get_logger
from src.integrations.engine import ActionExecutor
from src.integrations.manager import threat_intel_manager
from src.integrations.models import ExecutionStatus

logger = get_logger(__name__)


class PlaybookAction(ABC):
    """Base class for playbook actions"""

    name: str = "base_action"
    description: str = "Base action"

    @abstractmethod
    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Execute the action and return results"""
        pass

    def validate_parameters(self, parameters: dict[str, Any]) -> bool:
        """Validate action parameters"""
        return True


class EnrichIPAction(PlaybookAction):
    """Enrich IP address with threat intelligence"""

    name = "enrich_ip"
    description = "Enrich an IP address using threat intelligence providers"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ip = parameters.get("ip") or context.get("source_ip")
        if not ip:
            return {"success": False, "error": "No IP address provided"}

        providers = parameters.get("providers")

        try:
            result = await threat_intel_manager.enrich_ip(ip, providers)
            return {
                "success": True,
                "ip": ip,
                "enrichment": result,
            }
        except Exception as e:
            logger.error(f"IP enrichment failed: {e}")
            return {"success": False, "error": str(e)}


class EnrichDomainAction(PlaybookAction):
    """Enrich domain with threat intelligence"""

    name = "enrich_domain"
    description = "Enrich a domain using threat intelligence providers"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        domain = parameters.get("domain") or context.get("domain")
        if not domain:
            return {"success": False, "error": "No domain provided"}

        providers = parameters.get("providers")

        try:
            result = await threat_intel_manager.enrich_domain(domain, providers)
            return {
                "success": True,
                "domain": domain,
                "enrichment": result,
            }
        except Exception as e:
            logger.error(f"Domain enrichment failed: {e}")
            return {"success": False, "error": str(e)}


class EnrichHashAction(PlaybookAction):
    """Enrich file hash with threat intelligence"""

    name = "enrich_hash"
    description = "Enrich a file hash using threat intelligence providers"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        file_hash = parameters.get("hash") or context.get("file_hash")
        if not file_hash:
            return {"success": False, "error": "No file hash provided"}

        providers = parameters.get("providers")

        try:
            result = await threat_intel_manager.enrich_hash(file_hash, providers)
            return {
                "success": True,
                "hash": file_hash,
                "enrichment": result,
            }
        except Exception as e:
            logger.error(f"Hash enrichment failed: {e}")
            return {"success": False, "error": str(e)}


class SendNotificationAction(PlaybookAction):
    """Send notification via various channels"""

    name = "send_notification"
    description = "Send notification via email, Slack, or Teams"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        channel = parameters.get("channel", "email")
        recipients = parameters.get("recipients", [])
        subject = parameters.get("subject", "PySOAR Alert")
        message = parameters.get("message", "")

        # Template variable substitution
        for key, value in context.items():
            message = message.replace(f"{{{{{key}}}}}", str(value))
            subject = subject.replace(f"{{{{{key}}}}}", str(value))

        # Send notification via Celery task. If the enqueue fails (broker
        # down, serialization error), the notification was NOT sent — report
        # success=False so the playbook step reflects reality instead of
        # silently claiming on-call was paged.
        try:
            from src.workers.tasks import send_notification_task
            send_notification_task.delay(
                channel=channel,
                recipients=recipients,
                subject=subject,
                message=message,
            )
            logger.info(f"Notification queued via {channel} to {recipients}")
        except Exception as e:
            logger.error(f"Failed to queue notification: {e}")
            return {
                "success": False,
                "channel": channel,
                "recipients": recipients,
                "subject": subject,
                "error": f"notification not sent: {e}",
            }

        return {
            "success": True,
            "channel": channel,
            "recipients": recipients,
            "subject": subject,
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }


class UpdateAlertAction(PlaybookAction):
    """Update alert status or fields"""

    name = "update_alert"
    description = "Update an alert's status or other fields"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        alert_id = parameters.get("alert_id") or context.get("alert_id")
        if not alert_id:
            return {"success": False, "error": "No alert ID provided"}

        updates = {
            k: v for k, v in parameters.items()
            if k in ["status", "severity", "assigned_to", "resolution_notes"]
        }

        try:
            import asyncio
            from src.core.database import async_session_factory
            from src.models.alert import Alert
            from sqlalchemy import select

            async def _update():
                async with async_session_factory() as db:
                    result = await db.execute(select(Alert).where(Alert.id == alert_id))
                    alert = result.scalars().first()
                    if alert:
                        for key, value in updates.items():
                            if hasattr(alert, key):
                                setattr(alert, key, value)
                        await db.commit()
                        return True
                    return False

            loop = asyncio.new_event_loop()
            updated = loop.run_until_complete(_update())
            loop.close()
            logger.info(f"Updated alert {alert_id}: {updated}")
        except Exception as e:
            logger.error(f"Failed to update alert {alert_id}: {e}")
            updated = False

        return {
            "success": updated,
            "alert_id": alert_id,
            "updates": updates,
        }


class CreateIncidentAction(PlaybookAction):
    """Create a new incident"""

    name = "create_incident"
    description = "Create a new incident from an alert"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        title = parameters.get("title") or context.get("alert_title", "New Incident")
        severity = parameters.get("severity") or context.get("severity", "medium")

        try:
            import asyncio, uuid
            from src.core.database import async_session_factory
            from src.models.incident import Incident

            async def _create():
                async with async_session_factory() as db:
                    incident = Incident(
                        id=str(uuid.uuid4()),
                        title=title,
                        description=parameters.get("description", f"Auto-created from playbook. Alert: {context.get('alert_id', 'N/A')}"),
                        severity=severity,
                        status="open",
                        incident_type=parameters.get("type", "other"),
                    )
                    db.add(incident)
                    await db.commit()
                    return incident.id

            loop = asyncio.new_event_loop()
            incident_id = loop.run_until_complete(_create())
            loop.close()
            logger.info(f"Created incident {incident_id}: {title}")
        except Exception as e:
            logger.error(f"Failed to create incident: {e}")
            incident_id = None

        return {
            "success": incident_id is not None,
            "incident_created": incident_id is not None,
            "incident_id": incident_id,
            "title": title,
            "severity": severity,
        }


class ExecuteIntegrationAction(PlaybookAction):
    """Execute a configured integration connector action"""

    name = "execute_integration_action"
    description = "Execute a configured integration action using an installed connector"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        installation_id = parameters.get("installation_id")
        action_name = parameters.get("action_name")
        input_data = parameters.get("input_data", {}) or {}

        if not installation_id or not action_name:
            return {"success": False, "error": "installation_id and action_name are required"}

        try:
            executor = ActionExecutor()
            execution = await executor.execute_action(
                installation_id=installation_id,
                action_name=action_name,
                input_data=input_data,
                triggered_by="playbook",
                playbook_run_id=context.get("playbook_execution_id"),
            )

            return {
                "success": execution.get("status") == ExecutionStatus.SUCCESS.value,
                "execution": execution,
            }
        except Exception as e:
            logger.error(f"Integration action execution failed: {e}")
            return {"success": False, "error": str(e)}


class VirusTotalEnrichAndNotifyAction(PlaybookAction):
    """Enrich an IOC with VirusTotal and notify via Slack"""

    name = "virus_total_enrich_and_notify"
    description = "Enrich an IOC using VirusTotal and send a Slack notification with the results"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        ioc_type = parameters.get("ioc_type")
        value = parameters.get("value")
        vt_installation_id = parameters.get("virustotal_installation_id")
        slack_installation_id = parameters.get("slack_installation_id")
        slack_channel = parameters.get("slack_channel")
        message_template = parameters.get(
            "message_template",
            "VirusTotal enrichment completed for {value}: {summary}",
        )

        if not ioc_type or not value:
            return {"success": False, "error": "ioc_type and value are required"}
        if not vt_installation_id or not slack_installation_id:
            return {"success": False, "error": "virustotal_installation_id and slack_installation_id are required"}
        if not slack_channel:
            return {"success": False, "error": "slack_channel is required"}

        vt_action_map = {
            "ip": "scan_ip",
            "domain": "scan_domain",
            "hash": "scan_file",
            "url": "scan_url",
        }
        vt_action = vt_action_map.get(ioc_type.lower())
        if not vt_action:
            return {"success": False, "error": f"Unsupported IOC type: {ioc_type}"}

        try:
            executor = ActionExecutor()

            vt_result = await executor.execute_action(
                installation_id=vt_installation_id,
                action_name=vt_action,
                input_data={ioc_type: value},
                triggered_by="playbook",
                playbook_run_id=context.get("playbook_execution_id"),
            )

            if vt_result.get("status") != ExecutionStatus.SUCCESS.value:
                return {"success": False, "error": "VirusTotal enrichment failed", "details": vt_result}

            vt_output = vt_result.get("output_data") or {}
            indicator_id = await self._upsert_threat_indicator(
                ioc_type=ioc_type,
                value=value,
                enrichment=vt_output,
                context=context,
            )

            summary = self._summarize_vt_output(value, vt_output)
            message = message_template.format(value=value, summary=summary)

            slack_result = await executor.execute_action(
                installation_id=slack_installation_id,
                action_name="send_message",
                input_data={
                    "channel": slack_channel,
                    "text": message,
                },
                triggered_by="playbook",
                playbook_run_id=context.get("playbook_execution_id"),
            )

            return {
                "success": slack_result.get("status") == ExecutionStatus.SUCCESS.value,
                "virus_total": vt_output,
                "slack": slack_result,
                "indicator_id": indicator_id,
            }
        except Exception as e:
            logger.error(f"VirusTotal enrichment workflow failed: {e}")
            return {"success": False, "error": str(e)}

    async def _upsert_threat_indicator(
        self,
        ioc_type: str,
        value: str,
        enrichment: dict[str, Any],
        context: dict[str, Any],
    ) -> str:
        from sqlalchemy import select
        from src.core.database import async_session_factory
        from src.intel.models import ThreatIndicator

        organization_id = context.get("organization_id")
        async with async_session_factory() as db:
            result = await db.execute(
                select(ThreatIndicator).where(
                    ThreatIndicator.indicator_type == ioc_type,
                    ThreatIndicator.value == value,
                    ThreatIndicator.organization_id == organization_id,
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.confidence = enrichment.get("malicious", existing.confidence)
                existing.severity = "high" if enrichment.get("malicious", 0) > 0 else existing.severity
                existing.tags = list(
                    set(existing.tags or [])
                    | set(enrichment.get("tags", []))
                )
                existing.context = {**existing.context, "virustotal": enrichment}
                await db.commit()
                return existing.id

            indicator = ThreatIndicator(
                indicator_type=ioc_type,
                value=value,
                source="VirusTotal",
                confidence=enrichment.get("malicious"),
                severity="high" if enrichment.get("malicious", 0) > 0 else "medium",
                tags=enrichment.get("tags", []),
                context={"virustotal": enrichment},
                organization_id=organization_id,
            )
            db.add(indicator)
            await db.commit()
            return indicator.id

    def _summarize_vt_output(self, value: str, vt_output: dict[str, Any]) -> str:
        malicious = vt_output.get("malicious")
        suspicious = vt_output.get("suspicious")
        reputation = vt_output.get("reputation")
        summary_parts = []

        if malicious is not None:
            summary_parts.append(f"malicious={malicious}")
        if suspicious is not None:
            summary_parts.append(f"suspicious={suspicious}")
        if reputation is not None:
            summary_parts.append(f"reputation={reputation}")

        return ", ".join(summary_parts) if summary_parts else "no detailed results"


class RunScriptAction(PlaybookAction):
    """Execute a custom script or command"""

    name = "run_script"
    description = "Execute a predefined script"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        script_name = parameters.get("script_name")
        script_args = parameters.get("arguments", {})

        if not script_name:
            return {"success": False, "error": "No script name provided"}

        import subprocess
        try:
            cmd = [script_name] + [str(v) for v in script_args.values()] if script_args else [script_name]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=False)
            logger.info(f"Script {script_name} completed with return code {result.returncode}")
            output = result.stdout[:2000] if result.stdout else ""
            error = result.stderr[:500] if result.stderr else ""
        except subprocess.TimeoutExpired:
            output = ""
            error = "Script timed out after 60 seconds"
            result = type("R", (), {"returncode": -1})()
        except FileNotFoundError:
            output = ""
            error = f"Script not found: {script_name}"
            result = type("R", (), {"returncode": -1})()
        except Exception as e:
            output = ""
            error = str(e)
            result = type("R", (), {"returncode": -1})()

        return {
            "success": result.returncode == 0,
            "script": script_name,
            "arguments": script_args,
            "return_code": result.returncode,
            "output": output,
            "error": error,
        }


class ConditionalAction(PlaybookAction):
    """Evaluate a condition and branch execution"""

    name = "conditional"
    description = "Evaluate a condition for branching"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        field = parameters.get("field")
        operator = parameters.get("operator", "equals")
        value = parameters.get("value")

        if not field:
            return {"success": False, "error": "No field specified for condition"}

        # Get the actual value from context
        actual_value = context.get(field)

        # Evaluate condition
        result = False
        if operator == "equals":
            result = actual_value == value
        elif operator == "not_equals":
            result = actual_value != value
        elif operator == "contains":
            result = value in str(actual_value) if actual_value else False
        elif operator == "greater_than":
            result = float(actual_value) > float(value) if actual_value else False
        elif operator == "less_than":
            result = float(actual_value) < float(value) if actual_value else False
        elif operator == "exists":
            result = actual_value is not None
        elif operator == "not_exists":
            result = actual_value is None

        return {
            "success": True,
            "condition_met": result,
            "field": field,
            "operator": operator,
            "expected": value,
            "actual": actual_value,
        }


class WaitAction(PlaybookAction):
    """Wait for a specified duration"""

    name = "wait"
    description = "Pause execution for a specified time"

    async def execute(
        self,
        parameters: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        import asyncio

        seconds = parameters.get("seconds", 0)
        reason = parameters.get("reason", "Scheduled wait")

        if seconds > 0:
            await asyncio.sleep(min(seconds, 300))  # Max 5 minutes

        return {
            "success": True,
            "waited_seconds": seconds,
            "reason": reason,
        }


# Action registry
ACTION_REGISTRY: dict[str, type[PlaybookAction]] = {
    "enrich_ip": EnrichIPAction,
    "enrich_domain": EnrichDomainAction,
    "enrich_hash": EnrichHashAction,
    "send_notification": SendNotificationAction,
    "update_alert": UpdateAlertAction,
    "create_incident": CreateIncidentAction,
    "run_script": RunScriptAction,
    "conditional": ConditionalAction,
    "wait": WaitAction,
    "execute_integration_action": ExecuteIntegrationAction,
    "virus_total_enrich_and_notify": VirusTotalEnrichAndNotifyAction,
}


def get_action(action_name: str) -> Optional[PlaybookAction]:
    """Get an action instance by name"""
    action_class = ACTION_REGISTRY.get(action_name)
    if action_class:
        return action_class()
    return None


def list_available_actions() -> list[dict[str, str]]:
    """List all available actions"""
    return [
        {"name": name, "description": cls.description}
        for name, cls in ACTION_REGISTRY.items()
    ]
