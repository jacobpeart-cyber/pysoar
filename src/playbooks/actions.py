"""Playbook actions - the building blocks of automation"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

from src.core.logging import get_logger
from src.integrations.manager import threat_intel_manager

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

        # In production, this would actually send notifications
        logger.info(
            f"Sending notification via {channel}",
            recipients=recipients,
            subject=subject,
        )

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

        # In production, this would update the database
        logger.info(f"Updating alert {alert_id}", updates=updates)

        return {
            "success": True,
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

        # In production, this would create in database
        logger.info(f"Creating incident: {title}")

        return {
            "success": True,
            "incident_created": True,
            "title": title,
            "severity": severity,
        }


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

        # In production, this would execute approved scripts
        logger.info(f"Executing script: {script_name}", arguments=script_args)

        return {
            "success": True,
            "script": script_name,
            "arguments": script_args,
            "output": "Script execution simulated",
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
