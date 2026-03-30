"""PagerDuty API connector for incident response and on-call management"""

from typing import Any, Dict, Optional

from src.integrations.connectors.base import BaseConnector
from src.core.logging import get_logger

logger = get_logger(__name__)


class PagerDutyConnector(BaseConnector):
    """PagerDuty connector for incident management and on-call scheduling"""

    name = "pagerduty"
    base_url = "https://api.pagerduty.com"

    def _get_headers(self) -> Dict[str, str]:
        """Add PagerDuty token to headers"""
        headers = super()._get_headers()
        if token := self.credentials.get("api_token"):
            headers["Authorization"] = f"Token token={token}"
        headers["Accept"] = "application/vnd.pagerduty+json;version=2"
        return headers

    async def execute_action(self, action_name: str, params: Dict) -> Dict[str, Any]:
        """Execute PagerDuty action"""
        actions = {
            "create_incident": self.create_incident,
            "acknowledge_incident": self.acknowledge_incident,
            "resolve_incident": self.resolve_incident,
            "trigger_event": self.trigger_event,
            "list_oncall": self.list_oncall,
            "get_service": self.get_service,
        }

        if action := actions.get(action_name):
            return await action(**params)
        raise ValueError(f"Unknown action: {action_name}")

    async def create_incident(
        self,
        service_id: str,
        title: str,
        details: str,
        urgency: str = "high"
    ) -> Dict[str, Any]:
        """Create incident - POST /incidents"""
        if not self.is_configured:
            return {"error": "PagerDuty token not configured"}

        try:
            user_id = self.credentials.get("user_id", "")

            data = await self._make_request(
                "POST",
                "/incidents",
                json_data={
                    "incident": {
                        "title": title,
                        "description": details,
                        "service": {
                            "id": service_id,
                            "type": "service_reference",
                        },
                        "urgency": urgency,
                        "assignments": [
                            {
                                "assignee": {
                                    "id": user_id,
                                    "type": "user_reference",
                                }
                            }
                        ] if user_id else [],
                    }
                }
            )

            incident = data.get("incident", {})
            return {
                "provider": self.name,
                "success": True,
                "incident_id": incident.get("id"),
                "incident_number": incident.get("incident_number"),
                "status": incident.get("status"),
                "url": incident.get("html_url"),
            }
        except Exception as e:
            logger.error(f"PagerDuty create_incident error: {e}")
            return {"error": str(e)}

    async def acknowledge_incident(self, incident_id: str) -> Dict[str, Any]:
        """Acknowledge incident - PUT /incidents/{id}"""
        if not self.is_configured:
            return {"error": "PagerDuty token not configured"}

        try:
            data = await self._make_request(
                "PUT",
                f"/incidents/{incident_id}",
                json_data={
                    "incident": {
                        "status": "acknowledged",
                    }
                }
            )

            incident = data.get("incident", {})
            return {
                "provider": self.name,
                "success": True,
                "incident_id": incident_id,
                "status": incident.get("status"),
            }
        except Exception as e:
            logger.error(f"PagerDuty acknowledge_incident error: {e}")
            return {"error": str(e), "incident_id": incident_id}

    async def resolve_incident(self, incident_id: str) -> Dict[str, Any]:
        """Resolve incident - PUT /incidents/{id}"""
        if not self.is_configured:
            return {"error": "PagerDuty token not configured"}

        try:
            data = await self._make_request(
                "PUT",
                f"/incidents/{incident_id}",
                json_data={
                    "incident": {
                        "status": "resolved",
                    }
                }
            )

            incident = data.get("incident", {})
            return {
                "provider": self.name,
                "success": True,
                "incident_id": incident_id,
                "status": incident.get("status"),
            }
        except Exception as e:
            logger.error(f"PagerDuty resolve_incident error: {e}")
            return {"error": str(e), "incident_id": incident_id}

    async def trigger_event(
        self,
        routing_key: str,
        summary: str,
        severity: str = "error",
        details: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Trigger event - POST to events API v2"""
        if not routing_key:
            return {"error": "PagerDuty routing key not provided"}

        try:
            events_url = "https://events.pagerduty.com/v2/enqueue"

            data = await self._make_request(
                "POST",
                "",
                json_data={
                    "routing_key": routing_key,
                    "event_action": "trigger",
                    "payload": {
                        "summary": summary,
                        "severity": severity,
                        "source": "PySOAR",
                        "custom_details": details or {},
                    }
                }
            )

            return {
                "provider": self.name,
                "success": data.get("status") == "success",
                "dedup_key": data.get("dedup_key"),
            }
        except Exception as e:
            logger.error(f"PagerDuty trigger_event error: {e}")
            return {"error": str(e)}

    async def list_oncall(self, schedule_id: str) -> Dict[str, Any]:
        """List on-call - GET /oncalls"""
        if not self.is_configured:
            return {"error": "PagerDuty token not configured"}

        try:
            data = await self._make_request(
                "GET",
                "/oncalls",
                params={
                    "schedule_ids": [schedule_id],
                    "limit": 100,
                }
            )

            oncalls = []
            for oncall in data.get("oncalls", []):
                oncalls.append({
                    "id": oncall.get("id"),
                    "user": oncall.get("user", {}).get("summary"),
                    "schedule": oncall.get("schedule", {}).get("summary"),
                    "start": oncall.get("start"),
                    "end": oncall.get("end"),
                })

            return {
                "provider": self.name,
                "schedule_id": schedule_id,
                "oncall_count": len(oncalls),
                "oncalls": oncalls,
            }
        except Exception as e:
            logger.error(f"PagerDuty list_oncall error: {e}")
            return {"error": str(e), "schedule_id": schedule_id}

    async def get_service(self, service_id: str) -> Dict[str, Any]:
        """Get service - GET /services/{id}"""
        if not self.is_configured:
            return {"error": "PagerDuty token not configured"}

        try:
            data = await self._make_request(
                "GET",
                f"/services/{service_id}"
            )

            service = data.get("service", {})
            return {
                "provider": self.name,
                "service_id": service_id,
                "name": service.get("summary"),
                "status": service.get("status"),
                "escalation_policy": service.get("escalation_policy", {}).get("summary"),
                "teams": [t.get("summary") for t in service.get("teams", [])],
                "urgency": service.get("urgency_rule", {}).get("type"),
            }
        except Exception as e:
            logger.error(f"PagerDuty get_service error: {e}")
            return {"error": str(e), "service_id": service_id}
