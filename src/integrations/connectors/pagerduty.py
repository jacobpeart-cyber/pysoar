"""PagerDuty REST API v2 and Events API v2 connector (developer.pagerduty.com).

REST: ``Authorization: Token token=<api token>``,
``Accept: application/vnd.pagerduty+json;version=2``, and a ``From: <email of
a valid user>`` header on incident writes (required for account-level API
keys). Events API v2: ``POST https://events.pagerduty.com/v2/enqueue`` with a
per-service routing key in the body and no REST token.
"""

from typing import Any, Dict, List, Optional

from src.core.logging import get_logger
from src.integrations.connectors.base import (
    ActionSpec,
    BaseConnector,
    ConnectionTestResult,
    field_spec,
    object_schema,
    path_segment,
)

logger = get_logger(__name__)

EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"
_INCIDENT_ID = {"type": "string", "minLength": 1, "description": "PagerDuty incident id"}


class PagerDutyConnector(BaseConnector):
    """PagerDuty connector for incident management and on-call scheduling"""

    name = "pagerduty"
    base_url = "https://api.pagerduty.com"

    CREDENTIAL_FIELDS = [
        field_spec("api_token", "REST API token", "PagerDuty REST API key (account or user token)", secret=True),
        field_spec(
            "user_id", "Default assignee user id",
            "Optional PagerDuty user id that new incidents are assigned to", required=False,
        ),
    ]
    CONFIG_FIELDS = [
        field_spec(
            "from_email", "From email",
            "Email of a valid PagerDuty user, sent as the From header on incident writes",
        ),
    ]
    TEST_CALL = "GET /abilities"
    ACTIONS = {
        "create_incident": ActionSpec(
            "Create an incident on a service (POST /incidents).",
            object_schema({
                "service_id": {"type": "string", "minLength": 1},
                "title": {"type": "string", "minLength": 1},
                "details": {"type": "string"},
                "urgency": {"type": "string", "enum": ["high", "low"]},
            }, ["service_id", "title"]),
            "incident id, number, status, html_url",
            idempotent=False, side_effect=True, action_type="create", display_name="Create incident",
        ),
        "acknowledge_incident": ActionSpec(
            "Acknowledge an incident (PUT /incidents/{id}).",
            object_schema({"incident_id": _INCIDENT_ID}, ["incident_id"]),
            "incident id and status",
            idempotent=True, side_effect=True, action_type="update", display_name="Acknowledge incident",
        ),
        "resolve_incident": ActionSpec(
            "Resolve an incident (PUT /incidents/{id}).",
            object_schema({"incident_id": _INCIDENT_ID}, ["incident_id"]),
            "incident id and status",
            idempotent=True, side_effect=True, action_type="update", display_name="Resolve incident",
        ),
        "trigger_event": ActionSpec(
            "Send a trigger event to a service integration (Events API v2, POST /v2/enqueue).",
            object_schema({
                "routing_key": {"type": "string", "minLength": 1, "description": "Events API v2 integration key"},
                "summary": {"type": "string", "minLength": 1},
                "severity": {"type": "string", "enum": ["critical", "error", "warning", "info"]},
                "details": {"type": "object"},
            }, ["routing_key", "summary"]),
            "status and dedup_key",
            idempotent=False, side_effect=True, action_type="notify", display_name="Trigger event",
        ),
        "list_oncall": ActionSpec(
            "Who is on call for a schedule (GET /oncalls?schedule_ids[]=...).",
            object_schema({"schedule_id": {"type": "string", "minLength": 1}}, ["schedule_id"]),
            "on-call entries (user, schedule, start, end)",
            idempotent=True, side_effect=False, action_type="query", display_name="List on-call",
        ),
        "get_service": ActionSpec(
            "Read a service (GET /services/{id}).",
            object_schema({"service_id": {"type": "string", "minLength": 1}}, ["service_id"]),
            "name, status, escalation policy, teams, urgency rule",
            idempotent=True, side_effect=False, action_type="query", display_name="Get service",
        ),
    }

    def _get_headers(self) -> Dict[str, str]:
        """Add PagerDuty token to headers"""
        headers = super()._get_headers()
        if token := self.credentials.get("api_token"):
            headers["Authorization"] = f"Token token={token}"
        headers["Accept"] = "application/vnd.pagerduty+json;version=2"
        return headers

    def _from(self) -> Dict[str, str]:
        return {"From": str(self.config.get("from_email") or "")}

    async def test_connection(self) -> ConnectionTestResult:
        # /abilities works for account-level and user tokens alike; /users/me
        # answers 400 for account-level keys.
        return await self._probe(self.TEST_CALL, lambda: self._make_request("GET", "/abilities"))

    async def create_incident(
        self, service_id: str, title: str, details: str = "", urgency: str = "high",
    ) -> Dict[str, Any]:
        """Create incident - POST /incidents"""
        incident: Dict[str, Any] = {
            "type": "incident",
            "title": title,
            "service": {"id": service_id, "type": "service_reference"},
            "urgency": urgency,
        }
        if details:
            incident["body"] = {"type": "incident_body", "details": details}
        if user_id := self.credentials.get("user_id"):
            incident["assignments"] = [{"assignee": {"id": user_id, "type": "user_reference"}}]
        data = await self._make_request("POST", "/incidents", json_data={"incident": incident}, headers=self._from())
        result = data.get("incident") or {}
        return {
            "provider": self.name,
            "success": True,
            "incident_id": result.get("id"),
            "incident_number": result.get("incident_number"),
            "status": result.get("status"),
            "url": result.get("html_url"),
        }

    async def _set_status(self, incident_id: str, new_status: str) -> Dict[str, Any]:
        data = await self._make_request(
            "PUT",
            f"/incidents/{path_segment(incident_id)}",
            json_data={"incident": {"type": "incident_reference", "status": new_status}},
            headers=self._from(),
        )
        result = data.get("incident") or {}
        return {"provider": self.name, "success": True, "incident_id": incident_id, "status": result.get("status")}

    async def acknowledge_incident(self, incident_id: str) -> Dict[str, Any]:
        """Acknowledge incident - PUT /incidents/{id}"""
        return await self._set_status(incident_id, "acknowledged")

    async def resolve_incident(self, incident_id: str) -> Dict[str, Any]:
        """Resolve incident - PUT /incidents/{id}"""
        return await self._set_status(incident_id, "resolved")

    async def trigger_event(
        self, routing_key: str, summary: str, severity: str = "error", details: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Trigger event - POST https://events.pagerduty.com/v2/enqueue (202 Accepted)"""
        data = await self._make_request(
            "POST",
            EVENTS_API_URL,
            json_data={
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": summary,
                    "severity": severity,
                    "source": "PySOAR",
                    "custom_details": details or {},
                },
            },
            auth=False,
        )
        return {
            "provider": self.name,
            "success": data.get("status") == "success",
            "errors": data.get("errors") or data.get("message"),
            "dedup_key": data.get("dedup_key"),
        }

    async def list_oncall(self, schedule_id: str) -> Dict[str, Any]:
        """List on-call - GET /oncalls?schedule_ids[]=<id>"""
        data = await self._make_request("GET", "/oncalls", params={"schedule_ids[]": schedule_id, "limit": 100})
        oncalls: List[Dict[str, Any]] = [
            {
                "user": (o.get("user") or {}).get("summary"),
                "schedule": (o.get("schedule") or {}).get("summary"),
                "escalation_level": o.get("escalation_level"),
                "start": o.get("start"),
                "end": o.get("end"),
            }
            for o in data.get("oncalls") or []
        ]
        return {"provider": self.name, "schedule_id": schedule_id, "oncall_count": len(oncalls), "oncalls": oncalls}

    async def get_service(self, service_id: str) -> Dict[str, Any]:
        """Get service - GET /services/{id}"""
        data = await self._make_request("GET", f"/services/{path_segment(service_id)}")
        service = data.get("service") or {}
        return {
            "provider": self.name,
            "service_id": service_id,
            "name": service.get("summary") or service.get("name"),
            "status": service.get("status"),
            "escalation_policy": (service.get("escalation_policy") or {}).get("summary"),
            "teams": [t.get("summary") for t in service.get("teams") or []],
            "urgency": (service.get("incident_urgency_rule") or {}).get("type"),
        }
